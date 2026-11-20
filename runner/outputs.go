package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/falahat/dispatch-service/internal/artifact"
)

// outputsDir is the workdir folder the compute writes its outputs under.
const outputsDir = "outputs"

// outputUploads bounds how many files of one folder output upload at once, and
// inputFetches how many input blobs download at once.
const (
	outputUploads = 8
	inputFetches  = 8
)

// Outputs are untrusted compute data. The runner reads them through an os.Root
// pinned to the outputs folder it created before invoking, so no path, link or
// later rename can make it read a file outside that folder. Only regular files
// with a single link and plain folders are published: a link, a hard link or a
// special file fails the job, so a manifest only ever names plain files.

// outputViolation is a compute breaking the output rules. Retrying the same
// computation breaks them again, so the job fails as fatal.
type outputViolation struct{ reason string }

func (v *outputViolation) Error() string { return "outputs: " + v.reason }

func violation(format string, args ...any) error {
	return &outputViolation{reason: fmt.Sprintf(format, args...)}
}

// publishOutputs uploads every named output. made is the outputs folder as the
// runner created it; a folder found there under another identity is refused.
func (r *Runner) publishOutputs(ctx context.Context, outputsPath string, made os.FileInfo, named map[string]string) (map[string]artifact.Output, error) {
	root, err := os.OpenRoot(outputsPath)
	if err != nil {
		return nil, violation("open outputs folder: %v", err)
	}
	defer root.Close()
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(opened, made) {
		return nil, violation("the outputs folder was replaced during the run")
	}
	published := make(map[string]artifact.Output, len(named))
	for name, rel := range named {
		inner, err := insideOutputs(rel)
		if err != nil {
			return nil, err
		}
		output, err := r.publishOutput(ctx, root, inner)
		if err != nil {
			return nil, err
		}
		published[name] = output
	}
	return published, nil
}

// insideOutputs maps a result path ("outputs/a/b") to its name inside the
// outputs folder ("a/b", or "." for the folder itself).
func insideOutputs(rel string) (string, error) {
	if err := artifact.ValidateRelPath(rel); err != nil {
		return "", violation("%v", err)
	}
	if rel != outputsDir && !strings.HasPrefix(rel, outputsDir+"/") {
		return "", violation("%q is not under %s/", rel, outputsDir)
	}
	return path.Clean("." + strings.TrimPrefix(rel, outputsDir)), nil
}

func (r *Runner) publishOutput(ctx context.Context, root *os.Root, name string) (artifact.Output, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return artifact.Output{}, violation("%v", err)
	}
	switch {
	case info.Mode().IsRegular():
		address, size, err := r.putOutputFile(ctx, root, name, info)
		return artifact.Output{Address: address, Size: size, Kind: artifact.KindBlob}, err
	case info.IsDir():
		return r.putOutputFolder(ctx, root, name)
	default:
		return artifact.Output{}, violation("%q is not a regular file or a folder", name)
	}
}

// putOutputFile uploads one file read through root. The opened file must be the
// regular, singly linked file that was listed, so a swap after listing is refused.
func (r *Runner) putOutputFile(ctx context.Context, root *os.Root, name string, listed os.FileInfo) (artifact.Address, int64, error) {
	file, err := root.Open(name)
	if err != nil {
		return "", 0, violation("%v", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", 0, violation("%v", err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(info, listed) {
		return "", 0, violation("%q changed while it was published", name)
	}
	if hardLinked(info) {
		return "", 0, violation("%q has more than one hard link", name)
	}
	address, err := r.cas.PutOpenFile(ctx, file, info.Size())
	return address, info.Size(), err
}

type outputFile struct {
	name string // slash path inside the outputs folder
	info os.FileInfo
}

// putOutputFolder uploads a folder's files and returns a manifest of them, with
// paths relative to the folder and sorted, so equal folders share an address.
func (r *Runner) putOutputFolder(ctx context.Context, root *os.Root, dir string) (artifact.Output, error) {
	var files []outputFile
	err := fs.WalkDir(root.FS(), dir, func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return violation("%v", err)
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return violation("%q is not a regular file", name)
		}
		if len(files) == artifact.MaxManifestEntries {
			return violation("folder %q holds more than %d files", dir, artifact.MaxManifestEntries)
		}
		info, err := entry.Info()
		if err != nil {
			return violation("%v", err)
		}
		files = append(files, outputFile{name: name, info: info})
		return nil
	})
	if err != nil {
		return artifact.Output{}, err
	}
	slices.SortFunc(files, func(a, b outputFile) int { return strings.Compare(a.name, b.name) })
	addresses, err := r.putOutputFiles(ctx, root, files)
	if err != nil {
		return artifact.Output{}, err
	}
	manifest := artifact.Manifest{Kind: artifact.ManifestKind, Entries: make([]artifact.ManifestEntry, len(files))}
	for i, file := range files {
		manifest.Entries[i] = artifact.ManifestEntry{
			Path: strings.TrimPrefix(file.name, dir+"/"), Address: addresses[i], Size: file.info.Size(),
		}
	}
	if err := manifest.Validate(); err != nil {
		return artifact.Output{}, violation("folder %q: %v", dir, err)
	}
	body, err := json.Marshal(manifest)
	if err != nil {
		return artifact.Output{}, err
	}
	address, err := r.cas.PutBytes(ctx, body)
	return artifact.Output{Address: address, Size: int64(len(body)), Kind: artifact.KindManifest}, err
}

// putOutputFiles uploads files with at most outputUploads in flight and stops
// at the first error.
func (r *Runner) putOutputFiles(ctx context.Context, root *os.Root, files []outputFile) ([]artifact.Address, error) {
	addresses := make([]artifact.Address, len(files))
	uploads, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		workers sync.WaitGroup
		failed  sync.Once
		first   error
	)
	next := make(chan int)
	for range outputUploads {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range next {
				address, _, err := r.putOutputFile(uploads, root, files[i].name, files[i].info)
				if err != nil {
					failed.Do(func() { first = err; cancel() })
					continue
				}
				addresses[i] = address
			}
		}()
	}
feed:
	for i := range files {
		select {
		case next <- i:
		case <-uploads.Done():
			break feed
		}
	}
	close(next)
	workers.Wait()
	if first != nil {
		return nil, first
	}
	return addresses, ctx.Err()
}

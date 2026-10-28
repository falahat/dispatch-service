package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/falahat/dispatch-service/internal/artifact"
)

// fileCAS uses the same verified byte protocol inside one owner's private root.
// It exposes no listener; remote deployments continue to use the authenticated PEP.
type fileCAS struct{ root string }

func (c fileCAS) RoundTrip(request *http.Request) (*http.Response, error) {
	digest := strings.TrimPrefix(request.URL.Path, "/blobs/sha256/")
	if err := (artifact.Address("sha256:" + digest)).Validate(); err != nil {
		return nil, err
	}
	path := filepath.Join(c.root, "blobs", "sha256", digest)
	response := &http.Response{Header: make(http.Header), Request: request, Body: http.NoBody}
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			response.StatusCode = http.StatusNotFound
			return response, nil
		}
		if err != nil {
			return nil, err
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			file.Close()
			return nil, fmt.Errorf("local CAS requires a regular file")
		}
		response.StatusCode, response.ContentLength = http.StatusOK, info.Size()
		response.Body = file
		if request.Method == http.MethodHead {
			file.Close()
			response.Body = http.NoBody
		}
	case http.MethodPut:
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			return nil, err
		}
		file, err := os.CreateTemp(filepath.Dir(path), ".upload-")
		if err != nil {
			return nil, err
		}
		defer os.Remove(file.Name())
		hash := sha256.New()
		_, copyErr := io.Copy(io.MultiWriter(file, hash), request.Body)
		closeErr := file.Close()
		if copyErr != nil || closeErr != nil || hex.EncodeToString(hash.Sum(nil)) != digest {
			return nil, fmt.Errorf("local CAS upload failed integrity verification")
		}
		if err := os.Rename(file.Name(), path); err != nil {
			return nil, err
		}
		response.StatusCode = http.StatusCreated
	default:
		response.StatusCode = http.StatusMethodNotAllowed
	}
	return response, nil
}

//go:build unix

package runner

import (
	"os"
	"syscall"
)

// hardLinked reports whether a file has another name. A hard link in an output
// could publish a file the compute was never given, so outputs refuse it.
func hardLinked(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return !ok || uint64(stat.Nlink) != 1
}

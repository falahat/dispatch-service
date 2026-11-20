//go:build !unix

package runner

import "os"

// hardLinked cannot read a link count here. Runners deploy on Linux, where
// links_unix.go refuses hard-linked outputs.
func hardLinked(os.FileInfo) bool { return false }

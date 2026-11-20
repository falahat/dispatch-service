//go:build !(linux || darwin)

package runner

import (
	"context"
	"errors"
)

// takeGPULock needs flock, which this platform lacks.
func takeGPULock(context.Context, string) (func(), error) {
	return nil, errors.New("gpu lock: not supported on this platform")
}

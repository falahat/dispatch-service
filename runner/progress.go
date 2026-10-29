package runner

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// This file belongs to the installed executor, outside untrusted workload mounts.
func (r *Runner) commandProgress(jobID string) (json.RawMessage, error) {
	if len(r.cfg.Command) == 0 || jobID == "" {
		return nil, nil
	}
	file, err := os.Open(filepath.Join(r.cfg.WorkRoot, jobID, "invoke-progress.json"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, (1<<14)+1))
	if err != nil {
		return nil, err
	}
	var object map[string]json.RawMessage
	if len(data) > 1<<14 || json.Unmarshal(data, &object) != nil || object == nil {
		return nil, fmt.Errorf("command progress must be an object of at most 16 KiB")
	}
	return data, nil
}

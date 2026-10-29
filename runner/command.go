package runner

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

type executor interface {
	WaitReady(context.Context) (Health, error)
	Healthz(context.Context) (Health, error)
	Invoke(context.Context, InvokeRequest) (*InvokeResult, *InvokeFailure, error)
}

// The owner fixes the executable at installation. Invocation data never selects
// a host command. It reads InvokeRequest on stdin and writes invoke-result.json.
type commandExecutor struct {
	args     []string
	id, node string
}

func (c *commandExecutor) Healthz(context.Context) (Health, error) {
	_, err := exec.LookPath(c.args[0])
	return Health{Ready: err == nil, Op: "command", OpVersion: 1}, err
}

func (c *commandExecutor) WaitReady(ctx context.Context) (Health, error) {
	return c.Healthz(ctx)
}

func (c *commandExecutor) Invoke(ctx context.Context, request InvokeRequest) (*InvokeResult, *InvokeFailure, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return nil, nil, err
	}
	log, err := os.OpenFile(filepath.Join(request.Workdir, "invoke.log"), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, nil, err
	}
	defer log.Close()
	command := exec.CommandContext(ctx, c.args[0], c.args[1:]...)
	command.Dir, command.Stdin = request.Workdir, bytes.NewReader(body)
	command.Env = append(os.Environ(), "DISPATCH_WORKDIR="+request.Workdir,
		"DISPATCH_RUNNER_ID="+c.id, "DISPATCH_RUNNER_NODE="+c.node)
	command.Stdout, command.Stderr = log, log
	// A trusted executor handles SIGTERM by cancelling its own children/containers.
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	if err := command.Run(); err != nil && (ctx.Err() == nil || command.ProcessState == nil || command.ProcessState.ExitCode() != 0) {
		return nil, &InvokeFailure{ErrClass: "fatal", Message: err.Error()}, nil
	}
	file, err := os.Open(filepath.Join(request.Workdir, "invoke-result.json"))
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, 1<<20))
	decoder.DisallowUnknownFields()
	var result InvokeResult
	if err := decoder.Decode(&result); err != nil {
		return nil, nil, fmt.Errorf("command result: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return nil, nil, fmt.Errorf("command result contains trailing data")
	}
	return &result, nil, nil
}

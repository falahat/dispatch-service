package runner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/falahat/dispatch-service/internal/wire"
)

// GPU offering (WIRE.md "GPU placement", COMMAND.md). A runner started with
// --gpus reads its GPUs with nvidia-smi each time it asks for work and offers
// them; a grant names the one GPU its job may use, and the runner shows the
// command only that GPU.

// nvidiaSMI is the reading command; tests replace it.
var nvidiaSMI = "nvidia-smi"

// ParseGPUDevices checks a --gpus value: "all" or comma-separated host indexes.
func ParseGPUDevices(spec string) (all bool, indexes map[int]bool, err error) {
	if spec == "all" {
		return true, nil, nil
	}
	indexes = map[int]bool{}
	for _, f := range strings.Split(spec, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n < 0 || n > 63 {
			return false, nil, fmt.Errorf("gpus: %q is not \"all\" or a list of GPU indexes", spec)
		}
		indexes[n] = true
	}
	return false, indexes, nil
}

// readGPUs reads the GPUs named by spec. With a machine GPU lock each GPU is
// offered whole: holding the lock gives a job the GPU to itself, and a resident
// server under the same lock frees its memory when a job asks for it.
func readGPUs(ctx context.Context, spec string, locked bool) ([]wire.GPUReading, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	list, err := exec.CommandContext(ctx, nvidiaSMI, "--query-gpu=index,uuid,memory.total,memory.free",
		"--format=csv,noheader,nounits").Output()
	if err != nil {
		return nil, fmt.Errorf("nvidia-smi: %w", err)
	}
	apps, err := exec.CommandContext(ctx, nvidiaSMI, "--query-compute-apps=gpu_uuid,process_name",
		"--format=csv,noheader").Output()
	if err != nil {
		return nil, fmt.Errorf("nvidia-smi: %w", err)
	}
	gpus, err := parseGPUs(string(list), string(apps), spec)
	if locked {
		for i := range gpus {
			gpus[i].FreeMB, gpus[i].Processes = gpus[i].TotalMB, 0
		}
	}
	return gpus, err
}

// parseGPUs turns nvidia-smi's GPU list and compute-process list into readings
// for the GPUs spec names. The MPS server is not counted as a process.
func parseGPUs(list, apps, spec string) ([]wire.GPUReading, error) {
	all, indexes, err := ParseGPUDevices(spec)
	if err != nil {
		return nil, err
	}
	processes := map[string]int{}
	for _, line := range strings.Split(apps, "\n") {
		uuid, name, ok := strings.Cut(line, ",")
		if ok && filepath.Base(strings.TrimSpace(name)) != "nvidia-cuda-mps-server" {
			processes[strings.TrimSpace(uuid)]++
		}
	}
	var out []wire.GPUReading
	for _, line := range strings.Split(strings.TrimSpace(list), "\n") {
		f := strings.Split(line, ",")
		if len(f) != 4 {
			return nil, fmt.Errorf("nvidia-smi: unexpected line %q", line)
		}
		index, e1 := strconv.Atoi(strings.TrimSpace(f[0]))
		total, e2 := strconv.Atoi(strings.TrimSpace(f[2]))
		free, e3 := strconv.Atoi(strings.TrimSpace(f[3]))
		if err := errors.Join(e1, e2, e3); err != nil {
			return nil, fmt.Errorf("nvidia-smi: line %q: %w", line, err)
		}
		if all || indexes[index] {
			uuid := strings.TrimSpace(f[1])
			out = append(out, wire.GPUReading{Index: index, UUID: uuid, TotalMB: total, FreeMB: free, Processes: processes[uuid]})
		}
	}
	return out, nil
}

// offerGPUs reads the runner's GPUs for a request for work. A failed reading
// offers none, so the runner still takes jobs that need no GPU.
func (r *Runner) offerGPUs(ctx context.Context) []wire.GPUReading {
	if r.cfg.GPUs == "" {
		return nil
	}
	gpus, err := readGPUs(ctx, r.cfg.GPUs, r.cfg.GPULock != "")
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		if time.Since(r.gpuWarned) > time.Minute {
			r.log.Warn("cannot read GPUs; offering none", "err", err)
			r.gpuWarned = time.Now()
		}
		gpus = nil
	}
	r.offered = gpus
	return gpus
}

// wasOffered reports whether the runner's latest request offered this GPU.
func (r *Runner) wasOffered(g *wire.GrantGPU) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.offered {
		if o.UUID == g.UUID && o.Index == g.Index {
			return true
		}
	}
	return false
}

// gpuEnv replaces the GPU variables a command inherits: a granted job sees only
// its GPU, a job without one sees none. MPS clients join the machine's daemon
// only when it answers.
func gpuEnv(ctx context.Context, env []string, g *wire.GrantGPU, mpsPipe string) []string {
	out := env[:0:0]
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if name != "NVIDIA_VISIBLE_DEVICES" && name != "CUDA_VISIBLE_DEVICES" &&
			!strings.HasPrefix(name, "CUDA_MPS_") && !strings.HasPrefix(name, "DISPATCH_GPU_") {
			out = append(out, kv)
		}
	}
	if g == nil {
		return append(out, "CUDA_VISIBLE_DEVICES=")
	}
	out = append(out, "NVIDIA_VISIBLE_DEVICES="+strconv.Itoa(g.Index), "CUDA_VISIBLE_DEVICES="+g.UUID,
		"DISPATCH_GPU_INDEX="+strconv.Itoa(g.Index), "DISPATCH_GPU_UUID="+g.UUID,
		"DISPATCH_GPU_MEMORY_MB="+strconv.Itoa(g.MemoryMB), "DISPATCH_GPU_MODE="+string(g.Mode))
	if g.Mode == wire.GPUMPS && mpsPipe != "" && mpsAnswers(ctx, mpsPipe) {
		out = append(out, "CUDA_MPS_PIPE_DIRECTORY="+mpsPipe)
	}
	return out
}

// mpsAnswers reports whether an MPS control daemon serves the pipe directory.
func mpsAnswers(ctx context.Context, pipe string) bool {
	if _, err := os.Stat(filepath.Join(pipe, "control")); err != nil {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	check := exec.CommandContext(ctx, "nvidia-cuda-mps-control")
	check.Stdin = strings.NewReader("get_server_list\n")
	check.Env = append(os.Environ(), "CUDA_MPS_PIPE_DIRECTORY="+pipe)
	return check.Run() == nil
}

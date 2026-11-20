package runner

import (
	"context"
	"reflect"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

func TestParseGPUsReadsNvidiaSMI(t *testing.T) {
	list := "0, GPU-aaaaaaaa-0000-0000-0000-000000000001, 24564, 23000\n1, GPU-bbbbbbbb-0000-0000-0000-000000000002, 8192, 100\n"
	apps := "GPU-aaaaaaaa-0000-0000-0000-000000000001, /usr/bin/nvidia-cuda-mps-server\n" +
		"GPU-bbbbbbbb-0000-0000-0000-000000000002, python3\nGPU-bbbbbbbb-0000-0000-0000-000000000002, /opt/app/worker\n"
	got, err := parseGPUs(list, apps, "all")
	want := []wire.GPUReading{
		{Index: 0, UUID: "GPU-aaaaaaaa-0000-0000-0000-000000000001", TotalMB: 24564, FreeMB: 23000, Processes: 0},
		{Index: 1, UUID: "GPU-bbbbbbbb-0000-0000-0000-000000000002", TotalMB: 8192, FreeMB: 100, Processes: 2},
	}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("all: %+v %v", got, err)
	}
	if got, err := parseGPUs(list, "", "1"); err != nil || len(got) != 1 || got[0].Index != 1 {
		t.Fatalf("index 1: %+v %v", got, err)
	}
	if _, err := parseGPUs("0, GPU-x, [N/A], 10\n", "", "all"); err == nil {
		t.Fatal("an unreadable memory figure must fail the reading")
	}
	for _, spec := range []string{"", "gpu0", "-1", "0,,1"} {
		if _, _, err := ParseGPUDevices(spec); err == nil {
			t.Fatalf("spec %q accepted", spec)
		}
	}
}

func TestGPUEnvShowsOnlyTheGrantedGPU(t *testing.T) {
	inherited := []string{"PATH=/bin", "NVIDIA_VISIBLE_DEVICES=all", "CUDA_VISIBLE_DEVICES=0,1", "CUDA_MPS_PIPE_DIRECTORY=/tmp/mps", "DISPATCH_GPU_UUID=stale"}
	grant := &wire.GrantGPU{Index: 1, UUID: "GPU-bbbbbbbb-0000-0000-0000-000000000002", MemoryMB: 3000, Mode: wire.GPUMPS}
	got := gpuEnv(context.Background(), inherited, grant, "")
	want := []string{"PATH=/bin", "NVIDIA_VISIBLE_DEVICES=1", "CUDA_VISIBLE_DEVICES=GPU-bbbbbbbb-0000-0000-0000-000000000002",
		"DISPATCH_GPU_INDEX=1", "DISPATCH_GPU_UUID=GPU-bbbbbbbb-0000-0000-0000-000000000002",
		"DISPATCH_GPU_MEMORY_MB=3000", "DISPATCH_GPU_MODE=mps"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("granted: %q", got)
	}
	if got := gpuEnv(context.Background(), inherited, nil, ""); !reflect.DeepEqual(got, []string{"PATH=/bin", "CUDA_VISIBLE_DEVICES="}) {
		t.Fatalf("no grant: %q", got)
	}
	if inherited[1] != "NVIDIA_VISIBLE_DEVICES=all" {
		t.Fatal("gpuEnv changed the inherited environment in place")
	}
}

func TestGrantedGPUMustHaveBeenOffered(t *testing.T) {
	r := New(Config{RunnerID: "r", Lanes: []string{"embed"}, Command: []string{"true"}}, nil, nil, nil)
	r.offered = []wire.GPUReading{{Index: 0, UUID: "GPU-aaaaaaaa-0000-0000-0000-000000000001", TotalMB: 1, FreeMB: 1}}
	if !r.wasOffered(&wire.GrantGPU{Index: 0, UUID: "GPU-aaaaaaaa-0000-0000-0000-000000000001"}) ||
		r.wasOffered(&wire.GrantGPU{Index: 1, UUID: "GPU-aaaaaaaa-0000-0000-0000-000000000001"}) {
		t.Fatal("offer check")
	}
}

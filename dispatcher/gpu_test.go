package dispatcher

import (
	"context"
	"testing"

	"github.com/falahat/dispatch-service/internal/wire"
)

const (
	gpuA = "GPU-aaaaaaaa-0000-0000-0000-000000000001"
	gpuB = "GPU-bbbbbbbb-0000-0000-0000-000000000002"
)

func gpuJob(t *testing.T, d *Dispatcher, key, lane string, memoryMB int, mode wire.GPUMode) string {
	t.Helper()
	return enqueueOne(t, d, key, lane, invAddr(key), &wire.Policy{GPU: &wire.GPUNeed{MemoryMB: memoryMB, Mode: mode}})
}

func leaseGPUs(t *testing.T, d *Dispatcher, runner string, gpus []wire.GPUReading, lanes ...string) *wire.Grant {
	t.Helper()
	g, _, werr := d.Lease(context.Background(), runner, wire.Lease{Lanes: lanes, WaitS: 0, GPUs: gpus})
	if werr != nil {
		t.Fatalf("lease: %v", werr)
	}
	return g
}

func reading(uuid string, index, totalMB, freeMB, processes int) wire.GPUReading {
	return wire.GPUReading{Index: index, UUID: uuid, TotalMB: totalMB, FreeMB: freeMB, Processes: processes}
}

func TestSharedGPUJobsFitByDeclaredMemoryAndLiveFree(t *testing.T) {
	d, _ := newTestDispatcher(t)
	hello(t, d, "r1", "embed")
	gpuJob(t, d, "a", "embed", 10000, "")
	gpuJob(t, d, "b", "embed", 12000, wire.GPUShared)
	gpuJob(t, d, "c", "embed", 2000, wire.GPUShared)

	// A fresh GPU reports its memory free; the plane's own declarations are not in it yet.
	g := leaseGPUs(t, d, "r1", []wire.GPUReading{reading(gpuA, 0, 24000, 23000, 0)}, "embed")
	if g == nil || g.Job.GPU == nil || g.Job.GPU.UUID != gpuA || g.Job.GPU.MemoryMB != 10000 || g.Job.GPU.Mode != wire.GPUShared {
		t.Fatalf("first grant = %+v", g)
	}
	// 10000 + 12000 fits 24000 - 1024; the job's own figure fits the live free memory.
	g = leaseGPUs(t, d, "r1", []wire.GPUReading{reading(gpuA, 0, 24000, 14000, 1)}, "embed")
	if g == nil || g.Job.JobKey != "b" {
		t.Fatalf("second grant = %+v", g)
	}
	// 22000 + 2000 passes the 22976 limit even though 9000 MiB read free.
	if g := leaseGPUs(t, d, "r1", []wire.GPUReading{reading(gpuA, 0, 24000, 9000, 2)}, "embed"); g != nil {
		t.Fatalf("over-declared grant = %+v", g)
	}
	// Live free memory below the job's figure blocks it too, whatever the plane declared.
	d2, _ := newTestDispatcher(t)
	hello(t, d2, "r1", "embed")
	gpuJob(t, d2, "a", "embed", 5000, "")
	if g := leaseGPUs(t, d2, "r1", []wire.GPUReading{reading(gpuA, 0, 24000, 4000, 1)}, "embed"); g != nil {
		t.Fatalf("grant beyond live free memory = %+v", g)
	}
	if g := leaseGPUs(t, d2, "r1", []wire.GPUReading{reading(gpuA, 0, 24000, 5000, 1)}, "embed"); g == nil {
		t.Fatal("a job exactly the size of the free memory must fit")
	}
}

func TestRunnerWithoutGPUsTakesOnlyJobsWithoutGPU(t *testing.T) {
	d, _ := newTestDispatcher(t)
	hello(t, d, "r1", "embed")
	gpuJob(t, d, "gpu", "embed", 1000, "")
	enqueueOne(t, d, "cpu", "embed", invAddr("cpu"), nil)
	g, _ := leaseOne(t, d, "r1", "embed")
	if g == nil || g.Job.JobKey != "cpu" || g.Job.GPU != nil {
		t.Fatalf("grant = %+v", g)
	}
	if g, _ := leaseOne(t, d, "r1", "embed"); g != nil {
		t.Fatalf("a runner offering no GPU got %+v", g)
	}
}

func TestExclusiveNeedsAnIdleGPUAndTakesItAlone(t *testing.T) {
	d, _ := newTestDispatcher(t)
	hello(t, d, "r1", "embed")
	gpuJob(t, d, "x", "embed", 1000, wire.GPUExclusive)
	busy := []wire.GPUReading{reading(gpuA, 0, 24000, 20000, 1)}
	if g := leaseGPUs(t, d, "r1", busy, "embed"); g != nil {
		t.Fatalf("exclusive job placed beside another process: %+v", g)
	}
	idle := []wire.GPUReading{reading(gpuA, 0, 24000, 24000, 0)}
	g := leaseGPUs(t, d, "r1", idle, "embed")
	if g == nil || g.Job.GPU == nil || g.Job.GPU.Mode != wire.GPUExclusive {
		t.Fatalf("exclusive grant = %+v", g)
	}
	gpuJob(t, d, "small", "embed", 100, "")
	if g := leaseGPUs(t, d, "r1", idle, "embed"); g != nil {
		t.Fatalf("a GPU holding an exclusive job took %+v", g)
	}
	// Once the exclusive job ends the GPU takes work again.
	if werr := d.Complete("r1", wire.Complete{JobID: g.Job.JobID, LeaseID: g.Lease.LeaseID, Attempt: 1, ActionResult: sampleResult(invAddr("x"))}); werr != nil {
		t.Fatal(werr)
	}
	if g := leaseGPUs(t, d, "r1", idle, "embed"); g == nil || g.Job.JobKey != "small" {
		t.Fatalf("after the exclusive job: %+v", g)
	}
}

func TestGrantNamesTheFittingGPUWithMostFreeMemory(t *testing.T) {
	d, _ := newTestDispatcher(t)
	hello(t, d, "r1", "embed")
	gpuJob(t, d, "a", "embed", 3000, "")
	g := leaseGPUs(t, d, "r1", []wire.GPUReading{reading(gpuA, 0, 8000, 5000, 1), reading(gpuB, 1, 24000, 20000, 0)}, "embed")
	if g == nil || g.Job.GPU.UUID != gpuB || g.Job.GPU.Index != 1 {
		t.Fatalf("grant = %+v", g)
	}
	fleet, err := d.Fleet()
	if err != nil || len(fleet) != 1 || len(fleet[0].GPUs) != 2 || fleet[0].GPUs[1].UUID != gpuB {
		t.Fatalf("fleet = %+v, %v", fleet, err)
	}
}

func TestStarvedGPUJobHoldsBackOtherGPUStarts(t *testing.T) {
	d, clk := newTestDispatcher(t)
	hello(t, d, "r1", "embed")
	hello(t, d, "r2", "transcribe")
	gpuJob(t, d, "big", "embed", 20000, "")
	clk.Advance(int64(d.cfg.GPUStarveAfterS) * 1000)
	gpuJob(t, d, "small", "embed", 2000, "")
	gpuJob(t, d, "other-lane", "transcribe", 2000, "")
	enqueueOne(t, d, "cpu", "embed", invAddr("cpu"), nil)

	// Another program holds most of the GPU, so the starved job cannot start yet.
	crowded := []wire.GPUReading{reading(gpuA, 0, 24000, 6000, 1)}
	g := leaseGPUs(t, d, "r1", crowded, "embed")
	if g == nil || g.Job.JobKey != "cpu" {
		t.Fatalf("only the job without GPU may start: %+v", g)
	}
	if g := leaseGPUs(t, d, "r1", crowded, "embed"); g != nil {
		t.Fatalf("a smaller GPU job overtook the starved one: %+v", g)
	}
	// A runner of another lane offering the same GPU is held back too while r1 asks.
	if g := leaseGPUs(t, d, "r2", crowded, "transcribe"); g != nil {
		t.Fatalf("another lane took the starved job's GPU: %+v", g)
	}
	// A GPU the starved job could never use stays open.
	small := []wire.GPUReading{reading(gpuB, 1, 8000, 7000, 0)}
	if g := leaseGPUs(t, d, "r2", small, "transcribe"); g == nil || g.Job.JobKey != "other-lane" {
		t.Fatalf("grant on the small GPU = %+v", g)
	}
	// Once the GPU frees, the starved job goes first.
	if g := leaseGPUs(t, d, "r1", []wire.GPUReading{reading(gpuA, 0, 24000, 23500, 0)}, "embed"); g == nil || g.Job.JobKey != "big" {
		t.Fatalf("starved job grant = %+v", g)
	}
}

func TestGPUDeclarationsAndReadingsAreChecked(t *testing.T) {
	d, _ := newTestDispatcher(t)
	hello(t, d, "r1", "embed")
	for name, need := range map[string]wire.GPUNeed{"no memory": {MemoryMB: 0}, "bad mode": {MemoryMB: 1, Mode: "turbo"}} {
		_, werr := d.Enqueue(wire.Enqueue{Jobs: []wire.EnqueueJob{{JobKey: name, Lane: "embed", InvocationAddress: invAddr(name), Policy: &wire.Policy{GPU: &need}}}})
		if werr == nil || werr.Code != wire.CodeInvalid {
			t.Fatalf("%s: %v", name, werr)
		}
	}
	for name, gpus := range map[string][]wire.GPUReading{
		"bad uuid":      {reading("gpu0", 0, 1000, 1000, 0)},
		"same gpu":      {reading(gpuA, 0, 1000, 1000, 0), reading(gpuA, 1, 1000, 1000, 0)},
		"free > total":  {reading(gpuA, 0, 1000, 2000, 0)},
		"negative proc": {reading(gpuA, 0, 1000, 1000, -1)},
	} {
		_, _, werr := d.Lease(context.Background(), "r1", wire.Lease{Lanes: []string{"embed"}, GPUs: gpus})
		if werr == nil || werr.Code != wire.CodeInvalid {
			t.Fatalf("%s: %v", name, werr)
		}
	}
}

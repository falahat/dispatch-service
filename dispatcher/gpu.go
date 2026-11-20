package dispatcher

import (
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/falahat/dispatch-service/internal/wire"
)

// Placement by GPU memory (decisions D4-D7). A runner offers its GPUs with each
// request for work, read on the machine at that moment. The plane adds up the
// memory its own running jobs declared on each GPU, because a job that just
// started has not allocated yet. A shared or MPS job starts on a GPU while the
// declared memory of the jobs running there plus its own stays within the GPU's
// memory less the reserve, and the GPU really has that much free. An exclusive
// job needs a GPU with no running job and no compute process, and a GPU holding
// one takes nothing else. A GPU job that has waited past the starvation limit
// holds back new GPU starts on the GPUs where it could run until it starts.

// maxGPUWaitS bounds a long-poll that carries a reading, which ages as it waits.
const maxGPUWaitS = 5

// gpuOfferFreshS is how recently a runner must have asked for work with a GPU for
// its lanes to count as able to start a job there.
const gpuOfferFreshS = 15

// maxOfferedGPUs bounds one reading.
const maxOfferedGPUs = 16

var gpuUUIDRe = regexp.MustCompile(`^(GPU|MIG)-[0-9A-Fa-f-]{8,64}$`)

// gpuNeed is a job's GPU declaration with its mode resolved.
type gpuNeed struct {
	memoryMB int
	mode     wire.GPUMode
}

func resolveGPUNeed(n wire.GPUNeed) gpuNeed {
	if n.Mode == "" {
		n.Mode = wire.GPUShared
	}
	return gpuNeed{memoryMB: n.MemoryMB, mode: n.Mode}
}

func validateGPUNeed(n *wire.GPUNeed) error {
	if n.MemoryMB < 1 || n.MemoryMB > 1<<20 {
		return errors.New("enqueue: gpu.memory_mb out of range")
	}
	switch n.Mode {
	case "", wire.GPUShared, wire.GPUMPS, wire.GPUExclusive:
		return nil
	default:
		return errors.New("enqueue: invalid gpu.mode")
	}
}

func validateGPUReadings(gpus []wire.GPUReading) error {
	if len(gpus) > maxOfferedGPUs {
		return fmt.Errorf("lease: at most %d gpus", maxOfferedGPUs)
	}
	seen := make(map[string]bool, len(gpus))
	for _, g := range gpus {
		if g.Index < 0 || g.Index > 63 || !gpuUUIDRe.MatchString(g.UUID) || seen[g.UUID] ||
			g.TotalMB < 1 || g.TotalMB > 1<<20 || g.FreeMB < 0 || g.FreeMB > g.TotalMB || g.Processes < 0 {
			return fmt.Errorf("lease: invalid gpu reading for index %d", g.Index)
		}
		seen[g.UUID] = true
	}
	return nil
}

// insertGPUNeed records a job's GPU declaration at enqueue.
func insertGPUNeed(tx *sql.Tx, jobID string, need gpuNeed) error {
	_, err := tx.Exec(`INSERT INTO job_gpu(job_id, memory_mb, mode) VALUES(?,?,?)`, jobID, need.memoryMB, string(need.mode))
	return err
}

// jobGPUNeed loads a job's GPU declaration; ok is false for a job without one.
func jobGPUNeed(tx *sql.Tx, jobID string) (need gpuNeed, ok bool, err error) {
	var mode string
	err = tx.QueryRow(`SELECT memory_mb, mode FROM job_gpu WHERE job_id=?`, jobID).Scan(&need.memoryMB, &mode)
	if err == sql.ErrNoRows {
		return gpuNeed{}, false, nil
	}
	need.mode = wire.GPUMode(mode)
	return need, err == nil, err
}

// offeredGPU is one offered GPU with what the plane's running jobs declared on it.
type offeredGPU struct {
	reading   wire.GPUReading
	memoryMB  int
	jobs      int
	exclusive bool
}

func offeredGPUs(tx *sql.Tx, readings []wire.GPUReading) ([]offeredGPU, error) {
	out := make([]offeredGPU, len(readings))
	for i, r := range readings {
		out[i].reading = r
		var exclusive int
		err := tx.QueryRow(`SELECT COALESCE(SUM(g.memory_mb),0), COUNT(*), COALESCE(MAX(g.mode='exclusive'),0)
			FROM job_gpu g JOIN jobs j ON j.job_id=g.job_id WHERE g.gpu_uuid=? AND j.state='RUNNING'`, r.UUID).
			Scan(&out[i].memoryMB, &out[i].jobs, &exclusive)
		if err != nil {
			return nil, err
		}
		out[i].exclusive = exclusive != 0
	}
	return out, nil
}

// room is the most memory a shared job may declare on this GPU now; negative
// when it takes none.
func (o offeredGPU) room(reserveMB int) int {
	if o.exclusive {
		return -1
	}
	return min(o.reading.TotalMB-reserveMB-o.memoryMB, o.reading.FreeMB)
}

func (o offeredGPU) idle() bool { return o.jobs == 0 && o.reading.Processes == 0 }

func (o offeredGPU) fits(need gpuNeed, reserveMB int) bool {
	if need.mode == wire.GPUExclusive {
		return o.idle()
	}
	return need.memoryMB <= o.room(reserveMB)
}

// couldFit reports whether need fits on this GPU once it drains.
func (o offeredGPU) couldFit(need gpuNeed, reserveMB int) bool {
	return need.mode == wire.GPUExclusive || need.memoryMB <= o.reading.TotalMB-reserveMB
}

// pickGPU returns the fitting GPU with the most free memory.
func pickGPU(offered []offeredGPU, need gpuNeed, reserveMB int) (offeredGPU, bool) {
	var best offeredGPU
	found := false
	for _, o := range offered {
		if o.fits(need, reserveMB) && (!found || o.reading.FreeMB > best.reading.FreeMB) {
			best, found = o, true
		}
	}
	return best, found
}

// gpuFilter limits which queued jobs one claim may take: jobs that declare no
// GPU always, shared jobs up to room, exclusive jobs only when a GPU is idle.
type gpuFilter struct {
	room int
	idle bool
}

func filterFor(offered []offeredGPU, reserveMB int) gpuFilter {
	f := gpuFilter{room: -1}
	for _, o := range offered {
		f.room = max(f.room, o.room(reserveMB))
		f.idle = f.idle || o.idle()
	}
	return f
}

// sql returns the condition and its arguments for this filter.
func (f gpuFilter) sql() (string, []any) {
	idle := 0
	if f.idle {
		idle = 1
	}
	return `job_id NOT IN (SELECT job_id FROM job_gpu WHERE (mode='exclusive' AND ?=0) OR (mode!='exclusive' AND memory_mb>?))`,
		[]any{idle, f.room}
}

// gpuOffer is a runner's latest request for work that offered GPUs.
type gpuOffer struct {
	lanes   []string
	gpus    []wire.GPUReading
	askedMS int64 // 0 once the runner is no longer waiting for work
}

func (d *Dispatcher) recordGPUOffer(runnerID string, lanes []string, gpus []wire.GPUReading, now int64) {
	d.gpuMu.Lock()
	defer d.gpuMu.Unlock()
	if len(gpus) == 0 {
		delete(d.gpuOffers, runnerID)
		return
	}
	d.gpuOffers[runnerID] = gpuOffer{lanes: slices.Clone(lanes), gpus: slices.Clone(gpus), askedMS: now}
}

// stopWaiting marks a runner as no longer asking for work, keeping its reading
// for the fleet view.
func (d *Dispatcher) stopWaiting(runnerID string) {
	d.gpuMu.Lock()
	defer d.gpuMu.Unlock()
	if o, ok := d.gpuOffers[runnerID]; ok {
		o.askedMS = 0
		d.gpuOffers[runnerID] = o
	}
}

func (d *Dispatcher) runnerGPUs(runnerID string) []wire.GPUReading {
	d.gpuMu.Lock()
	defer d.gpuMu.Unlock()
	return slices.Clone(d.gpuOffers[runnerID].gpus)
}

// lanesByGPU returns, for each GPU, the lanes of the runners asking for work
// with it now.
func (d *Dispatcher) lanesByGPU(now int64) map[string]map[string]bool {
	d.gpuMu.Lock()
	defer d.gpuMu.Unlock()
	out := map[string]map[string]bool{}
	for _, o := range d.gpuOffers {
		if o.askedMS == 0 || now-o.askedMS > gpuOfferFreshS*1000 {
			continue
		}
		for _, g := range o.gpus {
			if out[g.UUID] == nil {
				out[g.UUID] = map[string]bool{}
			}
			for _, lane := range o.lanes {
				out[g.UUID][lane] = true
			}
		}
	}
	return out
}

// starvedGPUJob returns the GPU job that has waited longest past the starvation
// limit among those that a runner asking for work now could start on one of the
// offered GPUs once it drains, with the UUIDs of those GPUs.
func (d *Dispatcher) starvedGPUJob(tx *sql.Tx, offered []offeredGPU, now int64) (Job, gpuNeed, map[string]bool, error) {
	byGPU := d.lanesByGPU(now)
	var lanes []string
	for _, o := range offered {
		for lane := range byGPU[o.reading.UUID] {
			if !slices.Contains(lanes, lane) {
				lanes = append(lanes, lane)
			}
		}
	}
	if len(lanes) == 0 {
		return Job{}, gpuNeed{}, nil, nil
	}
	args := []any{now - int64(d.cfg.GPUStarveAfterS)*1000}
	for _, lane := range lanes {
		args = append(args, lane)
	}
	rows, err := tx.Query(`SELECT j.job_id, j.lane, g.memory_mb, g.mode FROM jobs j JOIN job_gpu g ON g.job_id=j.job_id
		WHERE j.state='QUEUED' AND j.next_attempt_at<=? AND j.lane IN (?`+strings.Repeat(",?", len(lanes)-1)+`)
		ORDER BY j.next_attempt_at ASC, j.created_ts ASC LIMIT 64`, args...)
	if err != nil {
		return Job{}, gpuNeed{}, nil, err
	}
	var jobID string
	var need gpuNeed
	var usable map[string]bool
	for usable == nil && rows.Next() {
		var id, lane, mode string
		var memoryMB int
		if err := rows.Scan(&id, &lane, &memoryMB, &mode); err != nil {
			rows.Close()
			return Job{}, gpuNeed{}, nil, err
		}
		n := gpuNeed{memoryMB: memoryMB, mode: wire.GPUMode(mode)}
		for _, o := range offered {
			if byGPU[o.reading.UUID][lane] && o.couldFit(n, d.cfg.GPUReserveMB) {
				if usable == nil {
					usable = map[string]bool{}
				}
				usable[o.reading.UUID] = true
			}
		}
		jobID, need = id, n
	}
	if err := rows.Close(); err != nil {
		return Job{}, gpuNeed{}, nil, err
	}
	if usable == nil {
		return Job{}, gpuNeed{}, nil, rows.Err()
	}
	job, err := getJobTx(tx, jobID)
	return job, need, usable, err
}

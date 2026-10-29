package dispatcher

import (
	"fmt"
	"os"

	"github.com/pelletier/go-toml/v2"
)

// Config is the dispatcher's plane.toml, read once at boot. Change = restart
// (downtime is free; there is no live reconfiguration surface to attack).
type Config struct {
	WaitForExecutor    bool   `toml:"wait_for_executor"` // Cancellation waits for execution cleanup and application persistence.
	DBPath             string `toml:"db_path"`
	RunnerListen       string `toml:"runner_listen"` // tailnet TCP, PEP-fronted in prod
	AppSocket          string `toml:"app_socket"`    // UDS path for the app/admin surface
	AppListen          string `toml:"app_listen"`    // loopback TCP fallback where AF_UNIX is absent
	HeartbeatIntervalS int    `toml:"heartbeat_interval_s"`
	LeaseTTLS          int    `toml:"lease_ttl_s"`
	MinWaitS           int    `toml:"min_wait_s"`
	MaxWaitS           int    `toml:"max_wait_s"`
	RunnerRatePerMin   int    `toml:"runner_rate_per_min"`
	SweepIntervalS     int    `toml:"sweep_interval_s"`

	// JobRetentionDays prunes TERMINAL jobs (SUCCEEDED/FAILED/REJECTED/CANCELLED) and
	// their attempt rows once they are older than this many days.
	//
	//   0 = NO TTL — keep the queue history FOREVER (this is the default).
	//
	// This is OPT-IN and only ever touches the dispatcher's own re-derivable queue
	// bookkeeping. It NEVER touches domain data: podcast episodes, transcripts, and
	// antibody analysis results live in each app's own store, not here — nothing in
	// this DB is a source of record. Set > 0 only to bound this queue DB's growth.
	JobRetentionDays int `toml:"job_retention_days"`

	Lanes  map[string]LaneConfig `toml:"lanes"`
	Budget BudgetConfig          `toml:"budget"`

	// DefaultLane applies to any lane not listed under [lanes].
	DefaultLane LaneConfig `toml:"default_lane"`
}

// LaneConfig is per-lane routing policy.
type LaneConfig struct {
	SingleAttempt bool `toml:"single_attempt"` // Fail visibly instead of requeueing execution or infrastructure failures.
	// Concurrency caps simultaneous RUNNING jobs in the lane. 0 = unbounded.
	Concurrency int `toml:"concurrency"`
	// PersistingWatermark: count(PERSISTING) beyond this pauses leasing on the
	// lane until the app drains its inbox (backpressure).
	PersistingWatermark int `toml:"persisting_watermark"`
}

// BudgetConfig is the cost gate. CapUSD is a decimal-as-string; $0 is the
// fail-closed default (any priced job cannot reserve until the cap is raised).
type BudgetConfig struct {
	CapUSD string `toml:"cap_usd"`
}

// DefaultConfig returns a config with production-sane defaults; callers layer a
// plane.toml over it.
func DefaultConfig() Config {
	return Config{
		DBPath:             "dispatch.db",
		RunnerListen:       "127.0.0.1:7700",
		AppSocket:          "",
		AppListen:          "127.0.0.1:7701",
		HeartbeatIntervalS: 15,
		LeaseTTLS:          300,
		MinWaitS:           0,
		MaxWaitS:           60,
		RunnerRatePerMin:   240,
		SweepIntervalS:     5,
		JobRetentionDays:   0, // 0 = keep terminal queue history forever (no TTL)
		Lanes:              map[string]LaneConfig{},
		Budget:             BudgetConfig{CapUSD: "0.00"},
		DefaultLane:        LaneConfig{Concurrency: 0, PersistingWatermark: 64},
	}
}

// LoadConfig reads a plane.toml, layering it over the defaults. Missing file
// is an error (config is explicit); an empty path returns the defaults.
func LoadConfig(path string) (Config, error) {
	c := DefaultConfig()
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Config{}, fmt.Errorf("config: %w", err)
	}
	dec := toml.NewDecoder(nil)
	_ = dec
	if err := toml.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if c.Lanes == nil {
		c.Lanes = map[string]LaneConfig{}
	}
	return c, nil
}

// Lane returns the config for a lane, falling back to DefaultLane.
func (c Config) Lane(name string) LaneConfig {
	if lc, ok := c.Lanes[name]; ok {
		return lc
	}
	return c.DefaultLane
}

// Validate checks the config is internally consistent.
func (c Config) Validate() error {
	if c.MaxWaitS < 1 {
		return fmt.Errorf("config: max_wait_s must be >= 1")
	}
	if c.MinWaitS < 0 || c.MinWaitS > c.MaxWaitS {
		return fmt.Errorf("config: min_wait_s must be in [0, max_wait_s]")
	}
	if c.LeaseTTLS < 1 {
		return fmt.Errorf("config: lease_ttl_s must be >= 1")
	}
	if c.HeartbeatIntervalS < 1 {
		return fmt.Errorf("config: heartbeat_interval_s must be >= 1")
	}
	if c.JobRetentionDays < 0 {
		return fmt.Errorf("config: job_retention_days must be >= 0 (0 = keep forever)")
	}
	if c.AppSocket == "" && c.AppListen == "" {
		return fmt.Errorf("config: one of app_socket / app_listen is required")
	}
	if _, err := parseUSD(c.Budget.CapUSD); err != nil {
		return fmt.Errorf("config: budget.cap_usd: %w", err)
	}
	return nil
}

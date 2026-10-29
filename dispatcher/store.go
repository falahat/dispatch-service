package dispatcher

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/falahat/dispatch-service/internal/wire"
	_ "modernc.org/sqlite"
)

// quarantineThreshold is the number of corroborated failures (a failure on this
// runner for a job that later SUCCEEDED on a different runner) that quarantines
// a runner. The corroboration requirement (success elsewhere) is the two-witness
// rule: a single-runner lane can never starve itself.
const quarantineThreshold = 2

// Store is the dispatcher's durable state: an embedded SQLite database in WAL
// mode. A single writer connection serializes all mutation; readers see a
// consistent snapshot. Domain bytes never live here — only key + address rows.
type Store struct {
	db *sql.DB
}

// OpenStore opens (creating if needed) the SQLite database at path and applies
// the schema. synchronous=FULL: the dispatcher favors durability over speed.
func OpenStore(path string) (*Store, error) {
	dsn := "file:" + url.PathEscape(path) +
		"?_pragma=journal_mode(WAL)" +
		"&_pragma=busy_timeout(10000)" +
		"&_pragma=foreign_keys(ON)" +
		"&_pragma=synchronous(FULL)" +
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	// One writer: SQLite permits a single writer; serializing here removes any
	// SQLITE_BUSY races and makes every write transaction linearizable.
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS jobs (
  job_id                TEXT PRIMARY KEY,
  job_key               TEXT NOT NULL,
  lane                  TEXT NOT NULL,
  invocation_address    TEXT NOT NULL,
  state                 TEXT NOT NULL,
  attempt               INTEGER NOT NULL DEFAULT 0,
  release_count         INTEGER NOT NULL DEFAULT 0,
  priority              INTEGER NOT NULL DEFAULT 5,
  max_attempts          INTEGER NOT NULL,
  backoff_class         TEXT NOT NULL,
  release_cap           INTEGER NOT NULL,
  expected_wall_s       INTEGER NOT NULL DEFAULT 0,
  error_class_overrides TEXT NOT NULL DEFAULT '{}',
  cost_cents            INTEGER NOT NULL DEFAULT 0,
  next_attempt_at       INTEGER NOT NULL DEFAULT 0,
  batch_scale           TEXT NOT NULL DEFAULT '',
  lease_id              TEXT,
  lease_deadline_ts     INTEGER,
  lease_runner_id       TEXT,
  result_json           TEXT,
  result_attempt        INTEGER,
  completed_ts          INTEGER,
  reason                TEXT,
  cancel_requested      INTEGER NOT NULL DEFAULT 0,
  created_ts            INTEGER NOT NULL,
  updated_ts            INTEGER NOT NULL
);

-- Live job_key uniqueness: at most one non-terminal job per key. This makes
-- enqueue idempotency a database invariant, not just application logic.
CREATE UNIQUE INDEX IF NOT EXISTS uq_jobs_live_key ON jobs(job_key)
  WHERE state NOT IN ('SUCCEEDED','FAILED','REJECTED','CANCELLED');

CREATE INDEX IF NOT EXISTS idx_jobs_claimable ON jobs(lane, state, priority, created_ts);
CREATE INDEX IF NOT EXISTS idx_jobs_state ON jobs(state);
CREATE INDEX IF NOT EXISTS idx_jobs_lease ON jobs(lease_id);

CREATE TABLE IF NOT EXISTS job_logs (
  job_id TEXT NOT NULL REFERENCES jobs(job_id) ON DELETE CASCADE,
  offset INTEGER NOT NULL,
  address TEXT NOT NULL,
  size INTEGER NOT NULL,
  PRIMARY KEY(job_id,offset)
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS job_progress (
  job_id TEXT PRIMARY KEY REFERENCES jobs(job_id) ON DELETE CASCADE,
  attempt INTEGER NOT NULL,
  payload TEXT NOT NULL
);

-- Per-attempt timeline: the dead-letter view and the quarantine witness source.
CREATE TABLE IF NOT EXISTS attempts (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id      TEXT NOT NULL,
  attempt     INTEGER NOT NULL,
  runner_id   TEXT,
  lease_id    TEXT,
  outcome     TEXT,          -- claimed | complete | fail | release | lease_expired
  error_class TEXT,
  reason      TEXT,
  started_ts  INTEGER,
  ended_ts    INTEGER
);
CREATE INDEX IF NOT EXISTS idx_attempts_job ON attempts(job_id);

CREATE TABLE IF NOT EXISTS runners (
  runner_id            TEXT PRIMARY KEY,
  node                 TEXT,
  version              TEXT,
  lanes                TEXT,
  capacity             INTEGER,
  gpu                  TEXT,
  vram_free_mb         INTEGER,
  last_seen_ts         INTEGER,
  quarantined          INTEGER NOT NULL DEFAULT 0,
  quarantine_reason    TEXT,
  corroborated_failures INTEGER NOT NULL DEFAULT 0,
  draining             INTEGER NOT NULL DEFAULT 0
);

-- One-row budget ledger. Amounts in integer cents.
CREATE TABLE IF NOT EXISTS budget (
  id           INTEGER PRIMARY KEY CHECK (id = 1),
  cap_cents    INTEGER NOT NULL DEFAULT 0,
  reserved_cents INTEGER NOT NULL DEFAULT 0,
  spent_cents  INTEGER NOT NULL DEFAULT 0
);

-- Append-only approval facts for priced jobs.
CREATE TABLE IF NOT EXISTS approvals (
  id      INTEGER PRIMARY KEY AUTOINCREMENT,
  job_id  TEXT NOT NULL,
  author  TEXT NOT NULL,
  reason  TEXT,
  action  TEXT NOT NULL,   -- approve | reject
  ts      INTEGER NOT NULL
);
`

func (s *Store) migrate() error {
	if _, err := s.db.Exec(schema); err != nil {
		return fmt.Errorf("store: migrate: %w", err)
	}
	// Ensure the singleton budget row exists.
	if _, err := s.db.Exec(`INSERT OR IGNORE INTO budget(id, cap_cents, reserved_cents, spent_cents) VALUES (1,0,0,0)`); err != nil {
		return fmt.Errorf("store: budget init: %w", err)
	}
	return nil
}

// SetBudgetCap sets the spending cap from a decimal-as-string.
func (s *Store) SetBudgetCap(usd string) error {
	cents, err := parseUSD(usd)
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`UPDATE budget SET cap_cents=? WHERE id=1`, int64(cents))
	return err
}

// writeTx runs fn inside an IMMEDIATE transaction (write lock acquired up front),
// committing on success and rolling back on error.
func (s *Store) writeTx(fn func(*sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("store: begin: %w", err)
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Job is the in-memory view of a jobs row for decision logic.
type Job struct {
	JobID             string
	JobKey            string
	Lane              string
	InvocationAddress string
	State             string
	Attempt           int
	ReleaseCount      int
	Policy            ResolvedPolicy
	CostCents         Money
	NextAttemptAt     int64
	BatchScale        string
	LeaseID           string
	LeaseDeadlineTS   int64
	LeaseRunnerID     string
	ResultJSON        string
	ResultAttempt     int
	CompletedTS       int64
	Reason            string
	CancelRequested   bool
	CreatedTS         int64
	UpdatedTS         int64
}

const jobColumns = `job_id, job_key, lane, invocation_address, state, attempt, release_count,
  priority, max_attempts, backoff_class, release_cap, expected_wall_s, error_class_overrides,
  cost_cents, next_attempt_at, batch_scale, lease_id, lease_deadline_ts, lease_runner_id,
  result_json, result_attempt, completed_ts, reason, cancel_requested, created_ts, updated_ts`

// scanner abstracts *sql.Row and *sql.Rows.
type scanner interface {
	Scan(dest ...any) error
}

func scanJob(sc scanner) (Job, error) {
	var j Job
	var (
		priority, maxAttempts, releaseCap, expectedWallS int
		backoffClass, overridesJSON                      string
		costCents, nextAttemptAt                         int64
		leaseID, leaseRunnerID, resultJSON, reason       sql.NullString
		leaseDeadline, resultAttempt, completedTS        sql.NullInt64
		cancel                                           int
	)
	err := sc.Scan(
		&j.JobID, &j.JobKey, &j.Lane, &j.InvocationAddress, &j.State, &j.Attempt, &j.ReleaseCount,
		&priority, &maxAttempts, &backoffClass, &releaseCap, &expectedWallS, &overridesJSON,
		&costCents, &nextAttemptAt, &j.BatchScale, &leaseID, &leaseDeadline, &leaseRunnerID,
		&resultJSON, &resultAttempt, &completedTS, &reason, &cancel, &j.CreatedTS, &j.UpdatedTS,
	)
	if err != nil {
		return Job{}, err
	}
	j.Policy = ResolvedPolicy{
		MaxAttempts:   maxAttempts,
		BackoffClass:  wire.BackoffClass(backoffClass),
		Priority:      priority,
		ReleaseCap:    releaseCap,
		ExpectedWallS: expectedWallS,
	}
	if overridesJSON != "" && overridesJSON != "{}" {
		m := map[wire.ErrorClass]string{}
		if err := json.Unmarshal([]byte(overridesJSON), &m); err == nil {
			j.Policy.ErrorClassOverrides = m
		}
	}
	j.CostCents = Money(costCents)
	j.NextAttemptAt = nextAttemptAt
	j.LeaseID = leaseID.String
	j.LeaseDeadlineTS = leaseDeadline.Int64
	j.LeaseRunnerID = leaseRunnerID.String
	j.ResultJSON = resultJSON.String
	j.ResultAttempt = int(resultAttempt.Int64)
	j.CompletedTS = completedTS.Int64
	j.Reason = reason.String
	j.CancelRequested = cancel != 0
	return j, nil
}

// getJobTx loads a job by id within a transaction, or (Job{}, sql.ErrNoRows).
func getJobTx(tx *sql.Tx, jobID string) (Job, error) {
	row := tx.QueryRow(`SELECT `+jobColumns+` FROM jobs WHERE job_id=?`, jobID)
	return scanJob(row)
}

// GetJob loads a job by id (read path).
func (s *Store) GetJob(jobID string) (Job, error) {
	row := s.db.QueryRow(`SELECT `+jobColumns+` FROM jobs WHERE job_id=?`, jobID)
	return scanJob(row)
}

// insertAttempt appends a row to the attempt timeline.
func insertAttempt(tx *sql.Tx, jobID string, attempt int, runnerID, leaseID, outcome, errClass, reason string, startedTS, endedTS int64) error {
	_, err := tx.Exec(
		`INSERT INTO attempts(job_id, attempt, runner_id, lease_id, outcome, error_class, reason, started_ts, ended_ts)
		 VALUES(?,?,?,?,?,?,?,?,?)`,
		jobID, attempt, nullStr(runnerID), nullStr(leaseID), outcome, nullStr(errClass), nullStr(reason), nullInt(startedTS), nullInt(endedTS))
	return err
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

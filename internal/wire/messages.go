package wire

import (
	"encoding/json"

	"github.com/falahat/dispatch-service/internal/artifact"
)

// Envelope is the outer frame body: {v, type, id, body}. Body stays raw so the
// dispatcher can route by type before strict-decoding the concrete message.
type Envelope struct {
	V    string          `json:"v"`
	Type string          `json:"type"`
	ID   string          `json:"id"`
	Body json.RawMessage `json:"body"`
}

// Message type strings. These match the schema's message keys and the wire
// `type` field (^[a-z_]{1,32}$).
const (
	TypeHello         = "hello"
	TypeHelloOK       = "hello_ok"
	TypeLease         = "lease"
	TypeGrant         = "grant"
	TypeEmpty         = "empty"
	TypeHeartbeat     = "heartbeat"
	TypeBeatOK        = "beat_ok"
	TypeComplete      = "complete"
	TypeFail          = "fail"
	TypeRelease       = "release"
	TypeEnqueue       = "enqueue"
	TypeEnqueueResult = "enqueue_result"
	TypeSubscribe     = "subscribe"
	TypeCompletion    = "completion"
	TypeTakeover      = "takeover"
	TypeAck           = "ack"
	TypeApproval      = "approval"
	TypeCancel        = "cancel"
	TypeApprove       = "approve"
	TypeReject        = "reject"
	TypeJobs          = "jobs"
	TypeFleet         = "fleet"
	TypeBudget        = "budget"
	TypeSweep         = "sweep"
	TypeStats         = "stats"
	TypeOK            = "ok"
	TypeError         = "error"
)

// ErrorClass is the closed enum of compute failure classes.
type ErrorClass string

const (
	ClassOOM       ErrorClass = "oom"
	ClassTimeout   ErrorClass = "timeout"
	ClassRateLimit ErrorClass = "rate_limit"
	ClassNetwork   ErrorClass = "network"
	ClassBadInput  ErrorClass = "bad_input"
	ClassIntegrity ErrorClass = "integrity"
	ClassFatal     ErrorClass = "fatal"
	ClassUnknown   ErrorClass = "unknown"
)

// ValidErrorClasses is the closed set for validation.
var ValidErrorClasses = map[ErrorClass]bool{
	ClassOOM: true, ClassTimeout: true, ClassRateLimit: true, ClassNetwork: true,
	ClassBadInput: true, ClassIntegrity: true, ClassFatal: true, ClassUnknown: true,
}

// ReleaseReason is the closed enum for a release ("couldn't start / couldn't ship").
type ReleaseReason string

const (
	ReleaseCASUnreachable ReleaseReason = "cas_unreachable"
	ReleaseCASMiss        ReleaseReason = "cas_miss"
	ReleaseIntegrity      ReleaseReason = "integrity"
	ReleaseWrongHardware  ReleaseReason = "wrong_hardware"
	ReleaseShipping       ReleaseReason = "shipping"
)

var ValidReleaseReasons = map[ReleaseReason]bool{
	ReleaseCASUnreachable: true, ReleaseCASMiss: true, ReleaseIntegrity: true,
	ReleaseWrongHardware: true, ReleaseShipping: true,
}

// ErrorCode is the closed enum of protocol error codes.
type ErrorCode string

const (
	CodeUnauthenticated ErrorCode = "unauthenticated"
	CodeForbidden       ErrorCode = "forbidden"
	CodeVersionMismatch ErrorCode = "version_mismatch"
	CodeInvalid         ErrorCode = "invalid"
	CodeNotLeaseholder  ErrorCode = "not_leaseholder"
	CodeGone            ErrorCode = "gone"
	CodeConflict        ErrorCode = "conflict"
	CodeBudget          ErrorCode = "budget"
	CodeBackpressure    ErrorCode = "backpressure"
	CodeRateLimited     ErrorCode = "rate_limited"
	CodeInternal        ErrorCode = "internal"
)

// BackoffClass is the closed enum of per-job backoff shapes.
type BackoffClass string

const (
	BackoffQuick    BackoffClass = "quick"
	BackoffStandard BackoffClass = "standard"
	BackoffLong     BackoffClass = "long"
)

// Disposition is the ack outcome.
type Disposition string

const (
	DispositionPersisted Disposition = "persisted"
	DispositionRejected  Disposition = "rejected"
)

// Policy is the dispatcher-enforced retry/routing policy attached to a job.
// Pointers distinguish "absent" (apply default) from an explicit value.
type Policy struct {
	MaxAttempts         *int                  `json:"max_attempts,omitempty"`
	BackoffClass        *BackoffClass         `json:"backoff_class,omitempty"`
	ErrorClassOverrides map[ErrorClass]string `json:"error_class_overrides,omitempty"`
	ExpectedWallS       *int                  `json:"expected_wall_s,omitempty"`
	Priority            *int                  `json:"priority,omitempty"`
	ReleaseCap          *int                  `json:"release_cap,omitempty"`
}

// --- runner surface ---

// RunnerIdent is the runner's self-description in hello.
type RunnerIdent struct {
	ID       string   `json:"id"` // public-key fingerprint
	Version  string   `json:"version"`
	Node     string   `json:"node"`
	Lanes    []string `json:"lanes"`
	Capacity int      `json:"capacity"`
}

type Hello struct {
	Contract string      `json:"contract"`
	Runner   RunnerIdent `json:"runner"`
}

type HelloOK struct {
	ServerTS           int64 `json:"server_ts"`
	HeartbeatIntervalS int   `json:"heartbeat_interval_s"`
	MinWaitS           int   `json:"min_wait_s"`
	MaxWaitS           int   `json:"max_wait_s"`
}

// Lease is the long-poll request.
type Lease struct {
	Lanes []string `json:"lanes"`
	WaitS int      `json:"wait_s"`
}

// GrantJob is the job description carried in a grant.
type GrantJob struct {
	JobID             string           `json:"job_id"`
	JobKey            string           `json:"job_key"`
	Lane              string           `json:"lane"`
	InvocationAddress artifact.Address `json:"invocation_address"`
	Attempt           int              `json:"attempt"`
	ExpectedWallS     int              `json:"expected_wall_s,omitempty"` // 0 = unset; sizes the runner's job budget
	Hints             *GrantHints      `json:"hints,omitempty"`
}

// GrantHints are optional sizing feedback (decimals as strings per the rule).
type GrantHints struct {
	BatchScale string `json:"batch_scale,omitempty"`
}

// LeaseGrant is the lease part of a grant (the fencing token + deadline).
type LeaseGrant struct {
	LeaseID    string `json:"lease_id"`
	TTLS       int    `json:"ttl_s"`
	DeadlineTS int64  `json:"deadline_ts"`
}

type Grant struct {
	Job   GrantJob   `json:"job"`
	Lease LeaseGrant `json:"lease"`
}

// Empty is the no-work reply to a lease long-poll.
type Empty struct {
	Reason      string `json:"reason,omitempty"` // backpressure | drained
	RetryAfterS *int   `json:"retry_after_s,omitempty"`
}

// HeartbeatStatus is the runner's health/telemetry on a heartbeat.
type HeartbeatStatus struct {
	Node         string   `json:"node"`
	Lanes        []string `json:"lanes"`
	Capacity     int      `json:"capacity"`
	GPU          string   `json:"gpu,omitempty"`
	VRAMFreeMB   *int     `json:"vram_free_mb,omitempty"`
	CurrentJobID string   `json:"current_job_id,omitempty"`
}

type Heartbeat struct {
	Status  HeartbeatStatus `json:"status"`
	LeaseID string          `json:"lease_id,omitempty"`
	Log     *LogChunk       `json:"log,omitempty"`
}

// LogChunk addresses bytes uploaded through the existing authenticated CAS.
type LogChunk struct {
	Offset  int64            `json:"offset"`
	Address artifact.Address `json:"address"`
	Size    int64            `json:"size"`
}

// Directive is a steering instruction returned on a heartbeat. Exactly one of
// the kinds is set per element.
type Directive struct {
	Kind         string `json:"kind"` // abandon | drain | throttle
	JobID        string `json:"job_id,omitempty"`
	LeaseAfterTS *int64 `json:"lease_after_ts,omitempty"`
}

const (
	DirectiveAbandon  = "abandon"
	DirectiveDrain    = "drain"
	DirectiveThrottle = "throttle"
)

type BeatOK struct {
	Directives []Directive `json:"directives"`
	LogOffset  *int64      `json:"log_offset,omitempty"`
}

type Complete struct {
	LeaseID      string                `json:"lease_id"`
	JobID        string                `json:"job_id"`
	Attempt      int                   `json:"attempt"`
	ActionResult artifact.ActionResult `json:"action_result"`
}

type Fail struct {
	LeaseID    string     `json:"lease_id"`
	JobID      string     `json:"job_id"`
	Attempt    int        `json:"attempt"`
	ErrorClass ErrorClass `json:"error_class"`
	Message    string     `json:"message"`
}

type Release struct {
	LeaseID string        `json:"lease_id"`
	JobID   string        `json:"job_id"`
	Reason  ReleaseReason `json:"reason"`
}

// --- app surface ---

// EnqueueJob is one job in an enqueue batch.
type EnqueueJob struct {
	JobKey            string           `json:"job_key"`
	Lane              string           `json:"lane"`
	InvocationAddress artifact.Address `json:"invocation_address"`
	Policy            *Policy          `json:"policy,omitempty"`
	CostEstimateUSD   string           `json:"cost_estimate_usd,omitempty"` // decimal-as-string
}

type Enqueue struct {
	Jobs []EnqueueJob `json:"jobs"`
}

type EnqueueResultItem struct {
	JobKey  string `json:"job_key"`
	JobID   string `json:"job_id"`
	Created bool   `json:"created"`
}

type EnqueueResult struct {
	Results []EnqueueResultItem `json:"results"`
}

type Subscribe struct{}

// Completion is one pushed completion in the subscription stream.
type Completion struct {
	JobID        string                `json:"job_id"`
	JobKey       string                `json:"job_key"`
	Lane         string                `json:"lane"`
	Attempt      int                   `json:"attempt"`
	ActionResult artifact.ActionResult `json:"action_result"`
	CompletedTS  int64                 `json:"completed_ts"`
}

type Takeover struct{}

type Ack struct {
	JobID       string      `json:"job_id"`
	Disposition Disposition `json:"disposition"`
	Reason      string      `json:"reason,omitempty"`
}

type Approval struct {
	JobID  string `json:"job_id"`
	Author string `json:"author"`
	Reason string `json:"reason"`
}

type Cancel struct {
	JobID  string `json:"job_id"`
	Reason string `json:"reason"`
}

// --- shared replies ---

type OK struct{}

type Error struct {
	Code      ErrorCode `json:"code"`
	Message   string    `json:"message"`
	Retryable bool      `json:"retryable"`
}

func (e Error) Error() string { return string(e.Code) + ": " + e.Message }

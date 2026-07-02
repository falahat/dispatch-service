package wire_test

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const (
	wireID = "https://falahat.dev/dispatch/v0/wire.schema.json"
	artID  = "https://falahat.dev/dispatch/v0/artifacts.schema.json"
)

// schemaSet compiles subschemas by $defs name against the frozen contract files.
type schemaSet struct{ c *jsonschema.Compiler }

func loadSchemas(t *testing.T) *schemaSet {
	t.Helper()
	c := jsonschema.NewCompiler()
	c.UseRegexpEngine(ecmaCompile)
	for id, rel := range map[string]string{
		wireID: "wire.schema.json",
		artID:  "artifacts.schema.json",
	} {
		f, err := os.Open(filepath.Join("..", "..", "contracts", "schemas", rel))
		if err != nil {
			t.Fatalf("open schema %s: %v", rel, err)
		}
		doc, err := jsonschema.UnmarshalJSON(f)
		f.Close()
		if err != nil {
			t.Fatalf("parse schema %s: %v", rel, err)
		}
		if err := c.AddResource(id, doc); err != nil {
			t.Fatalf("add schema %s: %v", rel, err)
		}
	}
	return &schemaSet{c: c}
}

// validate marshals v and validates it against wire.schema.json#/$defs/<def>.
func (s *schemaSet) validate(t *testing.T, def string, v any) {
	t.Helper()
	sch, err := s.c.Compile(wireID + "#/$defs/" + def)
	if err != nil {
		t.Fatalf("compile #/$defs/%s: %v", def, err)
	}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal %s: %v", def, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("reparse %s: %v", def, err)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("%s failed schema: %v\ninstance: %s", def, err, raw)
	}
}

const addrA = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
const addrB = "sha256:1111111111111111111111111111111111111111111111111111111111111111"

func sampleActionResult() artifact.ActionResult {
	return artifact.ActionResult{
		Kind:              artifact.ActionResultKind,
		InvocationAddress: addrA,
		Outputs:           map[string]artifact.Output{"transcript": {Address: addrB, Size: 482133}},
		Metrics:           map[string]int64{"wall_s": 512, "work_units": 3600},
		Runner:            artifact.RunnerInfo{Node: "desktop-ai", Version: "runner/0.1.0"},
	}
}

// messageCases pairs each wire message type with its schema $defs name and a
// valid sample value.
func messageCases() []struct {
	typ  string
	def  string
	body any
} {
	i3 := func(n int) *int { return &n }
	i64 := func(n int64) *int64 { return &n }
	bc := wire.BackoffStandard
	return []struct {
		typ  string
		def  string
		body any
	}{
		{wire.TypeHello, "hello", wire.Hello{Contract: "0.1", Runner: wire.RunnerIdent{ID: "fp", Version: "0.1", Node: "n", Lanes: []string{"transcribe"}, Capacity: 1}}},
		{wire.TypeHelloOK, "hello_ok", wire.HelloOK{ServerTS: 1, HeartbeatIntervalS: 15, MinWaitS: 0, MaxWaitS: 60}},
		{wire.TypeLease, "lease", wire.Lease{Lanes: []string{"transcribe"}, WaitS: 30}},
		{wire.TypeGrant, "grant", wire.Grant{Job: wire.GrantJob{JobID: "j_0000000000000000000000000A", JobKey: "k", Lane: "transcribe", InvocationAddress: addrA, Attempt: 1, Hints: &wire.GrantHints{BatchScale: "0.5"}}, Lease: wire.LeaseGrant{LeaseID: "l_0000000000000000000000000A", TTLS: 300, DeadlineTS: 123}}},
		{wire.TypeEmpty, "empty", wire.Empty{Reason: "backpressure", RetryAfterS: i3(5)}},
		{wire.TypeHeartbeat, "heartbeat", wire.Heartbeat{Status: wire.HeartbeatStatus{Node: "n", Lanes: []string{"transcribe"}, Capacity: 1, GPU: "4090", VRAMFreeMB: i3(9000), CurrentJobID: "j_0000000000000000000000000A"}, LeaseID: "l_0000000000000000000000000A"}},
		{wire.TypeBeatOK, "beat_ok", wire.BeatOK{Directives: []wire.Directive{{Kind: wire.DirectiveAbandon, JobID: "j_0000000000000000000000000A"}, {Kind: wire.DirectiveDrain}, {Kind: wire.DirectiveThrottle, LeaseAfterTS: i64(9999)}}}},
		{wire.TypeComplete, "complete", wire.Complete{LeaseID: "l_0000000000000000000000000A", JobID: "j_0000000000000000000000000A", Attempt: 1, ActionResult: sampleActionResult()}},
		{wire.TypeFail, "fail", wire.Fail{LeaseID: "l_0000000000000000000000000A", JobID: "j_0000000000000000000000000A", Attempt: 1, ErrorClass: wire.ClassOOM, Message: "cuda oom"}},
		{wire.TypeRelease, "release", wire.Release{LeaseID: "l_0000000000000000000000000A", JobID: "j_0000000000000000000000000A", Reason: wire.ReleaseCASUnreachable}},
		{wire.TypeEnqueue, "enqueue", wire.Enqueue{Jobs: []wire.EnqueueJob{{JobKey: "k", Lane: "transcribe", InvocationAddress: addrA, Policy: &wire.Policy{MaxAttempts: i3(3), BackoffClass: &bc}, CostEstimateUSD: "0.00"}}}},
		{wire.TypeEnqueueResult, "enqueue_result", wire.EnqueueResult{Results: []wire.EnqueueResultItem{{JobKey: "k", JobID: "j_0000000000000000000000000A", Created: true}}}},
		{wire.TypeSubscribe, "subscribe", wire.Subscribe{}},
		{wire.TypeCompletion, "completion", wire.Completion{JobID: "j_0000000000000000000000000A", JobKey: "k", Lane: "transcribe", Attempt: 1, ActionResult: sampleActionResult(), CompletedTS: 5}},
		{wire.TypeTakeover, "takeover", wire.Takeover{}},
		{wire.TypeAck, "ack", wire.Ack{JobID: "j_0000000000000000000000000A", Disposition: wire.DispositionPersisted}},
		{wire.TypeApproval, "approval", wire.Approval{JobID: "j_0000000000000000000000000A", Author: "aryan", Reason: "ok"}},
		{wire.TypeCancel, "cancel", wire.Cancel{JobID: "j_0000000000000000000000000A", Reason: "stale"}},
		{wire.TypeOK, "ok", wire.OK{}},
		{wire.TypeError, "error", wire.Error{Code: wire.CodeInvalid, Message: "bad", Retryable: false}},
	}
}

// TestMessagesMatchSchema validates every sample body against its schema.
func TestMessagesMatchSchema(t *testing.T) {
	s := loadSchemas(t)
	for _, tc := range messageCases() {
		t.Run(tc.def, func(t *testing.T) { s.validate(t, tc.def, tc.body) })
	}
}

// TestFrameRoundTrip frames each message and reads it back intact.
func TestFrameRoundTrip(t *testing.T) {
	for _, tc := range messageCases() {
		t.Run(tc.typ, func(t *testing.T) {
			var buf bytes.Buffer
			if err := wire.WriteMessage(&buf, "req-1", tc.typ, tc.body); err != nil {
				t.Fatalf("write: %v", err)
			}
			env, err := wire.ReadMessage(&buf)
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			if env.Type != tc.typ || env.ID != "req-1" || env.V != wire.ContractVersion {
				t.Fatalf("envelope mismatch: %+v", env)
			}
			// Body must be JSON-equal to a fresh marshal of the original.
			want, _ := json.Marshal(tc.body)
			if !jsonEqual(t, want, env.Body) {
				t.Fatalf("body mismatch:\n want %s\n got  %s", want, env.Body)
			}
		})
	}
}

// TestStrictDecodeRejectsUnknownField ensures unknown fields fail closed.
func TestStrictDecodeRejectsUnknownField(t *testing.T) {
	frame, err := wire.MarshalEnvelope("id1", wire.TypeAck, wire.Ack{JobID: "j_0000000000000000000000000A", Disposition: wire.DispositionPersisted})
	if err != nil {
		t.Fatal(err)
	}
	// Inject an unknown field into the body.
	var env wire.Envelope
	_ = json.Unmarshal(frame, &env)
	env.Body = json.RawMessage(`{"job_id":"j_0000000000000000000000000A","disposition":"persisted","evil":true}`)
	reframed, _ := json.Marshal(env)
	de, err := wire.DecodeEnvelope(reframed)
	if err != nil {
		t.Fatalf("envelope should decode: %v", err)
	}
	if _, err := wire.DecodeBody[wire.Ack](de); err == nil {
		t.Fatal("expected strict decode to reject unknown body field")
	}
}

// TestEnvelopeRejects covers malformed envelopes.
func TestEnvelopeRejects(t *testing.T) {
	cases := map[string]string{
		"bad version": `{"v":"9.9","type":"ok","id":"x","body":{}}`,
		"bad type":    `{"v":"0.1","type":"OK!","id":"x","body":{}}`,
		"empty id":    `{"v":"0.1","type":"ok","id":"","body":{}}`,
		"no body":     `{"v":"0.1","type":"ok","id":"x"}`,
		"unknown key": `{"v":"0.1","type":"ok","id":"x","body":{},"extra":1}`,
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := wire.DecodeEnvelope([]byte(frame)); err == nil {
				t.Fatalf("expected %s to be rejected", name)
			}
		})
	}
}

// TestFraming covers the length-prefix edge cases.
func TestFraming(t *testing.T) {
	t.Run("truncated payload -> unexpected EOF", func(t *testing.T) {
		// prefix says 10 bytes, only 3 present
		buf := []byte{0, 0, 0, 10, 'a', 'b', 'c'}
		_, err := wire.ReadFrame(bytes.NewReader(buf))
		if err != io.ErrUnexpectedEOF {
			t.Fatalf("want ErrUnexpectedEOF, got %v", err)
		}
	})
	t.Run("oversize prefix rejected before alloc", func(t *testing.T) {
		buf := []byte{0xFF, 0xFF, 0xFF, 0xFF} // ~4GiB claimed
		_, err := wire.ReadFrame(bytes.NewReader(buf))
		if _, ok := err.(wire.ErrFrameTooLarge); !ok {
			t.Fatalf("want ErrFrameTooLarge, got %v", err)
		}
	})
	t.Run("zero-length prefix rejected", func(t *testing.T) {
		buf := []byte{0, 0, 0, 0}
		if _, err := wire.ReadFrame(bytes.NewReader(buf)); err == nil {
			t.Fatal("want error on zero-length frame")
		}
	})
	t.Run("clean EOF at boundary", func(t *testing.T) {
		if _, err := wire.ReadFrame(bytes.NewReader(nil)); err != io.EOF {
			t.Fatalf("want EOF, got %v", err)
		}
	})
}

func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var x, y any
	if err := json.Unmarshal(a, &x); err != nil {
		t.Fatalf("unmarshal a: %v", err)
	}
	if err := json.Unmarshal(b, &y); err != nil {
		t.Fatalf("unmarshal b: %v", err)
	}
	xb, _ := json.Marshal(x)
	yb, _ := json.Marshal(y)
	return bytes.Equal(xb, yb)
}

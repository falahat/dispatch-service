package runner_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/falahat/dispatch-service/internal/artifact"
	"github.com/falahat/dispatch-service/internal/wire"
	"github.com/falahat/dispatch-service/runner"
)

// failingCommand prints a line, then reports the failure class it is given on its
// first attempt; a later attempt, which finds the marker the first one left in
// the runner's root, prints another line and succeeds.
const failingCommand = `import json, os, sys
request = json.load(sys.stdin)
marker = os.path.join(request['roots']['state'], 'tried')
if os.path.exists(marker):
    os.write(1, b'retried stage log line\n')
    json.dump({'outputs': {}, 'metrics': {'exit': 0}}, open('invoke-result.json', 'w'))
else:
    os.write(1, b'stage log line\n')
    open(marker, 'w').close()
    json.dump({'error_class': sys.argv[1], 'message': 'the stage said why'}, open('invoke-failure.json', 'w'))
`

func runFailingCommand(t *testing.T, class string, attempts int) (wire.JobView, string) {
	t.Helper()
	srv := startDispatcher(t)
	cas := newStubCAS()
	casSrv := httptest.NewServer(cas.handler())
	t.Cleanup(casSrv.Close)
	invBytes, _ := json.Marshal(artifact.Invocation{
		Kind: artifact.InvocationKind, Op: "run", OpVersion: 1, Params: json.RawMessage(`{}`),
		Inputs: map[string]artifact.Input{},
	})
	app := dialApp(t, srv.AppAddr())
	quick := wire.BackoffQuick
	env := app.call("e1", wire.TypeEnqueue, wire.Enqueue{Jobs: []wire.EnqueueJob{{
		JobKey: "fails-once", Lane: "embed", InvocationAddress: cas.put(invBytes),
		Policy: &wire.Policy{MaxAttempts: &attempts, BackoffClass: &quick},
	}}})
	enqueued, err := wire.DecodeBody[wire.EnqueueResult](env)
	if err != nil {
		t.Fatal(err)
	}
	rn := runner.New(runner.Config{
		RunnerID: "Rcmd", Node: "n1", Version: "runner/test",
		DispatcherAddr: srv.RunnerAddr(), CASBaseURL: casSrv.URL,
		Command:  []string{"python3", "-c", failingCommand, class},
		WorkRoot: t.TempDir(), Lanes: []string{"embed"}, Capacity: 1, LeaseWaitS: 2,
		Roots: map[string]string{"state": t.TempDir()}, NoDeadline: true,
	}, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go rn.Run(ctx)
	jobID := enqueued.Results[0].JobID
	view, err := wire.DecodeBody[wire.JobView](app.call("w1", "wait", map[string]string{"job_id": jobID}))
	if err != nil {
		t.Fatal(err)
	}
	page, err := wire.DecodeBody[struct {
		Entries    []wire.LogChunk `json:"entries"`
		NextOffset int64           `json:"next_offset"`
		Done       bool            `json:"done"`
	}](app.call("l1", "logs", map[string]any{"job_id": jobID, "after": 0}))
	if err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	cas.mu.Lock()
	for _, entry := range page.Entries {
		log.Write(cas.blobs[entry.Address.Hex()])
	}
	cas.mu.Unlock()
	return view, log.String()
}

// A command's failure carries its class to the dispatcher, with its log ahead of
// it: a final class ends the job at once, whatever attempts remain.
func TestCommandFailureOfAFinalClassEndsTheJob(t *testing.T) {
	view, log := runFailingCommand(t, "fatal", 3)
	if view.State != "FAILED" || view.Reason != "fail:fatal" || view.Attempt != 1 {
		t.Fatalf("job = %s %q after attempt %d, want FAILED fail:fatal after 1", view.State, view.Reason, view.Attempt)
	}
	last := view.Timeline[len(view.Timeline)-1]
	if last.ErrorClass != "fatal" || last.Reason != "the stage said why" {
		t.Fatalf("last timeline row = %+v, want the command's class and message", last)
	}
	if !strings.Contains(log, "stage log line") {
		t.Fatalf("the failed attempt's log did not reach the plane: %q", log)
	}
}

// A retriable class runs the job again, as the job's policy allows. The job's log
// holds both attempts' output in order: the retry's log continues after the first
// attempt's (D16).
func TestCommandFailureOfARetriableClassRunsAgain(t *testing.T) {
	view, log := runFailingCommand(t, "network", 2)
	if view.State != "PERSISTING" || view.Attempt != 2 {
		t.Fatalf("job = %s after attempt %d, want PERSISTING after 2", view.State, view.Attempt)
	}
	if log != "stage log line\nretried stage log line\n" {
		t.Fatalf("job log = %q, want the first attempt's line, then the retry's", log)
	}
}

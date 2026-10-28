package runner

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestTrustedCommandUsesExistingInvocationAndResult(t *testing.T) {
	work := t.TempDir()
	script := `import json,os,sys
request=json.load(sys.stdin)
assert request['deadline_ts']==0 and request['workdir']==os.getcwd()
assert os.environ['DISPATCH_RUNNER_ID']=='owner-worker'
print('command output',flush=True)
with open('invoke-result.json','w') as output:
 json.dump({'outputs':{},'metrics':{'exit':3}},output)
`
	executor := commandExecutor{args: []string{"python3", "-c", script}, id: "owner-worker"}
	result, failure, err := executor.Invoke(context.Background(), InvokeRequest{JobID: "example", Workdir: work})
	if err != nil || failure != nil || result.Metrics["exit"] != 3 {
		t.Fatalf("actual command result: %v %v %v", result, failure, err)
	}
	data, err := os.ReadFile(filepath.Join(work, "invoke.log"))
	if err != nil || string(data) != "command output\n" {
		t.Fatalf("actual command output: %q %v", data, err)
	}
}

func TestLocalCASUsesExistingIntegrityChecks(t *testing.T) {
	root := t.TempDir()
	store := NewCAS("file://"+root, nil, nil)
	address, err := store.PutBytes(context.Background(), []byte("actual content"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := store.GetBytes(context.Background(), address)
	if err != nil || string(data) != "actual content" {
		t.Fatalf("round trip: %q %v", data, err)
	}
	if err := os.WriteFile(filepath.Join(root, "blobs", "sha256", address.Hex()), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetBytes(context.Background(), address); err == nil {
		t.Fatal("changed bytes must fail existing content-address verification")
	}
}

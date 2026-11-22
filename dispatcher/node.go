package dispatcher

import (
	"database/sql"
	"errors"
	"regexp"
)

// Placement by data (decision D11). A job whose local artifacts lie on one node
// names that node in policy.node and is granted only to runners that gave that
// node at hello; lanes, the GPU rule and the starvation guard apply as for any
// job. The dispatcher never reads an invocation (D8), so the node rides in the
// policy, set by the app from the job's local artifacts, and the runner checks
// every local input against its own node before it runs anything.

// nodeRe matches the node shape of contracts/schemas/artifacts.schema.json.
var nodeRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func validateNode(node string) error {
	if !nodeRe.MatchString(node) {
		return errors.New("enqueue: invalid policy.node")
	}
	return nil
}

func insertJobNode(tx *sql.Tx, jobID, node string) error {
	_, err := tx.Exec(`INSERT INTO job_node(job_id, node) VALUES(?,?)`, jobID, node)
	return err
}

// runnerNode is the node a runner last named, or "" for one never seen.
func runnerNode(tx *sql.Tx, runnerID string) (string, error) {
	var node sql.NullString
	err := tx.QueryRow(`SELECT node FROM runners WHERE runner_id=?`, runnerID).Scan(&node)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return node.String, err
}

// onNode is the claim condition for a runner on node: jobs pinned to no node,
// or to this one.
func onNode(node string) (string, []any) {
	return `job_id NOT IN (SELECT job_id FROM job_node WHERE node != ?)`, []any{node}
}

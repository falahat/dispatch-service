// Package contracts exposes the frozen contract data (the job state machine and
// the JSON schemas) to Go code as a single source of truth. The files under
// this directory ARE the specification; embedding them here means the dispatcher
// and its tests derive legality from the exact same bytes the other language
// implementations read — no hand-copied transition table to drift.
package contracts

import (
	"embed"
	"encoding/json"
	"fmt"
)

//go:embed states.json
//go:embed schemas/wire.schema.json schemas/artifacts.schema.json
var files embed.FS

// Transition is one row of the state machine. From is nil for creation events
// (enqueue). Guard and Effect are prose describing the condition/side-effect;
// the dispatcher implements them in code — this table binds only which
// (from, event) -> to transitions are legal.
type Transition struct {
	From   *string `json:"from"`
	Event  string  `json:"event"`
	To     string  `json:"to"`
	Guard  string  `json:"guard,omitempty"`
	Effect string  `json:"effect,omitempty"`
}

// StateInfo is a state's metadata.
type StateInfo struct {
	Terminal bool `json:"terminal"`
}

// StateMachine is the parsed states.json.
type StateMachine struct {
	Version     string               `json:"version"`
	States      map[string]StateInfo `json:"states"`
	Transitions []Transition         `json:"transitions"`
}

var machine *StateMachine

func init() {
	b, err := files.ReadFile("states.json")
	if err != nil {
		panic("contracts: cannot read embedded states.json: " + err.Error())
	}
	var sm StateMachine
	if err := json.Unmarshal(b, &sm); err != nil {
		panic("contracts: cannot parse states.json: " + err.Error())
	}
	machine = &sm
}

// Machine returns the parsed state machine.
func Machine() *StateMachine { return machine }

// IsState reports whether name is a declared state.
func (sm *StateMachine) IsState(name string) bool {
	_, ok := sm.States[name]
	return ok
}

// IsTerminal reports whether the named state is terminal.
func (sm *StateMachine) IsTerminal(name string) bool {
	return sm.States[name].Terminal
}

// LegalTargets returns every 'to' state reachable from `from` on `event`. An
// empty result means the (from, event) pair is illegal. Pass from="" for
// creation events (from == null in the data).
func (sm *StateMachine) LegalTargets(from, event string) []string {
	var out []string
	for _, tr := range sm.Transitions {
		trFrom := ""
		if tr.From != nil {
			trFrom = *tr.From
		}
		if trFrom == from && tr.Event == event {
			out = append(out, tr.To)
		}
	}
	return out
}

// IsLegal reports whether (from -> to on event) is a declared transition.
func (sm *StateMachine) IsLegal(from, event, to string) bool {
	for _, t := range sm.LegalTargets(from, event) {
		if t == to {
			return true
		}
	}
	return false
}

// Schema returns the raw bytes of an embedded JSON schema by base name
// ("wire.schema.json" or "artifacts.schema.json").
func Schema(name string) ([]byte, error) {
	b, err := files.ReadFile("schemas/" + name)
	if err != nil {
		return nil, fmt.Errorf("contracts: schema %q: %w", name, err)
	}
	return b, nil
}

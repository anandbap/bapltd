// Package learn is BAP's observe → learn → recommend loop (ADR-002). Enforcement layers emit effect
// events (what the agent actually tried to touch and what the boundary decided); miners turn those into
// reviewable proposals; a human applies them. Nothing here changes policy by itself.
package learn

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Event is one observed effect.
type Event struct {
	ID           string    `json:"id,omitempty"`
	Agent        string    `json:"agent,omitempty"`
	Project      string    `json:"project,omitempty"`
	Mode         string    `json:"mode,omitempty"`
	Rule         string    `json:"rule,omitempty"`
	Grant        string    `json:"grant,omitempty"`
	Outcome      string    `json:"outcome,omitempty"`
	HumanID      string    `json:"human_id,omitempty"`
	DecisionID   string    `json:"decision_id,omitempty"`
	PredictionID string    `json:"prediction_id,omitempty"`
	Observed     bool      `json:"observed,omitempty"`
	WouldDeny    bool      `json:"would_deny,omitempty"`
	Time         time.Time `json:"time"`
	Kind         string    `json:"kind"`    // egress | fs | exec
	Target       string    `json:"target"`  // host:port, path, ...
	Verdict      string    `json:"verdict"` // allow | deny
	Session      string    `json:"session,omitempty"`
	Source       string    `json:"source,omitempty"` // egress-proxy | sandbox | hook
	// HumanApproved marks evidence grounded in a human decision (HITL approve / `egress allow`), the only
	// evidence strong enough to justify widening the boundary on its own.
	HumanApproved bool `json:"human_approved,omitempty"`
}

// Log is an append-only JSONL effect log, safe for concurrent writers in one process.
type Log struct {
	path string
	mu   sync.Mutex
}

func NewLog(path string) *Log { return &Log{path: path} }

func (l *Log) Path() string { return l.path }

func (l *Log) Append(e Event) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Outcome == "" {
		e.Outcome = e.Verdict
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(l.path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	b, _ := json.Marshal(e)
	if _, err = f.Write(append(b, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

// ReadAll returns every readable event; a missing file is an empty history and corrupt lines are skipped.
func (l *Log) ReadAll() ([]Event, error) {
	f, err := os.Open(l.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var e Event
		if json.Unmarshal(sc.Bytes(), &e) == nil && e.Kind != "" {
			out = append(out, e)
		}
	}
	return out, sc.Err()
}

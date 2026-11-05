package discovery

import (
	"database/sql"
	"encoding/json"
	_ "modernc.org/sqlite"
	"path/filepath"
	"testing"
	"time"
)

func fixtureReport(id string, when time.Time, names ...string) Report {
	r := Report{Version: 1, RunID: id, StartedAt: when, CompletedAt: when, Status: "complete", Scopes: []ScopeResult{{ID: "config", Status: "complete"}}, Observations: []Observation{}}
	for _, name := range names {
		r.Observations = append(r.Observations, Observation{Key: name, Scope: "config", Kind: "mcp_config", Name: name, Client: "claude-code", Evidence: "configured", ObservedAt: when})
	}
	return r
}
func TestDiscoveryInventoryPersistenceLifecycleAndReplay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "inventory.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	s, err := NewInventory(db)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Add(-time.Minute).UTC()
	r := fixtureReport("run-1", now, "one", "two")
	if _, err = s.Ingest("machine", "owner", r); err != nil {
		t.Fatal(err)
	}
	if duplicate, err := s.Ingest("machine", "owner", r); err != nil || !duplicate {
		t.Fatalf("retry: %v %v", duplicate, err)
	}
	changed := fixtureReport("run-1", now, "three")
	if _, err = s.Ingest("machine", "owner", changed); err != ErrConflict {
		t.Fatalf("run collision: %v", err)
	}
	page, _ := s.List("machine", "", "", "", 1, 0)
	if page.Total != 2 || page.Next == "" {
		t.Fatalf("two servers collapsed: %+v", page)
	}
	id := page.Findings[0].ID
	expires := time.Now().Add(time.Hour)
	if err = s.Disposition(id, "exception", "Pilot approved", &expires); err != nil {
		t.Fatal(err)
	}
	if _, err = s.List("", "", "", page.Next, 1, page.Revision); err != ErrConflict {
		t.Fatal("mutable snapshot accepted")
	}
	epochA, _ := s.Trigger("selected", []string{"machine"})
	epochB, _ := s.Trigger("selected", []string{"other"})
	if s.EpochFor("machine") != epochA || s.EpochFor("other") != epochB {
		t.Fatal("target directive overwritten")
	}
	partial := fixtureReport("run-2", now.Add(time.Second))
	partial.Status = "partial"
	partial.Scopes[0].Status = "error"
	if _, err = s.Ingest("machine", "owner", partial); err != nil {
		t.Fatal(err)
	}
	page, _ = s.List("machine", "", "present", "", 50, 0)
	if page.Total != 2 {
		t.Fatal("failed scope resolved inventory")
	}
	clean := fixtureReport("run-3", now.Add(2*time.Second))
	if _, err = s.Ingest("machine", "owner", clean); err != nil {
		t.Fatal(err)
	}
	page, _ = s.List("machine", "", "not_seen", "", 50, 0)
	if page.Total != 2 {
		t.Fatal("complete clean scan did not verify absence")
	}
	if _, err = s.Ingest("machine", "owner", fixtureReport("late", now.Add(time.Millisecond), "one")); err != nil {
		t.Fatal(err)
	}
	// Older observations cannot resurrect a finding after a newer clean scope.
	page, _ = s.List("machine", "", "not_seen", "", 50, 0)
	if page.Total != 2 {
		t.Fatal("late replay resurrected inventory")
	}
	before := s.revision
	db.Close()
	db, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s, err = NewInventory(db)
	if err != nil {
		t.Fatal(err)
	}
	page, _ = s.List("machine", "", "", "", 50, 0)
	if page.Total != 2 {
		t.Fatal("inventory lost on restart")
	}
	found := false
	for _, a := range page.Findings {
		if a.ID == id {
			found = a.Disposition == "exception" && a.Reason == "Pilot approved"
		}
	}
	if !found {
		t.Fatal("disposition lost")
	}
	if s.EpochFor("machine") != epochA || s.EpochFor("other") != epochB {
		t.Fatal("directives lost")
	}
	if s.revision == before {
		t.Fatal("snapshot revision reused")
	}
	if duplicate, err := s.Ingest("machine", "owner", r); !duplicate || err != nil {
		t.Fatal("replay after restart was not idempotent")
	}
}

func TestDiscoveryInventoryDedupesAcrossSupersededHostInstanceIDs(t *testing.T) {
	s, err := NewInventory(nil)
	if err != nil {
		t.Fatal(err)
	}

	t1 := time.Now().Add(-2 * time.Hour)
	t2 := time.Now()

	// 1. Old instance reports claude-code and bap-zero-trust
	report1 := Report{
		Version:     1,
		RunID:       "run-old",
		StartedAt:   t1,
		CompletedAt: t1,
		Status:      "complete",
		Scopes:      []ScopeResult{{ID: "agent-processes", Status: "complete"}, {ID: "native-mcp", Status: "complete"}},
		Observations: []Observation{
			{Key: "process-claude-code", Scope: "agent-processes", Kind: "agent_process", Name: "claude-code", Client: "claude-code", PID: 1234, Birth: "birth-1", Evidence: "running", ObservedAt: t1},
			{Key: "mcp-bap-zero-trust", Scope: "native-mcp", Kind: "mcp_config", Name: "bap-zero-trust", Client: "vscode", Evidence: "configured", ObservedAt: t1},
		},
	}
	if _, err := s.Ingest("desktop-c8lejnu-5276747e", "alice@example.com", report1); err != nil {
		t.Fatal(err)
	}

	// Old instance then sends a scan where claude-code is not running (marked not_seen)
	report1Stale := Report{
		Version:     1,
		RunID:       "run-old-stale",
		StartedAt:   t1.Add(time.Minute),
		CompletedAt: t1.Add(time.Minute),
		Status:      "complete",
		Scopes:      []ScopeResult{{ID: "agent-processes", Status: "complete"}, {ID: "native-mcp", Status: "complete"}},
		Observations: []Observation{
			{Key: "mcp-bap-zero-trust", Scope: "native-mcp", Kind: "mcp_config", Name: "bap-zero-trust", Client: "vscode", Evidence: "configured", ObservedAt: t1.Add(time.Minute)},
		},
	}
	if _, err := s.Ingest("desktop-c8lejnu-5276747e", "alice@example.com", report1Stale); err != nil {
		t.Fatal(err)
	}

	// 2. New instance on the same host reports current live state: claude-code is running (present)
	report2 := Report{
		Version:     1,
		RunID:       "run-new",
		StartedAt:   t2,
		CompletedAt: t2,
		Status:      "complete",
		Scopes:      []ScopeResult{{ID: "agent-processes", Status: "complete"}, {ID: "native-mcp", Status: "complete"}},
		Observations: []Observation{
			{Key: "process-claude-code", Scope: "agent-processes", Kind: "agent_process", Name: "claude-code", Client: "claude-code", PID: 5678, Birth: "birth-2", Evidence: "running", ObservedAt: t2},
			{Key: "mcp-bap-zero-trust", Scope: "native-mcp", Kind: "mcp_config", Name: "bap-zero-trust", Client: "vscode", Evidence: "configured", ObservedAt: t2},
		},
	}
	if _, err := s.Ingest("desktop-c8lejnu-f210c4fe", "alice@example.com", report2); err != nil {
		t.Fatal(err)
	}

	// 3. Query the global inventory list (instance = "")
	page, err := s.List("", "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}

	claudeCount := 0
	var claudeAsset Asset
	for _, a := range page.Findings {
		if a.Name == "claude-code" {
			claudeCount++
			claudeAsset = a
		}
	}

	if claudeCount != 1 {
		t.Fatalf("expected exactly 1 claude-code finding across same host, got %d", claudeCount)
	}
	if claudeAsset.State != "present" {
		t.Fatalf("expected claude-code state to be 'present', got %q", claudeAsset.State)
	}
	if claudeAsset.InstanceID != "desktop-c8lejnu-f210c4fe" {
		t.Fatalf("expected claude-code instance to be the active 'desktop-c8lejnu-f210c4fe', got %q", claudeAsset.InstanceID)
	}
}
func TestDiscoveryValidationAndCoverage(t *testing.T) {
	s, _ := NewInventory(nil)
	now := time.Now().UTC()
	r := fixtureReport("clean", now)
	if _, err := s.Ingest("machine", "owner", r); err != nil {
		t.Fatal(err)
	}
	summary := s.Summary([]string{"machine", "offline"})
	if summary["fresh_workstations"] != 1 || summary["not_scanned_workstations"] != 1 {
		t.Fatal(summary)
	}
	for _, change := range []func(*Report){func(r *Report) {
		r.Observations = fixtureReport("x", now, "one").Observations
		r.Observations[0].Evidence = "enforced"
	}, func(r *Report) { r.Scopes[0].Status = "error" }, func(r *Report) { r.Version = 2 }, func(r *Report) { r.Observations = make([]Observation, 513) }} {
		copy := fixtureReport("bad", now)
		change(&copy)
		if ValidateReport(copy) == nil {
			t.Fatal("invalid report accepted")
		}
	}
	raw, _ := json.Marshal(r)
	if len(raw) == 0 {
		t.Fatal("missing wire report")
	}
}

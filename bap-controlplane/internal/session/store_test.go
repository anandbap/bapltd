package session

import (
	"path/filepath"
	"testing"
	"time"

	"bap-controlplane/internal/audit"
)

func TestSessionIntentPersistsWithoutRawPrompt(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "sessions.db")
	store, err := NewStoreWithDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Start(SessionStartRequest{SessionID: "sess-intent", AppID: "claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.SetPromptAndIntent("sess-intent", "", IntentContext{
		Primary: "BUG_FIX", Secondary: []string{"DATABASE_CHANGE"}, Tags: []string{"DATABASE"},
		Confidence: .98, ClassifierVersion: "bap-intent-rules-v1", Source: "claude-user-prompt-submit",
		PromptHash: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", PromptCaptured: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	reopened, err := NewStoreWithDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.Get("sess-intent")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserPrompt != "" || got.Intent.Primary != "BUG_FIX" || len(got.Intent.Secondary) != 1 || got.Intent.Secondary[0] != "DATABASE_CHANGE" || got.Intent.PromptCaptured {
		t.Fatalf("intent did not survive restart: %#v", got)
	}
}

func TestSessionStore_Lifecycle(t *testing.T) {
	store := NewStore()

	// 1. Start a session
	sess, err := store.Start(SessionStartRequest{
		SessionID: "sess-claude-test1",
		AppID:     "claude-code",
		ClientPID: 1234,
		Hostname:  "dev-box",
	})
	if err != nil {
		t.Fatalf("failed to start session: %v", err)
	}
	if sess.Status != "active" {
		t.Fatalf("expected active status, got %s", sess.Status)
	}

	// 2. Record events
	store.RecordEvent("sess-claude-test1", audit.Event{
		EventID:     "ev-1",
		Executable:  "git",
		FullCommand: "git status",
		Decision:    "allow",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	})
	store.RecordEvent("sess-claude-test1", audit.Event{
		EventID:     "ev-2",
		Executable:  "cat",
		FullCommand: "cat .env",
		Decision:    "deny",
		Reason:      "Blocked credential file",
		Timestamp:   time.Now().UTC().Format(time.RFC3339),
	})

	// 3. Inspect session
	detail, err := store.Get("sess-claude-test1")
	if err != nil {
		t.Fatalf("failed to get session: %v", err)
	}
	if detail.TotalEvents != 2 {
		t.Errorf("expected 2 total events, got %d", detail.TotalEvents)
	}
	if detail.AllowedCount != 1 {
		t.Errorf("expected 1 allowed, got %d", detail.AllowedCount)
	}
	if detail.DeniedCount != 1 {
		t.Errorf("expected 1 denied, got %d", detail.DeniedCount)
	}
	if len(detail.Events) != 2 {
		t.Errorf("expected 2 events in detail, got %d", len(detail.Events))
	}

	// 4. Auto-instantiate on event with unknown session ID
	store.RecordEvent("sess-copilot-auto", audit.Event{
		EventID:     "ev-3",
		Source:      "copilot",
		Executable:  "ls",
		FullCommand: "ls",
		Decision:    "allow",
	})
	autoSess, err := store.Get("sess-copilot-auto")
	if err != nil {
		t.Fatalf("auto session not created: %v", err)
	}
	if autoSess.AppID != "copilot" {
		t.Errorf("expected auto session app_id copilot, got %s", autoSess.AppID)
	}

	// 5. List sessions
	list := store.List(10)
	if len(list) != 2 {
		t.Fatalf("expected 2 sessions listed, got %d", len(list))
	}
	// Latest first
	if list[0].SessionID != "sess-copilot-auto" {
		t.Errorf("expected latest session first, got %s", list[0].SessionID)
	}

	// 6. End session
	if err := store.End("sess-claude-test1", "normal exit"); err != nil {
		t.Fatalf("failed to end session: %v", err)
	}
	closed, _ := store.Get("sess-claude-test1")
	if closed.Status != "closed" {
		t.Errorf("expected status closed, got %s", closed.Status)
	}
	if closed.EndedAt == nil {
		t.Errorf("expected ended_at to be set")
	}
	if closed.CloseReason != "normal exit" {
		t.Errorf("expected close_reason 'normal exit', got %q", closed.CloseReason)
	}

	// 7. Test PurgeStale
	staleSess, _ := store.Start(SessionStartRequest{
		SessionID: "sess-stale-test",
		AppID:     "claude-code",
	})
	// Artificially age the session
	staleSess.LastActiveAt = time.Now().UTC().Add(-2 * time.Hour)
	purged := store.PurgeStale(1 * time.Hour)
	if purged != 1 {
		t.Errorf("expected 1 session purged, got %d", purged)
	}
	purgedSess, _ := store.Get("sess-stale-test")
	if purgedSess.Status != "closed" {
		t.Errorf("expected purged session to be closed, got %s", purgedSess.Status)
	}

	// 7b. Test Heartbeat resurrects and updates LastActiveAt
	resurrected, err := store.Heartbeat("sess-stale-test")
	if err != nil {
		t.Fatalf("Heartbeat failed: %v", err)
	}
	if resurrected.Status != "active" {
		t.Errorf("expected session to be resurrected to active, got %s", resurrected.Status)
	}

	// 8. Test Reset
	_, _ = store.Start(SessionStartRequest{SessionID: "sess-reset-1", AppID: "test"})
	_, _ = store.Start(SessionStartRequest{SessionID: "sess-reset-2", AppID: "test"})
	resetCount := store.Reset()
	if resetCount < 2 {
		t.Errorf("expected at least 2 sessions reset, got %d", resetCount)
	}
	r1, _ := store.Get("sess-reset-1")
	if r1.Status != "closed" {
		t.Errorf("expected reset session to be closed, got %s", r1.Status)
	}
}

func TestIntentCumulativeTrackingAndPersistence(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "intent_stats.db")
	store, err := NewStoreWithDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Initial counts are zero
	counts, total := store.GetIntentStats()
	if total != 0 {
		t.Fatalf("expected total 0, got %d", total)
	}
	if counts["BUG_FIX"] != 0 {
		t.Fatalf("expected BUG_FIX 0, got %d", counts["BUG_FIX"])
	}

	// 2. Start session with intent
	sess, err := store.Start(SessionStartRequest{
		SessionID: "sess-agent-1",
		AppID:     "claude-code",
		Intent:    IntentContext{Primary: "TEST_VERIFICATION"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess.Intent.Primary != "TEST_VERIFICATION" || sess.PromptCount != 1 || len(sess.IntentHistory) != 1 {
		t.Fatalf("unexpected initial session intent state: %#v", sess)
	}

	// Verify counts
	counts, total = store.GetIntentStats()
	if total != 1 || counts["TEST_VERIFICATION"] != 1 {
		t.Fatalf("expected 1 TEST_VERIFICATION, got total=%d, counts=%v", total, counts)
	}

	// 3. Submit second prompt with different intent on the same agent
	_, err = store.SetPromptAndIntent("sess-agent-1", "Fix login bug", IntentContext{Primary: "BUG_FIX"})
	if err != nil {
		t.Fatal(err)
	}

	counts, total = store.GetIntentStats()
	// Both TEST_VERIFICATION and BUG_FIX must exist! TEST_VERIFICATION must not disappear!
	if total != 2 {
		t.Fatalf("expected total 2, got %d", total)
	}
	if counts["TEST_VERIFICATION"] != 1 {
		t.Fatalf("expected TEST_VERIFICATION to remain 1, got %d", counts["TEST_VERIFICATION"])
	}
	if counts["BUG_FIX"] != 1 {
		t.Fatalf("expected BUG_FIX 1, got %d", counts["BUG_FIX"])
	}

	// 4. Submit third prompt with BUG_FIX again
	_, err = store.SetPromptAndIntent("sess-agent-1", "Fix database null pointer", IntentContext{Primary: "BUG_FIX"})
	if err != nil {
		t.Fatal(err)
	}

	counts, total = store.GetIntentStats()
	if total != 3 || counts["BUG_FIX"] != 2 || counts["TEST_VERIFICATION"] != 1 {
		t.Fatalf("expected total=3, BUG_FIX=2, TEST_VERIFICATION=1; got total=%d, counts=%v", total, counts)
	}

	// Check agent's history
	agentSess, err := store.Get("sess-agent-1")
	if err != nil {
		t.Fatal(err)
	}
	if agentSess.PromptCount != 3 || len(agentSess.IntentHistory) != 3 {
		t.Fatalf("expected 3 prompt history entries, got %#v", agentSess.IntentHistory)
	}

	// 4b. Idempotency test: Re-submitting identical prompt must NOT increment counts or duplicate history
	_, err = store.SetPromptAndIntent("sess-agent-1", "Fix database null pointer", IntentContext{Primary: "BUG_FIX"})
	if err != nil {
		t.Fatal(err)
	}
	countsPostReplay, totalPostReplay := store.GetIntentStats()
	if totalPostReplay != 3 || countsPostReplay["BUG_FIX"] != 2 {
		t.Fatalf("expected idempotent re-submission: total=3, BUG_FIX=2; got total=%d, counts=%v", totalPostReplay, countsPostReplay)
	}
	agentSessAfterReplay, _ := store.Get("sess-agent-1")
	if agentSessAfterReplay.PromptCount != 3 || len(agentSessAfterReplay.IntentHistory) != 3 {
		t.Fatalf("expected PromptCount=3 and IntentHistory len 3 after replay, got count=%d, hist=%v",
			agentSessAfterReplay.PromptCount, agentSessAfterReplay.IntentHistory)
	}

	// 5. Close and reload from SQLite DB to test persistence
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStoreWithDB(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()

	counts2, total2 := reopened.GetIntentStats()
	if total2 != 3 || counts2["BUG_FIX"] != 2 || counts2["TEST_VERIFICATION"] != 1 {
		t.Fatalf("reopened store intent stats mismatch: total=%d, counts=%v", total2, counts2)
	}

	// 6. Test ResetIntentStats
	reopened.ResetIntentStats()
	counts3, total3 := reopened.GetIntentStats()
	if total3 != 0 || counts3["BUG_FIX"] != 0 || counts3["TEST_VERIFICATION"] != 0 {
		t.Fatalf("expected 0 after reset, got total=%d, counts=%v", total3, counts3)
	}
}

func TestIntentAutoClassificationOnSessionStart(t *testing.T) {
	store := NewStore()

	// 1. Session start with prompt but omitted intent
	sess1, err := store.Start(SessionStartRequest{
		SessionID:  "sess-auto-1",
		AppID:      "test-agent",
		UserPrompt: "Analyze Q3 portfolio volatility and generate quarterly risk metrics",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess1.Intent.Primary != "INVESTIGATION" {
		t.Fatalf("expected INVESTIGATION, got %q", sess1.Intent.Primary)
	}

	// 2. Session start with deploy prompt
	sess2, err := store.Start(SessionStartRequest{
		SessionID:  "sess-auto-2",
		AppID:      "test-agent",
		UserPrompt: "Deploy microservice canary to us-east-1 production cluster",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess2.Intent.Primary != "DEPLOYMENT_RELEASE" {
		t.Fatalf("expected DEPLOYMENT_RELEASE, got %q", sess2.Intent.Primary)
	}

	// 3. Session start with security prompt
	sess3, err := store.Start(SessionStartRequest{
		SessionID:  "sess-auto-3",
		AppID:      "test-agent",
		UserPrompt: "Audit security perimeter and probe credential boundaries",
	})
	if err != nil {
		t.Fatal(err)
	}
	if sess3.Intent.Primary != "SECURITY_REMEDIATION" {
		t.Fatalf("expected SECURITY_REMEDIATION, got %q", sess3.Intent.Primary)
	}

	// 4. Verify cumulative stats
	counts, total := store.GetIntentStats()
	if total != 3 {
		t.Fatalf("expected 3 total prompts, got %d", total)
	}
	if counts["INVESTIGATION"] != 1 || counts["DEPLOYMENT_RELEASE"] != 1 || counts["SECURITY_REMEDIATION"] != 1 {
		t.Fatalf("unexpected counts: %v", counts)
	}
}

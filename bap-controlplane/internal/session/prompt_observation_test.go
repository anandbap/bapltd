package session

import (
	"path/filepath"
	"sync"
	"testing"

	"bap-controlplane/internal/audit"
)

func observeTest(t *testing.T, s *Store, id, text, turn, layer, category string) *Session {
	t.Helper()
	sess, _, err := s.ObservePrompt(id, text, IntentContext{Primary: category, Source: layer, PromptCaptured: true}, turn, layer)
	if err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestPromptFallbackPromotesToHookWithoutDoubleCounting(t *testing.T) {
	s := NewStore()
	_, _ = s.Start(SessionStartRequest{SessionID: "s", AppID: "codex"})
	observeTest(t, s, "s", "Review the change", "native-turn-1", "mcp", "INVESTIGATION")
	observeTest(t, s, "s", "Launcher summary", "native-turn-1", "launcher", "INVESTIGATION")
	got := observeTest(t, s, "s", "Fix the parser bug", "native-turn-1", "hook", "BUG_FIX")
	if got.PromptCount != 1 || got.UserPrompt != "Fix the parser bug" || got.Intent.Primary != "BUG_FIX" {
		t.Fatalf("hook did not replace fallback: %+v", got)
	}
	got = observeTest(t, s, "s", "Lower-quality summary", "native-turn-1", "broker", "INVESTIGATION")
	if got.PromptCount != 1 || got.Intent.Primary != "BUG_FIX" || got.UserPrompt != "Fix the parser bug" {
		t.Fatalf("lower layer replaced hook: %+v", got)
	}
	if s.totalPrompts != 1 || s.intentCounts["BUG_FIX"] != 1 || s.intentCounts["INVESTIGATION"] != 0 {
		t.Fatalf("duplicate or stale category counts: total=%d categories=%v", s.totalPrompts, s.intentCounts)
	}
}

func TestPromptTurnsSurviveRepeatsRetriesConcurrencyAndRestart(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		s := NewStore()
		path := filepath.Join(t.TempDir(), "sessions.db")
		if persistent {
			var err error
			s, err = NewStoreWithDB(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		_, _ = s.Start(SessionStartRequest{SessionID: "s", AppID: "codex"})
		observeTest(t, s, "s", "Continue", "turn-1", "hook", "FEATURE_ENHANCEMENT")
		got := observeTest(t, s, "s", "Continue", "turn-2", "hook", "FEATURE_ENHANCEMENT")
		if got.PromptCount != 2 {
			t.Fatal("identical text in distinct turns was lost")
		}
		observeTest(t, s, "s", "Old summary", "turn-1", "mcp", "INVESTIGATION")
		var workers sync.WaitGroup
		for i := 0; i < 20; i++ {
			workers.Add(1)
			go func() {
				defer workers.Done()
				_, _, _ = s.ObservePrompt("s", "Continue", IntentContext{Primary: "FEATURE_ENHANCEMENT"}, "turn-2", "mcp")
			}()
		}
		workers.Wait()
		if persistent {
			s.db.Close()
			var err error
			s, err = NewStoreWithDB(path)
			if err != nil {
				t.Fatal(err)
			}
			defer s.db.Close()
		} else {
			raw, err := s.MarshalCheckpoint()
			if err != nil {
				t.Fatal(err)
			}
			s = NewStore()
			if err = s.RestoreCheckpoint(raw); err != nil {
				t.Fatal(err)
			}
		}
		got = observeTest(t, s, "s", "Continue", "turn-2", "broker", "INVESTIGATION")
		if got.PromptCount != 2 || got.UserPrompt != "Continue" || got.Intent.Primary != "FEATURE_ENHANCEMENT" {
			t.Fatalf("retry/restart altered prompt state: %+v", got)
		}
	}
}

func TestBrokerContextAndHookShareLegacyPrompt(t *testing.T) {
	s := NewStore()
	_, _ = s.Start(SessionStartRequest{SessionID: "s", AppID: "codex"})
	s.RecordEvent("s", audit.Event{EventID: "broker-event", SessionID: "s", UserPrompt: "Fix bug", ReportingLayer: "broker", Executable: "git", Decision: "allow"})
	got := observeTest(t, s, "s", "Fix bug", "native-id", "hook", "BUG_FIX")
	if got.PromptCount != 1 {
		t.Fatalf("broker/hook counted twice: %d", got.PromptCount)
	}
	_, _ = s.Start(SessionStartRequest{SessionID: "other", AppID: "codex"})
	other := observeTest(t, s, "other", "Fix bug", "native-id", "hook", "BUG_FIX")
	if other.PromptCount != 1 || s.totalPrompts != 2 {
		t.Fatal("cross-session correlation collision")
	}
}

func TestCanonicalPromptViewPrefersHookAndKeepsActions(t *testing.T) {
	events := []audit.Event{
		{EventID: "m", SessionID: "s", Executable: "user_prompt", UserPrompt: "Summary", TurnID: "one", ReportingLayer: "mcp"},
		{EventID: "b", SessionID: "s", Executable: "git", FullCommand: "git status", UserPrompt: "Summary", TurnID: "one", ReportingLayer: "broker"},
		{EventID: "h", SessionID: "s", Executable: "user_prompt", UserPrompt: "Original request", TurnID: "one", ReportingLayer: "hook"},
		{EventID: "retry", SessionID: "s", Executable: "user_prompt", UserPrompt: "Original request", TurnID: "one", ReportingLayer: "hook"},
	}
	got := CanonicalPromptEvents(events)
	prompts, actions := 0, 0
	for _, ev := range got {
		if ev.Executable == "user_prompt" {
			prompts++
			if ev.ReportingLayer != "hook" {
				t.Fatal("hook did not win")
			}
		} else {
			actions++
		}
	}
	if prompts != 1 || actions != 1 {
		t.Fatalf("duplicate prompt or lost action: %+v", got)
	}
}

package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/audit"
)

func writeAudit(t *testing.T, entries ...audit.AuditEntry) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.jsonl")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, e := range entries {
		b, _ := json.Marshal(e)
		_, _ = f.Write(append(b, '\n'))
	}
	return p
}

func TestCollectBlockedEffectsOnlyReportsGrantFriction(t *testing.T) {
	now := time.Now()
	zsp := "ZeroStandingPrivilegeViolation: execution blocked without valid task grant"
	p := writeAudit(t,
		audit.AuditEntry{Timestamp: now, Decision: "deny", Reason: zsp, CanonicalAction: "dev:go:test", CanonicalResource: "dir://local", Executable: "go", FullCommand: "go test ./...", SessionID: "s1"},
		audit.AuditEntry{Timestamp: now.Add(time.Second), Decision: "deny", Reason: zsp, CanonicalAction: "dev:go:test", FullCommand: "go test ./pkg", SessionID: "s2"},
		audit.AuditEntry{Timestamp: now, Decision: "allow", CanonicalAction: "dev:go:build", FullCommand: "go build"},
		// A deliberate policy denial (secrets) is not friction and must not be recommendable.
		audit.AuditEntry{Timestamp: now, Decision: "deny", Reason: "Access to environment secret file (.env) is blocked by secret disclosure policy", CanonicalAction: "fs:file:read", FullCommand: "type .env"},
		audit.AuditEntry{Timestamp: now, Decision: "deny", Reason: zsp, CanonicalAction: "fs:file:write", CanonicalResource: "outside-workspace://unescaped", FullCommand: "echo x > ..\\y"},
	)
	groups, err := collectBlockedEffects(p, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	byAction := map[string]*blockedEffect{}
	for _, g := range groups {
		byAction[g.Action] = g
	}
	if g := byAction["dev:go:test"]; g == nil || g.Count != 2 || len(g.Sessions) != 2 {
		t.Fatalf("repeated blocks of one effect must group: %+v", g)
	}
	if byAction["dev:go:build"] != nil {
		t.Fatal("allowed calls are not failures")
	}
	if byAction["fs:file:read"] != nil {
		t.Fatal("a Cedar invariant denial must not be offered for recommendation")
	}
	if g := byAction["fs:file:write"]; g == nil || !g.Escaped {
		t.Fatalf("an outside-workspace call must be flagged: %+v", g)
	}
}

func TestRedactCommandRemovesSecrets(t *testing.T) {
	got := redactCommand("deploy --token=abc123SECRET --name x password: hunter2 " + strings.Repeat("A", 60))
	for _, leak := range []string{"abc123SECRET", "hunter2", strings.Repeat("A", 60)} {
		if strings.Contains(got, leak) {
			t.Fatalf("redaction leaked %q: %s", leak, got)
		}
	}
	if len(redactCommand(strings.Repeat("word ", 200))) > 210 {
		t.Fatal("hint must be truncated")
	}
}

func TestSubmitRecommendationSendsCredentialAndEffectOnly(t *testing.T) {
	var gotAuth string
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &got)
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"id":"rec-1","status":"pending","action":"dev:go:test","occurrences":1}`))
	}))
	defer srv.Close()

	g := &blockedEffect{Action: "dev:go:test", Executable: "go", CommandHint: "go test ./...", Reason: "zsp", Sessions: map[string]bool{}}
	if err := submitRecommendation(&StoredCredentials{ServerURL: srv.URL, SessionToken: "tok-1"}, g, "runs unit tests"); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tok-1" {
		t.Fatalf("the enrolled-workstation credential must be presented, got %q", gotAuth)
	}
	if got["action"] != "dev:go:test" || got["justification"] != "runs unit tests" {
		t.Fatalf("unexpected payload: %v", got)
	}
}

func TestSubmitRecommendationExplainsRefusals(t *testing.T) {
	for status, want := range map[int]string{401: "bap login", 409: "bapedge sync", 422: "refused"} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":"nope"}`))
		}))
		err := submitRecommendation(&StoredCredentials{ServerURL: srv.URL, SessionToken: "t"}, &blockedEffect{Action: "dev:go:test", Sessions: map[string]bool{}}, "")
		srv.Close()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("status %d: error should mention %q, got %v", status, want, err)
		}
	}
}

package api

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/authz"
	"bap-controlplane/internal/otc"
	"bap-controlplane/internal/policy"
	"bap-controlplane/internal/registry"
	"bap-controlplane/internal/session"
)

func durableFixture(t *testing.T, dir string) *Server {
	t.Helper()
	sessions, err := session.NewStoreWithDB(filepath.Join(dir, "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sessions.Close() })
	pol := policy.NewStore("permit(principal, action, resource);", "{}")
	signer, err := policy.LoadOrCreateSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	pol.SetSigner(signer)
	s := NewServer(registry.NewStore("bap.internal"), otc.NewStore(), authz.NewTokenMinter("stable-test-secret-long-enough-for-pilot", time.Minute), pol, nil, sessions)
	s.SetAdminSecurity("admin-secret-test", false)
	if err := s.EnableDurability(true); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDurableAuthorityRestart(t *testing.T) {
	dir := t.TempDir()
	s := durableFixture(t, dir)
	token, _ := enroll(t, s, "developer", "instance", "asset")
	_, rec, _ := recPost(t, s, token, map[string]any{"action": "dev:go:test"})
	if w := settingsCall(s, "POST", adminRecPrefix+"/"+rec.ID+"/approve", map[string]any{"note": "reviewed"}, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	sess, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "frozen-session", AppID: "developer", InstanceID: "instance"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.sessionStore.RevokeTarget(sess.SessionID, "test freeze"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.auditStore.Ingest([]audit.Event{{EventID: "stable-event", SessionID: sess.SessionID, Source: "broker", Decision: "allow", FullCommand: "git status"}}); err != nil {
		t.Fatal(err)
	}
	if w := call(s, "GET", "/health", nil, nil); w.Code != 200 || w.Header().Get("X-BAP-Durability") != "committed" {
		t.Fatal(w.Code, w.Body.String())
	}
	version := s.policyStore.GetBundle().Version
	count := len(s.auditStore.List(0))
	s.sessionStore.Close()
	restarted := durableFixture(t, dir)
	if b := syncBundle(t, restarted, token); b.Version != version || len(b.ApprovedEffects) != 1 {
		t.Fatalf("policy lost: %+v", b)
	}
	if _, err := restarted.workstationIdentity(requestWithBearer(token)); err != nil {
		t.Fatalf("enrollment lost: %v", err)
	}
	if got, err := restarted.sessionStore.Get("frozen-session"); err != nil || got.Status != "revoked" {
		t.Fatalf("freeze lost: %+v %v", got, err)
	}
	if n, err := restarted.auditStore.Ingest([]audit.Event{{EventID: "stable-event"}}); err != nil || n != 0 || len(restarted.auditStore.List(0)) != count {
		t.Fatalf("dedup lost: %d %v", n, err)
	}
	if valid, err := restarted.auditStore.VerifyChain(); !valid {
		t.Fatal(err)
	}
}

func TestDurabilityDoesNotAcknowledgeFailedCommit(t *testing.T) {
	s := durableFixture(t, t.TempDir())
	// Simulate loss of writable durable storage after startup. The request must not return the
	// successful enrollment code produced by the handler, and subsequent work must fail closed.
	if _, err := s.durable.db.Exec(`DROP TABLE authority_checkpoint`); err != nil {
		t.Fatal(err)
	}
	w := settingsCall(s, "POST", "/api/v1/agents/pre-register", map[string]any{"app_id": "test", "agent_name": "test", "owner_email": "owner@example.test"}, true)
	if w.Code != 503 || strings.Contains(w.Body.String(), "LTD-OTC") {
		t.Fatalf("unsafe ack: %d %s", w.Code, w.Body.String())
	}
	if again := call(s, "GET", "/health", nil, nil); again.Code != 503 {
		t.Fatal("poisoned authority remained ready")
	}
}

func TestDurabilityRejectsChangedSigningIdentity(t *testing.T) {
	dir := t.TempDir()
	s := durableFixture(t, dir)
	s.sessionStore.Close()
	sessions, err := session.NewStoreWithDB(filepath.Join(dir, "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	other := NewServer(registry.NewStore("bap.internal"), otc.NewStore(), authz.NewTokenMinter("different-key", time.Minute), policy.NewStore("", ""), nil, sessions)
	if err := other.EnableDurability(false); err == nil {
		t.Fatal("changed signing identity accepted")
	}
}

func requestWithBearer(token string) *http.Request {
	r, _ := http.NewRequest("GET", "http://localhost/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	return r
}

func TestDurableCheckpointRejectsCorruption(t *testing.T) {
	dir := t.TempDir()
	s := durableFixture(t, dir)
	if _, err := s.durable.db.Exec(`UPDATE authority_checkpoint SET payload=? WHERE id=1`, json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := s.EnableDurability(false); err == nil {
		t.Fatal("corrupt checkpoint accepted")
	}
}

func TestMissingCheckpointRequiresExplicitInitialization(t *testing.T) {
	sessions, err := session.NewStoreWithDB(filepath.Join(t.TempDir(), "new.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	s := NewServer(registry.NewStore("bap.internal"), otc.NewStore(), authz.NewTokenMinter("fixture-key", time.Minute), policy.NewStore("", ""), nil, sessions)
	if err := s.EnableDurability(false); err == nil {
		t.Fatal("missing authority initialized silently")
	}
}

func TestDurabilityFencesASecondWriter(t *testing.T) {
	dir := t.TempDir()
	first := durableFixture(t, dir)
	second := durableFixture(t, dir)
	if w := call(first, "GET", "/health", nil, nil); w.Code != 503 {
		t.Fatal("stale writer acknowledged authority")
	}
	if w := call(second, "GET", "/health", nil, nil); w.Code != 200 {
		t.Fatal("current writer unavailable")
	}
}

func TestDurableAuthorityFollowsAuthenticatedRotation(t *testing.T) {
	dir := t.TempDir()
	first := durableFixture(t, dir)
	next, err := first.policyStore.Signer().RotateTo(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	first.sessionStore.Close()
	sessions, err := session.NewStoreWithDB(filepath.Join(dir, "authority.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	pol := policy.NewStore("permit(principal, action, resource);", "{}")
	pol.SetSigner(next)
	restarted := NewServer(registry.NewStore("bap.internal"), otc.NewStore(), authz.NewTokenMinter("stable-test-secret-long-enough-for-pilot", time.Minute), pol, nil, sessions)
	if err := restarted.EnableDurability(false); err != nil {
		t.Fatalf("authenticated rotation refused: %v", err)
	}
}

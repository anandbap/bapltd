package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"bap-controlplane/internal/policy"
)

func recPost(t *testing.T, s *Server, token string, body map[string]any) (int, policy.Recommendation, string) {
	t.Helper()
	hdr := map[string]string{}
	if token != "" {
		hdr["Authorization"] = "Bearer " + token
	}
	w := call(s, http.MethodPost, "/api/v1/policy/recommendations", body, hdr)
	var rec policy.Recommendation
	_ = json.Unmarshal(w.Body.Bytes(), &rec)
	return w.Code, rec, w.Body.String()
}

func syncBundle(t *testing.T, s *Server, token string) policy.Bundle {
	t.Helper()
	b, code := syncAs(t, s, token, "")
	if code != http.StatusOK {
		t.Fatalf("sync failed: %d", code)
	}
	return b
}

func TestRecommendationRequiresRegisteredWorkstation(t *testing.T) {
	s, _ := newSettingsServer(t, t.TempDir())
	if code, _, _ := recPost(t, s, "", map[string]any{"action": "dev:go:test"}); code != http.StatusUnauthorized {
		t.Fatalf("no credential must be 401, got %d", code)
	}
	if code, _, _ := recPost(t, s, "forged.token.value", map[string]any{"action": "dev:go:test"}); code != http.StatusUnauthorized {
		t.Fatalf("forged credential must be 401, got %d", code)
	}
	if w := call(s, http.MethodGet, "/api/v1/policy/recommendations", nil, nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("listing without credential must be 401, got %d", w.Code)
	}
	for _, p := range []string{"/api/v1/admin/policy/recommendations", "/api/v1/admin/policy/recommendations/rec-1/approve"} {
		if w := settingsCall(s, http.MethodPost, p, map[string]any{}, false); w.Code != http.StatusUnauthorized {
			t.Fatalf("%s without admin must be 401, got %d", p, w.Code)
		}
	}
}

func TestRecommendationApprovalFlowsToThatMachineOnly(t *testing.T) {
	s, pol := newSettingsServer(t, t.TempDir())
	tokDev, _ := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	tokOther, _ := enroll(t, s, "other-box", "inst-other", "asset-other")
	syncBundle(t, s, tokDev) // binds the asset

	code, rec, body := recPost(t, s, tokDev, map[string]any{
		"action": "dev:go:test", "executable": "go", "command_hint": "go test ./...",
		"deny_reason": "ZeroStandingPrivilegeViolation", "justification": "runs unit tests",
	})
	if code != http.StatusAccepted || rec.ID == "" || rec.Status != policy.RecPending || rec.AssetID != "asset-dev" {
		t.Fatalf("submit: %d %s", code, body)
	}

	// Nothing changes until an administrator decides.
	if b := syncBundle(t, s, tokDev); len(b.ApprovedEffects) != 0 {
		t.Fatalf("pending recommendations must not alter policy: %v", b.ApprovedEffects)
	}
	before := pol.GetBundle().Version

	w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/recommendations/"+rec.ID+"/approve", map[string]any{"note": "ok"}, true)
	if w.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", w.Code, w.Body.String())
	}

	b := syncBundle(t, s, tokDev)
	if len(b.ApprovedEffects) != 1 || b.ApprovedEffects[0] != "dev:go:test" {
		t.Fatalf("approved effect must reach the recommending machine: %v", b.ApprovedEffects)
	}
	if b.Version <= before {
		t.Fatal("approval must advance the policy version so clients pick it up")
	}
	if !policy.VerifyEd25519(pol.Signer().PublicKeyB64(), policy.CanonicalBundlePayload(b, "asset-dev"), b.SignatureEd25519) {
		t.Fatal("bundle carrying approved effects must verify against the signed payload")
	}
	// The approval list is inside the signature: editing it invalidates the bundle.
	forged := b
	forged.ApprovedEffects = []string{"dev:go:test", "dev:go:build"}
	if policy.VerifyEd25519(pol.Signer().PublicKeyB64(), policy.CanonicalBundlePayload(forged, "asset-dev"), b.SignatureEd25519) {
		t.Fatal("tampered approved_effects must fail signature verification")
	}
	// Other machines are unaffected.
	if o := syncBundle(t, s, tokOther); len(o.ApprovedEffects) != 0 {
		t.Fatalf("approval must be per machine: %v", o.ApprovedEffects)
	}

	// Deciding twice is refused; the machine sees the outcome.
	if w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/recommendations/"+rec.ID+"/reject", map[string]any{}, true); w.Code != http.StatusConflict {
		t.Fatalf("second decision must be 409, got %d", w.Code)
	}
	mine := call(s, http.MethodGet, "/api/v1/policy/recommendations", nil, map[string]string{"Authorization": "Bearer " + tokDev})
	if !strings.Contains(mine.Body.String(), `"status":"approved"`) {
		t.Fatalf("machine must see its recommendation approved: %s", mine.Body.String())
	}
	otherView := call(s, http.MethodGet, "/api/v1/policy/recommendations", nil, map[string]string{"Authorization": "Bearer " + tokOther})
	if strings.Contains(otherView.Body.String(), rec.ID) {
		t.Fatal("a machine must only see its own recommendations")
	}

	// Revocation flows too.
	if w := settingsCall(s, http.MethodDelete, "/api/v1/admin/policy/approvals?asset_id=asset-dev&action=dev:go:test", nil, true); w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	if b := syncBundle(t, s, tokDev); len(b.ApprovedEffects) != 0 {
		t.Fatalf("revoked effect must disappear: %v", b.ApprovedEffects)
	}
}

func TestRecommendationRejectionChangesNothing(t *testing.T) {
	s, _ := newSettingsServer(t, t.TempDir())
	tok, _ := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	syncBundle(t, s, tok)
	_, rec, _ := recPost(t, s, tok, map[string]any{"action": "dev:go:build"})
	if w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/recommendations/"+rec.ID+"/reject", map[string]any{"note": "no"}, true); w.Code != http.StatusOK {
		t.Fatalf("reject: %d", w.Code)
	}
	if b := syncBundle(t, s, tok); len(b.ApprovedEffects) != 0 {
		t.Fatalf("rejected recommendation must not approve anything: %v", b.ApprovedEffects)
	}
}

func TestDangerousEffectsCanNeverBeRecommended(t *testing.T) {
	s, _ := newSettingsServer(t, t.TempDir())
	tok, _ := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	syncBundle(t, s, tok)
	for _, action := range []string{"net:egress", "http:post", "fs:file:delete", "git:push:write", "dev:package:install",
		"db:query:drop", "cli:python:exec", "secret:read", "../../etc", "", "DEV:GO:TEST;rm"} {
		code, _, body := recPost(t, s, tok, map[string]any{"action": action})
		if code != http.StatusUnprocessableEntity {
			t.Errorf("%q must be refused with 422, got %d %s", action, code, body)
		}
	}
}

func TestRecommendationsDeduplicateAndAreCapped(t *testing.T) {
	s, pol := newSettingsServer(t, t.TempDir())
	tok, _ := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	syncBundle(t, s, tok)
	_, first, _ := recPost(t, s, tok, map[string]any{"action": "dev:go:test"})
	_, again, _ := recPost(t, s, tok, map[string]any{"action": "dev:go:test", "justification": "again"})
	if again.ID != first.ID || again.Occurrences != 2 {
		t.Fatalf("a repeated recommendation must merge: %+v", again)
	}
	for i := 0; i < 40; i++ {
		recPost(t, s, tok, map[string]any{"action": "dev:tool" + strings.Repeat("x", i%5) + string(rune('a'+i%26)) + string(rune('a'+(i/26)%26))})
	}
	if n := len(pol.ListRecommendations("asset-dev", policy.RecPending)); n > 25 {
		t.Fatalf("pending recommendations per machine must be capped, got %d", n)
	}
}

func TestApprovedEffectsSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	s, _ := newSettingsServer(t, dir)
	tok, _ := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	syncBundle(t, s, tok)
	_, rec, _ := recPost(t, s, tok, map[string]any{"action": "fs:file:write"})
	settingsCall(s, http.MethodPost, "/api/v1/admin/policy/recommendations/"+rec.ID+"/approve", map[string]any{}, true)

	s2, pol2 := newSettingsServer(t, dir)
	if got := pol2.ApprovedEffectsFor("asset-dev"); len(got) != 1 || got[0] != "fs:file:write" {
		t.Fatalf("approvals must survive a control plane restart: %v", got)
	}
	if b := syncBundle(t, s2, tok); len(b.ApprovedEffects) != 1 {
		t.Fatalf("restarted control plane must keep serving approvals: %v", b.ApprovedEffects)
	}
}

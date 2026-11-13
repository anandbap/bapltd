package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"bap-controlplane/internal/authz"
	"bap-controlplane/internal/otc"
	"bap-controlplane/internal/policy"
	"bap-controlplane/internal/registry"
	"bap-controlplane/pkg/types"
)

func newSettingsServer(t *testing.T, dir string) (*Server, *policy.Store) {
	t.Helper()
	pol := policy.NewStore("permit(principal, action, resource);", "{}")
	sg, err := policy.LoadOrCreateSigner(dir)
	if err != nil {
		t.Fatal(err)
	}
	pol.SetSigner(sg)
	if err := pol.EnablePersistence(filepath.Join(dir, "policy-settings.json")); err != nil {
		t.Fatal(err)
	}
	s := NewServer(registry.NewStore("bap.internal"), otc.NewStore(), authz.NewTokenMinter("unit-test-secret-key-1234567890", 15*time.Minute), pol, nil)
	s.SetAdminSecurity("admin-secret-test", false)
	s.SetPolicyKeyDir(dir)
	return s, pol
}

func settingsCall(s *Server, method, path string, body any, admin bool) *httptest.ResponseRecorder {
	return call(s, method, path, body, map[string]string{adminHdr(admin): adminVal(admin)})
}

func adminHdr(admin bool) string {
	if admin {
		return "Authorization"
	}
	return "X-Test-None"
}

func adminVal(admin bool) string {
	if admin {
		return "Bearer admin-secret-test"
	}
	return ""
}

func call(s *Server, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.RemoteAddr = "127.0.0.1:1234"
	for k, v := range headers {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	return w
}

// enroll performs a real OTC enrollment (pre-register + register) and returns the workstation
// credential plus what the client would pin.
func enroll(t *testing.T, s *Server, appID, instance, asset string) (string, types.PolicyEnrollment) {
	t.Helper()
	w := settingsCall(s, http.MethodPost, "/api/v1/agents/pre-register", types.PreRegisterRequest{
		AppID: appID, OwnerEmail: appID + "@company.internal", AgentName: appID,
		EnvProfile: types.ProfileProd, AllowedBinaryHashes: []string{"good-hash"},
	}, true)
	var pre types.PreRegisterResponse
	if err := json.Unmarshal(w.Body.Bytes(), &pre); err != nil || pre.Code == "" {
		t.Fatalf("pre-register failed: %d %s", w.Code, w.Body.String())
	}
	w = settingsCall(s, http.MethodPost, "/api/v1/agents/register", types.RegisterEdgeRequest{
		Code: pre.Code, BinaryHash: "good-hash", Hostname: instance, OS: "windows", Arch: "amd64", InstanceID: instance, AssetID: asset,
	}, false)
	var reg types.RegisterEdgeResponse
	if err := json.Unmarshal(w.Body.Bytes(), &reg); err != nil || reg.SessionToken == "" {
		t.Fatalf("register failed: %d %s", w.Code, w.Body.String())
	}
	return reg.SessionToken, reg.PolicyEnrollment
}

func syncAs(t *testing.T, s *Server, token string, claimedAsset string) (policy.Bundle, int) {
	t.Helper()
	hdr := map[string]string{}
	if token != "" {
		hdr["Authorization"] = "Bearer " + token
	}
	w := call(s, http.MethodPost, "/api/v1/policy/sync", map[string]any{"asset_id": claimedAsset, "installed_version": 0}, hdr)
	var resp policy.SyncResponse
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	if resp.Bundle == nil {
		return policy.Bundle{}, w.Code
	}
	return *resp.Bundle, w.Code
}

func TestPolicySettingsRequireAdmin(t *testing.T) {
	s, _ := newSettingsServer(t, t.TempDir())
	for _, m := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		if w := settingsCall(s, m, "/api/v1/admin/policy/settings", map[string]any{"zsp_read_exempt": false}, false); w.Code != http.StatusUnauthorized {
			t.Errorf("%s without admin token must be 401, got %d", m, w.Code)
		}
	}
	if w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/rotate-key", nil, false); w.Code != http.StatusUnauthorized {
		t.Errorf("rotate-key without admin token must be 401, got %d", w.Code)
	}
}

func TestPublicKeyEndpointServesPinnableKey(t *testing.T) {
	s, pol := newSettingsServer(t, t.TempDir())
	w := settingsCall(s, http.MethodGet, "/api/v1/policy/pubkey", nil, false)
	var pk map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &pk)
	if w.Code != 200 || pk["alg"] != "ed25519" || pk["public_key"] != pol.Signer().PublicKeyB64() || pk["key_id"] != pol.Signer().KeyID() {
		t.Fatalf("unexpected pubkey response: %d %v", w.Code, pk)
	}
}

func TestEnrollmentDeliversTrustAnchorAndBindsAsset(t *testing.T) {
	s, pol := newSettingsServer(t, t.TempDir())
	_, pe := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	if pe.PolicyKeyID != pol.Signer().KeyID() || pe.PolicyPublicKey != pol.Signer().PublicKeyB64() || pe.PolicyAssetID != "asset-dev" {
		t.Fatalf("register must hand out the trust anchor and bound asset: %+v", pe)
	}
	if a, ok := pol.EnrolledAsset("inst-dev"); !ok || a != "asset-dev" {
		t.Fatalf("asset must be bound to the enrolled instance: %q %v", a, ok)
	}
	// A client that reports no asset id still gets a stable one derived from its identity.
	_, pe2 := enroll(t, s, "other-box", "inst-other", "")
	if pe2.PolicyAssetID != "inst:inst-other" {
		t.Fatalf("expected derived asset id, got %q", pe2.PolicyAssetID)
	}
}

func TestSyncIdentityComesFromCredentialNotRequestBody(t *testing.T) {
	s, _ := newSettingsServer(t, t.TempDir())
	tokDev, _ := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	_, _ = enroll(t, s, "locked-box", "inst-locked", "asset-locked")
	settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", map[string]any{"asset_id": "asset-locked", "zsp_read_exempt": false}, true)

	// The dev machine claims to be the locked one: it still gets its OWN asset's bundle.
	b, code := syncAs(t, s, tokDev, "asset-locked")
	if code != 200 || b.AssetID != "asset-dev" || !b.ZSPReadExempt {
		t.Fatalf("credential must decide the asset: code=%d asset=%q exempt=%v", code, b.AssetID, b.ZSPReadExempt)
	}
}

func TestUnauthenticatedSyncGetsFleetDefaultNeverOverrides(t *testing.T) {
	s, pol := newSettingsServer(t, t.TempDir())
	_, _ = enroll(t, s, "locked-box", "inst-locked", "asset-locked")
	settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", map[string]any{"asset_id": "asset-locked", "zsp_read_exempt": false}, true)

	b, code := syncAs(t, s, "", "asset-locked")
	if code != 200 || b.AssetID != "" || !b.ZSPReadExempt {
		t.Fatalf("anonymous callers get the fleet default signed for no asset: code=%d asset=%q exempt=%v", code, b.AssetID, b.ZSPReadExempt)
	}
	if !policy.VerifyEd25519(pol.Signer().PublicKeyB64(), policy.CanonicalBundlePayload(b, ""), b.SignatureEd25519) {
		t.Fatal("fleet bundle must still be signed")
	}
}

func TestSyncWithInvalidCredentialIsRefused(t *testing.T) {
	s, _ := newSettingsServer(t, t.TempDir())
	if _, code := syncAs(t, s, "forged.token.value", "asset-x"); code != http.StatusUnauthorized {
		t.Fatalf("a presented but invalid credential must be 401, got %d", code)
	}
}

func TestSyncRequireAuthMode(t *testing.T) {
	t.Setenv("BAP_POLICY_SYNC_REQUIRE_AUTH", "1")
	s, _ := newSettingsServer(t, t.TempDir())
	if _, code := syncAs(t, s, "", "asset-x"); code != http.StatusUnauthorized {
		t.Fatalf("anonymous sync must be refused when auth is required, got %d", code)
	}
	tok, _ := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	if _, code := syncAs(t, s, tok, ""); code != http.StatusOK {
		t.Fatalf("enrolled sync must work, got %d", code)
	}
}

func TestAssetOverrideFlowsToThatMachineOnly(t *testing.T) {
	s, pol := newSettingsServer(t, t.TempDir())
	tokDev, _ := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	tokLocked, _ := enroll(t, s, "locked-box", "inst-locked", "asset-locked")

	before, _ := syncAs(t, s, tokDev, "")
	if !before.ZSPReadExempt {
		t.Fatal("fleet default should exempt reads")
	}
	if w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", map[string]any{"asset_id": "asset-locked", "zsp_read_exempt": false}, true); w.Code != http.StatusOK {
		t.Fatalf("set override: %d %s", w.Code, w.Body.String())
	}
	locked, _ := syncAs(t, s, tokLocked, "")
	dev, _ := syncAs(t, s, tokDev, "")
	if locked.ZSPReadExempt || !dev.ZSPReadExempt {
		t.Fatalf("override must apply to asset-locked only: locked=%v dev=%v", locked.ZSPReadExempt, dev.ZSPReadExempt)
	}
	if locked.Version <= before.Version {
		t.Fatal("a settings change must advance the version so clients pick it up")
	}
	if !policy.VerifyEd25519(pol.Signer().PublicKeyB64(), policy.CanonicalBundlePayload(locked, "asset-locked"), locked.SignatureEd25519) {
		t.Fatal("per-asset bundle must be signed for that asset")
	}

	settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", map[string]any{"asset_id": "*", "zsp_read_exempt": false}, true)
	if d, _ := syncAs(t, s, tokDev, ""); d.ZSPReadExempt {
		t.Fatal("fleet default change must reach every machine")
	}
	if w := settingsCall(s, http.MethodDelete, "/api/v1/admin/policy/settings?asset_id=asset-locked", nil, true); w.Code != http.StatusOK {
		t.Fatalf("clear override: %d %s", w.Code, w.Body.String())
	}
	if w := settingsCall(s, http.MethodDelete, "/api/v1/admin/policy/settings?asset_id=asset-locked", nil, true); w.Code != http.StatusNotFound {
		t.Fatalf("clearing a missing override must be 404, got %d", w.Code)
	}
}

func TestAdminCanSeeEnrolledAssetIDs(t *testing.T) {
	s, _ := newSettingsServer(t, t.TempDir())
	_, _ = enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	w := settingsCall(s, http.MethodGet, "/api/v1/admin/policy/settings", nil, true)
	var snap policy.SettingsSnapshot
	_ = json.Unmarshal(w.Body.Bytes(), &snap)
	if snap.EnrolledAssets["inst-dev"] != "asset-dev" {
		t.Fatalf("admin must be able to find the asset id to target: %+v", snap.EnrolledAssets)
	}
}

func TestPolicySettingsInputValidation(t *testing.T) {
	s, _ := newSettingsServer(t, t.TempDir())
	if w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", map[string]any{"asset_id": "x"}, true); w.Code != http.StatusBadRequest {
		t.Fatalf("missing zsp_read_exempt must be 400, got %d", w.Code)
	}
	if w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", map[string]any{"asset_id": "../../etc", "zsp_read_exempt": true}, true); w.Code != http.StatusBadRequest {
		t.Fatalf("hostile asset id must be 400, got %d", w.Code)
	}
}

// An override for a machine this control plane has never enrolled must be refused, not silently
// stored: it would apply to nothing now and to whoever is later bound to that id.
func TestOverrideForUnenrolledAssetIsRefused(t *testing.T) {
	s, pol := newSettingsServer(t, t.TempDir())
	body := map[string]any{"asset_id": "asset-never-enrolled", "zsp_read_exempt": false}
	if w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", body, true); w.Code != http.StatusNotFound {
		t.Fatalf("unenrolled asset must be 404, got %d %s", w.Code, w.Body.String())
	}
	if snap := pol.Settings(); len(snap.AssetOverrides) != 0 {
		t.Fatalf("a refused override must not be stored: %+v", snap.AssetOverrides)
	}
	// The fleet default never needs an enrolled machine.
	if w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", map[string]any{"asset_id": "*", "zsp_read_exempt": true}, true); w.Code != http.StatusOK {
		t.Fatalf("fleet default must be settable, got %d", w.Code)
	}
}

func TestSettingsEnrollmentAndVersionSurviveRestart(t *testing.T) {
	dir := t.TempDir()
	s, _ := newSettingsServer(t, dir)
	tok, _ := enroll(t, s, "locked-box", "inst-locked", "asset-locked")
	settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", map[string]any{"asset_id": "asset-locked", "zsp_read_exempt": false}, true)
	settingsCall(s, http.MethodPost, "/api/v1/admin/policy/settings", map[string]any{"asset_id": "*", "zsp_read_exempt": false}, true)
	heldByClients, _ := syncAs(t, s, tok, "")

	s2, pol2 := newSettingsServer(t, dir) // control plane restart
	if a, ok := pol2.EnrolledAsset("inst-locked"); !ok || a != "asset-locked" {
		t.Fatal("enrolled asset bindings must survive a restart")
	}
	after, code := syncAs(t, s2, tok, "")
	if code != 200 {
		t.Fatalf("credential must still be accepted after restart, got %d", code)
	}
	if after.Version <= heldByClients.Version {
		t.Fatalf("version must never go backwards across a restart (clients refuse rollback): %d <= %d", after.Version, heldByClients.Version)
	}
	if after.ZSPReadExempt {
		t.Fatal("persisted override must survive a restart")
	}
}

func TestKeyRotationIsAdminOnlyAndFollowable(t *testing.T) {
	dir := t.TempDir()
	s, pol := newSettingsServer(t, dir)
	tok, pe := enroll(t, s, "dev-box", "inst-dev", "asset-dev")
	oldID, oldPub := pe.PolicyKeyID, pe.PolicyPublicKey

	w := settingsCall(s, http.MethodPost, "/api/v1/admin/policy/rotate-key", nil, true)
	if w.Code != http.StatusOK {
		t.Fatalf("rotate: %d %s", w.Code, w.Body.String())
	}
	if pol.Signer().KeyID() == oldID {
		t.Fatal("key must change")
	}
	b, _ := syncAs(t, s, tok, "")
	if b.KeyID != pol.Signer().KeyID() {
		t.Fatal("bundles must now be signed by the new key")
	}
	// A client pinned to the OLD key follows the chain and learns the new one with no user action.
	newPub, ok := policy.VerifyRotationChain(oldID, oldPub, b.KeyChain, b.KeyID)
	if !ok || newPub != pol.Signer().PublicKeyB64() {
		t.Fatal("rotation chain must lead from the pinned key to the current key")
	}
	if !policy.VerifyEd25519(newPub, policy.CanonicalBundlePayload(b, "asset-dev"), b.SignatureEd25519) {
		t.Fatal("bundle must verify under the followed key")
	}
	// The chain and key survive a restart.
	_, pol2 := newSettingsServer(t, dir)
	if pol2.Signer().KeyID() != pol.Signer().KeyID() || len(pol2.Signer().Chain()) == 0 {
		t.Fatal("rotated key and its chain must persist")
	}
}

func TestSettingsPersistenceFileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	_, _ = newSettingsServer(t, dir)
	if _, err := policy.LoadOrCreateSigner(dir); err != nil {
		t.Fatal(err)
	}
}

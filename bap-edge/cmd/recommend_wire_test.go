package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"bap-edge/internal/authz"
	"bap-edge/internal/policystore"
)

// This opt-in fixture runs an actual matching control-plane binary over loopback. It tests
// transport and edge signed-policy enforcement, not a browser or the human terminal challenge.
// CI supplies BAP_RECOMMENDATION_E2E=1 and BAP_CONTROLPLANE_TEST_BIN; missing artifacts fail.
func TestRecommendationWireEndToEnd(t *testing.T) {
	if os.Getenv("BAP_RECOMMENDATION_E2E") != "1" {
		t.Skip("enable the isolated wire fixture explicitly")
	}
	bin, err := filepath.Abs(os.Getenv("BAP_CONTROLPLANE_TEST_BIN"))
	if err != nil || os.Getenv("BAP_CONTROLPLANE_TEST_BIN") == "" {
		t.Fatal("matching control-plane binary required")
	}
	root := t.TempDir()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	base := "http://127.0.0.1:" + strconv.Itoa(port)
	policyPath := filepath.Join(root, "policy.cedar")
	if err := os.WriteFile(policyPath, []byte("permit(principal, action, resource);"), 0600); err != nil {
		t.Fatal(err)
	}
	start := func() *exec.Cmd {
		cmd := exec.Command(bin, "start", "--fg", "--mode", "dev", "--durable", "--initialize-authority", "--db", filepath.Join(root, "authority.db"), "--port", strconv.Itoa(port), "--policy", policyPath, "--admin-token", "wire-admin-test", "--secret", "wire-test-stable-signing-secret-32-characters")
		cmd.Dir = root
		for _, e := range os.Environ() {
			name := strings.ToUpper(strings.SplitN(e, "=", 2)[0])
			if !strings.HasPrefix(name, "BAP_") && !strings.HasPrefix(name, "LTD_") && name != "HOME" && name != "USERPROFILE" {
				cmd.Env = append(cmd.Env, e)
			}
		}
		cmd.Env = append(cmd.Env, "BAP_STATE_DIR="+filepath.Join(root, "server"), "BAP_ENVIRONMENT=development", "HOME="+root, "USERPROFILE="+root)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(20 * time.Second)
		for time.Now().Before(deadline) {
			client := &http.Client{Timeout: time.Second}
			resp, err := client.Get(base + "/health")
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					return cmd
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatal("isolated control plane did not become ready")
		return nil
	}
	server := start()
	defer func() { _ = server.Process.Kill(); _ = server.Wait() }()
	api := func(method, path, token string, body any, want int) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, base+path, bytes.NewReader(raw))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode != want {
			t.Fatalf("%s %s: want %d, got %d", method, path, want, resp.StatusCode)
		}
		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	enroll := func(instance, asset string) (*StoredCredentials, *policystore.Store) {
		t.Helper()
		pre := api("POST", "/api/v1/agents/pre-register", "wire-admin-test", map[string]any{"app_id": instance, "agent_name": instance, "owner_email": "fixture@example.test", "allowed_binary_hashes": []string{"fixture-hash"}}, 201)
		registration := api("POST", "/api/v1/agents/register", "", map[string]any{"one_time_code": pre["one_time_code"], "binary_hash": "fixture-hash", "hostname": instance, "instance_id": instance, "asset_id": asset}, 200)
		get := func(key string) string { value, _ := registration[key].(string); return value }
		creds := &StoredCredentials{ServerURL: base, SessionToken: get("session_token")}
		store := policystore.New(filepath.Join(root, instance))
		if err := store.PinEnrollment(get("policy_key_id"), get("policy_public_key"), get("policy_asset_id"), base); err != nil {
			t.Fatal(err)
		}
		store.SetAuthToken(creds.SessionToken)
		return creds, store
	}
	creds, store := enroll("wire-a", "asset-a")
	_, other := enroll("wire-b", "asset-b")
	sync := func(store *policystore.Store) {
		t.Helper()
		if _, fallback, err := store.SyncWithServer(base, "", 3*time.Second); err != nil || fallback {
			t.Fatalf("signed sync failed: fallback=%v error=%v", fallback, err)
		}
	}
	sync(store)
	old := authz.ApprovedEffectsProvider
	defer func() { authz.ApprovedEffectsProvider = old }()
	t.Setenv("BAP_ZSP_STRICT_READS", "")
	authz.ApprovedEffectsProvider = func() []string {
		_, _, st, err := store.Current()
		if err != nil {
			return nil
		}
		return st.ApprovedEffects
	}
	allowed := func(command string) bool {
		parts := strings.SplitN(command, " ", 2)
		args := ""
		if len(parts) > 1 {
			args = parts[1]
		}
		return authz.IsApprovedLocalCommand(command, parts[0], args, root)
	}
	if allowed("go test ./...") {
		t.Fatal("unapproved effect was exempt")
	}
	if err := submitRecommendation(creds, &blockedEffect{Action: "dev:go:test", Executable: "go", CommandHint: "go test ./...", Reason: "ZeroStandingPrivilegeViolation"}, "isolated wire fixture"); err != nil {
		t.Fatal(err)
	}
	queue := api("GET", "/api/v1/admin/policy/recommendations", "wire-admin-test", nil, 200)
	items := queue["recommendations"].([]any)
	if len(items) != 1 {
		t.Fatal("missing recommendation")
	}
	id := items[0].(map[string]any)["id"].(string)
	api("POST", "/api/v1/admin/policy/recommendations/"+id+"/approve", "wire-admin-test", map[string]string{"note": "reviewed"}, 200)
	sync(store)
	if !allowed("go test ./...") {
		t.Fatal("approved effect did not reach edge enforcement")
	}
	for _, command := range []string{"go build ./...", "go test ./... && rm -rf build", "curl https://example.invalid"} {
		if allowed(command) {
			t.Fatalf("unapproved command exempt: %s", command)
		}
	}
	sync(other)
	_, _, otherState, err := other.Current()
	if err != nil || len(otherState.ApprovedEffects) != 0 {
		t.Fatal("approval leaked to another asset")
	}
	api("POST", "/api/v1/policy/recommendations", "", map[string]string{"action": "dev:go:test"}, 401)
	api("POST", "/api/v1/policy/recommendations", creds.SessionToken, map[string]string{"action": "net:egress"}, 422)
	api("POST", "/api/v1/admin/policy/recommendations/"+id+"/reject", "wire-admin-test", nil, 409)
	// Restart the actual process at the same origin and signing/database configuration.
	_ = server.Process.Kill()
	_ = server.Wait()
	server = start()
	sync(store)
	if !allowed("go test ./...") {
		t.Fatal("approved policy/enrollment lost across restart")
	}
	api("DELETE", fmt.Sprintf("/api/v1/admin/policy/approvals?asset_id=asset-a&action=dev:go:test"), "wire-admin-test", nil, 200)
	sync(store)
	if allowed("go test ./...") {
		t.Fatal("revoked approval remained usable")
	}
}

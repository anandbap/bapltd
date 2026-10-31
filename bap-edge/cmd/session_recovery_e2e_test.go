package cmd

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"bap-edge/internal/httptransport"
)

func TestSessionRecoveryAgainstRestartedControlPlane(t *testing.T) {
	url, proof := os.Getenv("BAP_RECOVERY_E2E_URL"), os.Getenv("BAP_RECOVERY_E2E_PROOF")
	if url == "" {
		t.Skip("run control-plane restart E2E harness")
	}
	previousTransport, previousCredential, previousRestrictions := httptransport.MockTransport, recoveryCredential, recoveryRestrictions
	httptransport.MockTransport = heartbeatTransport(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+proof)
		return http.DefaultTransport.RoundTrip(r)
	})
	recoveryCredential = func(string) (StoredCredentials, error) {
		return StoredCredentials{ServerURL: url, InstanceID: "restart-machine", SessionToken: proof}, nil
	}
	blocked := false
	recoveryRestrictions = func(string) (bool, bool) { return blocked, false }
	t.Cleanup(func() {
		httptransport.MockTransport, recoveryCredential, recoveryRestrictions = previousTransport, previousCredential, previousRestrictions
	})
	client := httptransport.New(3 * time.Second)
	if status, _, _ := pulseHeartbeat(url, "restart-claude"); status != "ok" {
		t.Fatalf("initial authenticated heartbeat: %s", status)
	}
	for _, frozen := range []bool{false, true} {
		blocked = frozen
		req, _ := http.NewRequest("POST", url+"/e2e/restart", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		closeHeartbeatResponse(resp)
		if resp.StatusCode != 200 {
			t.Fatal("restart failed")
		}
		if status, _, _ := pulseHeartbeat(url, "restart-claude"); status != "missing" {
			t.Fatalf("expected unknown session after restart: %s", status)
		}
		status, reason := recoverMissingSession(context.Background(), client, url, "restart-claude", "claude-code", os.Getpid())
		want := "ok"
		if frozen {
			want = "revoked"
		}
		if status != want {
			t.Fatalf("recovery frozen=%v: %s %s", frozen, status, reason)
		}
		status, _, _ = pulseHeartbeat(url, "restart-claude")
		if status != want {
			t.Fatalf("post-recovery heartbeat: %s want %s", status, want)
		}
	}
}

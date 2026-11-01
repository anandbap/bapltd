package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"bap-controlplane/pkg/types"
)

func TestWorkstationLogoutUpgradeLoginReusesRegistration(t *testing.T) {
	for _, browserFlow := range []bool{false, true} {
		name := "verify"
		if browserFlow {
			name = "browser"
		}
		t.Run(name, func(t *testing.T) {
			s, ts := setupTestServerForOIDC()
			defer ts.Close()
			post := func(handler http.HandlerFunc, payload any) *httptest.ResponseRecorder {
				t.Helper()
				body, err := json.Marshal(payload)
				if err != nil {
					t.Fatal(err)
				}
				w := httptest.NewRecorder()
				handler(w, httptest.NewRequest("POST", "/", bytes.NewReader(body)))
				if w.Code != http.StatusOK {
					t.Fatalf("unexpected HTTP status %d: %s", w.Code, w.Body.String())
				}
				return w
			}
			login := func(hash string) types.OIDCDeviceTokenResponse {
				t.Helper()
				w := post(s.handleOIDCDeviceCode, types.OIDCDeviceCodeRequest{
					AppID: "workstation-laptop", Hostname: "alice-laptop", BinaryHash: hash,
					Provider: "google", OS: "windows", Arch: "amd64",
				})
				var code types.OIDCDeviceCodeResponse
				if err := json.Unmarshal(w.Body.Bytes(), &code); err != nil {
					t.Fatal(err)
				}
				if browserFlow {
					if _, err := s.authorizeDeviceSession(code.UserCode, "alice@example.test", "Engineering", "google", []string{"developers"}); err != nil {
						t.Fatal(err)
					}
				} else {
					post(s.handleOIDCDeviceVerify, types.OIDCDeviceVerifyRequest{
						UserCode: code.UserCode, UserEmail: "alice@example.test",
						Department: "Engineering", Provider: "google",
					})
				}
				w = post(s.handleOIDCDeviceToken, types.OIDCDeviceTokenRequest{DeviceCode: code.DeviceCode})
				var result types.OIDCDeviceTokenResponse
				if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				return result
			}
			first := login("release-one")
			// A software upgrade alone must not invalidate an enrolled login.
			if _, err := s.minter.Verify(first.SessionToken); err != nil {
				t.Fatal("existing login invalid before logout:", err)
			}
			post(s.handleDeregisterAgent, map[string]string{
				"agent_id": first.AgentID, "instance_id": first.InstanceID, "session_token": first.SessionToken,
			})
			second := login("release-two")
			if second.AgentID != first.AgentID || second.InstanceID != first.InstanceID || len(s.registry.List()) != 1 {
				t.Fatal("logout/login created a second workstation registration")
			}
			if _, err := s.minter.Verify(first.SessionToken); err == nil {
				t.Fatal("old logout credential became valid again")
			}
			heartbeat := post(s.handleHeartbeat, map[string]string{
				"agent_id": second.AgentID, "session_id": second.AgentID,
			})
			var presence map[string]any
			if err := json.Unmarshal(heartbeat.Body.Bytes(), &presence); err != nil {
				t.Fatal(err)
			}
			if presence["status"] == "revoked" || presence["action"] == "terminate" {
				t.Fatal("new login is still revoked by an old logout placeholder")
			}
			// A fresh authorization supersedes any previous credential even if
			// a client bypasses its local already-logged-in check.
			third := login("release-three")
			if third.AgentID != first.AgentID || third.InstanceID != first.InstanceID || len(s.registry.List()) != 1 {
				t.Fatal("fresh login replaced the workstation identity")
			}
			if _, err := s.minter.Verify(second.SessionToken); err == nil {
				t.Fatal("prior login credential was not superseded")
			}
			staleLogout, _ := json.Marshal(map[string]string{
				"agent_id": second.AgentID, "session_token": second.SessionToken,
			})
			w := httptest.NewRecorder()
			s.handleDeregisterAgent(w, httptest.NewRequest("POST", "/", bytes.NewReader(staleLogout)))
			if w.Code != http.StatusUnauthorized {
				t.Fatalf("stale logout accepted: %d", w.Code)
			}
			r := httptest.NewRequest("POST", "/", nil)
			r.Header.Set("Authorization", "Bearer "+third.SessionToken)
			if _, err := s.workstationIdentity(r); err != nil {
				t.Fatal("current login credential rejected:", err)
			}
			a, err := s.registry.Get(third.AgentID)
			if err != nil || a.EnrolledBinaryHash != "release-three" || a.Status != types.StatusActive || a.RevokedAt != nil {
				t.Fatal("registration was not refreshed")
			}
		})
	}
}

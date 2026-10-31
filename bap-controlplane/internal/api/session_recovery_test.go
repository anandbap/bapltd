package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

func recoveryProof(t testing.TB, s *Server, instance string) string {
	t.Helper()
	token, _, err := s.minter.MintWorkstationSession(&types.RegisteredAgent{AgentID: "station", AppID: "bapedge", InstanceID: instance, OwnerEmail: "operator@example.test"}, "binary")
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func resumeRequest(s *Server, proof, body string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/sessions/resume", strings.NewReader(body))
	if proof != "" {
		r.Header.Set("Authorization", "Bearer "+proof)
	}
	s.Handler().ServeHTTP(w, r)
	return w
}

func TestResumeAfterControlPlaneStateLoss(t *testing.T) {
	before, after := setupTestServer(), setupTestServer()
	proof := recoveryProof(t, before, "machine")
	body := `{"session_id":"open-claude","app_id":"claude-code","instance_id":"machine","client_pid":123,"user_email":"forged","grant_id":"forged"}`
	for i := 0; i < 2; i++ {
		w := resumeRequest(after, proof, body)
		if w.Code != 200 {
			t.Fatalf("resume %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	if len(after.sessionStore.List(0)) != 1 {
		t.Fatal("resume duplicated session")
	}
	sess, _ := after.sessionStore.Get("open-claude")
	if sess.InstanceID != "machine" || sess.GrantID != "" || sess.UserEmail == "forged" || sess.TotalEvents != 0 {
		t.Fatalf("unexpected recovered authority: %+v", sess)
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/api/v1/sessions/heartbeat", strings.NewReader(`{"session_id":"open-claude"}`))
	r.Header.Set("Authorization", "Bearer "+proof)
	after.Handler().ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("heartbeat after resume: %s", w.Body.String())
	}
}

func TestResumeCannotBypassAuthenticationOrAdministrativeState(t *testing.T) {
	for _, scenario := range []string{"no-proof", "wrong-instance", "closed", "revoked", "fleet-frozen", "local-frozen"} {
		t.Run(scenario, func(t *testing.T) {
			s := setupTestServer()
			proof := recoveryProof(t, s, "machine")
			body := `{"session_id":"session","app_id":"claude-code","instance_id":"machine","client_pid":123}`
			want := 200
			switch scenario {
			case "no-proof":
				proof = ""
				want = 401
			case "wrong-instance":
				proof = recoveryProof(t, s, "other")
				want = 401
			case "closed", "revoked":
				_, _ = s.sessionStore.Start(session.SessionStartRequest{SessionID: "session", AppID: "claude-code", InstanceID: "machine"})
				if scenario == "closed" {
					_ = s.sessionStore.End("session", "Stopped by administrator")
				} else {
					_ = s.sessionStore.RevokeSession("session", "Revoked")
				}
				want = 409
			case "fleet-frozen":
				s.policyStore.SetKillSwitch(true)
				want = 403
			case "local-frozen":
				body = `{"session_id":"session","app_id":"claude-code","instance_id":"machine","client_pid":123,"local_frozen":true}`
			}
			w := resumeRequest(s, proof, body)
			if w.Code != want {
				t.Fatalf("got %d want %d: %s", w.Code, want, w.Body.String())
			}
			if scenario == "local-frozen" {
				var result struct {
					Status string `json:"status"`
				}
				_ = json.Unmarshal(w.Body.Bytes(), &result)
				if result.Status != "revoked" {
					t.Fatal("cached freeze was dropped")
				}
			}
		})
	}
}

package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

func TestHeartbeatRequiresIdentityAndSessionOwnership(t *testing.T) {
	s := setupTestServer()
	_, _ = s.sessionStore.Start(session.SessionStartRequest{SessionID: "owned", AppID: "claude-code", InstanceID: "machine-a"})
	owner, other := recoveryProof(t, s, "machine-a"), recoveryProof(t, s, "machine-b")
	before, _ := s.sessionStore.Get("owned")
	for _, tc := range []struct {
		token, body string
		code        int
	}{
		{"", `{"session_id":"owned"}`, 401},
		{other, `{"session_id":"owned"}`, 403},
		{other, `{"agent_id":"owned"}`, 403},
		{owner, `{"session_id":"missing"}`, 404},
	} {
		r := httptest.NewRequest("POST", "/api/v1/sessions/heartbeat", strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("got %d want %d: %s", w.Code, tc.code, w.Body.String())
		}
	}
	after, _ := s.sessionStore.Get("owned")
	if !after.LastActiveAt.Equal(before.LastActiveAt) {
		t.Fatal("unauthorized heartbeat changed presence")
	}
	for _, path := range []string{"/api/v1/sessions/heartbeat", "/api/v1/instances/heartbeat", "/api/v1/control/heartbeat"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(`{"session_id":"owned"}`))
		r.Header.Set("Authorization", "Bearer "+owner)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != 200 {
			t.Fatalf("authenticated heartbeat failed: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestLifecycleCannotUseExecutionGrantOrCrossMachineIdentity(t *testing.T) {
	s := setupTestServer()
	proof := recoveryProof(t, s, "machine-a")
	agent := &types.RegisteredAgent{AgentID: "station", AppID: "bapedge", InstanceID: "machine-a", PermittedScopes: []string{"cli:exec"}}
	grant, _, _, err := s.minter.MintWithDetails(agent, "binary", []string{"cli:exec"}, "", "", "", nil, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		token, instance string
		code            int
	}{{grant, "machine-a", 401}, {proof, "machine-b", 403}} {
		r := httptest.NewRequest("POST", "/api/v1/sessions/start", strings.NewReader(`{"session_id":"owned","app_id":"claude-code","instance_id":"`+tc.instance+`"}`))
		r.Header.Set("Authorization", "Bearer "+tc.token)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code != tc.code {
			t.Fatalf("got %d want %d: %s", w.Code, tc.code, w.Body.String())
		}
	}
	if len(s.sessionStore.List(0)) != 0 {
		t.Fatal("unauthorized lifecycle request created a session")
	}
}

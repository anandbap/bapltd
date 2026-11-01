package api

import (
	"bap-controlplane/internal/pilot"
	"bap-controlplane/pkg/types"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPilotRosterAdminIsolationAndRecovery(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("test-admin", true)
	now := time.Now().UTC()
	call := func(method, token string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/v1/pilot/coverage", nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := call("GET", ""); w.Code == 200 || strings.Contains(w.Body.String(), "expected_workstations") {
		t.Fatal(w.Code, w.Body)
	}
	if w := call("GET", "test-admin"); w.Code != 503 {
		t.Fatal(w.Code, w.Body)
	}
	roster := pilot.Roster{SchemaVersion: 1, RosterID: "controlled-pilot", FreshnessSeconds: 60, Entries: []pilot.Entry{{PersonID: "operator", OwnerEmail: "operator@example.test", Team: "engineering", InstanceID: "station", Windows: []pilot.Window{{Start: now.Add(-time.Minute), End: now.Add(time.Hour)}}}}}
	b, _ := json.Marshal(roster)
	if err := s.ConfigurePilotRoster(strings.NewReader(string(b))); err != nil {
		t.Fatal(err)
	}
	if w := call("POST", "test-admin"); w.Code != 405 {
		t.Fatal(w.Code)
	}
	if w := call("GET", recoveryProof(t, s, "station")); w.Code == 200 {
		t.Fatal("enrollment proof read admin roster")
	}
	a, err := s.registry.PreRegister(types.PreRegisterRequest{AppID: "bap-workstation", OwnerEmail: "operator@example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.registry.Enroll(a.AgentID, "hash", "", "fixture", "windows", "amd64", "station"); err != nil {
		t.Fatal(err)
	}
	w := call("GET", "test-admin")
	var out pilot.Report
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil || w.Code != 200 || out.FreshWorkstations != 1 || out.ExpectedWorkstations != 1 {
		t.Fatal(w.Code, w.Body, err)
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("roster cached")
	}
	// A restarted registry must report missing, never invent a successful check-in.
	restarted := setupTestServer()
	restarted.SetAdminSecurity("test-admin", true)
	if err := restarted.ConfigurePilotRoster(strings.NewReader(string(b))); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/api/v1/pilot/coverage", nil)
	r.Header.Set("Authorization", "Bearer test-admin")
	w = httptest.NewRecorder()
	restarted.Handler().ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), `"state":"missing"`) {
		t.Fatal(w.Body)
	}
}

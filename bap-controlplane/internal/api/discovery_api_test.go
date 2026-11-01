package api

import (
	"bap-controlplane/internal/discovery"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDiscoveryAuthenticatedMetadataContract(t *testing.T) {
	s := setupTestServer()
	s.SetAdminSecurity("discovery-admin", true)
	proof := recoveryProof(t, s, "station-a")
	request := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	now := time.Now().UTC()
	report := discovery.Report{Version: 1, RunID: "clean", StartedAt: now, CompletedAt: now, Status: "complete", Scopes: []discovery.ScopeResult{{ID: "config", Status: "complete"}}, Observations: []discovery.Observation{}}
	raw, _ := json.Marshal(report)
	path := "/api/v1/discovery/shadow-it/scan"
	if w := request("POST", path, "", string(raw)); w.Code != 401 {
		t.Fatal(w.Code, w.Body)
	}
	if w := request("POST", path, "discovery-admin", string(raw)); w.Code != 401 {
		t.Fatal("admin impersonated collector", w.Code)
	}
	for _, body := range []string{`{"workspace_root":"C:/","env_map":{}}`, strings.TrimSuffix(string(raw), "}") + `,"instance_id":"forged"}`, string(raw) + ` {}`} {
		if w := request("POST", path, proof, body); w.Code != 400 {
			t.Fatal(w.Code, w.Body)
		}
	}
	for i := 0; i < 2; i++ {
		if w := request("POST", path, proof, string(raw)); w.Code != 200 {
			t.Fatal(w.Code, w.Body)
		}
	}
	for _, suffix := range []string{"findings", "reports", "summary"} {
		route := "/api/v1/discovery/shadow-it/" + suffix
		if w := request("GET", route, "", ""); w.Code != 401 {
			t.Fatal(suffix, w.Code)
		}
		if w := request("GET", route, "discovery-admin", ""); w.Code != 200 {
			t.Fatal(suffix, w.Code, w.Body)
		}
	}
	route := path + "/trigger"
	if w := request("POST", route, proof, `{"scope":"fleet"}`); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request("POST", route, "discovery-admin", `{}`); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w := request("POST", route, "discovery-admin", `{"scope":"fleet"}`); w.Code != 202 {
		t.Fatal(w.Code, w.Body)
	}
	if s.inventory.EpochFor("station-a") == 0 {
		t.Fatal("no directive")
	}
	if page, _ := s.inventory.List("station-a", "", "", "", 50, 0); page.Total != 0 {
		t.Fatal("clean report invented findings")
	}
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			r := report
			r.RunID = fmt.Sprintf("fleet-%d", i)
			b, _ := json.Marshal(r)
			w := request("POST", path, recoveryProof(t, s, fmt.Sprintf("fleet-%d", i)), string(b))
			if w.Code != 200 {
				t.Errorf("fleet: %d %s", w.Code, w.Body)
			}
		}(i)
	}
	wg.Wait()
	s.SetDiscoveryStorageError(errors.New("configured SQL initialization failed"))
	if w := request("POST", path, proof, string(raw)); w.Code != 503 {
		t.Fatal("configured storage failure acknowledged into memory", w.Code)
	}
}

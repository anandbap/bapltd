package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShowcaseAttestationValidInvalidAndIsolation(t *testing.T) {
	s := setupTestServer()
	s.adminToken = "showcase-test-fixture-token"
	before := len(s.sessionStore.List(0))
	req := httptest.NewRequest("POST", "/api/v1/admin/showcase/attestation", strings.NewReader(`{"demo_run_id":"demo-123","session_id":"diagnostic-123"}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Authorization", "Bearer showcase-test-fixture-token")
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result struct {
		Evidence []struct {
			Decision, Producer, Status string
			Diagnostic                 bool
		} `json:"evidence"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if len(result.Evidence) != 2 || result.Evidence[0].Decision != "accepted" || result.Evidence[1].Decision != "rejected" {
		t.Fatal(w.Body.String())
	}
	for _, e := range result.Evidence {
		if e.Status != "participated" || !e.Diagnostic || e.Producer == "" {
			t.Fatal(e)
		}
	}
	if len(s.sessionStore.List(0)) != before {
		t.Fatal("diagnostic mutated session store")
	}
}

func TestShowcaseAttestationRequiresAdminAndValidCorrelation(t *testing.T) {
	s := setupTestServer()
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/admin/showcase/attestation", strings.NewReader(`{}`)))
	if w.Code != 401 && w.Code != 503 {
		t.Fatal("unguarded diagnostic", w.Code)
	}
	for _, body := range []string{`{}`, `{"demo_run_id":"x","session_id":"y","extra":true}`, `{"demo_run_id":"x","session_id":"y"}{}`, `{"demo_run_id":"<script>","session_id":"y"}`} {
		w := httptest.NewRecorder()
		s.handleShowcaseAttestation(w, httptest.NewRequest("POST", "/", strings.NewReader(body)))
		if w.Code != 400 {
			t.Fatal(body, w.Code)
		}
	}
}

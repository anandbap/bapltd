package api

import (
	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/session"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOnboardingProbeIsWorkstationScopedAndDoesNotExposePrompts(t *testing.T) {
	s := setupTestServer()
	id := strings.Repeat("a", 32)
	since := time.Now().UTC().Add(-2 * time.Second)
	_, err := s.sessionStore.Start(session.SessionStartRequest{SessionID: "private-native-session", AppID: "claude-code", InstanceID: "station-a"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.auditStore.Ingest([]audit.Event{{EventID: "prompt", SessionID: "private-native-session", ReportingLayer: "hook", Executable: "user_prompt", UserPrompt: "BAP-ONBOARDING-" + id + " PRIVATE-PROMPT-CONTENT", Timestamp: since.Add(time.Second).Format(time.RFC3339Nano)}, {EventID: "policy", SessionID: "private-native-session", ReportingLayer: "broker", FullCommand: "git status", Decision: "allow", Timestamp: since.Add(500 * time.Millisecond).Format(time.RFC3339Nano)}})
	if err != nil {
		t.Fatal(err)
	}
	query := url.Values{"probe_id": {id}, "started_at": {since.Format(time.RFC3339Nano)}}
	call := func(proof string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "/api/v1/onboarding/probe?"+query.Encode(), nil)
		if proof != "" {
			r.Header.Set("Authorization", "Bearer "+proof)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	if w := call(""); w.Code != 401 {
		t.Fatal(w.Code)
	}
	owner := recoveryProof(t, s, "station-a")
	w := call(owner)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body)
	}
	var record map[string]any
	json.Unmarshal(w.Body.Bytes(), &record)
	if record["session_reference"] != probeReference("private-native-session") || record["prompt_record_observed"] != true || record["policy_record_observed"] != true || record["execution_success_verified"] != false {
		t.Fatal(record)
	}
	for _, private := range []string{"PRIVATE-PROMPT-CONTENT", "private-native-session", "git status"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("probe exposed private content", w.Body)
		}
	}
	w = call(recoveryProof(t, s, "station-b"))
	json.Unmarshal(w.Body.Bytes(), &record)
	if strings.Contains(w.Body.String(), "session_reference") || strings.Contains(w.Body.String(), probeReference("private-native-session")) {
		t.Fatal("foreign workstation evidence disclosed", w.Body)
	}
	query.Set("probe_id", "invalid")
	if w := call(owner); w.Code != 400 {
		t.Fatal(w.Code)
	}
	query.Set("probe_id", id)
	query.Set("started_at", since.Add(-time.Hour).Format(time.RFC3339Nano))
	if w := call(owner); w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestOnboardingSDKPromptCannotSatisfyNativeProbe(t *testing.T) {
	s := setupTestServer()
	id := strings.Repeat("b", 32)
	now := time.Now().UTC()
	s.sessionStore.Start(session.SessionStartRequest{SessionID: "sdk-session", AppID: "claude-code", InstanceID: "machine"})
	s.auditStore.Ingest([]audit.Event{{EventID: "sdk", SessionID: "sdk-session", ReportingLayer: "sdk", Executable: "user_prompt", UserPrompt: "BAP-ONBOARDING-" + id, Timestamp: now.Format(time.RFC3339Nano)}})
	r := httptest.NewRequest("GET", "/api/v1/onboarding/probe?"+url.Values{"probe_id": {id}, "started_at": {now.Add(-time.Second).Format(time.RFC3339Nano)}}.Encode(), nil)
	r.Header.Set("Authorization", "Bearer "+recoveryProof(t, s, "machine"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"prompt_record_observed":false`) {
		t.Fatal(w.Code, w.Body)
	}
}

func TestOnboardingPublicProbeDigestWorksWithoutPromptTextCapture(t *testing.T) {
	s := setupTestServer()
	id := strings.Repeat("c", 32)
	now := time.Now().UTC()
	s.sessionStore.Start(session.SessionStartRequest{SessionID: "private-capture-disabled", AppID: "claude-code", InstanceID: "machine"})
	text := "BAP-ONBOARDING-" + id + " Please run git status in this fixture repository, then describe the result."
	s.auditStore.Ingest([]audit.Event{{EventID: "hash-only", SessionID: "private-capture-disabled", ReportingLayer: "hook", Executable: "user_prompt", PromptHash: probeReference(text), PromptCaptured: false, Timestamp: now.Format(time.RFC3339Nano)}})
	r := httptest.NewRequest("GET", "/api/v1/onboarding/probe?"+url.Values{"probe_id": {id}, "started_at": {now.Add(-time.Second).Format(time.RFC3339Nano)}}.Encode(), nil)
	r.Header.Set("Authorization", "Bearer "+recoveryProof(t, s, "machine"))
	w := httptest.NewRecorder()
	s.Handler().ServeHTTP(w, r)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"prompt_record_observed":true`) || strings.Contains(w.Body.String(), text) {
		t.Fatal(w.Code, w.Body)
	}
}

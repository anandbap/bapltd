package api

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"bap-controlplane/internal/audit"
)

func TestIndependentReportingWithoutHookApprovalOrPrompt(t *testing.T) {
	s := setupTestServer()
	proof := recoveryProof(t, s, "reporting-machine")
	post := func(token, path, body string) int {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		if w.Code >= 500 {
			t.Fatalf("server error: %s", w.Body.String())
		}
		return w.Code
	}
	observed := `[{"event_id":"presence-event","session_id":"observed-codex","source":"codex","reporting_layer":"discovery","client_pid":42,"decision":"observed","instance_id":"forged","user_email":"forged"}]`
	if got := post("", "/api/v1/audit/ingest", observed); got != 401 {
		t.Fatalf("anonymous reporting: %d", got)
	}
	if got := post(proof, "/api/v1/audit/ingest", observed); got != 200 {
		t.Fatalf("presence: %d", got)
	}
	sess, _ := s.sessionStore.GetSummary("observed-codex")
	if sess.InstanceID != "reporting-machine" || sess.UserEmail == "forged" || sess.TotalEvents != 0 || sess.UserPrompt != "" || sess.GrantID != "" {
		t.Fatalf("invalid presence identity/authority: %+v", sess)
	}
	if sess.SessionSVID == "" || sess.WorkstationSPIFFEID == "" {
		t.Fatal("observed session is not bound to authenticated identity")
	}
	command := `[{"event_id":"command-event","session_id":"observed-codex","source":"codex","reporting_layer":"broker","client_pid":42,"decision":"deny","full_command":"blocked operation"}]`
	if got := post(recoveryProof(t, s, "other-machine"), "/api/v1/audit/ingest", command); got != 403 {
		t.Fatalf("cross-workstation audit: %d", got)
	}
	for i := 0; i < 2; i++ {
		if got := post(proof, "/api/v1/audit/ingest", command); got != 200 {
			t.Fatalf("command report: %d", got)
		}
	}
	sess, _ = s.sessionStore.GetSummary("observed-codex")
	if sess.TotalEvents != 1 || sess.DeniedCount != 1 || len(sess.ReportingLayers) != 2 {
		t.Fatalf("retry duplicate or missing coverage: %+v", sess)
	}
	if err := s.sessionStore.RevokeSession(sess.SessionID, "Frozen by administrator"); err != nil {
		t.Fatal(err)
	}
	if got := post(proof, "/api/v1/audit/ingest", strings.ReplaceAll(observed, "presence-event", "presence-after-freeze")); got != 200 {
		t.Fatal(got)
	}
	sess, _ = s.sessionStore.GetSummary(sess.SessionID)
	if sess.Status != "revoked" || sess.TotalEvents != 1 {
		t.Fatalf("presence restored authority: %+v", sess)
	}
	if valid, err := s.auditStore.VerifyChain(); !valid || err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentFirstReportsCannotMixWorkstationOwners(t *testing.T) {
	s := setupTestServer()
	proofs := []string{recoveryProof(t, s, "machine-a"), recoveryProof(t, s, "machine-b")}
	var wg sync.WaitGroup
	codes := make(chan int, 2)
	start := make(chan struct{})
	for i, proof := range proofs {
		wg.Add(1)
		go func(i int, proof string) {
			defer wg.Done()
			<-start
			body := `[{"event_id":"race-` + []string{"a", "b"}[i] + `","session_id":"unclaimed-codex","source":"codex","reporting_layer":"broker","decision":"deny"}]`
			r := httptest.NewRequest("POST", "/api/v1/audit/ingest", strings.NewReader(body))
			r.Header.Set("Authorization", "Bearer "+proof)
			w := httptest.NewRecorder()
			s.Handler().ServeHTTP(w, r)
			codes <- w.Code
		}(i, proof)
	}
	close(start)
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[200] != 1 || counts[403] != 1 {
		t.Fatalf("ownership race admitted mixed evidence: %v", counts)
	}
	if events := s.auditStore.List(100); len(events) != 1 {
		t.Fatalf("foreign event reached ledger: %v", events)
	}
}

func TestCodexPromptProducerAcceptedWithWorkstationProof(t *testing.T) {
	s := setupTestServer()
	proof := recoveryProof(t, s, "codex-machine")
	request := func(path, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+proof)
		w := httptest.NewRecorder()
		s.Handler().ServeHTTP(w, r)
		return w
	}
	w := request("/api/v1/sessions/start", `{"session_id":"codex-native","app_id":"codex","reporting_layer":"hook","client_pid":42}`)
	if w.Code != 200 {
		t.Fatalf("start: %d %s", w.Code, w.Body.String())
	}
	body := `{"session_id":"codex-native","producer":"codex-lifecycle-hook","prompt_hash":"` + strings.Repeat("a", 64) + `","prompt_capture_enabled":false,"intent":{"primary":"TEST_VERIFICATION","confidence":1,"classifier_version":"bap-intent-v1","source":"claude-user-prompt-submit"}}`
	w = request("/api/v1/sessions/prompt", body)
	if w.Code != 200 {
		t.Fatalf("Codex producer rejected: %d %s", w.Code, w.Body.String())
	}
	sess, _ := s.sessionStore.GetSummary("codex-native")
	if len(sess.ReportingLayers) != 1 || sess.ReportingLayers[0] != "hook" || sess.UserPrompt != "" || sess.Intent.PromptCaptured {
		t.Fatalf("capture policy not respected: %+v", sess)
	}
	data, _ := json.Marshal(s.auditStore.List(1))
	var events []audit.Event
	_ = json.Unmarshal(data, &events)
	if len(events) != 1 || events[0].ReportingLayer != "hook" {
		t.Fatal("hook evidence not recorded")
	}
}

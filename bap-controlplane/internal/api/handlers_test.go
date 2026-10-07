package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"bap-controlplane/internal/authz"
	"bap-controlplane/internal/otc"
	"bap-controlplane/internal/registry"
	"bap-controlplane/pkg/types"
)

func setupTestServer() *Server {
	reg := registry.NewStore("bap.internal")
	otcStore := otc.NewStore()
	minter := authz.NewTokenMinter("unit-test-secret-key-1234567890", 15*time.Minute)
	return NewServer(reg, otcStore, minter, nil, nil)
}

func TestAPIFullLifecycle(t *testing.T) {
	srv := setupTestServer()
	srv.SetAdminSecurity("test-admin", true)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-BAP-Admin-Token", "test-admin")
		srv.Handler().ServeHTTP(w, r)
	}))
	defer ts.Close()

	client := ts.Client()

	// 1. Health check
	resp, err := client.Get(ts.URL + "/api/v1/health")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("health check failed: status %v, err %v", resp.StatusCode, err)
	}

	// 2. Pre-Register an Agent
	preRegPayload := types.PreRegisterRequest{
		AppID:               "finance-service",
		OwnerEmail:          "alice@company.internal",
		AgentName:           "BillingAgent",
		EnvProfile:          types.ProfileProd,
		AllowedBinaryHashes: []string{"known-good-binary-sha256"},
		PermittedScopes:     []string{"billing:read", "cli:exec"},
	}
	body, _ := json.Marshal(preRegPayload)
	resp, err = client.Post(ts.URL+"/api/v1/agents/pre-register", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("pre-register failed: status %v", resp.StatusCode)
	}

	var preRegResp types.PreRegisterResponse
	_ = json.NewDecoder(resp.Body).Decode(&preRegResp)
	if preRegResp.Code == "" || preRegResp.AgentID == "" {
		t.Fatalf("invalid pre-register response: %+v", preRegResp)
	}

	// 3. Register Edge with Valid Hash and Valid Code -> Expect 200 OK
	validReg := types.RegisterEdgeRequest{
		Code:       preRegResp.Code,
		BinaryHash: "known-good-binary-sha256",
		Hostname:   "worker-01",
		OS:         "windows",
		Arch:       "amd64",
	}
	validBody, _ := json.Marshal(validReg)
	resp, err = client.Post(ts.URL+"/api/v1/agents/register", "application/json", bytes.NewReader(validBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for valid registration, got: %d", resp.StatusCode)
	}

	var regResp types.RegisterEdgeResponse
	_ = json.NewDecoder(resp.Body).Decode(&regResp)
	if regResp.SessionToken == "" || regResp.AgentID != preRegResp.AgentID {
		t.Fatalf("invalid registration response: %+v", regResp)
	}

	// 4. Replay Registration with already consumed code -> Expect 401 Unauthorized
	resp, err = client.Post(ts.URL+"/api/v1/agents/register", "application/json", bytes.NewReader(validBody))
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for replayed OTC, got: %d", resp.StatusCode)
	}

	// 5. Register with Wrong Hash in Prod -> Expect 403 Forbidden
	// Pre-register another agent
	preRegPayload2 := types.PreRegisterRequest{
		AppID:               "finance-service-2",
		OwnerEmail:          "bob@company.internal",
		AgentName:           "BillingAgent2",
		EnvProfile:          types.ProfileProd,
		AllowedBinaryHashes: []string{"expected-hash"},
	}
	body2, _ := json.Marshal(preRegPayload2)
	resp2, err := client.Post(ts.URL+"/api/v1/agents/pre-register", "application/json", bytes.NewReader(body2))
	if err != nil || resp2.StatusCode != http.StatusCreated {
		t.Fatalf("pre-register 2 failed: %v", resp2.StatusCode)
	}
	var preRegResp2 types.PreRegisterResponse
	_ = json.NewDecoder(resp2.Body).Decode(&preRegResp2)

	tamperedReg := types.RegisterEdgeRequest{
		Code:       preRegResp2.Code,
		BinaryHash: "evil-altered-binary-sha256",
		Hostname:   "worker-02",
		OS:         "windows",
		Arch:       "amd64",
	}
	tamperedBody, _ := json.Marshal(tamperedReg)
	resp, err = client.Post(ts.URL+"/api/v1/agents/register", "application/json", bytes.NewReader(tamperedBody))
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for bad hash, got: %d", resp.StatusCode)
	}

	// 6. Acquire Grant
	grantReq := types.AcquireGrantRequest{
		AgentID:    preRegResp.AgentID,
		BinaryHash: "known-good-binary-sha256",
	}
	grantBody, _ := json.Marshal(grantReq)
	resp, err = client.Post(ts.URL+"/api/v1/grants/acquire", "application/json", bytes.NewReader(grantBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for grant acquisition, got: %d", resp.StatusCode)
	}
	var grantAcqResp types.AcquireGrantResponse
	_ = json.NewDecoder(resp.Body).Decode(&grantAcqResp)

	// 6b. Consume Grant (Single-use) -> Expect 200 OK
	consumeReq := map[string]string{"token": grantAcqResp.Token, "resource": "cli:exec"}
	cBody, _ := json.Marshal(consumeReq)
	resp, err = client.Post(ts.URL+"/api/v1/grants/consume", "application/json", bytes.NewReader(cBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for grant consumption, got: %d", resp.StatusCode)
	}

	// 6c. Consume again (Replay attack on grant) -> Expect 403 Forbidden
	resp, err = client.Post(ts.URL+"/api/v1/grants/consume", "application/json", bytes.NewReader(cBody))
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on grant replay, got: %d", resp.StatusCode)
	}

	// 7. Policy Bundle and Sync
	resp, err = client.Get(ts.URL + "/api/v1/policy/bundle")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for policy bundle, got: %d", resp.StatusCode)
	}

	syncReq := map[string]any{"agent_id": preRegResp.AgentID, "installed_version": 0}
	syncBody, _ := json.Marshal(syncReq)
	resp, err = client.Post(ts.URL+"/api/v1/policy/sync", "application/json", bytes.NewReader(syncBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for policy sync, got: %d", resp.StatusCode)
	}

	// 8. Audit Ingest and List
	auditPayload := []map[string]any{
		{
			"event_id":     "audit-test-1",
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
			"source":       "test-agent",
			"executable":   "git",
			"full_command": "git log",
			"decision":     "allow",
			"exit_code":    0,
		},
	}
	auditBody, _ := json.Marshal(auditPayload)
	resp, err = client.Post(ts.URL+"/api/v1/audit/ingest", "application/json", bytes.NewReader(auditBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for audit ingest, got: %d", resp.StatusCode)
	}

	resp, err = client.Get(ts.URL + "/api/v1/audit/events")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for audit list, got: %d", resp.StatusCode)
	}

	// 9. Revoke Agent (Kill switch)
	revokeReq := map[string]string{"agent_id": preRegResp.AgentID}
	revokeBody, _ := json.Marshal(revokeReq)
	resp, err = client.Post(ts.URL+"/api/v1/agents/revoke", "application/json", bytes.NewReader(revokeBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for revocation, got: %d", resp.StatusCode)
	}

	// 10. Attempt grant after revocation -> Expect 403 Forbidden
	resp, err = client.Post(ts.URL+"/api/v1/grants/acquire", "application/json", bytes.NewReader(grantBody))
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for revoked agent grant request, got: %d", resp.StatusCode)
	}

	// 11. Multi-Instance Fleet Enrollment & SPIFFE IDs
	fleetPreReg := types.PreRegisterRequest{
		AppID:               "fleet-service",
		OwnerEmail:          "devops@company.internal",
		AgentName:           "FleetWorker",
		EnvProfile:          types.ProfileDev,
		AllowedBinaryHashes: []string{"fleet-binary-hash"},
		PermittedScopes:     []string{"cli:exec"},
		MaxInstances:        3,
	}
	fleetBody, _ := json.Marshal(fleetPreReg)
	resp, err = client.Post(ts.URL+"/api/v1/agents/pre-register", "application/json", bytes.NewReader(fleetBody))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("fleet pre-register failed: %v", resp.StatusCode)
	}
	var fleetPreResp types.PreRegisterResponse
	_ = json.NewDecoder(resp.Body).Decode(&fleetPreResp)
	if !strings.HasPrefix(fleetPreResp.Code, "BAP-FLEET-") {
		t.Fatalf("expected BAP-FLEET- prefix for multi-instance OTC, got %q", fleetPreResp.Code)
	}

	// Enroll Instance 1
	regInst1 := types.RegisterEdgeRequest{
		Code:       fleetPreResp.Code,
		BinaryHash: "fleet-binary-hash",
		Hostname:   "worker-alpha",
		InstanceID: "inst-001",
	}
	bodyInst1, _ := json.Marshal(regInst1)
	resp, err = client.Post(ts.URL+"/api/v1/agents/register", "application/json", bytes.NewReader(bodyInst1))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("instance 1 registration failed: %v", resp.StatusCode)
	}
	var respInst1 types.RegisterEdgeResponse
	_ = json.NewDecoder(resp.Body).Decode(&respInst1)
	if respInst1.SPIFFEID != "spiffe://bap.internal/app/fleet-service/instance/inst-001" {
		t.Fatalf("unexpected SPIFFE ID for inst1: %q", respInst1.SPIFFEID)
	}

	// Enroll Instance 2 using same fleet token
	regInst2 := types.RegisterEdgeRequest{
		Code:       fleetPreResp.Code,
		BinaryHash: "fleet-binary-hash",
		Hostname:   "worker-beta",
		InstanceID: "inst-002",
	}
	bodyInst2, _ := json.Marshal(regInst2)
	resp, err = client.Post(ts.URL+"/api/v1/agents/register", "application/json", bytes.NewReader(bodyInst2))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("instance 2 registration failed: %v", resp.StatusCode)
	}
	var respInst2 types.RegisterEdgeResponse
	_ = json.NewDecoder(resp.Body).Decode(&respInst2)
	if respInst2.SPIFFEID != "spiffe://bap.internal/app/fleet-service/instance/inst-002" {
		t.Fatalf("unexpected SPIFFE ID for inst2: %q", respInst2.SPIFFEID)
	}

	// 12. Instance Heartbeat
	hbReq := map[string]string{"agent_id": respInst1.AgentID}
	hbBody, _ := json.Marshal(hbReq)
	resp, err = client.Post(ts.URL+"/api/v1/instances/heartbeat", "application/json", bytes.NewReader(hbBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("heartbeat failed: %v", resp.StatusCode)
	}

	// 13. App-Level Fleet Revocation (Kill-Switch)
	appRevokeReq := map[string]string{"app_id": "fleet-service"}
	appRevokeBody, _ := json.Marshal(appRevokeReq)
	resp, err = client.Post(ts.URL+"/api/v1/apps/revoke", "application/json", bytes.NewReader(appRevokeBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("app revocation failed: %v", resp.StatusCode)
	}

	// Both instances should now be blocked
	grantReq1 := types.AcquireGrantRequest{AgentID: respInst1.AgentID, BinaryHash: "fleet-binary-hash"}
	gBody1, _ := json.Marshal(grantReq1)
	resp, err = client.Post(ts.URL+"/api/v1/grants/acquire", "application/json", bytes.NewReader(gBody1))
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for fleet-revoked instance 1, got %d", resp.StatusCode)
	}

	grantReq2 := types.AcquireGrantRequest{AgentID: respInst2.AgentID, BinaryHash: "fleet-binary-hash"}
	gBody2, _ := json.Marshal(grantReq2)
	resp, err = client.Post(ts.URL+"/api/v1/grants/acquire", "application/json", bytes.NewReader(gBody2))
	if err != nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for fleet-revoked instance 2, got %d", resp.StatusCode)
	}

	// 14. Session Lifecycle & Ingestion Linkage
	sessStartReq := map[string]any{
		"session_id": "sess-claude-api-test",
		"app_id":     "claude-code",
		"client_pid": 8888,
		"hostname":   "dev-machine",
	}
	sessBody, _ := json.Marshal(sessStartReq)
	resp, err = client.Post(ts.URL+"/api/v1/sessions/start", "application/json", bytes.NewReader(sessBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for session start, got: %d", resp.StatusCode)
	}

	// Ingest event tagged with this session
	taggedAudit := []map[string]any{
		{
			"event_id":     "sess-ev-1",
			"session_id":   "sess-claude-api-test",
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
			"source":       "claude-code",
			"executable":   "git",
			"full_command": "git status",
			"decision":     "allow",
			"exit_code":    0,
		},
		{
			"event_id":     "sess-ev-2",
			"session_id":   "sess-claude-api-test",
			"timestamp":    time.Now().UTC().Format(time.RFC3339),
			"source":       "claude-code",
			"executable":   "curl",
			"full_command": "curl untrusted-test.internal",
			"decision":     "deny",
			"exit_code":    1,
		},
	}
	tBody, _ := json.Marshal(taggedAudit)
	resp, err = client.Post(ts.URL+"/api/v1/audit/ingest", "application/json", bytes.NewReader(tBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for tagged audit ingest, got: %d", resp.StatusCode)
	}

	// Fetch session details
	resp, err = client.Get(ts.URL + "/api/v1/sessions/sess-claude-api-test")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for get session, got: %d", resp.StatusCode)
	}
	var sessDetail map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&sessDetail)
	if sessDetail["total_events"].(float64) != 2 {
		t.Fatalf("expected 2 total events on session, got: %v", sessDetail["total_events"])
	}
	if sessDetail["allowed_count"].(float64) != 1 || sessDetail["denied_count"].(float64) != 1 {
		t.Fatalf("expected 1 allow and 1 deny on session, got %v and %v", sessDetail["allowed_count"], sessDetail["denied_count"])
	}

	// End session
	sessEndReq := map[string]string{
		"session_id": "sess-claude-api-test",
		"reason":     "session completed successfully",
	}
	endBody, _ := json.Marshal(sessEndReq)
	resp, err = client.Post(ts.URL+"/api/v1/sessions/end", "application/json", bytes.NewReader(endBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for session end, got: %d", resp.StatusCode)
	}

	// Verify inspector data contains sessions
	resp, err = client.Get(ts.URL + "/api/v1/inspector/data")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for inspector data, got: %d", resp.StatusCode)
	}
	var inspData map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&inspData)
	sessionsArr, ok := inspData["sessions"].([]any)
	if !ok || len(sessionsArr) == 0 {
		t.Fatalf("expected sessions array in inspector data, got: %v", inspData["sessions"])
	}
	intentCounts, ok := inspData["intent_counts"].(map[string]any)
	if !ok {
		t.Fatalf("expected intent_counts map in inspector data, got: %v", inspData["intent_counts"])
	}
	if _, ok := inspData["total_prompts"]; !ok {
		t.Fatalf("expected total_prompts in inspector data")
	}
	_ = intentCounts
}

func TestPEPSimulateEgressScenarios(t *testing.T) {
	srv := setupTestServer()
	srv.SetAdminSecurity("test-admin", true)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Header.Set("X-BAP-Admin-Token", "test-admin")
		srv.Handler().ServeHTTP(w, r)
	}))
	defer ts.Close()

	client := ts.Client()

	// 1. Unapproved tenant exfiltration scenario
	body, _ := json.Marshal(map[string]string{"scenario": "unapproved_tenant"})
	resp, err := client.Post(ts.URL+"/api/v1/pep/simulate", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("simulate failed: %v", err)
	}
	var res1 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&res1)
	if res1["pep_decision"] != "DENY" || res1["error"] != "TenantMismatchBlocked" {
		t.Errorf("expected DENY TenantMismatchBlocked, got: %+v", res1)
	}
	if res1["destination_tenant_id"] != "attacker-org" {
		t.Errorf("expected attacker-org, got %v", res1["destination_tenant_id"])
	}

	// 2. External S3 bucket owner scenario
	body, _ = json.Marshal(map[string]string{"scenario": "external_s3_bucket"})
	resp, err = client.Post(ts.URL+"/api/v1/pep/simulate", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("simulate failed: %v", err)
	}
	var res2 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&res2)
	if res2["pep_decision"] != "DENY" || res2["destination_tenant_id"] != "999999999999" {
		t.Errorf("expected DENY for external s3 bucket, got: %+v", res2)
	}

	// 3. Approved tenant scenario
	body, _ = json.Marshal(map[string]string{"scenario": "approved_tenant"})
	resp, err = client.Post(ts.URL+"/api/v1/pep/simulate", "application/json", bytes.NewReader(body))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("simulate failed: %v", err)
	}
	var res3 map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&res3)
	if res3["pep_decision"] != "ALLOW" || res3["destination_tenant_id"] != "corp-org" {
		t.Errorf("expected ALLOW for approved tenant, got: %+v", res3)
	}
}

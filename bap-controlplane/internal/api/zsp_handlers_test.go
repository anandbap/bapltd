package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"bap-controlplane/pkg/types"
)

func TestZSPGrants_API_SyncAndQuery(t *testing.T) {
	srv := setupTestServer()

	now := time.Now().UTC()
	testGrant := types.TaskGrant{
		GrantID:            "grant-151647-e8595829a241",
		EnvelopeID:         "env-test-01",
		SessionID:          "sess-test-sync",
		PrincipalSVID:      "spiffe://bap.local/agent/claude",
		HumanOwner:         "developer@example.com",
		AllowedActions:     []string{"git:add", "fs:write"},
		AllowedResources:   []string{"workspace://current/GEMINI.md"},
		RequestedActions:   []string{"git:add", "fs:write"},
		RequestedResources: []string{"workspace://current/GEMINI.md"},
		NarrowingApplied:   false,
		MaxUses:            1,
		RemainingUses:      0,
		IssuedAt:           now,
		ExpiresAt:          now.Add(5 * time.Minute),
		IsBurned:           true,
		BurnReason:         "Consumed by git add",
		DelegationType:     "automatic",
		ClientType:         "claude-code",
		ConsumedCmd:        "git add GEMINI.md",
		ReceiptID:          "prf-123456",
	}

	bodyBytes, _ := json.Marshal([]types.TaskGrant{testGrant})

	// 1. Sync grant to Control Plane
	reqSync := httptest.NewRequest(http.MethodPost, "/api/v1/zsp/grants/sync", bytes.NewReader(bodyBytes))
	reqSync.Header.Set("Content-Type", "application/json")
	wSync := httptest.NewRecorder()
	srv.mux.ServeHTTP(wSync, reqSync)

	if wSync.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /api/v1/zsp/grants/sync, got: %d: %s", wSync.Code, wSync.Body.String())
	}

	// 2. Query grant list
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/zsp/grants?session_id=sess-test-sync", nil)
	wList := httptest.NewRecorder()
	srv.mux.ServeHTTP(wList, reqList)

	if wList.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /api/v1/zsp/grants, got: %d: %s", wList.Code, wList.Body.String())
	}

	var listResp struct {
		Count  int               `json:"count"`
		Grants []types.TaskGrant `json:"grants"`
	}
	if err := json.NewDecoder(wList.Body).Decode(&listResp); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if listResp.Count != 1 || len(listResp.Grants) != 1 {
		t.Fatalf("expected 1 grant, got %d", listResp.Count)
	}
	g := listResp.Grants[0]
	if g.GrantID != testGrant.GrantID || g.ConsumedCmd != "git add GEMINI.md" {
		t.Fatalf("grant details mismatch: %+v", g)
	}

	// 3. Query single grant by ID
	reqSingle := httptest.NewRequest(http.MethodGet, "/api/v1/zsp/grants/"+testGrant.GrantID, nil)
	wSingle := httptest.NewRecorder()
	srv.mux.ServeHTTP(wSingle, reqSingle)

	if wSingle.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /api/v1/zsp/grants/:id, got: %d", wSingle.Code)
	}
	var single types.TaskGrant
	if err := json.NewDecoder(wSingle.Body).Decode(&single); err != nil {
		t.Fatalf("failed to decode single grant: %v", err)
	}
	if single.GrantID != testGrant.GrantID || single.ReceiptID != "prf-123456" {
		t.Fatalf("single grant details mismatch: %+v", single)
	}

	// 4. Query STS inspector and verify zsp_grants includes this grant
	reqSTS := httptest.NewRequest(http.MethodGet, "/api/v1/sts/tokens", nil)
	wSTS := httptest.NewRecorder()
	srv.mux.ServeHTTP(wSTS, reqSTS)

	if wSTS.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /api/v1/sts/tokens, got: %d", wSTS.Code)
	}
	var stsResp struct {
		ZSPGrants []map[string]any `json:"zsp_grants"`
	}
	if err := json.NewDecoder(wSTS.Body).Decode(&stsResp); err != nil {
		t.Fatalf("failed to decode sts response: %v", err)
	}
	foundInSTS := false
	for _, zg := range stsResp.ZSPGrants {
		if zg["grant_id"] == testGrant.GrantID {
			foundInSTS = true
			if zg["command"] != "git add GEMINI.md" {
				t.Fatalf("expected command in STS zsp_grants to be 'git add GEMINI.md', got: %v", zg["command"])
			}
			break
		}
	}
	if !foundInSTS {
		t.Fatalf("expected grant %s to appear in STS inspector zsp_grants", testGrant.GrantID)
	}
}

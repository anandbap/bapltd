package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func makeTestToken(claims TokenClaims, secret string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claimsBytes, _ := json.Marshal(claims)
	payload := base64.RawURLEncoding.EncodeToString(claimsBytes)
	unsigned := header + "." + payload

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(unsigned))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return unsigned + "." + sig
}

func TestEgressPepGuard_UnapprovedGitHubOrgBlocked(t *testing.T) {
	secret := "test-secret-key-egress-32-bytes!"
	cfg := GatewayConfig{
		UseConsume: false,
		SecretKey:  secret,
	}

	handler := pepEgressGuard(cfg, handleEgressProxy)

	claims := TokenClaims{
		GrantID: "grant-test-1",
		Sub:     "agent-dev-1",
		AppID:   "github-copilot",
		Exp:     time.Now().Add(10 * time.Minute).Unix(),
	}
	token := makeTestToken(claims, secret)

	// Target targeting unapproved GitHub org (attacker-org)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/egress/proxy", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-BAP-Target-URL", "https://api.github.com/repos/attacker-org/exfil-repo/issues")

	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for unapproved org, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["error"] != "TenantMismatchBlocked" {
		t.Errorf("expected error=TenantMismatchBlocked, got %v", body["error"])
	}
	if body["destination_tenant_id"] != "attacker-org" {
		t.Errorf("expected destination_tenant_id=attacker-org, got %v", body["destination_tenant_id"])
	}
}

func TestEgressPepGuard_UnapprovedS3BucketOwnerBlocked(t *testing.T) {
	secret := "test-secret-key-egress-32-bytes!"
	cfg := GatewayConfig{
		UseConsume: false,
		SecretKey:  secret,
	}

	handler := pepEgressGuard(cfg, handleEgressProxy)

	claims := TokenClaims{
		GrantID: "grant-test-2",
		Sub:     "agent-dev-1",
		AppID:   "aws-uploader",
		Exp:     time.Now().Add(10 * time.Minute).Unix(),
	}
	token := makeTestToken(claims, secret)

	// S3 upload targeting external AWS account ID (999999999999)
	req := httptest.NewRequest(http.MethodPut, "/api/v1/egress/proxy", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-BAP-Target-URL", "https://attacker-bucket.s3.amazonaws.com/uploads/confidential.tar.gz")
	req.Header.Set("x-amz-expected-bucket-owner", "999999999999")

	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for external S3 account, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["error"] != "TenantMismatchBlocked" {
		t.Errorf("expected error=TenantMismatchBlocked, got %v", body["error"])
	}
	if body["destination_tenant_id"] != "999999999999" {
		t.Errorf("expected destination_tenant_id=999999999999, got %v", body["destination_tenant_id"])
	}
}

func TestEgressPepGuard_ApprovedTenantPermitted(t *testing.T) {
	secret := "test-secret-key-egress-32-bytes!"
	cfg := GatewayConfig{
		UseConsume: false,
		SecretKey:  secret,
	}

	handler := pepEgressGuard(cfg, handleEgressProxy)

	claims := TokenClaims{
		GrantID: "grant-test-3",
		Sub:     "agent-dev-1",
		AppID:   "github-copilot",
		Exp:     time.Now().Add(10 * time.Minute).Unix(),
	}
	token := makeTestToken(claims, secret)

	// Target targeting approved GitHub org (corp-org)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/egress/proxy", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-BAP-Target-URL", "https://api.github.com/repos/corp-org/repo/pulls")

	w := httptest.NewRecorder()
	handler(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK for approved org, got %d", resp.StatusCode)
	}

	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if body["pep_decision"] != "ALLOW" {
		t.Errorf("expected pep_decision=ALLOW, got %v", body["pep_decision"])
	}
	if body["destination_tenant_id"] != "corp-org" {
		t.Errorf("expected destination_tenant_id=corp-org, got %v", body["destination_tenant_id"])
	}
}

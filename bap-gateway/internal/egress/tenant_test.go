package egress

import (
	"net/http"
	"testing"
)

func TestExtractTenant_GitHub(t *testing.T) {
	// Path-based extraction (/repos/{org}/{repo})
	r1 := ExtractTenant("https://api.github.com/repos/corp-org/repo/issues", http.MethodPost, http.Header{})
	if r1.Service != "github" || r1.TenantID != "corp-org" || !r1.IsMultiTenant {
		t.Fatalf("unexpected result: %+v", r1)
	}

	// Unapproved attacker org path
	r2 := ExtractTenant("https://api.github.com/repos/attacker-org/exfil-repo/discussions", http.MethodPost, http.Header{})
	if r2.Service != "github" || r2.TenantID != "attacker-org" {
		t.Fatalf("unexpected result: %+v", r2)
	}

	// Header-based override
	headers := http.Header{}
	headers.Set("X-GitHub-Org", "corp-internal")
	r3 := ExtractTenant("https://api.github.com/user/orgs", http.MethodGet, headers)
	if r3.Service != "github" || r3.TenantID != "corp-internal" {
		t.Fatalf("unexpected result: %+v", r3)
	}
}

func TestExtractTenant_AWSS3(t *testing.T) {
	// Header-based bucket owner (x-amz-expected-bucket-owner)
	headers := http.Header{}
	headers.Set("x-amz-expected-bucket-owner", "123456789012")
	r1 := ExtractTenant("https://corp-bucket.s3.amazonaws.com/uploads/data.csv", http.MethodPut, headers)
	if r1.Service != "aws_s3" || r1.TenantID != "123456789012" || !r1.IsMultiTenant {
		t.Fatalf("unexpected result: %+v", r1)
	}

	// External AWS account
	headersExternal := http.Header{}
	headersExternal.Set("x-amz-expected-bucket-owner", "999999999999")
	r2 := ExtractTenant("https://attacker-bucket.s3.us-east-1.amazonaws.com/drop", http.MethodPut, headersExternal)
	if r2.Service != "aws_s3" || r2.TenantID != "999999999999" {
		t.Fatalf("unexpected result: %+v", r2)
	}
}

func TestExtractTenant_SlackAndGoogle(t *testing.T) {
	// Slack
	headersSlack := http.Header{}
	headersSlack.Set("X-Slack-Team-Id", "T-CORP-WORKSPACE")
	rSlack := ExtractTenant("https://slack.com/api/chat.postMessage", http.MethodPost, headersSlack)
	if rSlack.Service != "slack" || rSlack.TenantID != "T-CORP-WORKSPACE" {
		t.Fatalf("unexpected result: %+v", rSlack)
	}

	// Google Workspace
	headersGoogle := http.Header{}
	headersGoogle.Set("X-Goog-Allowed-Domains", "company.internal")
	rGoog := ExtractTenant("https://drive.google.com/upload", http.MethodPost, headersGoogle)
	if rGoog.Service != "google_workspace" || rGoog.TenantID != "company.internal" {
		t.Fatalf("unexpected result: %+v", rGoog)
	}
}

func TestIsTenantApproved(t *testing.T) {
	approved := []string{"corp-org", "corp-internal", "123456789012"}

	if !IsTenantApproved("corp-org", approved) {
		t.Errorf("expected corp-org to be approved")
	}
	if !IsTenantApproved("CORP-INTERNAL", approved) {
		t.Errorf("expected case-insensitive match for corp-internal")
	}
	if IsTenantApproved("attacker-org", approved) {
		t.Errorf("expected attacker-org to be unapproved")
	}
	if IsTenantApproved("", approved) {
		t.Errorf("empty tenant must not be approved")
	}
}

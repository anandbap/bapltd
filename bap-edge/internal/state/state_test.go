package state

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStateDirResolution(t *testing.T) {
	tempBase := t.TempDir()
	customDir := filepath.Join(tempBase, "custom_bapstate")

	// Test 1: BAP_STATE_DIR override
	t.Setenv("BAP_STATE_DIR", customDir)
	ResetForTesting()

	dir := Dir()
	if dir != customDir {
		t.Fatalf("expected BAP_STATE_DIR %s, got %s", customDir, dir)
	}

	if _, err := os.Stat(customDir); os.IsNotExist(err) {
		t.Fatalf("expected custom state dir to be created")
	}

	// Test 2: AuditLogPath inside state dir
	auditPath := AuditLogPath()
	expectedAudit := filepath.Join(customDir, "audit.jsonl")
	if auditPath != expectedAudit {
		t.Fatalf("expected audit path %s, got %s", expectedAudit, auditPath)
	}

	// Test 3: CredentialsPath inside state dir
	credsPath := CredentialsPath()
	expectedCreds := filepath.Join(customDir, "credentials.json")
	if credsPath != expectedCreds {
		t.Fatalf("expected creds path %s, got %s", expectedCreds, credsPath)
	}

	// Test 4: PolicyDir inside state dir
	polDir := PolicyDir()
	expectedPolicy := filepath.Join(customDir, "policy")
	if polDir != expectedPolicy {
		t.Fatalf("expected policy dir %s, got %s", expectedPolicy, polDir)
	}

	// Test 5: SessionsDir inside state dir
	sessDir := SessionsDir()
	expectedSessions := filepath.Join(customDir, "sessions")
	if sessDir != expectedSessions {
		t.Fatalf("expected sessions dir %s, got %s", expectedSessions, sessDir)
	}
}

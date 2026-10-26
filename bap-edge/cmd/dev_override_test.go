package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDevOverride_AgentInvocationBlocked(t *testing.T) {
	t.Setenv("LTD_SOURCE", "claude-code")
	err := RunDevOverride([]string{"on"})
	if err == nil {
		t.Fatal("expected AI agent invocation of dev-override to be blocked, but succeeded")
	}
}

func TestDevOverride_AdminTokenEnforcement(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origWd) }()

	const adminSecret = "super-ciso-secret-token-999"
	t.Setenv("BAP_CISO_TOKEN", adminSecret)
	t.Setenv("BAP_ADMIN_TOKEN", "")
	t.Setenv("BAP_DEV_OVERRIDE", "")
	t.Setenv("BAP_DEV_MODE", "")
	t.Setenv("LTD_SOURCE", "human")

	// 1. Without token: must fail
	err := RunDevOverride([]string{"on"})
	if err == nil {
		t.Fatal("expected failure when admin token is configured but not provided")
	}

	// 2. With wrong token: must fail
	err = RunDevOverride([]string{"on", "--token", "wrong-token"})
	if err == nil {
		t.Fatal("expected failure when wrong admin token is provided")
	}

	// 3. With correct token: must succeed
	err = RunDevOverride([]string{"on", "--token", adminSecret, "--duration", "2h"})
	if err != nil {
		t.Fatalf("expected success with correct admin token, got: %v", err)
	}

	// 4. Verify devOverrideActive() is true
	active, banner := devOverrideActive()
	if !active {
		t.Fatal("expected devOverrideActive to be true")
	}
	if banner == "" {
		t.Fatal("expected banner to be non-empty")
	}

	// 5. Test turning off
	err = RunDevOverride([]string{"off"})
	if err != nil {
		t.Fatalf("failed to turn off dev-override: %v", err)
	}
	active, _ = devOverrideActive()
	if active {
		t.Fatal("expected devOverrideActive to be false after off")
	}
}

func TestDevOverride_TamperedSignatureRejected(t *testing.T) {
	tmpDir := t.TempDir()
	origWd, _ := os.Getwd()
	_ = os.Chdir(tmpDir)
	defer func() { _ = os.Chdir(origWd) }()

	const adminSecret = "ciso-secret-123"
	t.Setenv("BAP_CISO_TOKEN", adminSecret)
	t.Setenv("BAP_ADMIN_TOKEN", "")
	t.Setenv("BAP_DEV_OVERRIDE", "")
	t.Setenv("BAP_DEV_MODE", "")
	t.Setenv("LTD_SOURCE", "human")

	err := RunDevOverride([]string{"on", "--token", adminSecret, "--duration", "2h"})
	if err != nil {
		t.Fatal(err)
	}

	// Tamper with the expires_at in .bap/dev-override.json without recomputing signature
	p := filepath.Join(".bap", "dev-override.json")
	tampered := `{"active": true, "activated_at": "` + time.Now().Format(time.RFC3339) + `", "expires_at": "` + time.Now().Add(100*time.Hour).Format(time.RFC3339) + `", "authorized_by": "attacker", "auth_method": "fake", "signature": "bad-sig"}`
	_ = os.WriteFile(p, []byte(tampered), 0644)

	active, _ := devOverrideActive()
	if active {
		t.Fatal("expected tampered dev-override file to be rejected by signature check")
	}
}

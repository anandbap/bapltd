package cmd

import (
	"path/filepath"
	"testing"

	"bap-edge/internal/authz"
)

// With an active human override, cross-folder step-up is pre-approved, but credential
// stores stay unauthorizable.
func TestDevOverride_PreapprovesCrossFolderButNeverCredentials(t *testing.T) {
	t.Setenv("BAP_ENVIRONMENT", "development")
	t.Setenv("BAP_DEV_OVERRIDE", "1h")
	t.Setenv("BAP_STATE_DIR", t.TempDir())

	ws := t.TempDir()
	outside := t.TempDir()

	ok, scope := authz.IsTargetAuthorized(ws, "sess", filepath.Join(outside, "notes.txt"), "write")
	if !ok || scope != "dev-override" {
		t.Fatalf("expected dev-override pre-approval, got ok=%v scope=%q", ok, scope)
	}
	for _, secret := range []string{".env", filepath.Join(".aws", "credentials"), filepath.Join(".ssh", "id_rsa")} {
		if ok, _ := authz.IsTargetAuthorized(ws, "sess", filepath.Join(outside, secret), "write"); ok {
			t.Fatalf("credential path %q must never be pre-approved by override", secret)
		}
	}
}

func TestDevOverride_NeverPreapprovesRootsOrSystemDirs(t *testing.T) {
	t.Setenv("BAP_ENVIRONMENT", "development")
	t.Setenv("BAP_DEV_OVERRIDE", "1h")
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	ws := t.TempDir()

	targets := []string{string(filepath.Separator)}
	if vol := filepath.VolumeName(ws); vol != "" {
		targets = append(targets, vol+string(filepath.Separator), vol+`\Windows\System32`)
	} else {
		targets = append(targets, "/etc/passwd", "/usr/bin")
	}
	for _, target := range targets {
		if ok, _ := authz.IsTargetAuthorized(ws, "sess", target, "delete"); ok {
			t.Fatalf("override must never pre-approve %q", target)
		}
	}
}

func TestDevOverride_InactiveRequiresTrust(t *testing.T) {
	t.Setenv("BAP_ENVIRONMENT", "production")
	t.Setenv("BAP_DEV_OVERRIDE", "1h")
	ws := t.TempDir()
	outside := t.TempDir()
	if ok, _ := authz.IsTargetAuthorized(ws, "sess", filepath.Join(outside, "x.txt"), "write"); ok {
		t.Fatal("production must not honor developer override")
	}
}

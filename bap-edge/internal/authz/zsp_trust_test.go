package authz

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// BAP-933: `bap trust <path>` must actually let the agent use that folder. Before this fix the trust
// store was only consulted for Cedar cross-folder writes; the ZSP resource boundary ignored it, so a
// trusted Downloads folder still failed with "resource file://... not in granted boundaries".

func trustSetup(t *testing.T) (zspDir, ws, outside string) {
	t.Helper()
	zspDir = t.TempDir()
	ws = t.TempDir()
	outside = t.TempDir()
	t.Setenv("BAP_GLOBAL_PERMISSIONS", filepath.Join(t.TempDir(), "global_permissions.json"))
	return zspDir, ws, outside
}

func mintFor(t *testing.T, zspDir, sess string, actions ...string) {
	t.Helper()
	if _, _, err := SubmitTaskEnvelope(zspDir, sess, "claude-code", "TASK_EXECUTION", "g", "g",
		actions, []string{"workspace://current"}, "", 20, 10*time.Minute); err != nil {
		t.Fatalf("mint %v: %v", actions, err)
	}
}

func check(t *testing.T, zspDir, sess, ws, action, target string) error {
	t.Helper()
	_, _, _, err := VerifyOrConsumeSessionZSPChecks(zspDir, sess, "claude-code",
		[]ZSPActionCheck{{Action: action, CanonicalResource: "file://" + filepath.ToSlash(target), EscapesWorkspace: true}},
		"", ws, true, nil)
	return err
}

func TestBAP933_TrustedFolderIsReadableUnderNormalGrant(t *testing.T) {
	zspDir, ws, outside := trustSetup(t)
	f := filepath.Join(outside, "calls-report.json")
	_ = os.WriteFile(f, []byte("{}"), 0600)

	mintFor(t, zspDir, "s1", "fs:read")

	// Not trusted yet: boundary refusal, exactly the reported failure.
	if err := check(t, zspDir, "s1", ws, "fs:read", f); !errors.Is(err, ErrResourceNotGranted) {
		t.Fatalf("untrusted folder must be refused, got %v", err)
	}

	// `bap trust` (write, delete): reading becomes possible, with the same grant.
	if err := GrantPermission(ws, "s1", outside, "global", []string{"write", "delete"}); err != nil {
		t.Fatal(err)
	}
	if err := check(t, zspDir, "s1", ws, "fs:read", f); err != nil {
		t.Fatalf("trusted folder must be readable under an fs:read grant, got %v", err)
	}
}

func TestBAP933_TrustDoesNotReplaceTheGrant(t *testing.T) {
	zspDir, ws, outside := trustSetup(t)
	f := filepath.Join(outside, "x.txt")
	_ = GrantPermission(ws, "s2", outside, "global", []string{"write", "delete"})

	// No grant at all: still zero standing privileges.
	if err := check(t, zspDir, "s2", ws, "fs:read", f); !errors.Is(err, ErrZeroStandingPrivilegeViolation) {
		t.Fatalf("trust alone must not authorize anything, got %v", err)
	}
	// A read grant does not allow writing, even in a trusted folder.
	mintFor(t, zspDir, "s2", "fs:read")
	if err := check(t, zspDir, "s2", ws, "fs:file:write", f); !errors.Is(err, ErrActionNotGranted) {
		t.Fatalf("read grant must not allow a write in a trusted folder, got %v", err)
	}
	// A write grant does.
	mintFor(t, zspDir, "s2", "fs:write")
	if err := check(t, zspDir, "s2", ws, "fs:file:write", f); err != nil {
		t.Fatalf("write grant + write trust should allow the write, got %v", err)
	}
}

func TestBAP933_ReadOnlyTrustDoesNotAllowWrites(t *testing.T) {
	zspDir, ws, outside := trustSetup(t)
	f := filepath.Join(outside, "x.txt")
	if err := GrantPermission(ws, "s3", outside, "global", []string{"read"}); err != nil {
		t.Fatal(err)
	}
	mintFor(t, zspDir, "s3", "fs:read", "fs:write")
	if err := check(t, zspDir, "s3", ws, "fs:read", f); err != nil {
		t.Fatalf("read trust should allow reads, got %v", err)
	}
	if err := check(t, zspDir, "s3", ws, "fs:file:write", f); !errors.Is(err, ErrResourceNotGranted) {
		t.Fatalf("read-only trust must not allow writes, got %v", err)
	}
}

func TestBAP933_TrustNeverOpensCredentialsOrSiblings(t *testing.T) {
	zspDir, ws, outside := trustSetup(t)
	sibling := t.TempDir()
	_ = GrantPermission(ws, "s4", outside, "global", []string{"write", "delete"})
	mintFor(t, zspDir, "s4", "fs:read")

	for _, p := range []string{
		filepath.Join(outside, ".env"),
		filepath.Join(outside, ".env.production"),
		filepath.Join(outside, ".ssh", "id_rsa"),
		filepath.Join(outside, ".aws", "credentials"),
		filepath.Join(outside, "server.pem"),
		filepath.Join(sibling, "other.txt"),                 // a different, untrusted folder
		filepath.Join(outside, "..", filepath.Base(sibling)), // traversal back out
	} {
		if err := check(t, zspDir, "s4", ws, "fs:read", p); !errors.Is(err, ErrResourceNotGranted) {
			t.Errorf("%s must stay outside the boundary, got %v", p, err)
		}
	}
}

func TestBAP934_PrescriptiveOutOfWorkspaceGuidance(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "report.json")
	checks := []ZSPActionCheck{{Action: "fs:read", CanonicalResource: "file://" + filepath.ToSlash(f), EscapesWorkspace: true}}
	target, action, ok := OutOfWorkspaceTarget(checks)
	if !ok || action != "fs:read" {
		t.Fatalf("expected an out-of-workspace target, got %q %q %v", target, action, ok)
	}
	msg := ZSPDenialSuggestion(ErrResourceNotGranted, "p", "s", "g", "fs:read", checks, "C:/ws")
	for _, want := range []string{"DEVELOPER ACTION REQUIRED", "bap trust", dir, "--project", "--session", "--global", "AGENT:"} {
		if !strings.Contains(msg, want) {
			t.Errorf("guidance missing %q:\n%s", want, msg)
		}
	}
	// Root / home targets get a refusal with a safe alternative, never a trust command for them.
	home, _ := os.UserHomeDir()
	for _, bad := range []string{`C:\`, home} {
		m := FormatOutOfWorkspaceSuggestion(bad, "fs:read", "C:/ws")
		if strings.Contains(m, "--project") || !strings.Contains(m, "cannot be trusted") {
			t.Errorf("%q must not be offered for trust:\n%s", bad, m)
		}
	}
	// A different failure keeps the normal grant guidance.
	if m := ZSPDenialSuggestion(ErrActionNotGranted, "p", "s", "g", "git:status", nil, "C:/ws"); !strings.Contains(m, "zsp authorize") {
		t.Errorf("non-boundary refusals keep the authorize guidance: %s", m)
	}
}

// BAP-934: a trust entry can never open roots, the home directory, OS folders or credential stores.
func TestBAP934_TrustGuardRefusesDangerousTargets(t *testing.T) {
	home, _ := os.UserHomeDir()
	bad := []string{
		string(filepath.Separator),
		`C:\`, `C:/`, `D:\`,
		`C:\Windows`, `C:\Windows\System32`, `C:\Program Files\Foo`,
		`/etc`, `/usr/local`,
		home,
		filepath.Dir(home),
		filepath.Join(home, ".ssh"),
		filepath.Join(home, ".aws", "credentials"),
		filepath.Join(home, "proj", ".env"),
	}
	for _, p := range bad {
		if err := ValidateTrustTarget(p); err == nil {
			t.Errorf("trusting %q must be refused", p)
		}
	}
	for _, p := range []string{filepath.Join(home, "Downloads"), filepath.Join(home, "pyprj", "other"), t.TempDir()} {
		if err := ValidateTrustTarget(p); err != nil {
			t.Errorf("trusting %q should be allowed, got %v", p, err)
		}
	}
	// And the guard sits in the single choke point every trust route uses.
	ws := t.TempDir()
	t.Setenv("BAP_GLOBAL_PERMISSIONS", filepath.Join(t.TempDir(), "g.json"))
	if err := GrantPermission(ws, "s", home, "global", []string{"write"}); err == nil {
		t.Error("GrantPermission must refuse the home directory")
	}
}

func TestBAP933_ProjectAndSessionScopesWorkToo(t *testing.T) {
	zspDir, ws, outside := trustSetup(t)
	f := filepath.Join(outside, "a.txt")
	mintFor(t, zspDir, "s5", "fs:read")
	if err := GrantPermission(ws, "s5", outside, "session", []string{"write"}); err != nil {
		t.Fatal(err)
	}
	if err := check(t, zspDir, "s5", ws, "fs:read", f); err != nil {
		t.Fatalf("session-scope trust should allow reads, got %v", err)
	}
	_ = os.RemoveAll(filepath.Join(ws, ".bap"))
	if err := check(t, zspDir, "s5", ws, "fs:read", f); !errors.Is(err, ErrResourceNotGranted) {
		t.Fatalf("revoked trust must close the boundary again, got %v", err)
	}
}

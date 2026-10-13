package authz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveCanonicalPath_Traversal(t *testing.T) {
	ws := t.TempDir()
	sub := filepath.Join(ws, "app", "subdir")
	if err := os.MkdirAll(sub, 0755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}

	target := filepath.Join(sub, "..", ".env")
	canonical := ResolveCanonicalPath(target, ws)
	expected := filepath.Clean(filepath.Join(ResolveCanonicalPath(ws, ""), "app", ".env"))

	if canonical != expected {
		t.Errorf("got canonical %q, want %q", canonical, expected)
	}

	forbidden, reason := IsForbiddenSecretPath(canonical)
	if !forbidden {
		t.Errorf("expected canonical path to be recognized as forbidden secret, reason: %s", reason)
	}
}

func TestResolveCanonicalPath_Symlink(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "secret.key")
	if err := os.WriteFile(secretFile, []byte("super-secret"), 0600); err != nil {
		t.Fatalf("write secret failed: %v", err)
	}

	linkPath := filepath.Join(tmpDir, "link.txt")
	if err := os.Symlink(secretFile, linkPath); err != nil {
		t.Skipf("symlinks not supported on this platform/privilege: %v", err)
	}

	canonical := ResolveCanonicalPath(linkPath, tmpDir)
	realSecret, _ := filepath.EvalSymlinks(secretFile)
	if canonical != realSecret {
		t.Errorf("expected symlink to resolve to %q, got %q", realSecret, canonical)
	}
}

func TestIsForbiddenSecretPath(t *testing.T) {
	cases := []struct {
		path      string
		forbidden bool
	}{
		{"/app/.env", true},
		{"C:\\project\\.env.production", true},
		{"/home/user/.ssh/id_rsa", true},
		{"/home/user/.aws/credentials", true},
		{"/etc/shadow", true},
		{"/project/src/main.go", false},
		{"/project/README.md", false},
	}

	for _, tc := range cases {
		f, _ := IsForbiddenSecretPath(tc.path)
		if f != tc.forbidden {
			t.Errorf("IsForbiddenSecretPath(%q) = %v; want %v", tc.path, f, tc.forbidden)
		}
	}
}

func TestIsPathOutsideWorkspaceCanonical(t *testing.T) {
	ws := t.TempDir()
	inside := filepath.Join(ws, "child", "file.txt")
	outside := filepath.Join(filepath.Dir(ws), "outside.txt")

	if IsPathOutsideWorkspaceCanonical(ws, inside) {
		t.Errorf("expected %q to be inside workspace %q", inside, ws)
	}
	if !IsPathOutsideWorkspaceCanonical(ws, outside) {
		t.Errorf("expected %q to be outside workspace %q", outside, ws)
	}

	// Traversal escape
	escape := filepath.Join(ws, "child", "..", "..", "outside.txt")
	if !IsPathOutsideWorkspaceCanonical(ws, escape) {
		t.Errorf("expected traversal %q to be outside workspace", escape)
	}

	// Windows backslashes check
	if strings.Contains(ws, "\\") {
		escapeWin := ws + "\\..\\escape.txt"
		if !IsPathOutsideWorkspaceCanonical(ws, escapeWin) {
			t.Errorf("expected windows traversal %q to be outside workspace", escapeWin)
		}
	}
}


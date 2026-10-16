package adapters

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCursorAdapter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "cursor-adapter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	adapter := NewCursorAdapter(tempDir, "", "sess-test-cursor", "agent-test-cursor")
	if err := adapter.ConfigureWorkspace(); err != nil {
		t.Fatalf("ConfigureWorkspace failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tempDir, ".cursorrules")); os.IsNotExist(err) {
		t.Errorf("expected .cursorrules to exist")
	}
	if _, err := os.Stat(filepath.Join(tempDir, ".cursor", "mcp.json")); os.IsNotExist(err) {
		t.Errorf("expected .cursor/mcp.json to exist")
	}

	evt, err := adapter.InterceptActivity("terminal_command", "git status")
	if err != nil {
		t.Fatalf("InterceptActivity failed: %v", err)
	}
	if evt.Decision != "ALLOW" {
		t.Errorf("expected ALLOW, got %s", evt.Decision)
	}
	if evt.HarnessType != "cursor" {
		t.Errorf("expected cursor harness, got %s", evt.HarnessType)
	}
}

func TestGeminiCLIAdapter(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "gemini-adapter-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	adapter := NewGeminiCLIAdapter(tempDir, "", "sess-test-gemini", "agent-test-gemini")
	if err := adapter.ConfigureWorkspace(); err != nil {
		t.Fatalf("ConfigureWorkspace failed: %v", err)
	}

	if _, err := os.Stat(filepath.Join(tempDir, "GEMINI.md")); os.IsNotExist(err) {
		t.Errorf("expected GEMINI.md to exist")
	}

	evt, err := adapter.InterceptActivity("prompt", "Analyze git repo")
	if err != nil {
		t.Fatalf("InterceptActivity failed: %v", err)
	}
	if evt.Decision != "ALLOW" {
		t.Errorf("expected ALLOW, got %s", evt.Decision)
	}
	if evt.HarnessType != "gemini-cli" {
		t.Errorf("expected gemini-cli harness, got %s", evt.HarnessType)
	}
}

func TestBrowserGuard(t *testing.T) {
	guard := NewBrowserGuard("", "sess-test-browser", "agent-test-browser")

	// 1. Navigation allow test
	allowed, _, evt := guard.EvaluateNavigation("http://localhost:8080/portal")
	if !allowed || evt.Decision != "ALLOW" {
		t.Errorf("expected localhost navigation to be allowed")
	}

	allowed, _, evt = guard.EvaluateNavigation("https://api.corp.internal/v1")
	if !allowed || evt.Decision != "ALLOW" {
		t.Errorf("expected *.corp.internal navigation to be allowed")
	}

	// 2. Navigation deny test
	allowed, reason, evt := guard.EvaluateNavigation("https://untrusted-test.internal/phish")
	if allowed || evt.Decision != "DENY" {
		t.Errorf("expected untrusted-test.internal navigation to be denied, reason: %s", reason)
	}

	// 3. Upload credential blocking
	allowed, _, evt = guard.EvaluateUpload(".env", []byte("SECRET_KEY=12345"))
	if allowed || evt.Decision != "DENY" {
		t.Errorf("expected .env upload to be blocked")
	}

	allowed, _, evt = guard.EvaluateUpload("id_rsa", []byte("private key data"))
	if allowed || evt.Decision != "DENY" {
		t.Errorf("expected id_rsa upload to be blocked")
	}

	allowed, _, evt = guard.EvaluateUpload("auth.pem", []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIE..."))
	if allowed || evt.Decision != "DENY" {
		t.Errorf("expected private key content upload to be blocked")
	}

	// 4. Safe upload allow
	allowed, _, evt = guard.EvaluateUpload("metrics.csv", []byte("timestamp,value\n2026-10-16,42"))
	if !allowed || evt.Decision != "ALLOW" {
		t.Errorf("expected clean CSV upload to be allowed")
	}
}

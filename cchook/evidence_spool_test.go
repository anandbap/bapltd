package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestFileHookEvidenceSurvivesWithoutNetworkOrPrompt(t *testing.T) {
	t.Setenv("BAP_STATE_DIR", t.TempDir())
	previous := fileHookEvidence
	defer func() { fileHookEvidence = previous }()
	fileHookEvidence.SessionID = "codex-file-session"
	fileHookEvidence.AppID = "codex"
	fileHookEvidence.Tool = "Read"
	fileHookEvidence.Path = "workspace/source.go"
	if err := spoolFileHookDecision("deny", "policy denied file read"); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(hookEvidenceDir())
	if err != nil || len(files) != 1 {
		t.Fatalf("missing atomic record: %v %v", files, err)
	}
	data, err := os.ReadFile(filepath.Join(hookEvidenceDir(), files[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	var ev map[string]any
	_ = json.Unmarshal(data, &ev)
	if ev["reporting_layer"] != "hook" || ev["decision"] != "deny" || ev["session_id"] != "codex-file-session" {
		t.Fatalf("lost evidence: %s", data)
	}
	if _, ok := ev["user_prompt"]; ok {
		t.Fatal("file-hook record invented prompt text")
	}
}

func TestHookUsesMasterEnrollmentDestination(t *testing.T) {
	previousDir := hookManagedDir
	hookManagedDir = func() string { return t.TempDir() }
	defer func() { hookManagedDir = previousDir }()
	previous := hookEnrollment
	defer func() { hookEnrollment = previous }()
	hookEnrollment = func() hookCredential {
		return hookCredential{ServerURL: "https://enrolled.example/", Token: "synthetic-proof"}
	}
	t.Setenv("BAP_SERVER_URL", "https://stale.example")
	if got := resolveServerURL(); got != "https://enrolled.example" {
		t.Fatalf("hook redirected by environment: %q", got)
	}
}

func TestManagedHookEndpointDoesNotFallBackToEnrollment(t *testing.T) {
	dir := t.TempDir()
	previousDir := hookManagedDir
	hookManagedDir = func() string { return dir }
	defer func() { hookManagedDir = previousDir }()
	previous := hookEnrollment
	hookEnrollment = func() hookCredential {
		return hookCredential{ServerURL: "https://old.example", Token: "synthetic-proof"}
	}
	defer func() { hookEnrollment = previous }()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"controlplane_url":"https://managed.example","lock_endpoints":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	if got := resolveServerURL(); got != "https://managed.example" {
		t.Fatalf("managed lock lost: %q", got)
	}
}

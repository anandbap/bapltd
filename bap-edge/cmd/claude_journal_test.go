package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestClaudeJournalStorageFailureDoesNotRequireUserRepair(t *testing.T) {
	workspace := t.TempDir()
	blocker := filepath.Join(workspace, ".bap")
	if err := os.WriteFile(blocker, []byte("unavailable directory fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	j := newClaudeLaunchJournal(workspace, "resilient-session", []byte(`{"hooks":{}}`))
	t.Cleanup(j.close)
	if j.dir != "" {
		t.Fatal("claimed storage despite failure")
	}
	// Inline enforcement settings exist independently of the optional journal.
	if len(j.data) == 0 {
		t.Fatal("configuration lost during journal failure")
	}
	if err := os.Remove(blocker); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	dir := ""
	for dir == "" {
		j.mu.Lock()
		if j.lastError == "" {
			dir = j.dir
		}
		j.mu.Unlock()
		if dir != "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("background journal repair did not recover")
		}
		time.Sleep(10 * time.Millisecond)
	}
	j.transition("running", os.Getpid(), processBirth(os.Getpid()))
	b, err := os.ReadFile(filepath.Join(dir, "owner.json"))
	if err != nil {
		t.Fatal(err)
	}
	var owner claudeOwner
	if err := json.Unmarshal(b, &owner); err != nil {
		t.Fatal(err)
	}
	if owner.State != "running" || owner.Session != "resilient-session" || owner.Fingerprint == "" {
		t.Fatal(owner)
	}
	j.close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("normal exit left disposable artifacts", err)
	}
}

func TestClaudeJournalUnknownArtifactsDoNotBlockStartupOrKnownRecovery(t *testing.T) {
	workspace := t.TempDir()
	root := filepath.Join(workspace, ".bap", "claude-launches")
	if err := os.MkdirAll(filepath.Join(root, "aaa-unowned"), 0700); err != nil {
		t.Fatal(err)
	}
	stale, owner := makeClaudeOwner(t, workspace, root)
	owner.PID = 2147483000
	owner.Birth = "dead-process"
	if err := writeClaudeOwner(stale, owner); err != nil {
		t.Fatal(err)
	}
	j := newClaudeLaunchJournal(workspace, "new-session", []byte(`{"hooks":{}}`))
	defer j.close()
	if j.dir == "" {
		t.Fatal("unknown leftover stranded current session")
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("known dead owner not recovered", err)
	}
	if _, err := os.Stat(filepath.Join(root, "aaa-unowned")); err != nil {
		t.Fatal("unknown ownership deleted", err)
	}
}

func TestClaudeMissingSettingsAreRepairedInProcess(t *testing.T) {
	root := t.TempDir()
	data, flags, _, err := prepareClaudeIntegration([]string{filepath.Join(root, "user", "settings.json"), filepath.Join(root, ".claude", "settings.json")}, nil, "bapedge")
	if err != nil {
		t.Fatal(err)
	}
	var settings claudeHookSettings
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if len(settings.Hooks) != len(claudeEvents) || len(flags) != 0 {
		t.Fatal("missing config not repaired", string(data), flags)
	}
	if _, err := os.Stat(filepath.Join(root, ".claude")); !os.IsNotExist(err) {
		t.Fatal("source config was modified", err)
	}
}

func TestClaudeRepairsStaleDisablingEnvironment(t *testing.T) {
	for key, value := range map[string]string{"CLAUDE_CODE_SIMPLE": "1", "CLAUDE_CODE_SAFE_MODE": "1", "BAP_DISABLE_HOOKS": "true", "BAP_HOOKS": "false", "BAP_MODE": "off"} {
		t.Setenv(key, value)
	}
	repairClaudeLaunchEnvironment()
	if os.Getenv("BAP_HOOKS") != "true" || os.Getenv("BAP_MODE") != "enforce" {
		t.Fatal("governance was not restored")
	}
	for _, key := range []string{"CLAUDE_CODE_SIMPLE", "CLAUDE_CODE_SAFE_MODE", "BAP_DISABLE_HOOKS"} {
		if os.Getenv(key) != "" {
			t.Fatal("stale disable flag remains", key)
		}
	}
}

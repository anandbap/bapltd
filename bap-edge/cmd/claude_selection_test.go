package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClaudeDuplicateReconciliationPreservesUserHooks(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "user", "settings.json")
	project := filepath.Join(dir, "project", "settings.json")
	original := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"bapedge plugin adapter"},{"type":"command","command":"user-hook","timeout":30}]}]}}`
	for _, path := range []string{user, project} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(original), 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, flags, _, err := prepareClaudeIntegration([]string{user, project}, nil, "C:/BAP/bapedge.exe")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(flags, " ") != "--setting-sources local" {
		t.Fatal(flags)
	}
	var settings struct {
		Hooks map[string][]struct {
			Hooks []map[string]any `json:"hooks"`
		} `json:"hooks"`
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	bap, userCount := 0, 0
	for _, group := range settings.Hooks["PreToolUse"] {
		for _, hook := range group.Hooks {
			command, _ := hook["command"].(string)
			if claudeBAPCommand(command) {
				bap++
			} else if command == "user-hook" {
				userCount++
				if hook["timeout"] != float64(30) {
					t.Fatal("user hook metadata lost")
				}
			}
		}
	}
	if bap != 1 || userCount != 2 {
		t.Fatalf("BAP %d user %d: %s", bap, userCount, data)
	}
	for _, path := range []string{user, project} {
		after, _ := os.ReadFile(path)
		if string(after) != original {
			t.Fatal("source modified")
		}
	}
}

func TestClaudeDuplicateDoesNotPromoteScopedPermissions(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "settings.json")
	project := filepath.Join(dir, "project", "settings.json")
	for _, path := range []string{user, project} {
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(`{"permissions":{"defaultMode":"auto"},"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"bapedge plugin adapter"}]}]}}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := prepareClaudeIntegration([]string{user, project}, nil, "bapedge"); err == nil || !strings.Contains(err.Error(), "cannot promote scoped settings") {
		t.Fatal(err)
	}
}

func TestClaudeManagedHookWinsOverDuplicateProjectCallbacks(t *testing.T) {
	dir := t.TempDir()
	user := filepath.Join(dir, "settings.json")
	managed := filepath.Join(dir, "managed.json")
	content := []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"bapedge plugin adapter"}]}]}}`)
	for _, path := range []string{user, managed} {
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	data, flags, _, err := prepareClaudeIntegration([]string{user, managed}, map[string]bool{managed: true}, "bapedge")
	if err != nil {
		t.Fatal(err)
	}
	if len(flags) != 2 || strings.Contains(flags[1], "user") {
		t.Fatal(flags)
	}
	var overlay claudeHookSettings
	if err := json.Unmarshal(data, &overlay); err != nil {
		t.Fatal(err)
	}
	if len(overlay.Hooks["PreToolUse"]) != 0 {
		t.Fatal("managed hook duplicated")
	}
	after, _ := os.ReadFile(managed)
	if string(after) != string(content) {
		t.Fatal("managed source changed")
	}
}

func TestClaudeMalformedUserSettingsRecoveredWithoutRewrite(t *testing.T) {
	root := t.TempDir()
	user := filepath.Join(root, "user", "settings.json")
	project := filepath.Join(root, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(project), 0700); err != nil {
		t.Fatal(err)
	}
	broken := []byte("{\"hooks\":{\"PreToolUse\":\"bad\\unescaped\"}")
	if err := os.WriteFile(project, broken, 0600); err != nil {
		t.Fatal(err)
	}
	data, flags, _, err := prepareClaudeIntegration([]string{user, project}, nil, "C:/Program Files/BAP/研发/bapedge.exe")
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(data) || strings.Join(flags, " ") != "--setting-sources user,local" {
		t.Fatal(string(data), flags)
	}
	var config claudeHookSettings
	if err := json.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	if len(config.Hooks) != len(claudeEvents) {
		t.Fatal("missing repaired hooks")
	}
	after, _ := os.ReadFile(project)
	if string(after) != string(broken) {
		t.Fatal("damaged source overwritten")
	}
}

func TestClaudeUnsafeCommandCharactersNeverCreateBrokenJSON(t *testing.T) {
	for _, path := range []string{"C:/Program Files/BAP/bapedge.exe", "C:/User A&B/研发/bapedge.exe", "C:/User O'Connor/bapedge.exe"} {
		data, _, _, err := prepareClaudeIntegration(nil, nil, path)
		if err != nil || !json.Valid(data) {
			t.Fatal(path, string(data), err)
		}
	}
	if _, _, _, err := prepareClaudeIntegration(nil, nil, "C:/bad\npath/bapedge.exe"); err == nil {
		t.Fatal("control character accepted in hook executable")
	}
}

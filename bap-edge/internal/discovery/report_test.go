package discovery

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiscoverySyntheticConfigurationPrivacyAndStableKeys(t *testing.T) {
	root := t.TempDir()
	// macOS temp paths may traverse /var -> /private/var. Use the real
	// directory so this parsing test does not exercise symlink rejection.
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, ".mcp.json")
	secret := "SYNTHETIC-DO-NOT-UPLOAD"
	body := `{"mcpServers":{"filesystem":{"command":"node","args":["` + secret + `"],"env":{"TOKEN":"` + secret + `"}},"database":{"url":"https://example.invalid/?secret=` + secret + `"}}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	sources := []ConfigSource{{path, "claude-code"}}
	first := Collect(sources, 10)
	if err := os.WriteFile(path, append([]byte{0xef, 0xbb, 0xbf}, []byte(body)...), 0600); err != nil {
		t.Fatal(err)
	}
	second := Collect(sources, 11)
	if first.Status != "complete" || len(first.Observations) != 2 || len(second.Observations) != 2 {
		t.Fatal(first)
	}
	if first.Observations[0].Key != second.Observations[0].Key || first.Observations[0].Key == first.Observations[1].Key {
		t.Fatal("unstable or colliding server keys")
	}
	raw, _ := json.Marshal(first)
	if strings.Contains(string(raw), secret) || strings.Contains(string(raw), root) || strings.Contains(string(raw), "example.invalid") {
		t.Fatal("private config content left workstation")
	}
	os.WriteFile(path, []byte(`{"mcpServers":`), 0600)
	broken := Collect(sources, 12)
	if broken.Status != "partial" || broken.Scopes[0].Status != "error" {
		t.Fatal("malformed scope looked clean")
	}
	os.Remove(path)
	clean := Collect(sources, 13)
	if clean.Status != "complete" || len(clean.Observations) != 0 {
		t.Fatal("empty completion missing")
	}
	vscode := filepath.Join(root, "vscode.json")
	os.WriteFile(vscode, []byte(`{"servers":{"remote":{"url":"https://example.invalid"}}}`), 0600)
	if r := Collect([]ConfigSource{{vscode, "vscode"}}, 0); len(r.Observations) != 1 {
		t.Fatal("VS Code schema not parsed")
	}
}

func TestDiscoveryRejectsSymlinkedConfiguration(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "config")
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "mcp.json")
	if err := os.WriteFile(path, []byte(`{"mcpServers":{"local":{"command":"node"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-config")
	if err := os.Symlink(directory, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report := Collect([]ConfigSource{{filepath.Join(link, "mcp.json"), "claude-code"}}, 0)
	if report.Status != "partial" || len(report.Scopes) != 1 ||
		report.Scopes[0].Status != "error" || len(report.Observations) != 0 {
		t.Fatalf("symlinked ancestor was not rejected: %+v", report)
	}
}

func TestDiscoveryQueueAndSafeLabels(t *testing.T) {
	root := t.TempDir()
	r := Collect([]ConfigSource{{filepath.Join(root, "absent.json"), "claude-code"}}, 0)
	if err := Queue(root, r); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Join(root, "pending"))
	if err != nil || len(files) != 1 {
		t.Fatal(files, err)
	}
	body, _ := os.ReadFile(filepath.Join(root, "pending", files[0].Name()))
	var copy Report
	if json.Unmarshal(body, &copy) != nil || copy.RunID != r.RunID {
		t.Fatal("atomic queue missing report")
	}
	if got := Label(`<img src=x onerror=alert(1)>`); strings.Contains(got, "<") {
		t.Fatal("unsafe label")
	}
	for _, source := range Sources(root, root) {
		if strings.Contains(source.Path, ".env") || strings.HasSuffix(source.Path, ".claude.json") {
			t.Fatal("credential scope scanned")
		}
	}
}

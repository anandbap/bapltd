package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"bap-edge/pkg/types"
)

func TestPluginInspection(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Missing state initially
	rec := InspectClaudePlugin(tmpDir)
	if rec.PluginInstalled {
		t.Errorf("expected plugin not installed in empty tempdir, got true")
	}
	if rec.State != types.PluginStateMissing && rec.State != types.PluginStateUnknown {
		t.Errorf("expected state Missing, got %s", rec.State)
	}

	// 2. Install plugin files
	pluginDir := filepath.Join(tmpDir, "plugins", "claude", ".claude-plugin")
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(`{"name":"test"}`), 0644); err != nil {
		t.Fatal(err)
	}

	recInstalled := InspectClaudePlugin(tmpDir)
	if !recInstalled.PluginInstalled {
		t.Errorf("expected plugin installed, got false")
	}
	if recInstalled.State != types.PluginStateInstalled && recInstalled.State != types.PluginStateDegraded && recInstalled.State != types.PluginStateActive {
		t.Errorf("expected state Installed, Degraded, or Active, got %s", recInstalled.State)
	}
}

func TestDefenseInDepthLayersCalculation(t *testing.T) {
	tmpDir := t.TempDir()
	layers := GetDefenseInDepthLayers(tmpDir)

	if len(layers) < 6 {
		t.Fatalf("expected at least 6 defense layer representations, got %d", len(layers))
	}

	expectedIDs := []string{"Layer 1A", "Layer 1B", "Layer 2", "Layer 3", "Layer 4", "Layer 5"}
	for i, id := range expectedIDs {
		if layers[i].LayerID != id {
			t.Errorf("expected layer %d to have ID %s, got %s", i, id, layers[i].LayerID)
		}
	}
}

func TestPluginDeduplication(t *testing.T) {
	sessionID := "test-dedup-session"
	cmdHash := computeCommandHash("echo hello", "")

	// 1. Check before record
	if _, found := checkDedup(sessionID, cmdHash); found {
		t.Errorf("expected no cached dedup initially")
	}

	// 2. Record
	recordDedup(sessionID, cmdHash, "allow", "", nil)

	// 3. Check immediately after record
	cached, found := checkDedup(sessionID, cmdHash)
	if !found {
		t.Fatalf("expected cached dedup record to be found")
	}
	if cached.Decision != "allow" {
		t.Errorf("expected decision 'allow', got %s", cached.Decision)
	}
}

func TestPluginSyntheticProbe(t *testing.T) {
	// Benign event
	benign := `{"tool_name":"Bash","tool_input":{"command":"echo test"}}`
	resp, err := executeSyntheticProbe("claude", benign, "PreToolUse")
	if err != nil {
		t.Fatalf("synthetic probe error: %v", err)
	}
	if !resp.Allowed {
		t.Errorf("expected benign command to be allowed, got: %s", resp.Reason)
	}

	// Sensitive credential exfiltration attempt
	sensitive := `{"tool_name":"Bash","tool_input":{"command":"cat ~/.ssh/id_rsa"}}`
	respDeny, err := executeSyntheticProbe("claude", sensitive, "PreToolUse")
	if err != nil {
		t.Fatalf("synthetic probe error: %v", err)
	}
	if respDeny.Allowed {
		t.Errorf("expected sensitive credential access to be blocked, but was allowed")
	}
}

func TestPluginVerificationHealthSpool(t *testing.T) {
	tmpDir := t.TempDir()
	recordEnforcementVerification("claude", tmpDir)

	hookActive, verified, lastObs := readHealthStatus("claude")
	if !hookActive || !verified {
		t.Errorf("expected hookActive and verified to be true after recordEnforcementVerification")
	}
	if lastObs == nil || time.Since(*lastObs) > 10*time.Second {
		t.Errorf("expected recent lastObs timestamp")
	}
}

func TestAntigravityPluginInspection(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Missing initially
	rec := InspectAntigravityPlugin(tmpDir)
	if rec.PluginInstalled {
		t.Errorf("expected plugin not installed initially")
	}

	// 2. Install plugin
	pluginDir := filepath.Join(tmpDir, "plugins", "antigravity")
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(`{"name":"bap-antigravity"}`), 0644); err != nil {
		t.Fatal(err)
	}

	recInstalled := InspectAntigravityPlugin(tmpDir)
	if !recInstalled.PluginInstalled {
		t.Errorf("expected Antigravity plugin installed")
	}
}

func TestOpenCodePluginInspection(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Missing initially
	rec := InspectOpenCodePlugin(tmpDir)
	if rec.PluginInstalled {
		t.Errorf("expected plugin not installed initially")
	}

	// 2. Install plugin
	pluginDir := filepath.Join(tmpDir, "plugins", "opencode")
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(`{"name":"bap-opencode-plugin"}`), 0644); err != nil {
		t.Fatal(err)
	}

	recInstalled := InspectOpenCodePlugin(tmpDir)
	if !recInstalled.PluginInstalled {
		t.Errorf("expected OpenCode plugin installed")
	}
}

func TestCodexPluginInspection(t *testing.T) {
	tmpDir := t.TempDir()

	// 1. Missing initially
	rec := InspectCodexPlugin(tmpDir)
	if rec.PluginInstalled {
		t.Errorf("expected plugin not installed initially")
	}

	// 2. Install plugin
	pluginDir := filepath.Join(tmpDir, "plugins", "codex")
	if err := os.MkdirAll(pluginDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginDir, "plugin.json"), []byte(`{"name":"bap-codex-plugin"}`), 0644); err != nil {
		t.Fatal(err)
	}

	recInstalled := InspectCodexPlugin(tmpDir)
	if !recInstalled.PluginInstalled {
		t.Errorf("expected Codex plugin installed")
	}
}

func TestMultiClientSyntheticProbes(t *testing.T) {
	clients := []string{"claude", "copilot", "antigravity", "opencode", "codex"}

	for _, client := range clients {
		// Benign test: allow
		benign := `{"tool_name":"run_command","tool_input":{"command":"echo test"}}`
		resp, err := executeSyntheticProbe(client, benign, "PreToolUse")
		if err != nil {
			t.Fatalf("client %s synthetic probe failed: %v", client, err)
		}
		if !resp.Allowed {
			t.Errorf("expected client %s benign probe allowed, got denied", client)
		}

		// Credential access: deny
		sensitive := `{"tool_name":"run_command","tool_input":{"command":"cat ~/.aws/credentials"}}`
		denyResp, err := executeSyntheticProbe(client, sensitive, "PreToolUse")
		if err != nil {
			t.Fatalf("client %s sensitive probe failed: %v", client, err)
		}
		if denyResp.Allowed {
			t.Errorf("expected client %s sensitive probe denied, got allowed", client)
		}
	}
}

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// isolate points the managed-config lookup at an empty temp dir and runs the
// test from a clean working directory so no real config leaks in.
func isolate(t *testing.T) (work, managed string) {
	t.Helper()
	if runtime.GOOS != "windows" {
		t.Skip("managed dir is fixed at /etc/bap on this platform")
	}
	managed = t.TempDir()
	t.Setenv("ProgramData", managed)
	// `config set` also syncs caches under the user's home and state dir.
	// Redirect all of them so a test run can never touch the developer's real config.
	home := t.TempDir()
	t.Setenv("USERPROFILE", home)
	t.Setenv("HOME", home)
	t.Setenv("BAP_STATE_DIR", filepath.Join(home, ".bapstate"))
	for _, k := range []string{"BAP_SERVER_URL", "BAP_CONTROL_PLANE_URL", "LTD_SERVER_URL", "BAP_ENFORCEMENT_MODE", "BAP_MODE"} {
		t.Setenv(k, "")
	}
	work = t.TempDir()
	t.Chdir(work)
	return work, managed
}

func TestConfigSetModeWritesEnforcementMode(t *testing.T) {
	work, _ := isolate(t)
	if err := RunConfig([]string{"set", "--mode", "audit"}); err != nil {
		t.Fatalf("set --mode audit failed: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(work, "bap-config.json"))
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Mode string `json:"enforcement_mode"`
	}
	if err := json.Unmarshal(data, &got); err != nil || got.Mode != "audit" {
		t.Fatalf("enforcement_mode not saved: %s (%v)", data, err)
	}
}

func TestConfigSetRejectsInvalidMode(t *testing.T) {
	isolate(t)
	err := RunConfig([]string{"set", "--mode", "off"})
	if err == nil || !strings.Contains(err.Error(), "invalid --mode") {
		t.Fatalf("expected invalid mode error, got %v", err)
	}
}

func TestConfigSetRefusedWhenEndpointsLocked(t *testing.T) {
	work, managed := isolate(t)
	dir := filepath.Join(managed, "BAP")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"),
		[]byte(`{"controlplane_url":"https://bap.corp.example","lock_endpoints":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	err := RunConfig([]string{"set", "--mode", "audit"})
	if err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("locked machine must refuse local changes, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(work, "bap-config.json")); statErr == nil {
		t.Fatal("a config file was written despite the lock")
	}
}

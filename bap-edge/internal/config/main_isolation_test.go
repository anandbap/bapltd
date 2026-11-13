package config

import (
	"os"
	"testing"
)

// TestMain keeps this package's tests away from the developer's real BAP state and home
// directory (policy cache, pinned signing key, credentials, global trust). Without it a test run
// on an enrolled workstation could pin or rewrite the real machine's signed policy.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bap-test-isolated-")
	if err != nil {
		panic(err)
	}
	for k, v := range map[string]string{
		"BAP_STATE_DIR": dir, "BAP_POLICY_DIR": "", "HOME": dir, "USERPROFILE": dir, "BAP_CREDENTIALS": "",
	} {
		os.Setenv(k, v)
	}
	os.Unsetenv("BAP_POLICY_DIR")
	os.Unsetenv("BAP_CREDENTIALS")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

package authz

import (
	"os"
	"testing"
)

// TestMain keeps this package's tests away from the developer's real BAP state and home
// directory (global/project trust grants, ZSP grants, policy cache).
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "bap-test-isolated-")
	if err != nil {
		panic(err)
	}
	for k, v := range map[string]string{"BAP_STATE_DIR": dir, "HOME": dir, "USERPROFILE": dir} {
		os.Setenv(k, v)
	}
	os.Unsetenv("BAP_POLICY_DIR")
	os.Unsetenv("BAP_CREDENTIALS")
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

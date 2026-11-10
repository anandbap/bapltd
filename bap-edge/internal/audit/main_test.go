package audit

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain keeps this package's tests hermetic. Delivery logic resolves its
// destination from the workstation enrollment, so on an enrolled developer
// machine the tests would otherwise post synthetic events to the real control
// plane and ignore their httptest servers.
func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "bap-audit-test-")
	if err != nil {
		panic(err)
	}
	os.Setenv("BAP_CREDENTIALS", filepath.Join(root, "no-enrollment.json"))
	for _, key := range []string{"BAP_SERVER_URL", "BAP_CONTROL_PLANE_URL", "LTD_SERVER_URL"} {
		os.Unsetenv(key)
	}
	code := m.Run()
	os.RemoveAll(root)
	os.Exit(code)
}

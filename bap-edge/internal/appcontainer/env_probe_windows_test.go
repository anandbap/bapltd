//go:build windows

package appcontainer

import (
	"os"
	"strings"
	"testing"
)

// Regression for a measured Windows quirk: an explicit environment lacking the profile variables makes
// CreateProcess-into-AppContainer fail with ERROR_ENVVAR_NOT_FOUND. Run must add them so a minimal,
// secret-free environment launches (the launcher's own environment is never inherited).
func TestMinimalExplicitEnvironmentLaunches(t *testing.T) {
	ws := t.TempDir()
	exe, _ := os.Executable()
	code, err := Run(Options{Name: "bap.test.boundary", Argv: []string{exe, "-bap-probe"}, Dir: ws,
		Env: []string{"ONLY_THIS=1"}, Writable: []string{ws}, Readable: []string{exe}})
	if err != nil {
		if strings.Contains(err.Error(), "access permissions") || strings.Contains(err.Error(), "CreateAppContainerProfile") || strings.Contains(err.Error(), "DeriveAppContainerSid") || strings.Contains(err.Error(), "The parameter is incorrect") {
			t.Skipf("appcontainer unsupported in this environment: %v", err)
		}
		t.Fatalf("code=%d err=%v", code, err)
	}
	if code != 0 {
		t.Fatalf("code=%d", code)
	}
}

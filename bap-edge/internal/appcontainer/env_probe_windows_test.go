//go:build windows

package appcontainer

import (
	"os"
	"testing"
)

// Regression for a measured Windows quirk: an explicit environment lacking the profile variables makes
// CreateProcess-into-AppContainer fail with ERROR_ENVVAR_NOT_FOUND. Run must add them so a minimal,
// secret-free environment launches (the launcher's own environment is never inherited).
func TestMinimalExplicitEnvironmentLaunches(t *testing.T) {
	ws := t.TempDir()
	exe, _ := os.Executable()
	code, err := Run(Options{Name: "bap.test.boundary", Argv: []string{exe, "-test.run=XXX"}, Dir: ws,
		Env: []string{"ONLY_THIS=1"}, Writable: []string{ws}, Readable: []string{exe}})
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
}

//go:build darwin

package sandbox

import (
	"os/exec"
	"syscall"
)

func GetActiveProfile() string {
	return "darwin-posix"
}

// ConfigureSandbox configures sandbox attributes for Darwin (macOS).
func ConfigureSandbox(cmd *exec.Cmd) func() {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	return func() {}
}

// PostStartProcess is a no-op on Darwin.
func PostStartProcess(cmd *exec.Cmd) func() {
	return func() {}
}

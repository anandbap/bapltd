//go:build !windows

package cmd

import (
	"os"
	"os/exec"
	"syscall"
)

// isElevated returns true if the current process is running as root (UID 0) on Unix.
func isElevated() bool {
	return os.Geteuid() == 0
}

func detachProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid: true,
	}
}

//go:build linux || darwin

package sandbox

import (
	"os/exec"
	"syscall"
)

func terminateProcessTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
	}
}

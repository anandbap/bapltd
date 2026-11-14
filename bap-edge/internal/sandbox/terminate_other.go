//go:build !linux && !darwin

package sandbox

import "os/exec"

func terminateProcessTree(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}

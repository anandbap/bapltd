//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"syscall"
)

func GetActiveProfile() string {
	return "linux-namespaces"
}

// ConfigureSandbox configures Linux kernel namespaces:
// syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET
// and maps the current UID and GID so the child process has file read permissions.
func ConfigureSandbox(cmd *exec.Cmd) func() {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:    true,
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
		UidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: os.Getuid(),
				HostID:      os.Getuid(),
				Size:        1,
			},
		},
		GidMappings: []syscall.SysProcIDMap{
			{
				ContainerID: os.Getgid(),
				HostID:      os.Getgid(),
				Size:        1,
			},
		},
		GidMappingsEnableSetgroups: false,
	}
	return func() {}
}

// PostStartProcess is a no-op on Linux.
func PostStartProcess(cmd *exec.Cmd) func() {
	return func() {}
}

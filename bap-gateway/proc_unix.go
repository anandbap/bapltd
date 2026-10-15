//go:build !windows

package main

import (
	"os"
	"syscall"
	"time"
)

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}

func getSysProcAttrDetached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
	}
}

func killProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	_ = syscall.Kill(pid, syscall.SIGTERM)
	time.Sleep(200 * time.Millisecond)
	if isProcessAlive(pid) {
		_ = p.Kill()
	}
	return nil
}

//go:build windows

package main

import (
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	processQueryLimitedInformation = 0x1000
	processQueryInformation        = 0x0400
	stillActive                    = 259
	createNoWindow                 = 0x08000000
	createNewProcessGroup          = 0x00000200
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess        = kernel32.NewProc("OpenProcess")
	procGetExitCodeProcess = kernel32.NewProc("GetExitCodeProcess")
	procCloseHandle        = kernel32.NewProc("CloseHandle")
)

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	handle, _, _ := procOpenProcess.Call(
		uintptr(processQueryLimitedInformation),
		0,
		uintptr(pid),
	)
	if handle == 0 {
		handle, _, _ = procOpenProcess.Call(uintptr(processQueryInformation), 0, uintptr(pid))
		if handle == 0 {
			return false
		}
	}
	defer procCloseHandle.Call(handle)

	var exitCode uint32
	ret, _, _ := procGetExitCodeProcess.Call(handle, uintptr(unsafe.Pointer(&exitCode)))
	if ret == 0 {
		return false
	}
	return exitCode == stillActive
}

func getSysProcAttrDetached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: createNoWindow | createNewProcessGroup,
	}
}

func killProcess(pid int) error {
	p, err := os.FindProcess(pid)
	if err == nil {
		_ = p.Kill()
	}
	_ = exec.Command("taskkill", "/F", "/PID", strconv.Itoa(pid)).Run()
	return nil
}

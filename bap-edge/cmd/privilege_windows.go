//go:build windows

package cmd

import (
	"os/exec"
	"syscall"
	"unsafe"
)

func detachProcess(cmd *exec.Cmd) {
	// CREATE_NO_WINDOW (0x08000000) | CREATE_NEW_PROCESS_GROUP (0x00000200)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		CreationFlags: 0x08000000 | 0x00000200,
	}
}

var (
	advapi32                 = syscall.NewLazyDLL("advapi32.dll")
	procOpenProcessToken     = advapi32.NewProc("OpenProcessToken")
	procGetTokenInformation = advapi32.NewProc("GetTokenInformation")
)

const (
	tokenQuery     = 0x0008
	tokenElevation = 20
)

type tokenElevationStruct struct {
	TokenIsElevated uint32
}

// isElevated returns true if the current process holds Administrator elevation on Windows.
func isElevated() bool {
	hProcess, err := syscall.GetCurrentProcess()
	if err != nil {
		return false
	}
	var token syscall.Token
	r, _, _ := procOpenProcessToken.Call(uintptr(hProcess), uintptr(tokenQuery), uintptr(unsafe.Pointer(&token)))
	if r == 0 {
		return false
	}
	defer syscall.CloseHandle(syscall.Handle(token))

	var elev tokenElevationStruct
	var retLen uint32
	r, _, _ = procGetTokenInformation.Call(
		uintptr(token),
		uintptr(tokenElevation),
		uintptr(unsafe.Pointer(&elev)),
		uintptr(unsafe.Sizeof(elev)),
		uintptr(unsafe.Pointer(&retLen)),
	)
	if r == 0 {
		return false
	}
	return elev.TokenIsElevated != 0
}

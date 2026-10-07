//go:build windows

package cmd

import (
	"os"
	"path/filepath"
	"strings"
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

func findOtherBapEdgePIDs() ([]int, error) {
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.CloseHandle(snapshot)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	if err := syscall.Process32First(snapshot, &entry); err != nil {
		return nil, err
	}

	currentPID := os.Getpid()
	currentExe := strings.ToLower(filepath.Base(os.Args[0]))

	var pids []int
	for {
		pid := int(entry.ProcessID)
		if pid != currentPID && pid > 0 {
			exeName := strings.ToLower(syscall.UTF16ToString(entry.ExeFile[:]))
			if exeName == "bapedge.exe" || exeName == "bap.exe" || exeName == "bap-daemon.exe" || exeName == currentExe {
				pids = append(pids, pid)
			}
		}

		err = syscall.Process32Next(snapshot, &entry)
		if err != nil {
			break
		}
	}
	return pids, nil
}

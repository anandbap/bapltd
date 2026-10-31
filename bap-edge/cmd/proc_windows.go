//go:build windows

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

func listAgentProcesses() ([]agentProcess, error) {
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
	var result []agentProcess
	for {
		name := syscall.UTF16ToString(entry.ExeFile[:])
		p := agentProcess{PID: int(entry.ProcessID), ParentPID: int(entry.ParentProcessID), Name: name}
		// Retain parent links for caller attribution; inspect birth only for agents.
		if agentApp(name) != "" {
			p.Birth = processBirth(p.PID)
		}
		result = append(result, p)
		if syscall.Process32Next(snapshot, &entry) != nil {
			break
		}
	}
	return result, nil
}

func processBirth(pid int) string {
	h, _, _ := procOpenProcess.Call(uintptr(processQueryLimitedInformation), 0, uintptr(pid))
	if h == 0 {
		return ""
	}
	defer procCloseHandle.Call(h)
	var birth, exit, kernel, user syscall.Filetime
	ok, _, _ := kernel32.NewProc("GetProcessTimes").Call(h, uintptr(unsafe.Pointer(&birth)), uintptr(unsafe.Pointer(&exit)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ok == 0 {
		return ""
	}
	return fmt.Sprintf("%08x%08x", birth.HighDateTime, birth.LowDateTime)
}

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

// getProcessExecutablePath inspects a PID and returns its full executable image path.
func getProcessExecutablePath(pid int) string {
	if pid <= 0 {
		return ""
	}
	procQueryFullProcessImageNameW := kernel32.NewProc("QueryFullProcessImageNameW")
	hProcess, _, _ := procOpenProcess.Call(uintptr(processQueryLimitedInformation), 0, uintptr(pid))
	if hProcess == 0 {
		hProcess, _, _ = procOpenProcess.Call(uintptr(processQueryInformation), 0, uintptr(pid))
	}
	if hProcess != 0 {
		defer procCloseHandle.Call(hProcess)
		var buf [1024]uint16
		size := uint32(len(buf))
		ret, _, _ := procQueryFullProcessImageNameW.Call(hProcess, 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)))
		if ret != 0 {
			return syscall.UTF16ToString(buf[:size])
		}
	}
	return ""
}

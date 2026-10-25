//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

func getProcessExecutablePath(pid int) string {
	if pid <= 0 {
		return ""
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procOpenProcess := kernel32.NewProc("OpenProcess")
	procCloseHandle := kernel32.NewProc("CloseHandle")
	procQueryFullProcessImageNameW := kernel32.NewProc("QueryFullProcessImageNameW")

	hProcess, _, _ := procOpenProcess.Call(0x1000, 0, uintptr(pid)) // PROCESS_QUERY_LIMITED_INFORMATION
	if hProcess == 0 {
		hProcess, _, _ = procOpenProcess.Call(0x0400, 0, uintptr(pid)) // PROCESS_QUERY_INFORMATION
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

func getParentPID(pid int) int {
	if pid <= 0 {
		return 0
	}
	snapshot, err := syscall.CreateToolhelp32Snapshot(syscall.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer syscall.CloseHandle(snapshot)

	var entry syscall.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := syscall.Process32First(snapshot, &entry); err != nil {
		return 0
	}
	for {
		if int(entry.ProcessID) == pid {
			return int(entry.ParentProcessID)
		}
		if err := syscall.Process32Next(snapshot, &entry); err != nil {
			break
		}
	}
	return 0
}

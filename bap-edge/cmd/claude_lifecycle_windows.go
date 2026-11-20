//go:build windows

package cmd

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

func acquireClaudeLifecycleLock(workspace string) (func(), error) {
	sum := sha256.Sum256([]byte(strings.ToLower(workspace)))
	name, _ := syscall.UTF16PtrFromString(fmt.Sprintf("Local\\BAP-ClaudeLifecycle-%x", sum[:16]))
	handle, _, err := kernel32.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return nil, fmt.Errorf("Claude lifecycle lock: %v", err)
	}
	if err == syscall.ERROR_ALREADY_EXISTS {
		procCloseHandle.Call(handle)
		return nil, errRuntimeRunning
	}
	return func() { procCloseHandle.Call(handle) }, nil
}

func replaceClaudeOwner(source, target string) error {
	src, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	// MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH; same-directory atomic
	// replacement without a remove/create gap.
	ok, _, callErr := kernel32.NewProc("MoveFileExW").Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), 9)
	if ok == 0 {
		return callErr
	}
	return nil
}

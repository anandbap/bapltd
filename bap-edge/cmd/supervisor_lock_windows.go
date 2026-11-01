//go:build windows

package cmd

import (
	"bap-edge/internal/state"
	"crypto/sha256"
	"fmt"
	"strings"
	"syscall"
	"unsafe"
)

// The OS releases this handle on a crash. No stale lock-file deletion race.
func acquireRuntimeLock(kind string) (func(), error) {
	sum := sha256.Sum256([]byte(strings.ToLower(state.Dir()) + "/" + kind))
	name, _ := syscall.UTF16PtrFromString(fmt.Sprintf("Local\\BAP-%x", sum[:16]))
	handle, _, err := kernel32.NewProc("CreateMutexW").Call(0, 0, uintptr(unsafe.Pointer(name)))
	if handle == 0 {
		return nil, fmt.Errorf("runtime lock unavailable: %v", err)
	}
	if err == syscall.ERROR_ALREADY_EXISTS {
		procCloseHandle.Call(handle)
		return nil, errRuntimeRunning
	}
	return func() { procCloseHandle.Call(handle) }, nil
}

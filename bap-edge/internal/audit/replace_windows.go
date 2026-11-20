//go:build windows

package audit

import (
	"syscall"
	"unsafe"
)

func replacePendingFile(source, target string) error {
	src, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return err
	}
	dst, err := syscall.UTF16PtrFromString(target)
	if err != nil {
		return err
	}
	ok, _, callErr := syscall.NewLazyDLL("kernel32.dll").NewProc("MoveFileExW").Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), 9)
	if ok == 0 {
		return callErr
	}
	return nil
}

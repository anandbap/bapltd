//go:build windows

package policystore

import (
	"syscall"
	"unsafe"
)

// machineID reads HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid.
func machineID() string {
	const keyWOW64_64 = 0x0100
	sub, err := syscall.UTF16PtrFromString(`SOFTWARE\Microsoft\Cryptography`)
	if err != nil {
		return ""
	}
	var h syscall.Handle
	if err := syscall.RegOpenKeyEx(syscall.HKEY_LOCAL_MACHINE, sub, 0, syscall.KEY_READ|keyWOW64_64, &h); err != nil {
		return ""
	}
	defer syscall.RegCloseKey(h)
	name, err := syscall.UTF16PtrFromString("MachineGuid")
	if err != nil {
		return ""
	}
	buf := make([]uint16, 128)
	n := uint32(len(buf) * 2)
	var typ uint32
	if err := syscall.RegQueryValueEx(h, name, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil {
		return ""
	}
	return syscall.UTF16ToString(buf[:n/2])
}

//go:build windows

package cmd

import (
	"os"
	"strings"
	"syscall"
	"unsafe"
)

type systemPowerStatus struct {
	ACLineStatus        byte
	BatteryFlag         byte
	BatteryLifePercent  byte
	SystemStatusFlag    byte
	BatteryLifeTime     uint32
	BatteryFullLifeTime uint32
}

// detectDeviceType detects whether the machine is a laptop, desktop, or server on Windows.
func detectDeviceType() string {
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	procGetSystemPowerStatus := kernel32.NewProc("GetSystemPowerStatus")
	if procGetSystemPowerStatus.Find() == nil {
		var sps systemPowerStatus
		ret, _, _ := procGetSystemPowerStatus.Call(uintptr(unsafe.Pointer(&sps)))
		if ret != 0 {
			// BatteryFlag 128 means no system battery
			// 255 means unknown
			if sps.BatteryFlag != 128 && sps.BatteryFlag != 255 {
				return "laptop"
			}
			if sps.BatteryLifePercent <= 100 && sps.BatteryLifePercent > 0 {
				return "laptop"
			}
		}
	}

	h, _ := os.Hostname()
	hLower := strings.ToLower(h)
	serverKeywords := []string{"srv", "server", "prod", "stage", "node", "vm", "cloud", "bastion"}
	for _, kw := range serverKeywords {
		if strings.Contains(hLower, kw) {
			return "server"
		}
	}
	return "desktop"
}

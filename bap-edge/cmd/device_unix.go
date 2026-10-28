//go:build !windows

package cmd

import (
	"os"
	"runtime"
	"strings"
)

// detectDeviceType detects whether the machine is a laptop, desktop, or server on Unix/Linux/macOS.
func detectDeviceType() string {
	if runtime.GOOS == "darwin" {
		return "laptop"
	}

	// Linux battery check
	candidates := []string{
		"/sys/class/power_supply/BAT0",
		"/sys/class/power_supply/BAT1",
		"/sys/class/power_supply/battery",
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return "laptop"
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

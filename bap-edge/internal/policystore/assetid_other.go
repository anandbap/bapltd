//go:build !windows

package policystore

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
)

func machineID() string {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		if data, err := os.ReadFile(p); err == nil {
			if id := strings.TrimSpace(string(data)); id != "" {
				return id
			}
		}
	}
	if runtime.GOOS == "darwin" {
		if out, err := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output(); err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if strings.Contains(line, "IOPlatformUUID") {
					if i := strings.LastIndex(line, "= \""); i >= 0 {
						return strings.Trim(strings.TrimSpace(line[i+2:]), "\"")
					}
				}
			}
		}
	}
	return ""
}

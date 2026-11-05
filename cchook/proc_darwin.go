//go:build darwin

package main

import (
	"context"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// macOS has no /proc filesystem. Use the system ps binary without a shell,
// bounding lookup time and avoiding PATH-controlled executable resolution.
func processField(pid int, field string) string {
	if pid <= 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/bin/ps", "-ww", "-p", strconv.Itoa(pid), "-o", field+"=").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

func getProcessExecutablePath(pid int) string {
	path := processField(pid, "comm")
	if !filepath.IsAbs(path) {
		return ""
	}
	return path
}

func getParentPID(pid int) int {
	parent, err := strconv.Atoi(processField(pid, "ppid"))
	if err != nil || parent <= 0 {
		return 0
	}
	return parent
}

func getProcessBirth(pid int) string {
	return processField(pid, "lstart")
}

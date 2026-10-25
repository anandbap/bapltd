//go:build !windows

package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func getProcessExecutablePath(pid int) string {
	if pid <= 0 {
		return ""
	}
	if link, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid)); err == nil {
		return link
	}
	return ""
}

func getParentPID(pid int) int {
	if pid <= 0 {
		return 0
	}
	// On Linux, read /proc/<pid>/stat
	statBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		idx := bytes.LastIndexByte(statBytes, ')')
		if idx != -1 && len(statBytes) > idx+2 {
			fields := strings.Fields(string(statBytes[idx+2:]))
			if len(fields) >= 2 {
				if ppid, err := strconv.Atoi(fields[1]); err == nil {
					return ppid
				}
			}
		}
	}
	return 0
}

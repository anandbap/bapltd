//go:build !windows && !darwin

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

func getProcessBirth(pid int) string {
	if pid <= 0 {
		return ""
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return ""
	}
	idx := bytes.LastIndexByte(stat, ')')
	if idx == -1 || len(stat) <= idx+2 {
		return ""
	}
	fields := strings.Fields(string(stat[idx+2:]))
	if len(fields) < 20 {
		return ""
	}
	return strings.TrimSpace(string(boot)) + ":" + fields[19]
}

//go:build !windows

package main

import (
	"fmt"
	"os"
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

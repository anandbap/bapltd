//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func isProcessAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil
}

func getSysProcAttrDetached() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		Setpgid: true,
	}
}

func findOtherBapEdgePIDs() ([]int, error) {
	currentPID := os.Getpid()
	currentExe := strings.ToLower(filepath.Base(os.Args[0]))

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var pids []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 || pid == currentPID {
			continue
		}
		commPath := filepath.Join("/proc", entry.Name(), "comm")
		commBytes, err := os.ReadFile(commPath)
		if err != nil {
			continue
		}
		comm := strings.ToLower(strings.TrimSpace(string(commBytes)))
		if comm == "bapedge" || comm == "bap" || comm == "bap-daemon" || comm == currentExe {
			pids = append(pids, pid)
		}
	}
	return pids, nil
}

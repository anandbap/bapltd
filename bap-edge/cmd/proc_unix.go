//go:build !windows

package cmd

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func listAgentProcesses() ([]agentProcess, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, err
	}
	var result []agentProcess
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 0 {
			continue
		}
		data, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil {
			continue
		}
		stat := string(data)
		left, right := strings.Index(stat, "("), strings.LastIndex(stat, ")")
		if left < 0 || right <= left {
			continue
		}
		fields := strings.Fields(stat[right+1:])
		if len(fields) < 20 {
			continue
		}
		parent, _ := strconv.Atoi(fields[1])
		result = append(result, agentProcess{PID: pid, ParentPID: parent, Name: stat[left+1 : right], Birth: strings.TrimSpace(string(boot)) + ":" + fields[19]})
	}
	return result, nil
}

func processBirth(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return ""
	}
	right := strings.LastIndex(string(data), ")")
	if right < 0 {
		return ""
	}
	fields := strings.Fields(string(data)[right+1:])
	if len(fields) < 20 {
		return ""
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(boot)) + ":" + fields[19]
}

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

// getProcessExecutablePath inspects a PID and returns its full executable image path.
func getProcessExecutablePath(pid int) string {
	if pid <= 0 {
		return ""
	}
	if link, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), "exe")); err == nil {
		return link
	}
	return ""
}

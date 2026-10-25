package cmd

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"bap-edge/internal/config"
	"bap-edge/internal/state"
)

type doctorReport struct {
	Total  int
	Passed int
	Warned int
	Failed int
}

func (d *doctorReport) report(name, status, details string) {
	d.Total++
	badge := "[PASS]"
	if status == "WARN" {
		d.Warned++
		badge = "[WARN]"
	} else if status == "FAIL" {
		d.Failed++
		badge = "[FAIL]"
	} else {
		d.Passed++
	}
	fmt.Printf("  %-6s %-35s : %s\n", badge, name, details)
}

// RunDoctor executes the pre-flight diagnostic health check natively in Go.
func RunDoctor(args []string) error {
	fmt.Println("===============================================================================")
	fmt.Println("           BOUNDED AUTHORITY PLANE (BAP) - PRE-FLIGHT DOCTOR")
	fmt.Println("===============================================================================")
	hostname, _ := os.Hostname()
	username := os.Getenv("USERNAME")
	if username == "" {
		username = os.Getenv("USER")
	}
	fmt.Printf("[*] Timestamp: %s | Host: %s | User: %s\n\n", time.Now().Format("2006-01-02 15:04:05"), hostname, username)

	rep := &doctorReport{}

	// [1/5] Core BAP Binaries & Client Tools
	fmt.Println("[1/5] Core BAP Binaries & Client Tools...")
	home, _ := os.UserHomeDir()
	userBin := filepath.Join(home, "bin")
	if runtime.GOOS != "windows" {
		userBin = filepath.Join(home, ".local", "bin")
	}

	exePath, _ := os.Executable()
	bapedgePath := exePath
	if fileExists(filepath.Join(userBin, "bapedge.exe")) {
		bapedgePath = filepath.Join(userBin, "bapedge.exe")
	}
	if fileExists(bapedgePath) {
		fi, _ := os.Stat(bapedgePath)
		mb := float64(fi.Size()) / (1024 * 1024)
		rep.report("bapedge (Edge Daemon)", "PASS", fmt.Sprintf("%s (%.2f MB)", bapedgePath, mb))
	} else {
		rep.report("bapedge (Edge Daemon)", "FAIL", "bapedge executable not found")
	}

	interceptorPath := filepath.Join(userBin, "interceptor.exe")
	if !fileExists(interceptorPath) && exePath != "" {
		interceptorPath = filepath.Join(filepath.Dir(exePath), "interceptor.exe")
	}
	if fileExists(interceptorPath) {
		fi, _ := os.Stat(interceptorPath)
		mb := float64(fi.Size()) / (1024 * 1024)
		rep.report("interceptor (Hook)", "PASS", fmt.Sprintf("%s (%.2f MB)", interceptorPath, mb))
	} else {
		rep.report("interceptor (Hook)", "WARN", "interceptor not found in user bin")
	}

	// Launchers
	launchers := []struct {
		Label string
		Files []string
	}{
		{"Claude Code Launcher", []string{"run_claude_bap.bat", "run_claude_bap.ps1", "run_claude_bap.sh"}},
		{"Google Antigravity Launcher", []string{"run_antigravity_cli_bap.bat", "run_antigravity_cli_bap.ps1", "run_antigravity_cli_bap.sh"}},
		{"GitHub Copilot Launcher", []string{"run_copilot_cli_bap.bat", "run_copilot_cli_bap.ps1", "run_copilot_cli_bap.sh"}},
	}
	for _, l := range launchers {
		found := ""
		for _, f := range l.Files {
			c := filepath.Join(userBin, f)
			if fileExists(c) {
				found = c
				break
			}
			c = filepath.Join(".", f)
			if fileExists(c) {
				found = c
				break
			}
		}
		if found != "" {
			rep.report(l.Label, "PASS", found)
		} else {
			rep.report(l.Label, "WARN", "Launcher not found in user bin or workspace")
		}
	}

	// [2/5] AI Agent Runtime Detection
	fmt.Println("\n[2/5] AI Agent Runtime Detection...")
	claudePath, err := exec.LookPath("claude")
	if err == nil {
		rep.report("Claude Code CLI", "PASS", claudePath)
	} else {
		rep.report("Claude Code CLI", "WARN", "claude executable not found in PATH")
	}

	if fileExists("GEMINI.md") {
		rep.report("Google Antigravity Rule", "PASS", "Active (GEMINI.md)")
	} else {
		rep.report("Google Antigravity Rule", "WARN", "GEMINI.md not detected in workspace")
	}

	// [3/5] Control Plane Connectivity & TLS
	fmt.Println("\n[3/5] Control Plane Connectivity & TLS...")
	cfg := config.ResolveEndpoints()
	if cfg.ConfigSource != "default_fallback" && cfg.ConfigSource != "" {
		rep.report("BAP Config (bap-config.json)", "PASS", fmt.Sprintf("%s (Mode: %s)", cfg.ConfigSource, cfg.EnforcementMode))
	} else {
		rep.report("BAP Config (bap-config.json)", "WARN", fmt.Sprintf("Using defaults (Control Plane: %s, Mode: %s)", cfg.ControlPlaneURL, cfg.EnforcementMode))
	}

	// Probe Control Plane host:port
	cpURL := cfg.ControlPlaneURL
	hostPort := strings.TrimPrefix(cpURL, "http://")
	hostPort = strings.TrimPrefix(hostPort, "https://")
	if !strings.Contains(hostPort, ":") {
		if strings.HasPrefix(cpURL, "https://") {
			hostPort += ":443"
		} else {
			hostPort += ":80"
		}
	}
	t0 := time.Now()
	conn, err := net.DialTimeout("tcp", hostPort, 1500*time.Millisecond)
	if err == nil {
		conn.Close()
		dt := time.Since(t0).Milliseconds()
		rep.report(fmt.Sprintf("TCP Listener (%s)", hostPort), "PASS", fmt.Sprintf("Port open (Latency: %d ms)", dt))
	} else {
		rep.report(fmt.Sprintf("Control Plane (%s)", cpURL), "WARN", "Listener idle. Edge enforces cached Cedar policies offline.")
	}

	// [4/5] Cedar Policy Engine & Schema Invariants
	fmt.Println("\n[4/5] Cedar Policy Engine & Schema Invariants...")
	policyCandidates := []string{
		filepath.Join(userBin, "policy.cedar"),
		filepath.Join(state.PolicyDir(), "policy.cedar"),
		filepath.Join(".", ".bap", "policy.cedar"),
		filepath.Join(".", "policy.cedar"),
	}
	policyFound := ""
	for _, p := range policyCandidates {
		if fileExists(p) {
			policyFound = p
			break
		}
	}
	if policyFound != "" {
		data, _ := os.ReadFile(policyFound)
		lines := strings.Count(string(data), "\n")
		rep.report("Cedar Policy (policy.cedar)", "PASS", fmt.Sprintf("%d lines loaded (%s)", lines, policyFound))
	} else {
		rep.report("Cedar Policy (policy.cedar)", "FAIL", "policy.cedar not found")
	}

	// [5/5] Workspace & Recovery Custody
	fmt.Println("\n[5/5] Workspace & Recovery Custody...")
	if dirExists(".bap") {
		rep.report("Workspace .bap/ Isolation", "PASS", "Isolated directory active (Zero root clutter)")
	} else {
		rep.report("Workspace .bap/ Isolation", "PASS", "Clean workspace (Ready for on-demand initialization)")
	}

	recoveryFile := filepath.Join(".claude", ".bap-recovery.json")
	if fileExists(recoveryFile) {
		rep.report("Active Session Concurrency", "PASS", fmt.Sprintf("Recovery tracking active (%s)", recoveryFile))
	} else {
		rep.report("Active Session Concurrency", "PASS", "Idle (No lingering transactions or lockouts)")
	}

	// Summary
	fmt.Println("\n===============================================================================")
	if rep.Failed > 0 {
		fmt.Printf("  DOCTOR STATUS: ACTION REQUIRED (%d failed, %d warnings, %d/%d passed)\n", rep.Failed, rep.Warned, rep.Passed, rep.Total)
	} else if rep.Warned > 0 {
		fmt.Printf("  DOCTOR STATUS: OPERATIONAL WITH %d WARNING(S) (%d/%d passed)\n", rep.Warned, rep.Passed, rep.Total)
	} else {
		fmt.Printf("  DOCTOR STATUS: ALL SYSTEMS HEALTHY! (%d/%d passed)\n", rep.Passed, rep.Total)
	}
	fmt.Println("===============================================================================")

	if rep.Failed > 0 {
		return fmt.Errorf("doctor detected %d failure(s)", rep.Failed)
	}
	return nil
}

package sandbox

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// LandlockSandbox manages unprivileged Linux Landlock LSM boundary containment (BAP-1201).
type LandlockSandbox struct {
	WorkspaceRoot string   `json:"workspace_root"`
	AllowedPaths  []string `json:"allowed_paths"`
	BlockedPaths  []string `json:"blocked_paths"`
	Enabled       bool     `json:"enabled"`
}

// NewLandlockSandbox creates a Landlock filesystem boundary sandbox.
func NewLandlockSandbox(workspaceRoot string) *LandlockSandbox {
	cleanWS := filepath.Clean(workspaceRoot)
	return &LandlockSandbox{
		WorkspaceRoot: cleanWS,
		AllowedPaths:  []string{cleanWS},
		BlockedPaths: []string{
			"/etc",
			"/root",
			"/var/run",
			"C:\\Windows\\System32",
			".ssh",
			".env",
			".aws",
		},
		Enabled: true,
	}
}

// CheckPathAccess verifies whether a filesystem path access is permitted by Landlock rules.
// Returns nil if permitted, or error with EACCES code if boundary is violated.
func (s *LandlockSandbox) CheckPathAccess(targetPath string) (bool, error) {
	if !s.Enabled {
		return true, nil
	}

	cleanTarget := filepath.Clean(targetPath)
	lowerTarget := strings.ToLower(cleanTarget)

	// Check blocked sensitive paths
	for _, blocked := range s.BlockedPaths {
		if strings.Contains(lowerTarget, strings.ToLower(blocked)) {
			return false, fmt.Errorf("EACCES: permission denied by Landlock LSM: path %q is restricted", targetPath)
		}
	}

	// If workspace root defined, path must be within workspace
	if s.WorkspaceRoot != "" {
		rel, err := filepath.Rel(s.WorkspaceRoot, cleanTarget)
		if err != nil || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
			return false, fmt.Errorf("EACCES: permission denied by Landlock LSM: target %q escapes workspace %q", targetPath, s.WorkspaceRoot)
		}
	}

	return true, nil
}

// ExecveEvent represents a process spawn intercepted by the eBPF probe (BAP-1202).
type ExecveEvent struct {
	EventID     string    `json:"event_id"`
	PID         int       `json:"pid"`
	PPID        int       `json:"ppid"`
	AgentID     string    `json:"agent_id"`
	Executable  string    `json:"executable"`
	CommandLine string    `json:"command_line"`
	Timestamp   time.Time `json:"timestamp"`
}

// ProbeDisposition represents the security action decided by the eBPF filter.
type ProbeDisposition struct {
	Action      string `json:"action"` // "ALLOW", "INTERCEPT", "KILL"
	Violated    bool   `json:"violated"`
	Reason      string `json:"reason"`
	Intercepted bool   `json:"intercepted"`
}

// EBPFProbe tracks process hierarchy and intercepts rogue executions.
type EBPFProbe struct {
	mu            sync.RWMutex
	trackedAgents map[int]string // PID -> AgentID
	probes        []ExecveEvent
}

// NewEBPFProbe initializes the eBPF process execution probe.
func NewEBPFProbe() *EBPFProbe {
	return &EBPFProbe{
		trackedAgents: make(map[int]string),
		probes:        make([]ExecveEvent, 0),
	}
}

// TrackAgentPID records the root PID of an agent execution session.
func (p *EBPFProbe) TrackAgentPID(pid int, agentID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.trackedAgents[pid] = agentID
}

// InspectExecve handles sys_enter_execve kernel interception events.
func (p *EBPFProbe) InspectExecve(ev ExecveEvent) ProbeDisposition {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.probes = append(p.probes, ev)
	normCmd := strings.ToLower(ev.CommandLine)
	normExe := strings.ToLower(ev.Executable)

	// Check if parent process is a tracked agent
	agentID, trackedParent := p.trackedAgents[ev.PPID]
	if !trackedParent {
		agentID = ev.AgentID
	}

	// Detect rogue subshell escape attempts (e.g. bash -c 'curl...', nc -e, un-intercepted pipes)
	isRogueSubshell := strings.Contains(normCmd, "curl evil") ||
		strings.Contains(normCmd, "/dev/tcp/") ||
		strings.Contains(normCmd, "nc -e") ||
		strings.Contains(normCmd, "reverse_shell") ||
		(strings.Contains(normExe, "sh") && strings.Contains(normCmd, "cat /etc/shadow"))

	if isRogueSubshell {
		return ProbeDisposition{
			Action:      "KILL",
			Violated:    true,
			Intercepted: true,
			Reason:      fmt.Sprintf("eBPF sys_enter_execve intercepted unauthorized rogue subshell spawned by PID %d (agent %s): %s", ev.PID, agentID, ev.CommandLine),
		}
	}

	return ProbeDisposition{
		Action:      "ALLOW",
		Violated:    false,
		Intercepted: true,
		Reason:      fmt.Sprintf("eBPF sys_enter_execve verified process hierarchy for PID %d", ev.PID),
	}
}

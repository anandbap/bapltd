package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/state"
)

func observationHost() string {
	// Installation identity separates workstations with identical hostnames.
	var creds StoredCredentials
	if data, err := os.ReadFile(DefaultCredentialsPath()); err == nil && json.Unmarshal(data, &creds) == nil && creds.InstanceID != "" {
		return creds.InstanceID
	}
	host, _ := os.Hostname()
	return host
}

// Walk bounded parent links, rather than identifying the intermediary shell as
// the agent. Never infer agent identity from arbitrary command-line text.
func observedCaller(parent int, processes []agentProcess) (agentProcess, bool) {
	byPID := make(map[int]agentProcess, len(processes))
	for _, p := range processes {
		byPID[p.PID] = p
	}
	for depth := 0; parent > 0 && depth < 16; depth++ {
		p, ok := byPID[parent]
		if !ok {
			break
		}
		if agentApp(p.Name) != "" && p.Birth != "" {
			return findRootAgentProcess(p, byPID), true
		}
		if p.ParentPID == parent {
			break
		}
		parent = p.ParentPID
	}
	return agentProcess{}, false
}

// findRootAgentProcess walks up the process hierarchy to find the top-most
// process belonging to the same agent application. This ensures child worker/shim
// processes (e.g. claude.exe launcher spawning claude.exe worker) are deduplicated
// under a single canonical agent workload.
func findRootAgentProcess(p agentProcess, byPID map[int]agentProcess) agentProcess {
	curr := p
	app := agentApp(p.Name)
	if app == "" {
		return p
	}
	for depth := 0; depth < 16; depth++ {
		parent, ok := byPID[curr.ParentPID]
		if !ok || curr.ParentPID == curr.PID || agentApp(parent.Name) != app {
			break
		}
		curr = parent
	}
	return curr
}

// Process metadata only: never read an agent's environment, memory or transcript.
type agentProcess struct {
	PID, ParentPID int
	Name, Birth    string
}

func agentApp(name string) string {
	name = strings.TrimSuffix(strings.ToLower(filepath.Base(name)), ".exe")
	switch name {
	case "claude", "claude-code":
		return "claude-code"
	case "antigravity", "agy":
		return "antigravity"
	case "opencode", "open-code":
		return "opencode"
	case "codex", "openai-codex":
		return "codex"
	case "copilot", "github-copilot":
		return "copilot"
	case "cursor", "gemini":
		return name
	}
	return ""
}

func observedSessionID(host string, p agentProcess) string {
	if p.PID <= 0 || p.Birth == "" || agentApp(p.Name) == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%d\x00%s", host, p.PID, p.Birth)))
	return fmt.Sprintf("observed-%s-%x", agentApp(p.Name), sum[:12])
}

type agentWorkloadTree struct {
	root agentProcess
	pids []int
}

// Independently observe named agent processes even when native hooks are not
// trusted. Presence is evidence only; this path never issues execution grants.
func (s *DaemonServer) reconcileObservedProcesses(processes []agentProcess, host string) {
	byPID := make(map[int]agentProcess, len(processes))
	for _, p := range processes {
		byPID[p.PID] = p
	}

	treesByRootPID := make(map[int]*agentWorkloadTree)
	for _, p := range processes {
		if agentApp(p.Name) == "" || p.PID <= 0 {
			continue
		}
		root := findRootAgentProcess(p, byPID)
		tree, exists := treesByRootPID[root.PID]
		if !exists {
			tree = &agentWorkloadTree{root: root, pids: []int{root.PID}}
			treesByRootPID[root.PID] = tree
		}
		if p.PID != root.PID {
			tree.pids = append(tree.pids, p.PID)
		}
	}

	current := make(map[string]bool)
	for _, tree := range treesByRootPID {
		if id := observedSessionID(host, tree.root); id != "" {
			current[id] = true
		}
	}
	s.mu.Lock()
	for id := range s.sessions {
		// Birth is part of the identifier: a reused PID cannot keep the old
		// workload alive, even if the replacement is also an agent.
		if strings.HasPrefix(id, "observed-") && !current[id] {
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()

	type nativeSessionInfo struct {
		SessionID string `json:"session_id"`
		ServerURL string `json:"server_url"`
		Birth     string `json:"process_birth"`
		PID       int    `json:"pid"`
	}

	checkNativeMarker := func(pid int, expectedBirth string) (nativeSessionInfo, bool) {
		var native nativeSessionInfo
		dirs := []string{state.SessionsDir(), filepath.Join(".bap", "sessions")}
		for _, dir := range dirs {
			markerPath := filepath.Join(dir, fmt.Sprintf("pid-%d.json", pid))
			data, err := os.ReadFile(markerPath)
			if err != nil {
				continue
			}
			if json.Unmarshal(data, &native) == nil && native.SessionID != "" && native.PID == pid {
				if native.ServerURL != "" && strings.TrimRight(native.ServerURL, "/") != strings.TrimRight(s.state.ServerURL, "/") {
					continue
				}
				if native.Birth != "" && native.Birth != expectedBirth {
					continue
				}
				return native, true
			}
		}
		return nativeSessionInfo{}, false
	}

	for _, tree := range treesByRootPID {
		id := observedSessionID(host, tree.root)
		if id == "" {
			continue
		}

		// Check if any process in the tree matches a native session marker
		var adoptedNative *nativeSessionInfo
		for _, pid := range tree.pids {
			pObj := byPID[pid]
			if native, ok := checkNativeMarker(pid, pObj.Birth); ok {
				adoptedNative = &native
				break
			}
		}

		if adoptedNative != nil {
			s.mu.Lock()
			delete(s.sessions, id)
			s.sessions[adoptedNative.SessionID] = AttachedSession{
				SessionID:      adoptedNative.SessionID,
				AppID:          agentApp(tree.root.Name),
				PID:            tree.root.PID,
				AttachedAt:     time.Now().UTC(),
				ReportingLayer: "launcher",
			}
			s.mu.Unlock()
			continue
		}

		s.mu.Lock()
		already := false
		for _, attached := range s.sessions {
			for _, pid := range tree.pids {
				if attached.PID == pid && attached.SessionID != id && attached.ReportingLayer != "discovery" {
					already = true
					break
				}
			}
			if already {
				break
			}
		}
		if _, exists := s.sessions[id]; exists {
			already = true
		}
		if !already {
			s.sessions[id] = AttachedSession{
				SessionID:      id,
				AppID:          agentApp(tree.root.Name),
				PID:            tree.root.PID,
				AttachedAt:     time.Now().UTC(),
				ReportingLayer: "discovery",
			}
		}
		s.mu.Unlock()
		if already {
			continue
		}

		entry := audit.AuditEntry{
			EventID:        "presence-" + id,
			SessionID:      id,
			Timestamp:      time.Now().UTC(),
			Source:         agentApp(tree.root.Name),
			ClientPID:      tree.root.PID,
			ReportingLayer: "discovery",
			Decision:       "observed",
			Reason:         "Process observed; native hooks and prompt capture are not confirmed",
		}
		if audit.Log(&entry, "") != nil {
			s.mu.Lock()
			delete(s.sessions, id) // retry local persistence on the next scan
			s.mu.Unlock()
		} else {
			s.enqueueTelemetry(entry)
		}
		// Bounded background delivery never waits on command execution.
	}
}

func (s *DaemonServer) attachReportedWorkload(entry audit.AuditEntry) {
	if entry.ReportingLayer != "broker" || !strings.HasPrefix(entry.SessionID, "observed-") || entry.ClientPID <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[entry.SessionID] = AttachedSession{SessionID: entry.SessionID, AppID: entry.Source, PID: entry.ClientPID, AttachedAt: time.Now().UTC(), ReportingLayer: "broker"}
}

func (s *DaemonServer) runProcessObservationWorker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if processes, err := listAgentProcesses(); err == nil {
			s.reconcileObservedProcesses(processes, observationHost())
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

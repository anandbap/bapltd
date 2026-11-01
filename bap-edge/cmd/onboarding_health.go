package cmd

import (
	"bap-edge/internal/state"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Diagnostics report observed callbacks, never infer hook approval from files.
func localOnboardingHealth(now time.Time) map[string]any {
	phases := map[string]any{}
	for _, event := range []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"} {
		phases[event] = map[string]any{"status": "not_observed", "last_observed_at": nil}
	}
	dir := filepath.Join(state.Dir(), "reporting-health")
	if f, err := os.Open(dir); err == nil {
		defer f.Close()
		files, _ := f.ReadDir(64)
		for _, file := range files {
			if file.IsDir() || !strings.HasPrefix(file.Name(), "claude-code-") || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}
			st, err := file.Info()
			if err != nil || !st.Mode().IsRegular() || st.Size() > 4096 {
				continue
			}
			body, err := os.ReadFile(filepath.Join(dir, file.Name()))
			if err != nil {
				continue
			}
			var signal struct {
				App              string    `json:"app"`
				Event            string    `json:"event"`
				ObservedAt       time.Time `json:"observed_at"`
				Source           string    `json:"source"`
				SessionReference string    `json:"session_reference"`
				ProbeID          string    `json:"probe_id"`
			}
			if json.Unmarshal(body, &signal) != nil || signal.App != "claude-code" || signal.Source != "native_callback" || signal.ObservedAt.IsZero() || signal.ObservedAt.After(now.Add(5*time.Second)) {
				continue
			}
			event := signal.Event
			if event == "UserPrompt" {
				event = "UserPromptSubmit"
			}
			if event == "PostToolUseFailure" {
				event = "PostToolUse"
			}
			if _, ok := phases[event]; !ok {
				continue
			}
			current := phases[event].(map[string]any)
			if last, ok := current["last_observed_at"].(time.Time); ok && last.After(signal.ObservedAt) {
				continue
			}
			status := "observed"
			if now.Sub(signal.ObservedAt) > 15*time.Minute {
				status = "stale"
			}
			phases[event] = map[string]any{"status": status, "last_observed_at": signal.ObservedAt}
			if len(signal.SessionReference) == 64 {
				phases[event].(map[string]any)["session_reference"] = signal.SessionReference
			}
			if len(signal.ProbeID) == 32 {
				phases[event].(map[string]any)["probe_id"] = signal.ProbeID
			}
		}
	}
	startup := map[string]any{"status": "not_registered", "registered": false}
	if st, err := os.Lstat(filepath.Join(state.Dir(), "startup.json")); err == nil && st.Mode().IsRegular() && st.Size() <= 8192 {
		if body, err := os.ReadFile(filepath.Join(state.Dir(), "startup.json")); err == nil {
			var record map[string]any
			if json.Unmarshal(body, &record) == nil {
				startup = map[string]any{"status": record["status"], "registered": record["registered"], "scope": record["scope"]}
			}
		}
	}
	supervisor := map[string]any{"status": "not_running"}
	if st, err := readSupervisorState(); err == nil {
		supervisor = map[string]any{"status": st.Status, "pid": st.PID, "last_checked_at": st.CheckedAt, "restart_attempts": st.Restarts, "error": st.Error, "version": st.Version, "git_commit": st.Commit}
		if now.Sub(st.CheckedAt) > 10*time.Second {
			supervisor["status"] = "stale"
		}
	}
	if _, err := os.Stat(daemonPausePath()); err == nil {
		supervisor["intentional_pause"] = true
	}
	identity := map[string]any{"status": "not_enrolled"}
	if st, err := os.Stat(state.CredentialsPath()); err == nil && st.Size() <= 64<<10 {
		if body, err := os.ReadFile(state.CredentialsPath()); err == nil {
			var credentials StoredCredentials
			if json.Unmarshal(body, &credentials) == nil && credentials.SessionToken != "" && credentials.InstanceID != "" {
				identity = map[string]any{"status": "local_record_present", "instance_id": credentials.InstanceID, "authentication": "requires control-plane acknowledgment"}
			}
		}
	}
	provenance := map[string]any{"status": "not_inspected", "inspection_scope": "installation snapshot; use doctor for current file integrity"}
	if st, err := os.Lstat(filepath.Join(state.Dir(), "release-provenance.json")); err == nil && st.Mode().IsRegular() && st.Size() <= 8192 {
		if body, err := os.ReadFile(filepath.Join(state.Dir(), "release-provenance.json")); err == nil {
			var record map[string]any
			if json.Unmarshal(body, &record) == nil {
				for _, key := range []string{"status", "release_id", "source_qualified", "publisher_signature"} {
					if value, ok := record[key]; ok {
						provenance[key] = value
					}
				}
			}
		}
	}
	return map[string]any{"status": "partial", "identity": identity, "release_provenance": provenance, "claude_callbacks": phases, "hook_approval": "unknown: supplied by native client; file presence is not approval", "startup": startup, "supervisor": supervisor, "readiness": "requires enrolled identity, authenticated upload and an operator-validated native prompt/tool probe", "scope": "local reported callback metadata; not attested completeness or enforcement"}
}

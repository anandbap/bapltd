package fim

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrHookTampered      = errors.New("governance hook binary or configuration tampered or deleted on disk")
	ErrSettingsTampered  = errors.New("managed settings modified to disable BAP protections")
	ErrPolicyMissing     = errors.New("security policy bundle deleted or missing from disk")
)

// IntegrityReport records the outcome of FIM validation
type IntegrityReport struct {
	Valid              bool     `json:"valid"`
	IsQuarantined      bool     `json:"is_quarantined"`
	QuarantineReason   string   `json:"quarantine_reason,omitempty"`
	TamperDetails      []string `json:"tamper_details,omitempty"`
}

// VerifyIntegrity checks workspace hooks, managed configurations, and local quarantine status
func VerifyIntegrity(workspaceRoot string) (*IntegrityReport, error) {
	if workspaceRoot == "" {
		workspaceRoot, _ = os.Getwd()
	}
	workspaceRoot = filepath.Clean(workspaceRoot)

	report := &IntegrityReport{
		Valid:         true,
		TamperDetails: make([]string, 0),
	}

	// 1. Check local quarantine markers
	quarantinePaths := []string{
		filepath.Join(workspaceRoot, ".bap", "quarantined"),
		filepath.Join(workspaceRoot, ".bapstate", "quarantined"),
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		quarantinePaths = append(quarantinePaths, filepath.Join(home, ".bapstate", "quarantined"))
	}

	for _, qp := range quarantinePaths {
		if data, err := os.ReadFile(qp); err == nil {
			report.IsQuarantined = true
			report.QuarantineReason = strings.TrimSpace(string(data))
			if report.QuarantineReason == "" {
				report.QuarantineReason = "Device quarantined by enterprise administrator"
			}
			break
		}
	}

	// 2. Check .claude/managed-settings.json integrity if present or if .claude exists
	claudeDir := filepath.Join(workspaceRoot, ".claude")
	if fi, err := os.Stat(claudeDir); err == nil && fi.IsDir() {
		settingsPath := filepath.Join(claudeDir, "managed-settings.json")
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			// If .bap-recovery.json exists indicating active BAP session, managed-settings.json must exist
			recoveryPath := filepath.Join(claudeDir, ".bap-recovery.json")
			if _, rErr := os.Stat(recoveryPath); rErr == nil {
				report.Valid = false
				detail := fmt.Sprintf("Missing %s during active governed session", settingsPath)
				report.TamperDetails = append(report.TamperDetails, detail)
				return report, fmt.Errorf("%w: %s", ErrSettingsTampered, detail)
			}
		} else {
			var settings map[string]any
			if err := json.Unmarshal(data, &settings); err == nil {
				// dangerouslySkipPermissions MUST NOT be true
				if skip, ok := settings["dangerouslySkipPermissions"].(bool); ok && skip {
					report.Valid = false
					detail := "dangerouslySkipPermissions set to true in managed-settings.json"
					report.TamperDetails = append(report.TamperDetails, detail)
					return report, fmt.Errorf("%w: %s", ErrSettingsTampered, detail)
				}
				// Verify pre_tool_use hook is not emptied or redirected to a non-BAP executor
				if hooks, ok := settings["lifecycle_hooks"].(map[string]any); ok {
					if preTool, ok := hooks["pre_tool_use"].(string); ok {
						preLower := strings.ToLower(preTool)
						if preLower == "" || (!strings.Contains(preLower, "bapedge") && !strings.Contains(preLower, "interceptor")) {
							report.Valid = false
							detail := fmt.Sprintf("pre_tool_use hook modified to unauthorized target %q", preTool)
							report.TamperDetails = append(report.TamperDetails, detail)
							return report, fmt.Errorf("%w: %s", ErrHookTampered, detail)
						}
					}
				}
			}
		}
	}

	// 3. Check policy.cedar existence
	policyCandidates := []string{
		filepath.Join(workspaceRoot, "policy.cedar"),
		filepath.Join(workspaceRoot, ".bap", "policy.cedar"),
	}
	foundPolicy := false
	for _, pc := range policyCandidates {
		if fi, err := os.Stat(pc); err == nil && fi.Size() > 0 {
			foundPolicy = true
			break
		}
	}
	// Also check global policy cache
	if !foundPolicy && home != "" {
		globalPolicy := filepath.Join(home, ".bapstate", "policy", "policy.cedar")
		if fi, err := os.Stat(globalPolicy); err == nil && fi.Size() > 0 {
			foundPolicy = true
		}
	}

	if !foundPolicy {
		report.Valid = false
		detail := "policy.cedar missing or empty in workspace"
		report.TamperDetails = append(report.TamperDetails, detail)
		return report, fmt.Errorf("%w: %s", ErrPolicyMissing, detail)
	}

	return report, nil
}

// SetQuarantineStatus creates or removes local quarantine marker
func SetQuarantineStatus(workspaceRoot string, quarantined bool, reason string) error {
	if workspaceRoot == "" {
		workspaceRoot, _ = os.Getwd()
	}
	bapDir := filepath.Join(workspaceRoot, ".bap")
	_ = os.MkdirAll(bapDir, 0700)
	target := filepath.Join(bapDir, "quarantined")

	if quarantined {
		if reason == "" {
			reason = "Endpoint quarantined: missing heartbeats or hook tampering detected"
		}
		return os.WriteFile(target, []byte(reason), 0600)
	}
	_ = os.Remove(target)
	return nil
}

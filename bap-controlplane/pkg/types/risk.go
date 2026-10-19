package types

import (
	"strings"
)

// RiskTier represents the risk classification level of an agent (BAP-731).
type RiskTier string

const (
	RiskTierLow      RiskTier = "TIER_1_LOW"
	RiskTierMedium   RiskTier = "TIER_2_MEDIUM"
	RiskTierHigh     RiskTier = "TIER_3_HIGH"
	RiskTierCritical RiskTier = "TIER_4_CRITICAL"
)

// RiskParams defines the multi-variable inputs for agent risk classification.
type RiskParams struct {
	Environment     string   // e.g. "development", "staging", "production"
	DataSensitivity string   // e.g. "public", "internal", "confidential", "restricted"
	PermittedActions []string // e.g. ["read"], ["read", "write"], ["admin", "delete"]
	NetworkReach    string   // e.g. "isolated", "internal", "egress_restricted", "internet", "production_vpc"
	AutonomyLevel   string   // e.g. "supervised", "semi_autonomous", "autonomous"
	ToolCapabilities []string // e.g. ["search", "read_file"], ["bash", "execute"], ["deploy", "cloud_admin"]
}

// CalculateRiskTier evaluates multi-variable parameters to determine the appropriate RiskTier.
func CalculateRiskTier(params RiskParams) RiskTier {
	env := strings.ToLower(strings.TrimSpace(params.Environment))
	data := strings.ToLower(strings.TrimSpace(params.DataSensitivity))
	net := strings.ToLower(strings.TrimSpace(params.NetworkReach))
	autonomy := strings.ToLower(strings.TrimSpace(params.AutonomyLevel))

	// Check for Critical conditions:
	// 1. Production environment with direct mutations or cloud/admin tools
	// 2. Restricted data access with autonomous execution
	if env == "production" || env == "prod" {
		for _, tool := range params.ToolCapabilities {
			t := strings.ToLower(tool)
			if strings.Contains(t, "deploy") || strings.Contains(t, "admin") || strings.Contains(t, "delete") || strings.Contains(t, "db_write") {
				return RiskTierCritical
			}
		}
		if data == "restricted" || data == "pci" || data == "phi" {
			return RiskTierCritical
		}
		if autonomy == "autonomous" {
			return RiskTierCritical
		}
		return RiskTierHigh
	}

	// Check for High risk conditions:
	// Staging or internal with write/execute permissions or confidential data
	if env == "staging" || net == "production_vpc" || data == "restricted" || data == "confidential" {
		return RiskTierHigh
	}

	for _, act := range params.PermittedActions {
		a := strings.ToLower(act)
		if a == "write" || a == "execute" || a == "mutate" || a == "shell" {
			// Dev environment with write access -> Medium
			return RiskTierMedium
		}
	}

	for _, tool := range params.ToolCapabilities {
		t := strings.ToLower(tool)
		if strings.Contains(t, "bash") || strings.Contains(t, "exec") || strings.Contains(t, "write") {
			return RiskTierMedium
		}
	}

	// Default for read-only, public/internal, supervised workloads
	return RiskTierLow
}

// RequiresHITL determines if the risk tier necessitates mandatory Human-in-the-Loop approval.
func (r RiskTier) RequiresHITL() bool {
	return r == RiskTierHigh || r == RiskTierCritical
}

// RequiresSandboxIsolation determines if OS-level sandbox isolation is mandatory.
func (r RiskTier) RequiresSandboxIsolation() bool {
	return r != RiskTierLow
}

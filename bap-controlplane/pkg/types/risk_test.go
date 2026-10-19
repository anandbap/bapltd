package types

import (
	"testing"
)

func TestCalculateRiskTier(t *testing.T) {
	tests := []struct {
		name     string
		params   RiskParams
		expected RiskTier
		hitl     bool
		sandbox  bool
	}{
		{
			name: "Low Risk Documentation Agent",
			params: RiskParams{
				Environment:      "development",
				DataSensitivity:  "public",
				PermittedActions: []string{"read"},
				NetworkReach:     "isolated",
				AutonomyLevel:    "supervised",
				ToolCapabilities: []string{"search", "read_file"},
			},
			expected: RiskTierLow,
			hitl:     false,
			sandbox:  false,
		},
		{
			name: "Medium Risk Coding Agent (Local Refactoring)",
			params: RiskParams{
				Environment:      "development",
				DataSensitivity:  "internal",
				PermittedActions: []string{"read", "write"},
				NetworkReach:     "egress_restricted",
				AutonomyLevel:    "supervised",
				ToolCapabilities: []string{"read_file", "write_file", "bash"},
			},
			expected: RiskTierMedium,
			hitl:     false,
			sandbox:  true,
		},
		{
			name: "High Risk Staging Deployment Agent",
			params: RiskParams{
				Environment:      "staging",
				DataSensitivity:  "confidential",
				PermittedActions: []string{"read", "write", "execute"},
				NetworkReach:     "internal",
				AutonomyLevel:    "semi_autonomous",
				ToolCapabilities: []string{"deploy", "run_tests"},
			},
			expected: RiskTierHigh,
			hitl:     true,
			sandbox:  true,
		},
		{
			name: "Critical Risk Production Cloud Admin",
			params: RiskParams{
				Environment:      "production",
				DataSensitivity:  "restricted",
				PermittedActions: []string{"admin", "delete"},
				NetworkReach:     "production_vpc",
				AutonomyLevel:    "autonomous",
				ToolCapabilities: []string{"cloud_admin", "db_write"},
			},
			expected: RiskTierCritical,
			hitl:     true,
			sandbox:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := CalculateRiskTier(tc.params)
			if actual != tc.expected {
				t.Fatalf("expected tier %s, got %s", tc.expected, actual)
			}
			if actual.RequiresHITL() != tc.hitl {
				t.Fatalf("expected RequiresHITL %v, got %v", tc.hitl, actual.RequiresHITL())
			}
			if actual.RequiresSandboxIsolation() != tc.sandbox {
				t.Fatalf("expected RequiresSandboxIsolation %v, got %v", tc.sandbox, actual.RequiresSandboxIsolation())
			}
		})
	}
}

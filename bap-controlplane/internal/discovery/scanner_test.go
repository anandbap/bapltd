package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestScannerDetectsUnmanagedEnvVars(t *testing.T) {
	scanner := NewScanner()

	customEnv := map[string]string{
		"AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"OPENAI_API_KEY":        "sk-proj-1234567890abcdef1234567890abcdef",
		"DATABASE_URL":          "postgres://user:secretpass@db.internal:5432/prod",
		"GITHUB_TOKEN":          "ghp_11223344556677889900aabbccddeeff11",
		"NORMAL_VAR":            "just_a_value",
	}

	report := scanner.Scan(ScanRequest{
		EnvMap: customEnv,
	})

	if report.TotalFindings != 4 {
		t.Fatalf("expected 4 findings, got %d", report.TotalFindings)
	}

	if report.CriticalCount < 3 {
		t.Errorf("expected at least 3 critical findings for AWS, OpenAI, and DB credentials, got %d", report.CriticalCount)
	}

	if report.UnmanagedEnvVarCount != 4 {
		t.Errorf("expected 4 unmanaged env var count, got %d", report.UnmanagedEnvVarCount)
	}

	// Verify masking
	for _, f := range report.Findings {
		if valMask, ok := f.Metadata["value_mask"].(string); ok {
			if len(valMask) > 12 && valMask != "***" {
				t.Errorf("expected masked secret, got %s", valMask)
			}
		}
	}
}

func TestScannerDetectsShadowMCPServers(t *testing.T) {
	tmpDir := t.TempDir()

	// Write mock unmanaged mcp.json
	mcpConfig := `{
		"mcpServers": {
			"filesystem-shadow": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user"]
			},
			"bap-managed-tool": {
				"command": "bapedge",
				"args": ["mcp", "serve"]
			},
			"rogue-postgres": {
				"command": "python",
				"args": ["-m", "mcp_server_postgres", "--connection", "postgres://localhost/db"]
			}
		}
	}`

	cfgPath := filepath.Join(tmpDir, "mcp.json")
	if err := os.WriteFile(cfgPath, []byte(mcpConfig), 0600); err != nil {
		t.Fatalf("failed to write mcp.json: %v", err)
	}

	scanner := NewScanner()
	report := scanner.Scan(ScanRequest{
		WorkspaceRoot: tmpDir,
		EnvMap:        map[string]string{}, // empty env
	})

	// bap-managed-tool should NOT be flagged; filesystem-shadow and rogue-postgres MUST be flagged
	if report.UnmanagedMCPCount != 2 {
		t.Fatalf("expected 2 unmanaged MCP servers, got %d", report.UnmanagedMCPCount)
	}

	foundFS := false
	foundPG := false
	for _, f := range report.Findings {
		if f.Type == FindingUnmanagedMCP {
			if f.Name == "Shadow MCP Server: filesystem-shadow" {
				foundFS = true
				if f.RiskLevel != RiskCritical {
					t.Errorf("expected CRITICAL risk for filesystem MCP server, got %s", f.RiskLevel)
				}
			}
			if f.Name == "Shadow MCP Server: rogue-postgres" {
				foundPG = true
				if f.RiskLevel != RiskCritical {
					t.Errorf("expected CRITICAL risk for postgres MCP server, got %s", f.RiskLevel)
				}
			}
		}
	}

	if !foundFS || !foundPG {
		t.Errorf("missing expected shadow MCP findings: fs=%v, pg=%v", foundFS, foundPG)
	}
}

func TestScannerEpochTriggerAndAdvancement(t *testing.T) {
	scanner := NewScanner()
	initialEpoch := scanner.CurrentEpoch()

	epoch1 := scanner.TriggerFleetScan()
	if epoch1 <= initialEpoch {
		t.Errorf("expected epoch1 (%d) > initialEpoch (%d)", epoch1, initialEpoch)
	}

	epoch2 := scanner.TriggerFleetScan()
	if epoch2 <= epoch1 {
		t.Errorf("expected epoch2 (%d) > epoch1 (%d)", epoch2, epoch1)
	}

	report := scanner.Scan(ScanRequest{
		EnvMap: map[string]string{"AWS_SECRET_ACCESS_KEY": "AKIAEXAMPLE12345"},
	})
	if report.FleetEpoch <= epoch2 {
		t.Errorf("expected report.FleetEpoch (%d) to advance beyond epoch2 (%d)", report.FleetEpoch, epoch2)
	}
}

func TestScannerDeduplicationAndMemoryBounds(t *testing.T) {
	scanner := NewScanner()
	scanner.maxReports = 5

	// Ingest same client finding across multiple scan cycles
	for i := 0; i < 10; i++ {
		scanner.Scan(ScanRequest{
			AgentID:  "agent-laptop-001",
			Hostname: "dev-laptop-alpha",
			ClientFindings: []Finding{
				{
					Type:      FindingUnmanagedEnvVar,
					Target:    "OPENAI_API_KEY",
					Name:      "Local LLM Key",
					RiskLevel: RiskCritical,
				},
				{
					Type:      FindingUnmanagedMCP,
					Target:    "C:\\Users\\dev\\.cursor\\mcp.json",
					Name:      "Rogue DB MCP",
					RiskLevel: RiskHigh,
				},
			},
		})
	}

	findings := scanner.GetFindings()
	// Should be exactly 2 deduplicated findings, NOT 20!
	if len(findings) != 2 {
		t.Fatalf("expected 2 deduplicated findings, got %d", len(findings))
	}

	// Historical reports should be capped at maxReports (5), NOT 10!
	reports := scanner.GetReports()
	if len(reports) != 5 {
		t.Fatalf("expected exactly 5 capped reports, got %d", len(reports))
	}
}

func TestScannerHighVolumeConcurrency(t *testing.T) {
	scanner := NewScanner()
	const numWorkers = 50
	const iterations = 50

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	for w := 0; w < numWorkers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if i%10 == 0 {
					scanner.TriggerFleetScan()
				}
				if i%3 == 0 {
					_ = scanner.GetFindings()
				}
				if i%5 == 0 {
					_ = scanner.GetReports()
				}
				scanner.Scan(ScanRequest{
					AgentID:  fmt.Sprintf("agent-%d", workerID),
					Hostname: fmt.Sprintf("host-%d", workerID),
					ClientFindings: []Finding{
						{
							Type:      FindingUnmanagedEnvVar,
							Target:    fmt.Sprintf("ENV_SECRET_%d", workerID),
							RiskLevel: RiskCritical,
						},
					},
				})
			}
		}()
	}

	wg.Wait()

	findings := scanner.GetFindings()
	if len(findings) < numWorkers {
		t.Errorf("expected at least %d findings from %d workers, got %d", numWorkers, numWorkers, len(findings))
	}
}

func TestScannerResilienceToCorruptedInputs(t *testing.T) {
	scanner := NewScanner()

	// 1. Completely empty request
	r1 := scanner.Scan(ScanRequest{})
	if r1.TotalFindings != 0 && len(r1.Findings) != 0 {
		t.Errorf("expected 0 findings for empty request, got %d", r1.TotalFindings)
	}

	// 2. Corrupted finding with empty targets and extreme string lengths
	giantString := strings.Repeat("A", 10000)
	r2 := scanner.Scan(ScanRequest{
		AgentID:  "agent-corrupted",
		Hostname: "host-corrupted",
		ClientFindings: []Finding{
			{
				Type:     FindingType("CORRUPTED_UNKNOWN_TYPE"),
				Target:   giantString,
				Metadata: map[string]any{"nested": nil, "payload": giantString},
			},
		},
	})
	if r2.TotalFindings != 1 {
		t.Errorf("expected scanner to safely ingest corrupted finding without panic, got %d", r2.TotalFindings)
	}

	findings := scanner.GetFindings()
	if len(findings) == 0 {
		t.Error("expected finding to be retrievable")
	}
}


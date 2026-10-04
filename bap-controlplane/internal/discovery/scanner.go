package discovery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// RiskLevel defines the severity of a discovered shadow asset.
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRITICAL"
	RiskHigh     RiskLevel = "HIGH"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskLow      RiskLevel = "LOW"
)

// FindingType categorizes the shadow IT discovery item.
type FindingType string

const (
	FindingUnmanagedMCP       FindingType = "UNMANAGED_LOCAL_MCP_SERVER"
	FindingUnmanagedEnvVar    FindingType = "UNMANAGED_ENV_VARIABLE"
	FindingUnprotectedEnvFile FindingType = "UNPROTECTED_ENV_FILE"
	FindingRawProcess         FindingType = "UNSUPERVISED_AGENT_PROCESS"
)

// Finding represents an individual shadow IT or unmanaged asset.
type Finding struct {
	ID             string         `json:"id"`
	Type           FindingType    `json:"type"`
	Name           string         `json:"name"`
	Target         string         `json:"target"`
	RiskLevel      RiskLevel      `json:"risk_level"`
	RiskScore      float64        `json:"risk_score"`
	Details        string         `json:"details"`
	Remediation    string         `json:"remediation"`
	DiscoveredAt   time.Time      `json:"discovered_at"`
	IsManagedByBAP bool           `json:"is_managed_by_bap"`
	AgentID        string         `json:"agent_id,omitempty"`
	Hostname       string         `json:"hostname,omitempty"`
	Metadata       map[string]any `json:"metadata,omitempty"`
}

// ScanRequest allows callers to supply scan parameters, custom env maps, or remote client findings.
type ScanRequest struct {
	WorkspaceRoot  string            `json:"workspace_root,omitempty"`
	ConfigPaths    []string          `json:"config_paths,omitempty"`
	EnvMap         map[string]string `json:"env_map,omitempty"` // optional override for testing/remote agents
	AgentID        string            `json:"agent_id,omitempty"`
	Hostname       string            `json:"hostname,omitempty"`
	ClientFindings []Finding         `json:"client_findings,omitempty"`
}

// ScanReport summarizes a complete shadow IT discovery evaluation.
type ScanReport struct {
	ScanID               string    `json:"scan_id"`
	Timestamp            time.Time `json:"timestamp"`
	TotalFindings        int       `json:"total_findings"`
	CriticalCount        int       `json:"critical_count"`
	HighCount            int       `json:"high_count"`
	MediumCount          int       `json:"medium_count"`
	UnmanagedMCPCount    int       `json:"unmanaged_mcp_count"`
	UnmanagedEnvVarCount int       `json:"unmanaged_env_var_count"`
	UnprotectedFileCount int       `json:"unprotected_file_count"`
	Findings             []Finding `json:"findings"`
	Summary              string    `json:"summary"`
	FleetEpoch           int64     `json:"fleet_epoch,omitempty"`
}

// Sensitive env variable patterns that indicate standing credentials bypassing BAP.
var sensitiveEnvPatterns = []struct {
	KeyRegex    *regexp.Regexp
	Name        string
	Risk        RiskLevel
	Score       float64
	Remediation string
}{
	{
		KeyRegex:    regexp.MustCompile(`(?i)^(AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN)$`),
		Name:        "AWS Standing Secret",
		Risk:        RiskCritical,
		Score:       0.95,
		Remediation: "Migrate to BAP Ephemeral Bounded Grants; remove standing AWS credentials from environment.",
	},
	{
		KeyRegex:    regexp.MustCompile(`(?i)^(OPENAI_API_KEY|ANTHROPIC_API_KEY|CO_API_KEY|MISTRAL_API_KEY)$`),
		Name:        "LLM Provider API Key",
		Risk:        RiskCritical,
		Score:       0.90,
		Remediation: "Proxy LLM tool calls through BAP Gateway PEP with zero standing developer keys.",
	},
	{
		KeyRegex:    regexp.MustCompile(`(?i)^(DATABASE_URL|POSTGRES_PASSWORD|MONGO_URI|REDIS_URL|MYSQL_PWD)$`),
		Name:        "Database Connection String",
		Risk:        RiskCritical,
		Score:       0.95,
		Remediation: "Remove persistent DB connection strings; enforce just-in-time microservice PEP access.",
	},
	{
		KeyRegex:    regexp.MustCompile(`(?i)^(GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|GITHUB_PAT)$`),
		Name:        "Source Code Management Token",
		Risk:        RiskHigh,
		Score:       0.85,
		Remediation: "Enforce GitHub Copilot / git command supervision via bapedge broker.",
	},
	{
		KeyRegex:    regexp.MustCompile(`(?i)^(STRIPE_SECRET_KEY|STRIPE_API_KEY|SENDGRID_API_KEY|SLACK_BOT_TOKEN)$`),
		Name:        "Third-Party SaaS Secret",
		Risk:        RiskHigh,
		Score:       0.80,
		Remediation: "Vault SaaS credentials in enterprise secrets manager; gate third-party tools behind Cedar policies.",
	},
}

// High-risk MCP server command patterns (e.g. bash, filesystem, postgres)
var highRiskMCPTools = []string{
	"filesystem", "postgres", "mysql", "sqlite", "terminal", "shell", "bash", "execute", "github", "aws", "gcp",
}

// Scanner orchestrates shadow IT scans.
type Scanner struct {
	mu           sync.RWMutex
	reports      []ScanReport
	findings     []Finding
	findingIndex map[string]int
	currentEpoch int64
	maxFindings  int
	maxReports   int
}

// NewScanner creates an initialized Scanner.
func NewScanner() *Scanner {
	return &Scanner{
		reports:      make([]ScanReport, 0),
		findings:     make([]Finding, 0),
		findingIndex: make(map[string]int),
		currentEpoch: 1,
		maxFindings:  10000,
		maxReports:   100,
	}
}

// TriggerFleetScan advances the fleet scan epoch to broadcast a scan directive to all connected agents.
func (s *Scanner) TriggerFleetScan() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UnixNano()
	if now <= s.currentEpoch {
		s.currentEpoch++
	} else {
		s.currentEpoch = now
	}
	return s.currentEpoch
}

// CurrentEpoch returns the active fleet scan epoch.
func (s *Scanner) CurrentEpoch() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentEpoch
}

// MaskSecret returns a safe preview of a secret string (e.g. "sk-an...***").
func MaskSecret(val string) string {
	if len(val) <= 6 {
		return "***"
	}
	return val[:4] + "...***"
}

// Scan executes full shadow IT discovery across unmanaged MCP configs and environment variables.
func (s *Scanner) Scan(req ScanRequest) ScanReport {
	s.mu.Lock()
	defer s.mu.Unlock()

	findings := make([]Finding, 0)
	scanID := fmt.Sprintf("scan-%d", time.Now().UnixNano())

	// If remote client findings were submitted by a laptop agent, ingest them
	if len(req.ClientFindings) > 0 {
		for _, cf := range req.ClientFindings {
			if cf.AgentID == "" {
				cf.AgentID = req.AgentID
			}
			if cf.Hostname == "" {
				cf.Hostname = req.Hostname
			}
			findings = append(findings, cf)
		}
	} else {
		// Centrally triggered scan advances the fleet epoch to broadcast to all connected laptops
		now := time.Now().UnixNano()
		if now <= s.currentEpoch {
			s.currentEpoch++
		} else {
			s.currentEpoch = now
		}

		// 1. Scan Environment Variables
		envFindings := s.scanEnvironmentVariables(req.EnvMap)
		findings = append(findings, envFindings...)

		// 2. Scan Workspace .env Files
		if req.WorkspaceRoot != "" {
			envFileFindings := s.scanEnvFiles(req.WorkspaceRoot)
			findings = append(findings, envFileFindings...)
		}

		// 3. Scan Known MCP Configuration Locations & Provided Configs
		mcpFindings := s.scanMCPConfigurations(req.WorkspaceRoot, req.ConfigPaths)
		findings = append(findings, mcpFindings...)
	}

	// Attribute findings to reporting agent/host if provided
	for i := range findings {
		if req.AgentID != "" && findings[i].AgentID == "" {
			findings[i].AgentID = req.AgentID
		}
		if req.Hostname != "" && findings[i].Hostname == "" {
			findings[i].Hostname = req.Hostname
		}
	}

	// Compute counts
	var crit, high, med int
	var mcpCount, envCount, fileCount int
	for _, f := range findings {
		switch f.RiskLevel {
		case RiskCritical:
			crit++
		case RiskHigh:
			high++
		case RiskMedium:
			med++
		}
		switch f.Type {
		case FindingUnmanagedMCP:
			mcpCount++
		case FindingUnmanagedEnvVar:
			envCount++
		case FindingUnprotectedEnvFile:
			fileCount++
		}
	}

	summary := fmt.Sprintf("Shadow IT Scan completed. Identified %d findings (%d CRITICAL, %d HIGH, %d MEDIUM). %d unmanaged MCP servers, %d unmanaged environment credentials.",
		len(findings), crit, high, med, mcpCount, envCount)

	report := ScanReport{
		ScanID:               scanID,
		Timestamp:            time.Now().UTC(),
		FleetEpoch:           s.currentEpoch,
		TotalFindings:        len(findings),
		CriticalCount:        crit,
		HighCount:            high,
		MediumCount:          med,
		UnmanagedMCPCount:    mcpCount,
		UnmanagedEnvVarCount: envCount,
		UnprotectedFileCount: fileCount,
		Findings:             findings,
		Summary:              summary,
	}

	// Bounded historical reports
	s.reports = append(s.reports, report)
	if s.maxReports > 0 && len(s.reports) > s.maxReports {
		s.reports = s.reports[len(s.reports)-s.maxReports:]
	}

	// Ingest findings with deduplication and bounded memory safety
	for _, f := range findings {
		key := fmt.Sprintf("%s|%s|%s|%s", f.AgentID, f.Hostname, f.Type, f.Target)
		if idx, exists := s.findingIndex[key]; exists && idx < len(s.findings) {
			s.findings[idx] = f
		} else {
			if s.maxFindings > 0 && len(s.findings) >= s.maxFindings {
				replaceIdx := len(s.findings) % s.maxFindings
				s.findings[replaceIdx] = f
				s.findingIndex[key] = replaceIdx
			} else {
				s.findingIndex[key] = len(s.findings)
				s.findings = append(s.findings, f)
			}
		}
	}
	return report
}

// scanEnvironmentVariables checks environment variables for unmanaged secrets.
func (s *Scanner) scanEnvironmentVariables(customEnv map[string]string) []Finding {
	var findings []Finding

	envMap := make(map[string]string)
	if customEnv != nil && len(customEnv) > 0 {
		envMap = customEnv
	} else {
		for _, e := range os.Environ() {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				envMap[parts[0]] = parts[1]
			}
		}
	}

	for k, v := range envMap {
		if strings.TrimSpace(v) == "" {
			continue
		}
		for _, p := range sensitiveEnvPatterns {
			if p.KeyRegex.MatchString(k) {
				findings = append(findings, Finding{
					ID:             fmt.Sprintf("find-env-%s-%d", strings.ToLower(k), time.Now().UnixNano()),
					Type:           FindingUnmanagedEnvVar,
					Name:           fmt.Sprintf("Unmanaged Secret: %s (%s)", k, p.Name),
					Target:         k,
					RiskLevel:      p.Risk,
					RiskScore:      p.Score,
					Details:        fmt.Sprintf("Environment variable %s contains plaintext credentials (%s). This bypasses BAP's Zero Standing Privilege invariant.", k, MaskSecret(v)),
					Remediation:    p.Remediation,
					DiscoveredAt:   time.Now(),
					IsManagedByBAP: false,
					Metadata: map[string]any{
						"env_key":    k,
						"category":   p.Name,
						"value_mask": MaskSecret(v),
					},
				})
				break
			}
		}
	}
	return findings
}

// scanEnvFiles scans workspace directories for unmanaged .env files.
func (s *Scanner) scanEnvFiles(ws string) []Finding {
	var findings []Finding
	targets := []string{".env", ".env.local", ".env.production", ".env.development", ".env.test"}

	for _, t := range targets {
		p := filepath.Join(ws, t)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			findings = append(findings, Finding{
				ID:             fmt.Sprintf("find-file-%s-%d", t, time.Now().UnixNano()),
				Type:           FindingUnprotectedEnvFile,
				Name:           fmt.Sprintf("Unprotected Secrets File: %s", t),
				Target:         p,
				RiskLevel:      RiskHigh,
				RiskScore:      0.75,
				Details:        fmt.Sprintf("Local environment file %s found on disk. Plaintext secrets are vulnerable to unauthorized agent reading or exfiltration.", p),
				Remediation:    "Move secrets to corporate Vault/KMS and ensure file is listed in .gitignore.",
				DiscoveredAt:   time.Now(),
				IsManagedByBAP: false,
				Metadata: map[string]any{
					"file_path": p,
					"size":      fi.Size(),
				},
			})
		}
	}
	return findings
}

// MCPConfig format used by Claude Desktop, Cursor, and VS Code.
type MCPConfig struct {
	MCPServers map[string]struct {
		Command string            `json:"command"`
		Args    []string          `json:"args"`
		Env     map[string]string `json:"env,omitempty"`
	} `json:"mcpServers"`
}

// scanMCPConfigurations checks config paths and discovery locations for shadow MCP servers.
func (s *Scanner) scanMCPConfigurations(ws string, extraPaths []string) []Finding {
	var findings []Finding

	// Discoverable paths
	candidatePaths := make([]string, 0)
	if ws != "" {
		candidatePaths = append(candidatePaths,
			filepath.Join(ws, "mcp.json"),
			filepath.Join(ws, ".mcp.json"),
			filepath.Join(ws, ".cursor", "mcp.json"),
			filepath.Join(ws, ".vscode", "mcp.json"),
		)
	}

	// Add OS default Claude Desktop config paths if present
	if appData := os.Getenv("APPDATA"); appData != "" {
		candidatePaths = append(candidatePaths, filepath.Join(appData, "Claude", "claude_desktop_config.json"))
	}
	if home := os.Getenv("USERPROFILE"); home != "" {
		candidatePaths = append(candidatePaths, filepath.Join(home, ".cursor", "mcp.json"))
	}
	candidatePaths = append(candidatePaths, extraPaths...)

	visited := make(map[string]bool)
	for _, path := range candidatePaths {
		if path == "" || visited[path] {
			continue
		}
		visited[path] = true

		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		var cfg MCPConfig
		if err := json.Unmarshal(data, &cfg); err != nil {
			continue
		}

		for srvName, srvDef := range cfg.MCPServers {
			cmdLine := srvDef.Command + " " + strings.Join(srvDef.Args, " ")
			isManaged := strings.Contains(strings.ToLower(cmdLine), "bapedge") || strings.Contains(strings.ToLower(cmdLine), "bapmcp")

			if !isManaged {
				risk := RiskHigh
				score := 0.70
				cmdLower := strings.ToLower(cmdLine)
				for _, h := range highRiskMCPTools {
					if strings.Contains(cmdLower, h) || strings.Contains(strings.ToLower(srvName), h) {
						risk = RiskCritical
						score = 0.90
						break
					}
				}

				findings = append(findings, Finding{
					ID:             fmt.Sprintf("find-mcp-%s-%d", srvName, time.Now().UnixNano()),
					Type:           FindingUnmanagedMCP,
					Name:           fmt.Sprintf("Shadow MCP Server: %s", srvName),
					Target:         path,
					RiskLevel:      risk,
					RiskScore:      score,
					Details:        fmt.Sprintf("Local MCP server %q executes command %q outside BAP policy governance.", srvName, cmdLine),
					Remediation:    fmt.Sprintf("Wrap %q command with 'bapedge mcp' or register in BAP fleet catalog to enforce Cedar guardrails.", srvName),
					DiscoveredAt:   time.Now(),
					IsManagedByBAP: false,
					Metadata: map[string]any{
						"server_name": srvName,
						"command":     srvDef.Command,
						"args":        srvDef.Args,
						"config_path": path,
						"env_keys":    keysOf(srvDef.Env),
					},
				})
			}
		}
	}

	return findings
}

func keysOf(m map[string]string) []string {
	res := make([]string, 0, len(m))
	for k := range m {
		res = append(res, k)
	}
	return res
}

// GetFindings returns all accumulated findings across scans.
func (s *Scanner) GetFindings() []Finding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Finding, len(s.findings))
	copy(out, s.findings)
	return out
}

// GetReports returns all completed scan reports.
func (s *Scanner) GetReports() []ScanReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ScanReport, len(s.reports))
	copy(out, s.reports)
	return out
}

package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"bap-edge/internal/pinning"
)

// Severity levels for scan findings
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// VulnerabilityCategory classifies the detected threat
type VulnerabilityCategory string

const (
	CatPromptInjection     VulnerabilityCategory = "PROMPT_INJECTION"
	CatMaliciousPayload    VulnerabilityCategory = "MALICIOUS_PAYLOAD"
	CatSupplyChainBypass   VulnerabilityCategory = "SUPPLY_CHAIN_BYPASS"
	CatUnpinnedAsset       VulnerabilityCategory = "UNPINNED_ASSET"
	CatContentDrift        VulnerabilityCategory = "CONTENT_DRIFT"
	CatUnprotectedSecret   VulnerabilityCategory = "UNPROTECTED_SECRET"
	CatShadowMCP           VulnerabilityCategory = "SHADOW_MCP"
)

// ScanVulnerability represents a single detected issue
type ScanVulnerability struct {
	ID          string                `json:"id"`
	Category    VulnerabilityCategory `json:"category"`
	Severity    Severity              `json:"severity"`
	Title       string                `json:"title"`
	Description string                `json:"description"`
	TargetFile  string                `json:"target_file"`
	LineNumber  int                   `json:"line_number,omitempty"`
	Evidence    string                `json:"evidence,omitempty"`
	Remediation string                `json:"remediation"`
}

// AddonScanResult represents the consolidated scan output
type AddonScanResult struct {
	Timestamp       time.Time           `json:"timestamp"`
	WorkspaceRoot   string              `json:"workspace_root"`
	FilesScanned    int                 `json:"files_scanned"`
	Vulnerabilities []ScanVulnerability `json:"vulnerabilities"`
	Passed          bool                `json:"passed"`
	HighestSeverity Severity            `json:"highest_severity"`
}

// Rule defines a regex-based detection pattern
type Rule struct {
	Category    VulnerabilityCategory
	Severity    Severity
	Title       string
	Description string
	Remediation string
	Pattern     *regexp.Regexp
}

var scanRules = []Rule{
	// 1. Prompt Injection & Jailbreaks
	{
		Category:    CatPromptInjection,
		Severity:    SeverityCritical,
		Title:       "Prompt Injection: Instruction Override / Jailbreak Pattern",
		Description: "Skill or prompt instructs the model to ignore previous instructions or corporate system rules.",
		Remediation: "Remove adversarial prompt injection instructions from the skill file.",
		Pattern:     regexp.MustCompile(`(?i)(ignore\s+(all\s+)?previous\s+instructions|disregard\s+(all\s+)?prior\s+instructions|you\s+are\s+now\s+in\s+unrestricted\s+mode|bypass\s+(all\s+)?security\s+(guidelines|invariants|boundaries)|override\s+system\s+prompt)`),
	},
	{
		Category:    CatPromptInjection,
		Severity:    SeverityCritical,
		Title:       "Prompt Injection: Explicit BAP / Governance Bypass Attempt",
		Description: "Prompt directly commands agent to disable, kill, or bypass BAP daemon, policies, or hooks.",
		Remediation: "Remove BAP tampering directives from prompt/skill instructions.",
		Pattern:     regexp.MustCompile(`(?i)(bypass\s+bap|disable\s+bap|kill\s+bapedge|stop\s+bapedge|delete\s+\.bap|tamper\s+with\s+policy\.cedar)`),
	},
	{
		Category:    CatPromptInjection,
		Severity:    SeverityHigh,
		Title:       "Prompt Injection: Credential Exfiltration Instruction",
		Description: "Prompt explicitly instructs the agent to dump, read, or transmit credentials or private keys.",
		Remediation: "Ensure prompts do not request standing secrets, SSH keys, or environment credential dumps.",
		Pattern:     regexp.MustCompile(`(?i)(dump\s+(all\s+)?(env|environment\s+variables|credentials|secrets)|cat\s+~?/\.ssh/id_|print\s+os\.environ|read\s+aws_secret_access_key)`),
	},

	// 2. Malicious Payloads & Obfuscation
	{
		Category:    CatMaliciousPayload,
		Severity:    SeverityCritical,
		Title:       "Malicious Payload: Obfuscated Base64 Shell Execution",
		Description: "Skill attempts to decode and execute base64 payload in shell or python without inspection.",
		Remediation: "Replace obfuscated inline base64 code execution with explicit, auditable tool commands.",
		Pattern:     regexp.MustCompile(`(?i)(base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh)|b64decode\(.+\)\s*;\s*exec\(|powershell(\.exe)?\s+(-e|-enc|-encodedcommand)\s+[A-Za-z0-9+/=]{16,})`),
	},
	{
		Category:    CatMaliciousPayload,
		Severity:    SeverityCritical,
		Title:       "Malicious Payload: Interactive Reverse Shell / Socket Payload",
		Description: "Skill contains signatures of raw reverse shells or netcat backdoor commands.",
		Remediation: "Remove reverse shell command syntax immediately.",
		Pattern:     regexp.MustCompile(`(?i)(nc(\.exe)?\s+(-e|--exec)\s+|bash\s+-i\s+>&?\s*/dev/tcp/|python(\.exe)?\s+-c\s+['"].*import\s+socket,subprocess)`),
	},
	{
		Category:    CatMaliciousPayload,
		Severity:    SeverityHigh,
		Title:       "Malicious Payload: Unverified Remote Script Download & Execution",
		Description: "Skill attempts unverified piped curl/wget execution directly into shell interpreter.",
		Remediation: "Avoid 'curl | bash' or 'wget | sh'; pin scripts and verify cryptographic checksums before running.",
		Pattern:     regexp.MustCompile(`(?i)(curl\s+[^|\n]+\|\s*(sh|bash|zsh)|wget\s+[^|\n]+-O\s*-\s*\|\s*(sh|bash|zsh))`),
	},

	// 3. Supply Chain Bypass
	{
		Category:    CatSupplyChainBypass,
		Severity:    SeverityHigh,
		Title:       "Supply Chain: Public Registry Direct Bypass (pip / npm / maven)",
		Description: "Skill or config explicitly bypasses corporate mirror by forcing public registries.",
		Remediation: "Remove public registry flags (--index-url, --registry); use enterprise corporate mirror configuration.",
		Pattern:     regexp.MustCompile(`(?i)(--index-url\s+https?://(www\.)?pypi\.org/simple|--extra-index-url\s+https?://(www\.)?pypi\.org|--registry\s+https?://registry\.npmjs\.org|-DremoteRepositories=https?://repo\.maven\.apache\.org)`),
	},
}

// Scanner performs recursive add-on, skill, and configuration scanning
type Scanner struct {
	WorkspaceRoot string
	ManifestPath  string
	Rules         []Rule
}

// NewScanner initializes a Scanner with default enterprise rules
func NewScanner(workspaceRoot string, manifestPathOpt ...string) *Scanner {
	if workspaceRoot == "" {
		workspaceRoot, _ = os.Getwd()
	}
	workspaceRoot = filepath.Clean(workspaceRoot)
	manifestPath := filepath.Join(workspaceRoot, ".bap", "pins.json")
	if len(manifestPathOpt) > 0 && manifestPathOpt[0] != "" {
		manifestPath = manifestPathOpt[0]
	} else if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifestPath = pinning.DefaultManifestPath()
	}

	return &Scanner{
		WorkspaceRoot: workspaceRoot,
		ManifestPath:  manifestPath,
		Rules:         scanRules,
	}
}

// Scan performs the complete add-on and extension security audit
func (s *Scanner) Scan() (*AddonScanResult, error) {
	result := &AddonScanResult{
		Timestamp:       time.Now().UTC(),
		WorkspaceRoot:   s.WorkspaceRoot,
		Vulnerabilities: make([]ScanVulnerability, 0),
		Passed:          true,
		HighestSeverity: SeverityInfo,
	}

	// 1. Discover all skill files, prompt templates, and configs
	targetFiles := s.discoverAddonFiles()
	result.FilesScanned = len(targetFiles)

	// 2. Load pinning manifest if the manifest file actually exists
	var manifest *pinning.PinManifest
	if s.ManifestPath != "" {
		if _, err := os.Stat(s.ManifestPath); err == nil {
			manifest, _ = pinning.LoadManifest(s.ManifestPath)
		}
	}
	pinnedMap := make(map[string]pinning.PinnedAsset)
	hasAssetsForWorkspace := false
	if manifest != nil {
		for _, a := range manifest.Assets {
			rel, err := filepath.Rel(s.WorkspaceRoot, a.Path)
			if err == nil && !strings.HasPrefix(rel, "..") {
				hasAssetsForWorkspace = true
				pinnedMap[filepath.Clean(rel)] = a
			}
			pinnedMap[filepath.Clean(a.Path)] = a
		}
	}

	// 3. Audit each file
	for _, relPath := range targetFiles {
		absPath := filepath.Join(s.WorkspaceRoot, relPath)
		data, err := os.ReadFile(absPath)
		if err != nil {
			continue
		}

		content := string(data)
		lines := strings.Split(content, "\n")

		// Heuristic pattern scanning line by line
		for lineIdx, line := range lines {
			for _, rule := range s.Rules {
				if rule.Pattern.MatchString(line) {
					vulnID := fmt.Sprintf("vuln-%s-%d-%d", filepath.Base(relPath), lineIdx+1, time.Now().UnixNano()%10000)
					vuln := ScanVulnerability{
						ID:          vulnID,
						Category:    rule.Category,
						Severity:    rule.Severity,
						Title:       rule.Title,
						Description: rule.Description,
						TargetFile:  relPath,
						LineNumber:  lineIdx + 1,
						Evidence:    strings.TrimSpace(line),
						Remediation: rule.Remediation,
					}
					result.Vulnerabilities = append(result.Vulnerabilities, vuln)
				}
			}
		}

		// 4. Pinning / AIR attestation verification
		isSkillOrPrompt := strings.HasSuffix(strings.ToLower(relPath), "skill.md") ||
			strings.HasSuffix(strings.ToLower(relPath), "gemini.md") ||
			strings.HasSuffix(strings.ToLower(relPath), "claude.md") ||
			strings.HasSuffix(strings.ToLower(relPath), "agents.md")

		if isSkillOrPrompt && manifest != nil && hasAssetsForWorkspace {
			cleanRel := filepath.Clean(relPath)
			pinnedAsset, isPinned := pinnedMap[cleanRel]
			if !isPinned {
				// Also check if any asset path ends with this relative path
				for _, pa := range pinnedMap {
					if strings.HasSuffix(filepath.Clean(pa.Path), cleanRel) {
						pinnedAsset = pa
						isPinned = true
						break
					}
				}
			}

			if !isPinned {
				result.Vulnerabilities = append(result.Vulnerabilities, ScanVulnerability{
					ID:          fmt.Sprintf("unpinned-%s", filepath.Base(relPath)),
					Category:    CatUnpinnedAsset,
					Severity:    SeverityMedium,
					Title:       "Unpinned Agent Skill / Prompt",
					Description: fmt.Sprintf("Asset %s is active in workspace but not cryptographically pinned in %s.", relPath, filepath.Base(s.ManifestPath)),
					TargetFile:  relPath,
					Remediation: fmt.Sprintf("Run 'bapedge pin add %s' to attest and register cryptographic hash.", relPath),
				})
			} else {
				// Check content drift
				curHash, hashErr := pinning.ComputeFileHash(absPath)
				if hashErr == nil && curHash != pinnedAsset.ExpectedHash {
					result.Vulnerabilities = append(result.Vulnerabilities, ScanVulnerability{
						ID:          fmt.Sprintf("drift-%s", filepath.Base(relPath)),
						Category:    CatContentDrift,
						Severity:    SeverityHigh,
						Title:       "Cryptographic Content Drift Detected",
						Description: fmt.Sprintf("Asset %s hash (%s) differs from pinned hash (%s). File modified on disk.", relPath, curHash, pinnedAsset.ExpectedHash),
						TargetFile:  relPath,
						Remediation: fmt.Sprintf("Review unauthorized changes and run 'bapedge pin update %s' if modifications are approved.", pinnedAsset.ID),
					})
				}
			}
		}
	}

	// Calculate highest severity and pass/fail state
	for _, v := range result.Vulnerabilities {
		if v.Severity == SeverityCritical || v.Severity == SeverityHigh {
			result.Passed = false
		}
		if severityWeight(v.Severity) > severityWeight(result.HighestSeverity) {
			result.HighestSeverity = v.Severity
		}
	}

	return result, nil
}

func severityWeight(s Severity) int {
	switch s {
	case SeverityCritical:
		return 4
	case SeverityHigh:
		return 3
	case SeverityMedium:
		return 2
	case SeverityLow:
		return 1
	default:
		return 0
	}
}

// discoverAddonFiles scans workspace for skills, prompts, rules, and MCP manifests
func (s *Scanner) discoverAddonFiles() []string {
	var files []string
	ignoreDirs := map[string]bool{
		".git":         true,
		"node_modules": true,
		"vendor":       true,
		".bapstate":    true,
		"dist":         true,
		"__pycache__":  true,
		".pytest_cache": true,
		"archive":      true,
	}

	_ = filepath.Walk(s.WorkspaceRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			if ignoreDirs[info.Name()] {
				return filepath.SkipDir
			}
			return nil
		}

		rel, err := filepath.Rel(s.WorkspaceRoot, path)
		if err != nil {
			return nil
		}

		lowerName := strings.ToLower(info.Name())
		if lowerName == "skill.md" ||
			lowerName == "gemini.md" ||
			lowerName == "claude.md" ||
			lowerName == "agents.md" ||
			lowerName == ".cursorrules" ||
			lowerName == "mcp.json" ||
			lowerName == "claude_desktop_config.json" ||
			lowerName == "mcp_config.json" ||
			(strings.HasPrefix(lowerName, "policy") && strings.HasSuffix(lowerName, ".cedar")) {
			files = append(files, rel)
		}

		return nil
	})

	return files
}

// FormatTerminal generates human-readable console output
func (r *AddonScanResult) FormatTerminal() string {
	var sb strings.Builder
	sb.WriteString("================================================================================\n")
	sb.WriteString("  [BAP CONTINUOUS SCANNER] 🛡️  Add-on, Skill & Extension Threat Audit\n")
	sb.WriteString("================================================================================\n")
	sb.WriteString(fmt.Sprintf("  Workspace:        %s\n", r.WorkspaceRoot))
	sb.WriteString(fmt.Sprintf("  Files Audited:    %d\n", r.FilesScanned))
	sb.WriteString(fmt.Sprintf("  Vulnerabilities:  %d detected\n", len(r.Vulnerabilities)))
	if r.Passed {
		sb.WriteString("  Compliance:       ✅ PASSED (No Critical/High findings)\n")
	} else {
		sb.WriteString(fmt.Sprintf("  Compliance:       🚨 FAILED (Highest Severity: %s)\n", r.HighestSeverity))
	}
	sb.WriteString("--------------------------------------------------------------------------------\n")

	if len(r.Vulnerabilities) == 0 {
		sb.WriteString("  All installed skills, prompt manifests, and MCP configs comply with BAP invariants.\n")
		sb.WriteString("================================================================================\n")
		return sb.String()
	}

	for i, v := range r.Vulnerabilities {
		icon := "⚠️"
		if v.Severity == SeverityCritical {
			icon = "🔥"
		} else if v.Severity == SeverityHigh {
			icon = "🚨"
		} else if v.Severity == SeverityMedium {
			icon = "⚡"
		}
		sb.WriteString(fmt.Sprintf("  [%d] %s [%s] %s\n", i+1, icon, v.Severity, v.Title))
		sb.WriteString(fmt.Sprintf("      File:        %s", v.TargetFile))
		if v.LineNumber > 0 {
			sb.WriteString(fmt.Sprintf(" (Line %d)", v.LineNumber))
		}
		sb.WriteString("\n")
		sb.WriteString(fmt.Sprintf("      Detail:      %s\n", v.Description))
		if v.Evidence != "" {
			trimmed := v.Evidence
			if len(trimmed) > 80 {
				trimmed = trimmed[:77] + "..."
			}
			sb.WriteString(fmt.Sprintf("      Evidence:    %s\n", trimmed))
		}
		sb.WriteString(fmt.Sprintf("      Fix:         %s\n", v.Remediation))
		sb.WriteString("\n")
	}

	sb.WriteString("================================================================================\n")
	return sb.String()
}

// ToJSON serializes scan results to JSON
func (r *AddonScanResult) ToJSON() (string, error) {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

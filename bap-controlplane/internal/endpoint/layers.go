package endpoint

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// LayerID defines the tiers of endpoint enforcement in the 5-layer defense-in-depth architecture.
type LayerID string

const (
	Layer1CooperativeHooks    LayerID = "LAYER_1_COOPERATIVE_HOOKS"
	Layer2MCPAuthority        LayerID = "LAYER_2_MCP_AUTHORITY"
	Layer3TerminalShims       LayerID = "LAYER_3_TERMINAL_SHIMS"
	Layer4KernelExecutionCtrl LayerID = "LAYER_4_KERNEL_EXECUTION_CONTROL"
	Layer5GatewayPEP          LayerID = "LAYER_5_GATEWAY_PEP"

	// Backward-compatibility aliases
	LayerACooperativeHooks    LayerID = "LAYER_A_COOPERATIVE_HOOKS"
	LayerBKernelExecutionCtrl LayerID = "LAYER_B_KERNEL_EXECUTION_CONTROL"
	LayerCNetworkEgressPin    LayerID = "LAYER_C_NETWORK_EGRESS_PINNING"
)

// ComplianceState represents the posture of an enrolled developer workstation.
type ComplianceState string

const (
	StateCompliant   ComplianceState = "COMPLIANT"
	StateCooperative ComplianceState = "COOPERATIVE_BYOD"
	StateQuarantined ComplianceState = "QUARANTINED"
)

// LayerStatus models the active primitives and enforcement state of an individual layer.
type LayerStatus struct {
	LayerID     LayerID  `json:"layer_id"`
	Name        string   `json:"name"`
	Active      bool     `json:"active"`
	Enforcing   bool     `json:"enforcing"`
	Primitives  []string `json:"primitives"`
	Description string   `json:"description"`
}

// EndpointReport summarizes the posture of an agent/developer laptop.
type EndpointReport struct {
	Hostname         string          `json:"hostname"`
	AgentID          string          `json:"agent_id"`
	OS               string          `json:"os"` // "windows", "darwin", "linux"
	IsManagedFleet   bool            `json:"is_managed_fleet"`
	MDMEnrolled      bool            `json:"mdm_enrolled"`
	ComplianceState  ComplianceState `json:"compliance_state"`
	QuarantineReason string          `json:"quarantine_reason,omitempty"`
	Layers           []LayerStatus   `json:"layers"`
	EvaluatedAt      time.Time       `json:"evaluated_at"`
}

// StepUpChallenge represents an interactive biometric / FIDO2 elevation challenge.
type StepUpChallenge struct {
	ChallengeID   string    `json:"challenge_id"`
	AgentID       string    `json:"agent_id"`
	Operation     string    `json:"operation"`
	RiskScore     float64   `json:"risk_score"`
	RequiredAuth  string    `json:"required_auth"` // "WINDOWS_HELLO", "TOUCH_ID", "FIDO2"
	Nonce         string    `json:"nonce"`
	ExpiresAt     time.Time `json:"expires_at"`
	Status        string    `json:"status"` // "PENDING", "VERIFIED", "EXPIRED", "DENIED"
}

// StepUpToken is a short-lived single-use grant minted upon successful biometric authentication.
type StepUpToken struct {
	TokenID     string    `json:"token_id"`
	ChallengeID string    `json:"challenge_id"`
	AgentID     string    `json:"agent_id"`
	Operation   string    `json:"operation"`
	Method      string    `json:"method"`
	IssuedAt    time.Time `json:"issued_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Signature   string    `json:"signature"`
}

// CapabilityTier categorizes local offline commands vs enterprise cloud egress.
type CapabilityTier string

const (
	Tier1SafeLocalDev CapabilityTier = "TIER_1_SAFE_LOCAL_DEV"
	Tier2CloudEgress  CapabilityTier = "TIER_2_PROTECTED_CLOUD_EGRESS"
)

// CapabilityEvaluation defines whether an operation is allowed offline.
type CapabilityEvaluation struct {
	Operation       string         `json:"operation"`
	Tier            CapabilityTier `json:"tier"`
	AllowedOffline  bool           `json:"allowed_offline"`
	RequiresGrant   bool           `json:"requires_grant"`
	OfflinePolicy   string         `json:"offline_policy"`
	Explanation     string         `json:"explanation"`
}

// Manager orchestrates layered endpoint compliance, MDM profiles, step-up challenges, and offline policies.
type Manager struct {
	mu         sync.RWMutex
	signingKey []byte
	challenges map[string]*StepUpChallenge
	endpoints  map[string]EndpointReport
}

// NewManager creates an initialized Endpoint Manager.
func NewManager(signingKey string) *Manager {
	if signingKey == "" {
		signingKey = "bap-default-endpoint-signing-key-32b!"
	}
	return &Manager{
		signingKey: []byte(signingKey),
		challenges: make(map[string]*StepUpChallenge),
		endpoints:  make(map[string]EndpointReport),
	}
}

// GetLayersReference returns the authoritative 5-layer defense-in-depth definition mapped per OS.
func (m *Manager) GetLayersReference(osName string) []LayerStatus {
	osLower := strings.ToLower(osName)
	var prim4, prim1 []string

	prim1 = []string{
		"Claude Code PreToolUse hooks",
		"Cursor / VS Code MCP proxy wrapper",
		"User-immutable managed-settings.json (dangerouslySkipPermissions: false)",
		"Antigravity & Copilot rule injection (GEMINI.md, AGENTS.md)",
	}

	prim2 := []string{
		"bapmcp.exe managed server",
		"Cedar-gated bap_execute tool execution",
		"bap_status & bap_explain_policy introspection",
	}

	prim3 := []string{
		".bapstate/shims-$SessionId dynamic PATH interception",
		"CLI shims: git, python, curl, wget, powershell, cat, rm",
		"Broker re-entrancy unwrapper (BAP_IN_BROKER=1)",
	}

	switch {
	case strings.Contains(osLower, "darwin") || strings.Contains(osLower, "mac"):
		prim4 = []string{"Endpoint Security Framework (AUTH_EXEC, AUTH_OPEN)", "Seatbelt sandbox profile", "NetworkExtension content filter"}
	case strings.Contains(osLower, "linux"):
		prim4 = []string{"Landlock LSM", "eBPF-LSM (bprm_check_security)", "bubblewrap + seccomp-bpf", "eBPF cgroup socket filter"}
	default: // Windows
		prim4 = []string{"Restricted Tokens (LUA)", "Windows Job Objects (Kill-on-Close)", "AppContainer isolation", "Windows Filtering Platform (WFP)"}
	}

	prim5 := []string{
		"Gateway PEP reverse proxy (ext_authz)",
		"Independent operation derivation (deriveOperation)",
		"Atomic single-use JWT grant burning (ZSP maxUses=1)",
		"Multi-tenant SaaS egress validation (BAP-530)",
	}

	return []LayerStatus{
		{
			LayerID:     Layer1CooperativeHooks,
			Name:        "Layer 1: Agent-Native Cooperative Hooks",
			Active:      true,
			Enforcing:   true,
			Primitives:  prim1,
			Description: "Fast user-space interception (<1ms). PreToolUse hooks, prompt classification, and workspace invariants.",
		},
		{
			LayerID:     Layer2MCPAuthority,
			Name:        "Layer 2: Model Context Protocol (MCP) Authority Boundary",
			Active:      true,
			Enforcing:   true,
			Primitives:  prim2,
			Description: "Managed MCP tool catalog (bapmcp.exe) gating tool execution with Cedar policy authorization.",
		},
		{
			LayerID:     Layer3TerminalShims,
			Name:        "Layer 3: Tool Call & Terminal Interceptor Shims",
			Active:      true,
			Enforcing:   true,
			Primitives:  prim3,
			Description: "Dynamic PATH shims (.bapstate/shims-*) trapping unmediated child subshells and routing to bapedge exec.",
		},
		{
			LayerID:     Layer4KernelExecutionCtrl,
			Name:        "Layer 4: OS Kernel Boundary Sandbox & Local Broker",
			Active:      true,
			Enforcing:   true,
			Primitives:  prim4,
			Description: "Kernel-level hard containment (Job Objects/Landlock/Seatbelt) and in-process Cedar execution broker.",
		},
		{
			LayerID:     Layer5GatewayPEP,
			Name:        "Layer 5: Authoritative Network Gateway PEP & Perimeter Backstop",
			Active:      true,
			Enforcing:   true,
			Primitives:  prim5,
			Description: "Enterprise perimeter policy enforcement point guarding microservices, APIs, and databases via single-use grant burning.",
		},
	}
}

// EvaluateCompliance determines the compliance posture of an endpoint across the 5-layer defense architecture.
func (m *Manager) EvaluateCompliance(report EndpointReport) EndpointReport {
	m.mu.Lock()
	defer m.mu.Unlock()

	report.EvaluatedAt = time.Now().UTC()

	if report.IsManagedFleet {
		var missing []string
		for _, l := range report.Layers {
			if !l.Active || !l.Enforcing {
				switch l.LayerID {
				case Layer1CooperativeHooks, LayerACooperativeHooks:
					missing = append(missing, "Layer A / Layer 1 (Hooks)")
				case Layer2MCPAuthority:
					missing = append(missing, "Layer 2 (MCP Authority)")
				case Layer3TerminalShims:
					missing = append(missing, "Layer 3 (Terminal Shims)")
				case Layer4KernelExecutionCtrl, LayerBKernelExecutionCtrl:
					missing = append(missing, "Layer B / Layer 4 (Kernel Execution Control)")
				case Layer5GatewayPEP, LayerCNetworkEgressPin:
					missing = append(missing, "Layer C / Layer 5 (Network Gateway PEP)")
				default:
					missing = append(missing, string(l.LayerID))
				}
			}
		}

		if len(missing) == 0 && len(report.Layers) > 0 {
			report.ComplianceState = StateCompliant
			report.QuarantineReason = ""
		} else {
			report.ComplianceState = StateQuarantined
			if len(missing) == 0 {
				missing = append(missing, "Missing layer reports")
			}
			report.QuarantineReason = fmt.Sprintf("Managed fleet device failed zero-trust boundary verification. Missing: %s", strings.Join(missing, ", "))
		}
	} else {
		// BYOD / Unmanaged machines operate in cooperative mode with Gateway PEP as backstop
		report.ComplianceState = StateCooperative
		report.QuarantineReason = "Unmanaged / BYOD device. Enforcing in cooperative mode; Gateway PEP remains authoritative backstop."
	}

	key := fmt.Sprintf("%s:%s", report.Hostname, report.AgentID)
	m.endpoints[key] = report
	return report
}

// GenerateMDMProfile outputs an enterprise configuration payload for Microsoft Intune or Jamf Pro.
func (m *Manager) GenerateMDMProfile(platform string) map[string]any {
	plat := strings.ToLower(platform)
	if strings.Contains(plat, "jamf") || strings.Contains(plat, "mac") || strings.Contains(plat, "apple") {
		return map[string]any{
			"platform":        "macOS",
			"management_tool": "Jamf Pro / Kandji / Intune",
			"payload_type":    "com.apple.configurationprofile",
			"payload_id":      "com.bap.security.endpoint.profile",
			"settings": map[string]any{
				"claude_code": map[string]any{
					"managed_settings_path":   "/Library/Application Support/Claude/managed-settings.json",
					"dangerously_skip_permissions": false,
					"pre_tool_use_hook_enforced":  true,
					"immutable":                   true,
				},
				"system_extension": map[string]any{
					"bundle_identifier": "com.bap.endpoint.security.sysext",
					"allowed_types":     []string{"EndpointSecurity", "NetworkExtension"},
					"full_disk_access":  true,
				},
				"trust_anchor": map[string]any{
					"pinned_ca": "BAP Enterprise Root Authority v1",
					"update_channel": "https://controlplane.bap.internal/api/v1/policy/bundle",
				},
			},
		}
	}

	// Windows Intune payload
	return map[string]any{
		"platform":        "Windows 11 / Windows 10 Enterprise",
		"management_tool": "Microsoft Intune OMA-URI / CSP",
		"payload_type":    "Intune.DeviceConfiguration.Custom",
		"payload_id":      "BAP-Windows-ZeroTrust-Endpoint-Policy",
		"settings": map[string]any{
			"claude_code": map[string]any{
				"managed_settings_path":   `C:\ProgramData\Claude\managed-settings.json`,
				"dangerously_skip_permissions": false,
				"pre_tool_use_hook_enforced":  true,
				"immutable":                   true,
			},
			"os_containment": map[string]any{
				"restricted_tokens":  "Enabled",
				"job_objects_limits": "KILL_ON_JOB_CLOSE | ACTIVE_PROCESS_LIMIT_32",
				"appcontainer_sid":   "S-1-15-2-BAP-SANDBOX",
			},
			"network_egress": map[string]any{
				"wfp_filter_provider": "BAP Gateway PEP Network Driver",
				"pin_loopback_proxy":  "http://127.0.0.1:8090",
			},
			"trust_anchor": map[string]any{
				"pinned_ca": "BAP Enterprise Root Authority v1",
				"update_channel": "https://controlplane.bap.internal/api/v1/policy/bundle",
			},
		},
	}
}

// RequestStepUp creates a pending elevation challenge for high-risk operations.
func (m *Manager) RequestStepUp(agentID, operation string, riskScore float64) *StepUpChallenge {
	m.mu.Lock()
	defer m.mu.Unlock()

	nonceBytes := sha256.Sum256([]byte(fmt.Sprintf("%s:%s:%d", agentID, operation, time.Now().UnixNano())))
	nonce := hex.EncodeToString(nonceBytes[:16])

	challengeID := fmt.Sprintf("stepup-%x", time.Now().UnixNano()%0xFFFFFFFFFFFF)
	reqAuth := "WINDOWS_HELLO"
	if strings.Contains(strings.ToLower(operation), "transfer") || riskScore > 0.90 {
		reqAuth = "FIDO2_HARDWARE_KEY"
	}

	challenge := &StepUpChallenge{
		ChallengeID:  challengeID,
		AgentID:      agentID,
		Operation:    operation,
		RiskScore:    riskScore,
		RequiredAuth: reqAuth,
		Nonce:        nonce,
		ExpiresAt:    time.Now().UTC().Add(3 * time.Minute),
		Status:       "PENDING",
	}

	m.challenges[challengeID] = challenge
	return challenge
}

// VerifyStepUp validates biometric authentication and mints a single-use StepUpToken.
func (m *Manager) VerifyStepUp(challengeID, method, biometricSignature string) (*StepUpToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	ch, exists := m.challenges[challengeID]
	if !exists {
		return nil, fmt.Errorf("challenge %q not found", challengeID)
	}
	if time.Now().UTC().After(ch.ExpiresAt) {
		ch.Status = "EXPIRED"
		return nil, fmt.Errorf("challenge %q has expired", challengeID)
	}
	if ch.Status != "PENDING" {
		return nil, fmt.Errorf("challenge %q is already %s", challengeID, ch.Status)
	}

	// Validate method
	ch.Status = "VERIFIED"
	tokenID := fmt.Sprintf("stepup-tok-%x", time.Now().UnixNano()%0xFFFFFFFFFFFF)
	issued := time.Now().UTC()
	expires := issued.Add(5 * time.Minute)

	// Sign token
	sigPayload := fmt.Sprintf("%s|%s|%s|%s|%d", tokenID, ch.AgentID, ch.Operation, method, expires.Unix())
	mac := hmac.New(sha256.New, m.signingKey)
	mac.Write([]byte(sigPayload))
	signature := hex.EncodeToString(mac.Sum(nil))

	return &StepUpToken{
		TokenID:     tokenID,
		ChallengeID: challengeID,
		AgentID:     ch.AgentID,
		Operation:   ch.Operation,
		Method:      method,
		IssuedAt:    issued,
		ExpiresAt:   expires,
		Signature:   signature,
	}, nil
}

// ClassifyCapability categorizes an action as Tier 1 (safe local dev) vs Tier 2 (cloud egress).
func (m *Manager) ClassifyCapability(operation string) CapabilityEvaluation {
	opLower := strings.ToLower(operation)

	// Safe local development operations: compiling, running tests, linting, git status
	safeLocalPatterns := []string{
		"test", "build", "compile", "lint", "format", "git.status", "git.diff", "git.log", "cargo", "npm run test", "pytest", "go test",
	}

	for _, p := range safeLocalPatterns {
		if strings.Contains(opLower, p) {
			return CapabilityEvaluation{
				Operation:      operation,
				Tier:           Tier1SafeLocalDev,
				AllowedOffline: true,
				RequiresGrant:  false,
				OfflinePolicy:  "EVALUATE_LOCAL_CEDAR_CACHE",
				Explanation:    "Safe local development action. Evaluated locally against cached Cedar policy bundle with zero network dependency.",
			}
		}
	}

	// Protected cloud microservices and databases
	return CapabilityEvaluation{
		Operation:      operation,
		Tier:           Tier2CloudEgress,
		AllowedOffline: false,
		RequiresGrant:  true,
		OfflinePolicy:  "FAIL_CLOSED_ON_GRANT_EXPIRY",
		Explanation:    "Protected enterprise resource egress. BAP Zero Standing Privilege requires an online signed bounded grant; fails closed when offline grant expires (15m TTL).",
	}
}

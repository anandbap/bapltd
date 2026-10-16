package antibypass

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var (
	ErrBypassAttemptDetected = errors.New("AntiBypassViolation: unmediated execution or environment tampering blocked")
	ErrMissingSessionContext = errors.New("AntiBypassViolation: execution attempted without active BAP session provenance")
)

// AntiBypassViolation holds forensic details of an intercepted bypass attempt
type AntiBypassViolation struct {
	ViolationID string    `json:"violation_id"`
	SessionID   string    `json:"session_id"`
	Command     string    `json:"command"`
	Vector      string    `json:"vector"` // "env_tampering", "unmediated_socket", "raw_subshell", "shim_evasion"
	Reason      string    `json:"reason"`
	Timestamp   time.Time `json:"timestamp"`
}

// AntiBypassEngine detects and halts unmediated subshell, raw socket, and proxy evasion bypasses
type AntiBypassEngine struct {
	ProtectedEnvVars []string
	EvasionPatterns  []*regexp.Regexp
}

// NewAntiBypassEngine initializes the anti-bypass defense engine
func NewAntiBypassEngine() *AntiBypassEngine {
	patterns := []*regexp.Regexp{
		// Unset proxy or security variables
		regexp.MustCompile(`(?i)\b(unset|set\s+[-+]x|\$env:HTTP_PROXY\s*=|remove-item\s+env:)\s*(HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|BAP_SESSION_ID|BAP_GATEWAY_URL)`),
		// Raw socket opens or bypass invocations without BAP mediation
		regexp.MustCompile(`(?i)\b(nc|ncat|netcat)\s+-[a-z0-9]*[elv]`),
		regexp.MustCompile(`(?i)(python|python3|perl|ruby)\s+-[cpe]\s+.*(socket\.(connect|bind)|IO::Socket|TCPSocket\.open)`),
		regexp.MustCompile(`(?i)\/dev\/(tcp|udp)\/[0-9a-zA-Z\.\-]+`),
		// Raw curl or invoke-webrequest with direct bypass flags
		regexp.MustCompile(`(?i)\b(curl|wget)\s+.*(--noproxy|\bno_proxy\b)`),
	}

	return &AntiBypassEngine{
		ProtectedEnvVars: []string{
			"BAP_SESSION_ID",
			"BAP_GATEWAY_URL",
			"HTTP_PROXY",
			"HTTPS_PROXY",
			"ALL_PROXY",
		},
		EvasionPatterns: patterns,
	}
}

// CheckCommand inspects an attempted command line and environment for anti-bypass invariants
func (e *AntiBypassEngine) CheckCommand(sessionID, command string, envVars map[string]string) (*AntiBypassViolation, error) {
	effectiveSessionID := strings.TrimSpace(sessionID)
	if effectiveSessionID == "" && envVars != nil {
		effectiveSessionID = strings.TrimSpace(envVars["BAP_SESSION_ID"])
	}
	if effectiveSessionID == "" {
		effectiveSessionID = strings.TrimSpace(os.Getenv("BAP_SESSION_ID"))
	}

	// 1. Session Provenance Invariant
	if effectiveSessionID == "" {
		viol := &AntiBypassViolation{
			ViolationID: generateViolationID("sess"),
			SessionID:   sessionID,
			Command:     command,
			Vector:      "missing_session_provenance",
			Reason:      "Execution attempted outside an attested BAP session context",
			Timestamp:   time.Now().UTC(),
		}
		_ = e.recordViolation(viol)
		return viol, fmt.Errorf("%w: %s", ErrMissingSessionContext, viol.Reason)
	}

	// 2. Command Evasion Regex Pattern Check
	for _, pattern := range e.EvasionPatterns {
		if pattern.MatchString(command) {
			viol := &AntiBypassViolation{
				ViolationID: generateViolationID("evade"),
				SessionID:   sessionID,
				Command:     command,
				Vector:      "unmediated_socket_or_evasion",
				Reason:      fmt.Sprintf("Command matched unmediated bypass or socket pattern %q", pattern.String()),
				Timestamp:   time.Now().UTC(),
			}
			_ = e.recordViolation(viol)
			return viol, fmt.Errorf("%w: %s", ErrBypassAttemptDetected, viol.Reason)
		}
	}

	// 3. Environment Variable Tampering Check
	for _, protected := range e.ProtectedEnvVars {
		if val, exists := envVars[protected]; exists {
			if strings.TrimSpace(val) == "" && (protected == "BAP_SESSION_ID" || protected == "HTTP_PROXY") {
				viol := &AntiBypassViolation{
					ViolationID: generateViolationID("env"),
					SessionID:   sessionID,
					Command:     command,
					Vector:      "env_tampering",
					Reason:      fmt.Sprintf("Attempted to unset or clear protected security variable %s", protected),
					Timestamp:   time.Now().UTC(),
				}
				_ = e.recordViolation(viol)
				return viol, fmt.Errorf("%w: %s", ErrBypassAttemptDetected, viol.Reason)
			}
		}
	}

	return nil, nil
}

func (e *AntiBypassEngine) recordViolation(viol *AntiBypassViolation) error {
	dir := ".bapstate"
	_ = os.MkdirAll(dir, 0755)
	logFile := filepath.Join(dir, "bypass_violations.jsonl")

	entry := fmt.Sprintf(`{"violation_id":"%s","session_id":"%s","vector":"%s","reason":"%s","command":"%s","timestamp":"%s"}`+"\n",
		viol.ViolationID, viol.SessionID, viol.Vector, strings.ReplaceAll(viol.Reason, `"`, `\"`),
		strings.ReplaceAll(viol.Command, `"`, `\"`), viol.Timestamp.Format(time.RFC3339))

	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err == nil {
		defer f.Close()
		_, _ = f.WriteString(entry)
	}
	return nil
}

func generateViolationID(prefix string) string {
	raw := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("viol-%s-%s", prefix, hex.EncodeToString(h[:4]))
}

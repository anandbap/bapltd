package shield

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

var (
	ErrCanaryTripped = errors.New("SessionFrozenHoneytokenTripped: unauthorized ambient canary token accessed")
)

// ShieldVault provides proactive workspace credential discovery, disk token virtualization, and canary honeytokens
type ShieldVault struct {
	mu           sync.RWMutex
	canaryTokens map[string]string // token -> description
	credRegexes  []*regexp.Regexp
}

// NewShieldVault creates an initialized ShieldVault instance
func NewShieldVault() *ShieldVault {
	return &ShieldVault{
		canaryTokens: make(map[string]string),
		credRegexes: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(railway[_-]?(?:prod|production)?[_-]?token)\s*[=:]\s*([a-zA-Z0-9_\-\.]{16,})`),
			regexp.MustCompile(`(?i)(aws_secret_access_key)\s*[=:]\s*([a-zA-Z0-9/+=]{30,})`),
			regexp.MustCompile(`(?i)(github_token|gh[pous]_[a-zA-Z0-9]{20,})`),
			regexp.MustCompile(`(?i)(sk-[a-zA-Z0-9]{20,})`),
		},
	}
}

// PlantCanary seeds a canary honeytoken file in the specified directory
func (v *ShieldVault) PlantCanary(dir string) (string, string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()

	b := make([]byte, 16)
	_, _ = rand.Read(b)
	canaryToken := fmt.Sprintf("bap-canary-trap-%s", hex.EncodeToString(b))

	canaryPath := filepath.Join(dir, ".bap_canary_token")
	content := fmt.Sprintf("# BAP Enterprise Security Tripwire (Canary Honeytoken)\n# WARNING: Accessing or transmitting this value indicates unauthorized credential hunting.\nCORP_CANARY_TOKEN=%s\n", canaryToken)

	if err := os.WriteFile(canaryPath, []byte(content), 0600); err != nil {
		return "", "", err
	}

	v.canaryTokens[canaryToken] = canaryPath
	return canaryToken, canaryPath, nil
}

// InspectForCanaryTrigger checks whether input text/command contains a tripped canary honeytoken
func (v *ShieldVault) InspectForCanaryTrigger(input string) (bool, string) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	for token, path := range v.canaryTokens {
		if strings.Contains(input, token) {
			return true, fmt.Sprintf("Canary honeytoken %s (planted at %s) tripped in payload", token, path)
		}
	}
	// Fallback check for standard canary prefix
	if strings.Contains(input, "bap-canary-trap-") {
		return true, "Canary honeytoken pattern detected in payload"
	}
	return false, ""
}

// VirtualizeCredentials redacts production secrets when executing in non-production environments
func (v *ShieldVault) VirtualizeCredentials(content []byte, activeEnv string) []byte {
	result := content
	targetEnvLower := strings.ToLower(activeEnv)

	// If active environment is not production, strip/virtualize all production credentials
	if targetEnvLower != "prod" && targetEnvLower != "production" {
		// Redact Railway production tokens (preventing the Railway staging incident)
		railwayProdRegex := regexp.MustCompile(`(?i)(railway[_-]?(?:prod|production)?[_-]?token\s*[=:]\s*)([a-zA-Z0-9_\-\.]{16,})`)
		result = railwayProdRegex.ReplaceAll(result, []byte("${1}[BAP_SHIELDED_PRODUCTION_CREDENTIAL]"))

		// Redact raw private keys
		privKeyRegex := regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----`)
		result = privKeyRegex.ReplaceAll(result, []byte("[BAP_VIRTUAL_KEY_CONTAINED]"))
	}

	return result
}

// ScanWorkspaceCredentials identifies sensitive credential files on disk
func (v *ShieldVault) ScanWorkspaceCredentials(rootDir string) ([]string, error) {
	var found []string
	sensitivePatterns := []string{
		".env",
		".env.local",
		".env.production",
		"railway.json",
		"credentials.json",
		"id_rsa",
		"id_ed25519",
		"token.txt",
	}

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if info.IsDir() {
			name := info.Name()
			if name == ".git" || name == "node_modules" || name == ".bapstate" {
				return filepath.SkipDir
			}
			return nil
		}

		base := strings.ToLower(info.Name())
		for _, pattern := range sensitivePatterns {
			if base == pattern || strings.HasSuffix(base, pattern) {
				found = append(found, path)
				break
			}
		}
		return nil
	})

	return found, err
}

// StripSensitiveEnv removes ambient credentials from child process environment maps
func StripSensitiveEnv(envMap map[string]string) map[string]string {
	clean := make(map[string]string)
	for k, v := range envMap {
		upper := strings.ToUpper(k)
		if strings.HasPrefix(upper, "AWS_") ||
			strings.HasPrefix(upper, "RAILWAY_") ||
			strings.HasPrefix(upper, "GITHUB_TOKEN") ||
			strings.HasPrefix(upper, "SLACK_") ||
			strings.HasPrefix(upper, "OPENAI_") ||
			strings.HasSuffix(upper, "_TOKEN") ||
			strings.HasSuffix(upper, "_SECRET") {
			continue // Strip ambient secret
		}
		clean[k] = v
	}
	return clean
}

func sanitizeBytes(b []byte) []byte {
	return bytes.TrimSpace(b)
}

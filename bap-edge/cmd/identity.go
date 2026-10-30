package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// resolveLocalIdentity resolves operator and workload identities using a 5-stage pipeline:
// STAGE 1: apiKeyHelper / Corporate User ID Token (Primary Identity Source)
// STAGE 2: Corporate & System Environment Variables (BAP_USER_EMAIL, USERNAME, USER, LOGNAME)
// STAGE 3: Cross-Platform Native Standard Library (os/user.Current)
// STAGE 4: Home Directory Basename Fallback
// STAGE 5: Graceful Degradation Worst-Case ("NA" - Never Crash)
func resolveLocalIdentity() (userID, userEmail, spiffeID string) {
	// =========================================================================
	// STAGE 1: apiKeyHelper / Corporate User ID Token
	// =========================================================================
	if hUser, hEmail := resolveFromAPIKeyHelper(); hUser != "" || hEmail != "" {
		userID = hUser
		userEmail = hEmail
	}

	// =========================================================================
	// STAGE 2: Corporate & System Environment Variables (Fallback when no apiKeyHelper)
	// =========================================================================
	if userEmail == "" {
		userEmail = os.Getenv("BAP_USER_EMAIL")
		if userEmail == "" {
			userEmail = os.Getenv("USER_EMAIL")
		}
	}
	if userID == "" {
		userID = os.Getenv("BAP_USER_ID")
		if userID == "" {
			if u := os.Getenv("USERNAME"); u != "" {
				userID = u
			} else if u := os.Getenv("USER"); u != "" {
				userID = u
			} else if u := os.Getenv("LOGNAME"); u != "" {
				userID = u
			}
		}
	}

	// Unified Workstation Credentials Fallback (~/.bapstate/credentials.json)
	if userEmail == "" || userID == "" {
		credsPath := DefaultCredentialsPath()
		if data, err := os.ReadFile(credsPath); err == nil {
			var creds StoredCredentials
			if err := json.Unmarshal(data, &creds); err == nil {
				if userEmail == "" && creds.UserEmail != "" {
					userEmail = creds.UserEmail
				}
				if userID == "" && creds.AgentID != "" {
					userID = creds.AgentID
				}
			}
		}
	}

	// =========================================================================
	// STAGE 3: Cross-Platform Standard Library (os/user.Current)
	// =========================================================================
	if userID == "" {
		if curUser, err := user.Current(); err == nil && curUser.Username != "" {
			userID = curUser.Username
		}
	}

	// =========================================================================
	// STAGE 4: Home Directory Basename Fallback (e.g. C:\Users\alice -> alice)
	// =========================================================================
	if userID == "" {
		if home, err := os.UserHomeDir(); err == nil && home != "" && home != "/" {
			base := filepath.Base(filepath.Clean(home))
			if base != "." && base != "/" && base != "\\" {
				userID = base
			}
		}
	}

	// =========================================================================
	// STAGE 5: Worst-Case Graceful Degradation ("NA" - Never Crash)
	// =========================================================================
	if userID == "" {
		userID = "NA"
	}
	if userEmail == "" {
		userEmail = "NA"
	}

	// Workload Identity Resolution (SPIFFE / SVID)
	spiffeID = os.Getenv("BAP_SPIFFE_ID")
	if spiffeID == "" {
		spiffeID = os.Getenv("BAP_WORKLOAD_ID")
	}
	if spiffeID == "" {
		credsPath := DefaultCredentialsPath()
		if data, err := os.ReadFile(credsPath); err == nil {
			var creds StoredCredentials
			if err := json.Unmarshal(data, &creds); err == nil && creds.SPIFFEID != "" {
				spiffeID = creds.SPIFFEID
			}
		}
	}
	if spiffeID == "" {
		spiffeID = "NA"
	}
	return
}

// resolveFromAPIKeyHelper checks for apiKeyHelper configuration, direct ID tokens, or executes the helper.
func resolveFromAPIKeyHelper() (userID, userEmail string) {
	// 1. Check direct token environment variables first
	for _, envVar := range []string{"BAP_ID_TOKEN", "CLAUDE_ID_TOKEN", "USER_ID_TOKEN", "ID_TOKEN"} {
		if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
			if u, e := extractIdentityFromTokenOrOutput(val); u != "" || e != "" {
				return u, e
			}
		}
	}

	// 2. Discover apiKeyHelper command
	helperCmd := findClaudeAPIKeyHelper()
	if helperCmd == "" {
		return "", ""
	}

	// 3. Execute the helper script/binary
	out, err := executeAPIKeyHelper(helperCmd)
	if err != nil || out == "" {
		return "", ""
	}

	return extractIdentityFromTokenOrOutput(out)
}

// findClaudeAPIKeyHelper searches environment variables and Claude config files for apiKeyHelper.
func findClaudeAPIKeyHelper() string {
	// Check environment variables first
	for _, envVar := range []string{"BAP_API_KEY_HELPER", "CLAUDE_API_KEY_HELPER", "API_KEY_HELPER", "apiKeyHelper"} {
		if val := strings.TrimSpace(os.Getenv(envVar)); val != "" {
			return val
		}
	}

	// Check Claude configuration files
	home, _ := os.UserHomeDir()
	var candidatePaths []string
	if home != "" {
		candidatePaths = append(candidatePaths,
			filepath.Join(home, ".claude.json"),
			filepath.Join(home, ".claude", "settings.json"),
		)
	}
	candidatePaths = append(candidatePaths,
		filepath.Join(".claude", "config.json"),
		filepath.Join(".claude", "settings.json"),
	)

	for _, path := range candidatePaths {
		if data, err := os.ReadFile(path); err == nil {
			var cfg map[string]interface{}
			if err := json.Unmarshal(data, &cfg); err == nil {
				if val, ok := cfg["apiKeyHelper"].(string); ok && strings.TrimSpace(val) != "" {
					return strings.TrimSpace(val)
				}
			}
		}
	}

	return ""
}

// executeAPIKeyHelper executes the helper command with a 2-second timeout context.
func executeAPIKeyHelper(helperCmd string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd.exe", "/c", helperCmd)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", helperCmd)
	}

	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// extractIdentityFromTokenOrOutput parses identity from JWT, JSON, or plain text token output.
func extractIdentityFromTokenOrOutput(raw string) (userID, userEmail string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}

	// 1. Try parsing as JWT (three period-separated base64 segments)
	if parts := strings.Split(raw, "."); len(parts) == 3 {
		if claims := parseJWTPayload(raw); claims != nil {
			// Extract email
			for _, k := range []string{"email", "upn", "user_email", "mail"} {
				if v, ok := claims[k].(string); ok && strings.TrimSpace(v) != "" {
					userEmail = strings.TrimSpace(v)
					break
				}
			}
			// Extract user ID / username
			for _, k := range []string{"preferred_username", "sub", "username", "unique_name", "oid", "name"} {
				if v, ok := claims[k].(string); ok && strings.TrimSpace(v) != "" {
					userID = strings.TrimSpace(v)
					break
				}
			}
			if userEmail != "" && userID == "" {
				userID = strings.Split(userEmail, "@")[0]
			}
			if userID != "" && userEmail == "" && strings.Contains(userID, "@") {
				userEmail = userID
				userID = strings.Split(userEmail, "@")[0]
			}
			if userID != "" || userEmail != "" {
				return userID, userEmail
			}
		}
		// If it has 3 parts separated by dots, it was intended as a JWT; do not treat invalid JWT as plain username
		return "", ""
	}

	// 2. Try parsing as JSON object
	if strings.HasPrefix(raw, "{") && strings.HasSuffix(raw, "}") {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(raw), &obj); err == nil {
			for _, k := range []string{"email", "user_email", "upn", "mail"} {
				if v, ok := obj[k].(string); ok && strings.TrimSpace(v) != "" {
					userEmail = strings.TrimSpace(v)
					break
				}
			}
			for _, k := range []string{"user_id", "userId", "username", "preferred_username", "sub", "name"} {
				if v, ok := obj[k].(string); ok && strings.TrimSpace(v) != "" {
					userID = strings.TrimSpace(v)
					break
				}
			}
			if userEmail != "" && userID == "" {
				userID = strings.Split(userEmail, "@")[0]
			}
			if userID != "" || userEmail != "" {
				return userID, userEmail
			}
		}
		return "", ""
	}

	// 3. Try parsing as plain email or username
	if strings.Contains(raw, "@") && !strings.Contains(raw, " ") && !strings.Contains(raw, "\n") {
		userEmail = raw
		userID = strings.Split(raw, "@")[0]
		return userID, userEmail
	}

	// Plain username: alphanumeric, underscore, dash without dots or spaces
	if len(raw) <= 64 && !strings.Contains(raw, " ") && !strings.Contains(raw, "\n") && !strings.Contains(raw, ".") {
		return raw, ""
	}

	return "", ""
}

// parseJWTPayload decodes the payload segment of a JWT.
func parseJWTPayload(rawToken string) map[string]interface{} {
	parts := strings.Split(strings.TrimSpace(rawToken), ".")
	if len(parts) < 2 {
		return nil
	}
	payloadSegment := parts[1]
	// Handle base64 padding
	switch len(payloadSegment) % 4 {
	case 2:
		payloadSegment += "=="
	case 3:
		payloadSegment += "="
	}
	data, err := base64.URLEncoding.DecodeString(payloadSegment)
	if err != nil {
		data, err = base64.StdEncoding.DecodeString(payloadSegment)
		if err != nil {
			data, err = base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				return nil
			}
		}
	}
	var claims map[string]interface{}
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil
	}
	return claims
}

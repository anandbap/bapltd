package sandbox

import (
	"regexp"
	"strings"
)

// Sensitive environment variable prefixes or names that must be stripped from agent processes
var sensitiveEnvPrefixes = []string{
	"AWS_SECRET",
	"AWS_SESSION",
	"AWS_SECURITY",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"OPENAI_API",
	"ANTHROPIC_API",
	"SLACK_TOKEN",
	"SLACK_BOT",
	"AZURE_CLIENT_SECRET",
	"GOOGLE_APPLICATION_CREDENTIALS",
	"NPM_TOKEN",
	"PYPI_PASSWORD",
	"CARGO_REGISTRY_TOKEN",
	"DATABASE_URL",
	"DB_PASSWORD",
	"STRIPE_API_KEY",
	"SENDGRID_API_KEY",
}

var sensitiveEnvSuffixes = []string{
	"_SECRET",
	"_SECRET_KEY",
	"_API_KEY",
	"_PRIVATE_KEY",
	"_PASSWORD",
	"_PASSWD",
	"_AUTH_TOKEN",
	"_ACCESS_TOKEN",
}

// Explicit allowlist of variables that might match prefixes/suffixes but are necessary for BAP runtime
var allowedEnvNames = map[string]bool{
	"CORP_OBO_TOKEN": true,
	"BAP_SESSION_ID": true,
	"BAP_SERVER_URL": true,
	"BAP_MODE":       true,
	"BAP_AGENT_SANDBOX": true,
	"BAP_IN_BROKER":  true,
	"LTD_SOURCE":     true,
	"LTD_SESSION_ID": true,
}

// ScrubEnvironment removes ambient credentials and high-privilege secrets from the environment slice.
func ScrubEnvironment(env []string) []string {
	scrubbed := make([]string, 0, len(env))
	for _, entry := range env {
		parts := strings.SplitN(entry, "=", 2)
		if len(parts) == 0 {
			continue
		}
		varName := parts[0]
		upperVar := strings.ToUpper(varName)

		if allowedEnvNames[upperVar] {
			scrubbed = append(scrubbed, entry)
			continue
		}

		// Check sensitive prefixes
		isSensitive := false
		for _, prefix := range sensitiveEnvPrefixes {
			if strings.HasPrefix(upperVar, prefix) {
				isSensitive = true
				break
			}
		}

		// Check sensitive suffixes
		if !isSensitive {
			for _, suffix := range sensitiveEnvSuffixes {
				if strings.HasSuffix(upperVar, suffix) {
					isSensitive = true
					break
				}
			}
		}

		// Check exact sensitive names
		if !isSensitive {
			switch upperVar {
			case "AWS_ACCESS_KEY_ID", "ID_RSA", "SSH_AUTH_SOCK", "SECRET", "PASSWORD", "API_KEY", "ACCESS_TOKEN":
				isSensitive = true
			}
		}

		if !isSensitive {
			scrubbed = append(scrubbed, entry)
		}
	}
	return scrubbed
}

// Regex patterns for detecting and redacting secrets in tool outputs (stdout / stderr)
var (
	rePrivateKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9_ -]*PRIVATE KEY-----.*?-----END [A-Z0-9_ -]*PRIVATE KEY-----`)
	reAWSKey     = regexp.MustCompile(`\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b`)
	reAWSSecret  = regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})["']?`)
	reGHPAT      = regexp.MustCompile(`\b(ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82}|gho_[0-9a-zA-Z]{36})\b`)
	reAnthropic  = regexp.MustCompile(`\bsk-ant-[a-zA-Z0-9_-]{20,100}\b`)
	reOpenAI     = regexp.MustCompile(`\bsk-[a-zA-Z0-9_-]{20,64}\b`)
	reSlack      = regexp.MustCompile(`\bxox[baprs]-[0-9a-zA-Z-]{10,72}\b`)
	reBearerJWT  = regexp.MustCompile(`(?i)(Bearer\s+)eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}`)
	reGenericSec = regexp.MustCompile(`(?i)(password|passwd|api_key|client_secret)\s*[:=]\s*["']([^"'\s]{8,})["']`)
)

// RedactSecrets scans command output and redacts detected secrets and private keys.
func RedactSecrets(output string) string {
	if output == "" {
		return ""
	}

	res := rePrivateKey.ReplaceAllString(output, "[BAP_REDACTED_PRIVATE_KEY]")
	res = reAWSKey.ReplaceAllString(res, "[BAP_REDACTED_AWS_KEY]")
	res = reAWSSecret.ReplaceAllString(res, "$1=[BAP_REDACTED_AWS_SECRET]")
	res = reGHPAT.ReplaceAllString(res, "[BAP_REDACTED_GITHUB_TOKEN]")
	res = reAnthropic.ReplaceAllString(res, "[BAP_REDACTED_ANTHROPIC_KEY]")
	res = reOpenAI.ReplaceAllString(res, "[BAP_REDACTED_OPENAI_KEY]")
	res = reSlack.ReplaceAllString(res, "[BAP_REDACTED_SLACK_TOKEN]")
	res = reBearerJWT.ReplaceAllString(res, "${1}[BAP_REDACTED_JWT_TOKEN]")
	res = reGenericSec.ReplaceAllString(res, `$1="[BAP_REDACTED_SECRET]"`)

	return res
}

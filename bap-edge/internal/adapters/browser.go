package adapters

import (
	"bytes"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
)

// BrowserGuard provides policy gating and CDP/Playwright interception for browser agents
type BrowserGuard struct {
	AllowedDomains    []string
	ControlPlaneURL   string
	SessionID         string
	AgentID           string
	BlockedExtensions []string
}

// NewBrowserGuard creates an initialized BrowserGuard with enterprise defaults
func NewBrowserGuard(controlPlaneURL, sessionID, agentID string, customAllowedDomains ...string) *BrowserGuard {
	if sessionID == "" {
		sessionID = "sess-browser-playwright"
	}
	if agentID == "" {
		agentID = "playwright-browser-agent"
	}

	allowed := []string{
		"localhost",
		"127.0.0.1",
		"bap.internal",
		"*.corp.internal",
		"*.internal.local",
		"github.com",
		"salesforce.com",
		"workato.com",
	}
	if len(customAllowedDomains) > 0 {
		allowed = append(allowed, customAllowedDomains...)
	}

	blockedExts := []string{
		".env",
		".pem",
		".key",
		".pkcs12",
		".pfx",
		"id_rsa",
		"id_ed25519",
		"credentials.json",
		"client_secret.json",
		"token.txt",
	}

	return &BrowserGuard{
		AllowedDomains:    allowed,
		ControlPlaneURL:   controlPlaneURL,
		SessionID:         sessionID,
		AgentID:           agentID,
		BlockedExtensions: blockedExts,
	}
}

// EvaluateNavigation checks whether a URL navigation is permitted under zero-trust egress rules
func (g *BrowserGuard) EvaluateNavigation(targetURL string) (bool, string, *CanonicalActivityEvent) {
	parsed, err := url.Parse(targetURL)
	if err != nil {
		event := NewActivityEvent("browser-playwright", g.SessionID, g.AgentID, "navigation", targetURL, "DENY", "Invalid URL format")
		_ = ReportActivity(g.ControlPlaneURL, event)
		return false, "Invalid URL format", event
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		host = strings.ToLower(targetURL)
	}

	allowed := false
	for _, pattern := range g.AllowedDomains {
		if pattern == "*" || pattern == host {
			allowed = true
			break
		}
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(host, suffix) {
				allowed = true
				break
			}
		}
	}

	decision := "ALLOW"
	reason := fmt.Sprintf("Domain %q allowed by browser egress policy", host)
	if !allowed {
		decision = "DENY"
		reason = fmt.Sprintf("Unapproved domain %q navigation blocked by BAP browser policy", host)
	}

	event := NewActivityEvent("browser-playwright", g.SessionID, g.AgentID, "navigation", targetURL, decision, reason)
	event.Metadata["hostname"] = host
	event.Metadata["scheme"] = parsed.Scheme
	_ = ReportActivity(g.ControlPlaneURL, event)

	return allowed, reason, event
}

// EvaluateUpload inspects DOM file upload events and intercepts credential exfiltration attempts
func (g *BrowserGuard) EvaluateUpload(filename string, content []byte) (bool, string, *CanonicalActivityEvent) {
	base := strings.ToLower(filepath.Base(filename))

	// Check blocked file names and extensions
	for _, blocked := range g.BlockedExtensions {
		if strings.EqualFold(base, blocked) || strings.HasSuffix(base, blocked) {
			reason := fmt.Sprintf("Sensitive credential file %q upload blocked by BAP policy", filename)
			event := NewActivityEvent("browser-playwright", g.SessionID, g.AgentID, "upload", filename, "DENY", reason)
			event.Metadata["filename"] = filename
			_ = ReportActivity(g.ControlPlaneURL, event)
			return false, reason, event
		}
	}

	// Content inspection for private keys or AWS secret keys
	if len(content) > 0 {
		lowerContent := bytes.ToLower(content)
		if bytes.Contains(lowerContent, []byte("-----begin openssh private key")) ||
			bytes.Contains(lowerContent, []byte("-----begin rsa private key")) ||
			bytes.Contains(lowerContent, []byte("-----begin private key")) ||
			bytes.Contains(lowerContent, []byte("aws_secret_access_key")) {
			reason := fmt.Sprintf("Cryptographic secret or API credential detected in upload payload %q", filename)
			event := NewActivityEvent("browser-playwright", g.SessionID, g.AgentID, "upload", filename, "DENY", reason)
			event.Metadata["filename"] = filename
			_ = ReportActivity(g.ControlPlaneURL, event)
			return false, reason, event
		}
	}

	reason := fmt.Sprintf("File upload %q permitted", filename)
	event := NewActivityEvent("browser-playwright", g.SessionID, g.AgentID, "upload", filename, "ALLOW", reason)
	event.Metadata["filename"] = filename
	_ = ReportActivity(g.ControlPlaneURL, event)
	return true, reason, event
}

package main

import (
	"bap-gateway/internal/egress"
	"bap-gateway/internal/httptransport"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type GatewayConfig struct {
	Port         int
	ControlPlane string
	SecretKey    string
	UseConsume   bool
}

type ConsumeResponse struct {
	Consumed      bool     `json:"consumed"`
	GrantID       string   `json:"grant_id"`
	AgentID       string   `json:"agent_id"`
	AppID         string   `json:"app_id"`
	SessionID     string   `json:"session_id,omitempty"`
	Action        string   `json:"action,omitempty"`
	Resource      string   `json:"resource,omitempty"`
	PolicyVersion string   `json:"policy_version,omitempty"`
	Scopes        []string `json:"scopes"`
	ExpiresAt     int64    `json:"expires_at"`
	Lineage       []string `json:"lineage,omitempty"`
	LineageTree   string   `json:"lineage_tree,omitempty"`
	RootAgentID   string   `json:"root_agent_id,omitempty"`
	ParentGrantID string   `json:"parent_grant_id,omitempty"`
}

type TokenClaims struct {
	GrantID       string   `json:"jti"`
	Sub           string   `json:"sub"`
	AppID         string   `json:"app_id"`
	InstanceID    string   `json:"instance_id,omitempty"`
	SPIFFEID      string   `json:"spiffe_id,omitempty"`
	AgentName     string   `json:"agent_name"`
	EnvProfile    string   `json:"env_profile"`
	SessionID     string   `json:"session_id,omitempty"`
	Action        string   `json:"action,omitempty"`
	Resource      string   `json:"resource,omitempty"`
	PolicyVersion string   `json:"policy_version,omitempty"`
	Scopes        []string `json:"scopes"`
	Exp           int64    `json:"exp"`
	// Delegation Lineage & Attenuation (BAP-532)
	ParentGrantID string   `json:"parent_grant_id,omitempty"`
	RootGrantID   string   `json:"root_grant_id,omitempty"`
	RootAgentID   string   `json:"root_agent_id,omitempty"`
	ParentAgentID string   `json:"parent_agent_id,omitempty"`
	Lineage       []string `json:"lineage,omitempty"`
	LineageTree   string   `json:"lineage_tree,omitempty"`
	Depth         int      `json:"depth,omitempty"`
}

func main() {
	defaultCP, defaultPort := resolveConfig()
	port := flag.Int("port", defaultPort, "Port for BAP Gateway PEP HTTP server")
	cpURL := flag.String("controlplane", defaultCP, "BAP Control Plane base URL")
	defaultSecret := ""
	if envSec := os.Getenv("BAP_SECRET_KEY"); envSec != "" {
		defaultSecret = envSec
	}
	secret := flag.String("secret", defaultSecret, "HMAC secret key for offline JWT verification")
	consume := flag.Bool("consume", true, "Atomically consume single-use grants via control plane")
	flag.Parse()
 if !*consume && (*secret == "" || *secret == "ltd-service-bounded-authority-secret-key-32b!") { log.Fatal("Offline verification requires an explicitly configured private signing secret") }

	cfg := GatewayConfig{
		Port:         *port,
		ControlPlane: strings.TrimRight(*cpURL, "/"),
		SecretKey:    *secret,
		UseConsume:   *consume,
	}

	mux := http.NewServeMux()

	// Public Health
	mux.HandleFunc("/health", handleHealth)
	mux.HandleFunc("/api/v1/health", handleHealth)

	// Protected Backend Endpoints (Guarded by Gateway PEP)
	mux.HandleFunc("/api/v1/financial-records", pepGuard(cfg, handleFinancialRecords))
	mux.HandleFunc("/api/v1/core-banking/", pepGuard(cfg, handleCoreBanking))

	// Identity-Aware Egress Guard (BAP-530: PromptArmor Multi-Tenant Exfiltration Defense)
	mux.HandleFunc("/api/v1/egress/proxy", pepEgressGuard(cfg, handleEgressProxy))
	mux.HandleFunc("/api/v1/egress", pepEgressGuard(cfg, handleEgressProxy))
	mux.HandleFunc("/egress/", pepEgressGuard(cfg, handleEgressProxy))

	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Printf("===============================================================================")
	log.Printf("   BAP ZERO-TRUST GATEWAY POLICY ENFORCEMENT POINT (PEP)")
	log.Printf("   Emulating Envoy Proxy / Istio Ingress with ext_authz Semantics")
	log.Printf("===============================================================================")
	log.Printf("[bap-gateway] Listening on http://localhost%s", addr)
	log.Printf("[bap-gateway] Control Plane PEP Target : %s", cfg.ControlPlane)
	log.Printf("[bap-gateway] Atomic Grant Burning    : %v", cfg.UseConsume)
	log.Printf("[bap-gateway] Protected Endpoints      : /api/v1/financial-records, /api/v1/core-banking/*, /api/v1/egress/*")

	server := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("[bap-gateway] ERROR: Could not start gateway on %s: %v", addr, err)
		log.Printf("[bap-gateway] Note: Port %d is already in use by another running instance or process.", cfg.Port)
		time.Sleep(1 * time.Second)
		os.Exit(1)
	}
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"service":   "bap-gateway-pep",
		"status":    "healthy",
		"mode":      "envoy-ext-authz-emulator",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}

// BAP-411: PEP derives authoritative action and resource strictly from HTTP request method and path,
// deliberately ignoring any client-provided action hints (e.g. X-Agent-Action headers).
func deriveOperation(method, path string) (action, resource string) {
	cleanPath := strings.TrimRight(path, "/")
	if strings.HasPrefix(cleanPath, "/api/v1/financial-records") {
		if method == http.MethodGet {
			return "financial.records.read", "/api/v1/financial-records"
		}
		return "financial.records.write", "/api/v1/financial-records"
	}
	if strings.HasPrefix(cleanPath, "/api/v1/core-banking") {
		if method == http.MethodGet {
			return "core_banking.read", cleanPath
		} else if method == http.MethodPost {
			return "core_banking.transfer", cleanPath
		}
		return "core_banking.write", cleanPath
	}
	return strings.ToLower(method) + ":" + cleanPath, cleanPath
}

// pepGuard enforces BAP Grant authentication on every incoming request.
// If the caller is a rogue agent (no BAP grant or invalid/consumed token), it drops the request with 401/403.
func pepGuard(cfg GatewayConfig, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		authHeader := r.Header.Get("Authorization")

		// 1. Rogue Detection: Missing or malformed Authorization header
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			durationMs := time.Since(start).Milliseconds()
			log.Printf("[BAP-GATEWAY-PEP] [BLOCKED ROGUE AGENT] 401 Unauthorized | Path: %s | Source: %s | Latency: %dms | Reason: Missing BAP Grant Bearer Token",
				r.URL.Path, r.RemoteAddr, durationMs)

			emitGatewayAudit(cfg, "", "rogue-agent", "unknown", r.URL.Path, r.Method, "deny", "BLOCKED ROGUE AGENT: Missing BAP Grant Bearer Token at Gateway PEP (HTTP 401)", durationMs, 401)

			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":         "AccessDenied",
				"gateway":       "bap-gateway-pep",
				"pep_decision":  "DENY",
				"message":       "Blocked by Zero-Trust Gateway PEP: Rogue agent request lacking BAP Bearer Grant.",
				"security_note": "Internal microservice was NEVER contacted. Access requires a valid BAP Grant from bapcontrolplane.",
				"required_auth": "Bearer <bap_grant_token>",
			})
			return
		}

		token := strings.TrimSpace(authHeader[7:])
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":        "AccessDenied",
				"pep_decision": "DENY",
				"message":      "Empty Bearer token provided.",
			})
			return
		}

		// BAP-411: PEP derives actual operation from trusted request characteristics, ignoring agent headers
		action, resource := deriveOperation(r.Method, r.URL.Path)
		sessID := r.Header.Get("X-BAP-Session-ID")

		// 2. Grant Validation & Atomic Consumption (BAP-412 & BAP-417)
		valid, claims, err := validateGrantWithDetails(cfg, token, action, resource, sessID)
		durationMs := time.Since(start).Milliseconds()

		if !valid || err != nil {
			reason := "Invalid, expired, or replayed BAP Grant"
			if err != nil {
				reason = err.Error()
			}
			log.Printf("[BAP-GATEWAY-PEP] [BLOCKED FORBIDDEN] 403 Forbidden | Path: %s | Source: %s | Latency: %dms | Reason: %s",
				r.URL.Path, r.RemoteAddr, durationMs, reason)

			emitGatewayAudit(cfg, sessID, "unauthorized-agent", "unknown", r.URL.Path, r.Method, "deny", "BLOCKED FORBIDDEN: "+reason+" (HTTP 403)", durationMs, 403)

			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":         "Forbidden",
				"gateway":       "bap-gateway-pep",
				"pep_decision":  "DENY",
				"message":       "BAP Grant verification failed: " + reason,
				"security_note": "Token signature invalid, expired, or already burned.",
			})
			return
		}

		// 3. Permitted Governed Request: Inject verified identity headers into request context
		log.Printf("[BAP-GATEWAY-PEP] [PERMIT GOVERNED] 200 OK | Path: %s | Workload: %s | App: %s | Latency: %dms",
			r.URL.Path, claims.Sub, claims.AppID, durationMs)

		emitGatewayAudit(cfg, sessID, claims.Sub, claims.AppID, r.URL.Path, r.Method, "allow", "GATEWAY PEP: Verified BAP Grant for "+claims.Sub+" (HTTP 200)", durationMs, 200)

		r.Header.Set("X-BAP-Verified-Workload", claims.Sub)
		r.Header.Set("X-BAP-Verified-App", claims.AppID)
		r.Header.Set("X-BAP-Verified-Grant", claims.GrantID)
		if claims.Action != "" {
			r.Header.Set("X-BAP-Verified-Action", claims.Action)
		}
		if claims.Resource != "" {
			r.Header.Set("X-BAP-Verified-Resource", claims.Resource)
		}
		if claims.LineageTree != "" {
			r.Header.Set("X-BAP-Verified-Lineage", claims.LineageTree)
		}
		if claims.RootAgentID != "" {
			r.Header.Set("X-BAP-Verified-Root-Agent", claims.RootAgentID)
		}
		if claims.ParentGrantID != "" {
			r.Header.Set("X-BAP-Verified-Parent-Grant", claims.ParentGrantID)
		}

		next(w, r)
	}
}

// pepEgressGuard enforces identity-aware egress control and multi-tenant exfiltration defense (BAP-530).
// It verifies destination tenant identifiers against approved enterprise tenants (e.g. corp-org, corp-internal).
func pepEgressGuard(cfg GatewayConfig, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		authHeader := r.Header.Get("Authorization")

		// Determine target destination URL/host
		targetURL := r.Header.Get("X-BAP-Target-URL")
		if targetURL == "" {
			targetURL = r.URL.Query().Get("target")
		}
		if targetURL == "" {
			targetURL = r.URL.String()
		}

		sessID := r.Header.Get("X-BAP-Session-ID")

		// 1. Rogue Detection: Missing or malformed Authorization header
		if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
			durationMs := time.Since(start).Milliseconds()
			log.Printf("[BAP-GATEWAY-PEP] [EGRESS BLOCKED ROGUE] 401 Unauthorized | Target: %s | Source: %s | Reason: Missing BAP Grant",
				targetURL, r.RemoteAddr)

			emitGatewayAuditWithTenant(cfg, sessID, "rogue-agent", "unknown", targetURL, r.Method, "deny", "BLOCKED ROGUE AGENT: Missing BAP Grant Bearer Token at Gateway Egress PEP (HTTP 401)", "", targetURL, durationMs, 401)

			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":         "AccessDenied",
				"gateway":       "bap-gateway-pep",
				"pep_decision":  "DENY",
				"message":       "Blocked by Zero-Trust Gateway Egress PEP: Rogue agent request lacking BAP Bearer Grant.",
				"security_note": "Outbound egress destination was NEVER contacted. Access requires a valid BAP Grant.",
				"required_auth": "Bearer <bap_grant_token>",
			})
			return
		}

		token := strings.TrimSpace(authHeader[7:])
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"error":        "AccessDenied",
				"pep_decision": "DENY",
				"message":      "Empty Bearer token provided.",
			})
			return
		}

		// 2. Multi-Tenant Egress Inspection (BAP-530 PromptArmor Defense)
		extraction := egress.ExtractTenant(targetURL, r.Method, r.Header)
		approvedList := egress.GetApprovedTenants()

		// If destination is a multi-tenant SaaS service, enforce tenant authorization
		if extraction.IsMultiTenant {
			if extraction.TenantID == "" || !egress.IsTenantApproved(extraction.TenantID, approvedList) {
				durationMs := time.Since(start).Milliseconds()
				reason := fmt.Sprintf("Tenant mismatch: Destination tenant '%s' for service '%s' is not in approved enterprise tenant list %v",
					extraction.TenantID, extraction.Service, approvedList)

				log.Printf("[BAP-GATEWAY-PEP] [BLOCKED MULTI-TENANT EXFILTRATION] 403 Forbidden | Target: %s | Service: %s | Tenant: %s | Reason: %s",
					targetURL, extraction.Service, extraction.TenantID, reason)

				emitGatewayAuditWithTenant(cfg, sessID, "unauthorized-egress", "promptarmor-defense", targetURL, r.Method, "deny",
					"BLOCKED EXFILTRATION: TenantMismatchBlocked - "+reason+" (HTTP 403)", extraction.TenantID, extraction.CanonicalResource, durationMs, 403)

				writeJSON(w, http.StatusForbidden, map[string]any{
					"error":                 "TenantMismatchBlocked",
					"gateway":               "bap-gateway-pep",
					"pep_decision":          "DENY",
					"http_status":           403,
					"message":               "Blocked by Multi-Tenant Exfiltration Defense: Destination tenant identity is not approved.",
					"destination_service":   extraction.Service,
					"destination_tenant_id": extraction.TenantID,
					"canonical_resource":    extraction.CanonicalResource,
					"security_rule":         "PromptArmor Defense: Same-domain multi-tenant egress to unauthorized tenants is forbidden.",
					"approved_tenants":      approvedList,
				})
				return
			}
		}

		// 3. Grant Validation & Atomic Consumption
		action := "HTTP:" + r.Method
		resource := extraction.CanonicalResource
		if resource == "" {
			resource = targetURL
		}

		valid, claims, err := validateGrantWithDetails(cfg, token, action, resource, sessID)
		durationMs := time.Since(start).Milliseconds()

		if !valid || err != nil {
			// Fallback check: try with standard egress action/resource if specific didn't match
			valid2, claims2, err2 := validateGrantWithDetails(cfg, token, "", "", sessID)
			if !valid2 || err2 != nil {
				reason := "Invalid, expired, or replayed BAP Grant"
				if err != nil {
					reason = err.Error()
				}
				log.Printf("[BAP-GATEWAY-PEP] [EGRESS BLOCKED FORBIDDEN] 403 Forbidden | Target: %s | Reason: %s", targetURL, reason)

				emitGatewayAuditWithTenant(cfg, sessID, "unauthorized-agent", "unknown", targetURL, r.Method, "deny",
					"BLOCKED FORBIDDEN: "+reason+" (HTTP 403)", extraction.TenantID, extraction.CanonicalResource, durationMs, 403)

				writeJSON(w, http.StatusForbidden, map[string]any{
					"error":         "Forbidden",
					"gateway":       "bap-gateway-pep",
					"pep_decision":  "DENY",
					"message":       "BAP Grant verification failed for egress: " + reason,
					"security_note": "Token signature invalid, expired, or already burned.",
				})
				return
			}
			claims = claims2
		}

		// 4. Permitted Governed Egress Request: Inject verified headers into request context
		log.Printf("[BAP-GATEWAY-PEP] [PERMIT EGRESS] 200 OK | Target: %s | Service: %s | Tenant: %s | Workload: %s",
			targetURL, extraction.Service, extraction.TenantID, claims.Sub)

		emitGatewayAuditWithTenant(cfg, sessID, claims.Sub, claims.AppID, targetURL, r.Method, "allow",
			"GATEWAY PEP: Verified BAP Grant for "+claims.Sub+" to tenant "+extraction.TenantID+" (HTTP 200)",
			extraction.TenantID, extraction.CanonicalResource, durationMs, 200)

		r.Header.Set("X-BAP-Verified-Workload", claims.Sub)
		r.Header.Set("X-BAP-Verified-App", claims.AppID)
		r.Header.Set("X-BAP-Verified-Grant", claims.GrantID)
		if extraction.TenantID != "" {
			r.Header.Set("X-BAP-Verified-Tenant", extraction.TenantID)
		}
		if extraction.Service != "" {
			r.Header.Set("X-BAP-Verified-Service", extraction.Service)
		}
		if extraction.CanonicalResource != "" {
			r.Header.Set("X-BAP-Verified-Resource", extraction.CanonicalResource)
		}

		next(w, r)
	}
}

func emitGatewayAudit(cfg GatewayConfig, sessionID, agentID, appID, path, method, decision, reason string, durationMs int64, exitCode int) {
	emitGatewayAuditWithTenant(cfg, sessionID, agentID, appID, path, method, decision, reason, "", "", durationMs, exitCode)
}

func emitGatewayAuditWithTenant(cfg GatewayConfig, sessionID, agentID, appID, path, method, decision, reason, destinationTenantID, canonicalResource string, durationMs int64, exitCode int) {
	ev := map[string]any{
		"event_id":              fmt.Sprintf("ev-pep-%d", time.Now().UnixNano()),
		"session_id":            sessionID,
		"agent_id":              agentID,
		"timestamp":             time.Now().UTC().Format(time.RFC3339),
		"source":                "bap-gateway-pep",
		"executable":            fmt.Sprintf("%s %s", method, path),
		"full_command":          fmt.Sprintf("PEP GATEWAY %s %s [%s]", method, path, strings.ToUpper(decision)),
		"decision":              decision,
		"reason":                reason,
		"duration_ms":           durationMs,
		"exit_code":             exitCode,
		"destination_tenant_id": destinationTenantID,
		"canonical_resource":    canonicalResource,
	}

	go func() {
		// 1. Post to Control Plane
		if cfg.ControlPlane != "" {
			data, _ := json.Marshal(ev)
			client := httptransport.New(2 * time.Second)
			_, _ = client.Post(cfg.ControlPlane+"/api/v1/audit/ingest", "application/json", bytes.NewReader(data))
		}

		// 2. Append to local .bapstate/audit.jsonl or legacy ltd-audit.jsonl
		for _, auditFile := range []string{".bapstate/audit.jsonl", "../.bapstate/audit.jsonl", "ltd-audit.jsonl", "../ltd-audit.jsonl"} {
			if f, err := os.OpenFile(auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
				data, _ := json.Marshal(ev)
				_, _ = f.Write(append(data, '\n'))
				_ = f.Close()
				break
			}
		}
	}()
}

func validateGrant(cfg GatewayConfig, token, resource string) (bool, *TokenClaims, error) {
	return validateGrantWithDetails(cfg, token, "", resource, "")
}

func validateGrantWithDetails(cfg GatewayConfig, token, action, resource, sessionID string) (bool, *TokenClaims, error) {
	// Mode A: Central Control Plane Atomic Consumption (/api/v1/grants/consume)
	if cfg.UseConsume {
		payload := map[string]string{
			"token":      token,
			"action":     action,
			"resource":   resource,
			"session_id": sessionID,
		}
		body, _ := json.Marshal(payload)
		url := fmt.Sprintf("%s/api/v1/grants/consume", cfg.ControlPlane)

		client := httptransport.New(2 * time.Second)
		resp, err := client.Post(url, "application/json", bytes.NewBuffer(body))
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				var consumeResp ConsumeResponse
				if err := json.NewDecoder(resp.Body).Decode(&consumeResp); err == nil && consumeResp.Consumed {
					claims := &TokenClaims{
						GrantID:       consumeResp.GrantID,
						Sub:           consumeResp.AgentID,
						AppID:         consumeResp.AppID,
						SessionID:     consumeResp.SessionID,
						Action:        consumeResp.Action,
						Resource:      consumeResp.Resource,
						PolicyVersion: consumeResp.PolicyVersion,
						Scopes:        consumeResp.Scopes,
						Exp:           consumeResp.ExpiresAt,
						Lineage:       consumeResp.Lineage,
						LineageTree:   consumeResp.LineageTree,
						RootAgentID:   consumeResp.RootAgentID,
						ParentGrantID: consumeResp.ParentGrantID,
					}
					return true, claims, nil
				}
			} else {
				respBody, _ := io.ReadAll(resp.Body)
				return false, nil, fmt.Errorf("control plane rejected grant (HTTP %d): %s", resp.StatusCode, string(respBody))
			}
		}
		return false, nil, fmt.Errorf("central grant consumption unavailable or returned an invalid response; access denied")
	}

	// Mode B: Local Cryptographic Fallback (Decentralized HMAC verification)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return false, nil, fmt.Errorf("malformed JWT token")
	}

	unsigned := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(cfg.SecretKey))
	mac.Write([]byte(unsigned))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(parts[2]), []byte(expectedSig)) {
		return false, nil, fmt.Errorf("cryptographic signature mismatch")
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, nil, fmt.Errorf("failed to decode claims base64")
	}

	var claims TokenClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return false, nil, fmt.Errorf("failed to parse claims JSON")
	}

	if time.Now().Unix() >= claims.Exp {
		return false, nil, fmt.Errorf("BAP grant expired at %s", time.Unix(claims.Exp, 0).Format(time.RFC3339))
	}

	// BAP-412: Operation matching checks
	if claims.SessionID != "" && sessionID != "" && !strings.EqualFold(claims.SessionID, sessionID) {
		return false, nil, fmt.Errorf("session mismatch: grant bound to %s, caller presented %s", claims.SessionID, sessionID)
	}
	if claims.Action != "" && action != "" && claims.Action != "*" && !strings.EqualFold(claims.Action, action) {
		return false, nil, fmt.Errorf("action mismatch: grant authorized %s, requested %s", claims.Action, action)
	}
	if claims.Resource != "" && resource != "" && claims.Resource != "*" && !strings.EqualFold(claims.Resource, resource) {
		return false, nil, fmt.Errorf("resource mismatch: grant authorized %s, requested %s", claims.Resource, resource)
	}

	return true, &claims, nil
}

func handleFinancialRecords(w http.ResponseWriter, r *http.Request) {
	workload := r.Header.Get("X-BAP-Verified-Workload")
	appID := r.Header.Get("X-BAP-Verified-App")

	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "success",
		"gateway":           "bap-gateway-pep",
		"pep_decision":      "ALLOW",
		"verified_workload": workload,
		"verified_app":      appID,
		"security_boundary": "Perimeter Gateway Enforcement Verified",
		"accounts": []map[string]any{
			{"account_id": "ACC-98124", "holder": "Apex Capital Management", "balance": 42500000.00, "currency": "USD", "risk_tier": "Tier-1"},
			{"account_id": "ACC-54219", "holder": "Global Sovereign Fund LTD", "balance": 18200000.00, "currency": "EUR", "risk_tier": "Tier-1"},
			{"account_id": "ACC-11048", "holder": "Enterprise Treasury Reserve", "balance": 95000000.00, "currency": "USD", "risk_tier": "Critical"},
		},
	})
}

func handleCoreBanking(w http.ResponseWriter, r *http.Request) {
	workload := r.Header.Get("X-BAP-Verified-Workload")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "success",
		"gateway":           "bap-gateway-pep",
		"verified_workload": workload,
		"action":            "core_banking_query",
		"transaction_id":    fmt.Sprintf("TXN-%d", time.Now().UnixNano()%1000000),
	})
}

func handleEgressProxy(w http.ResponseWriter, r *http.Request) {
	workload := r.Header.Get("X-BAP-Verified-Workload")
	tenant := r.Header.Get("X-BAP-Verified-Tenant")
	service := r.Header.Get("X-BAP-Verified-Service")
	res := r.Header.Get("X-BAP-Verified-Resource")

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                "permitted",
		"gateway":               "bap-gateway-pep",
		"pep_decision":          "ALLOW",
		"http_status":           200,
		"verified_workload":     workload,
		"destination_tenant_id": tenant,
		"destination_service":   service,
		"canonical_resource":    res,
		"security_boundary":     "Egress PEP Multi-Tenant Inspection Verified",
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func resolveConfig() (string, int) {
	defaultCP := "http://localhost:8080"
	defaultPort := 9090

	// 1. Check environment variables
	if v := os.Getenv("BAP_SERVER_URL"); v != "" {
		defaultCP = strings.TrimRight(v, "/")
	} else if v := os.Getenv("BAP_CONTROL_PLANE_URL"); v != "" {
		defaultCP = strings.TrimRight(v, "/")
	}

	if v := os.Getenv("BAP_GATEWAY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			defaultPort = p
		}
	} else if v := os.Getenv("PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil && p > 0 {
			defaultPort = p
		}
	}

	// 2. Candidate paths for bap-config.json
	var candidates []string
	if custom := os.Getenv("BAP_CONFIG"); custom != "" {
		candidates = append(candidates, custom)
	}

	if cwd, err := os.Getwd(); err == nil {
		curr := cwd
		for i := 0; i < 4; i++ {
			candidates = append(candidates, filepath.Join(curr, "bap-config.json"))
			parent := filepath.Dir(curr)
			if parent == curr {
				break
			}
			curr = parent
		}
	}

	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		candidates = append(candidates, filepath.Join(exeDir, "bap-config.json"))
		candidates = append(candidates, filepath.Join(exeDir, "..", "bap-config.json"))
	}

	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".bap", "config.json"))
		candidates = append(candidates, filepath.Join(home, ".bap", "bap-config.json"))
	}

	if runtime.GOOS == "windows" {
		if progData := os.Getenv("ProgramData"); progData != "" {
			candidates = append(candidates, filepath.Join(progData, "BAP", "bap-config.json"))
			candidates = append(candidates, filepath.Join(progData, "BAP", "config.json"))
		}
	} else {
		candidates = append(candidates, "/etc/bap/bap-config.json")
		candidates = append(candidates, "/etc/bap/config.json")
	}

	for _, p := range candidates {
		if data, err := os.ReadFile(p); err == nil {
			var cfg struct {
				ControlPlaneURL string `json:"controlplane_url"`
				GatewayURL      string `json:"gateway_url"`
			}
			if err := json.Unmarshal(data, &cfg); err == nil {
				if cfg.ControlPlaneURL != "" && os.Getenv("BAP_SERVER_URL") == "" && os.Getenv("BAP_CONTROL_PLANE_URL") == "" {
					defaultCP = strings.TrimRight(cfg.ControlPlaneURL, "/")
				}
				if cfg.GatewayURL != "" && os.Getenv("BAP_GATEWAY_PORT") == "" && os.Getenv("PORT") == "" {
					if u, err := url.Parse(cfg.GatewayURL); err == nil && u.Port() != "" {
						if p, err := strconv.Atoi(u.Port()); err == nil && p > 0 {
							defaultPort = p
						}
					}
				}
				log.Printf("[bap-gateway] Resolved configuration from: %s", p)
				break
			}
		}
	}

	return defaultCP, defaultPort
}

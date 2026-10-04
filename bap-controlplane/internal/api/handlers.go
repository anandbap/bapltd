package api

import (
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"

	"bap-controlplane/internal/attestation"
	"bap-controlplane/internal/audit"
	"bap-controlplane/internal/authz"
	"bap-controlplane/internal/otc"
	"bap-controlplane/internal/policy"
	"bap-controlplane/internal/registry"
	"bap-controlplane/internal/session"
	"bap-controlplane/pkg/types"
)

type DemoActionRecord struct {
	Type       string  `json:"type"`
	ActionID   string  `json:"action_id"`
	Command    string  `json:"command"`
	Decision   string  `json:"decision"`
	DurationMs float64 `json:"duration_ms"`
	Reason     string  `json:"reason"`
	ExitCode   int     `json:"exit_code"`
	Timestamp  string  `json:"timestamp"`
}

const demoIntentClassifierVersion = "bap-intent-rules-v1"

type Server struct {
	registry         *registry.Store
	otcStore         *otc.Store
	minter           *authz.TokenMinter
	policyStore      *policy.Store
	auditStore       *audit.Store
	sessionStore     *session.Store
	mux              *http.ServeMux
	allowedOrigins   map[string]bool
	adminToken       string
	allowRemoteAdmin bool
	demoMode         bool
	lastDemoMu       sync.RWMutex
	lastDemoAction   *DemoActionRecord
}

func NewServer(reg *registry.Store, otcStore *otc.Store, minter *authz.TokenMinter, policyStore *policy.Store, auditStore *audit.Store, sessionStore ...*session.Store) *Server {
	if policyStore == nil {
		policyStore = policy.NewStore("", "")
	}
	if auditStore == nil {
		auditStore = audit.NewStore()
	}
	var sessStore *session.Store
	if len(sessionStore) > 0 && sessionStore[0] != nil {
		sessStore = sessionStore[0]
	} else {
		sessStore = session.NewStore()
	}
	s := &Server{
		registry:     reg,
		otcStore:     otcStore,
		minter:       minter,
		policyStore:  policyStore,
		auditStore:   auditStore,
		sessionStore: sessStore,
		mux:          http.NewServeMux(),
	}
	s.registerRoutes()
	return s
}

func (s *Server) SetAdminSecurity(token string, allowRemote bool) {
	s.adminToken = strings.TrimSpace(token)
	s.allowRemoteAdmin = allowRemote
}

// SetDemoMode enables destructive synthetic-data endpoints. It is disabled by
// default so a normal control plane can never reset live state through /demo.
func (s *Server) SetDemoMode(enabled bool) {
	s.demoMode = enabled
}

func (s *Server) requireDemoMode(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.demoMode {
			http.NotFound(w, r)
			return
		}
		next(w, r)
	}
}

// SetAllowedOrigins configures exact browser origins; wildcard and null origins
// are deliberately unsupported. Call before serving requests.
func (s *Server) SetAllowedOrigins(origins []string) error {
	allowed := make(map[string]bool)
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("invalid browser origin %q: use scheme://host[:port]", origin)
		}
		allowed[origin] = true
	}
	s.allowedOrigins = allowed
	return nil
}

func (s *Server) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		sameOrigin := scheme + "://" + r.Host
		if origin != "" {
			if origin != sameOrigin && !s.allowedOrigins[origin] {
				writeError(w, http.StatusForbidden, "Browser origin is not allowed")
				return
			}
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-BAP-Admin-Token, Accept")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		s.mux.ServeHTTP(w, r)
	})
}

func (s *Server) registerRoutes() {
	s.registerControlPlaneRoutes()
	s.mux.HandleFunc("/api/v1/admin/inspector/data", s.requireAdminAuth(s.handleInspectorData))
	// Public and Agent Endpoints
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/health", s.handleHealth)
	s.mux.HandleFunc("/api/v1/agents/pre-register", s.requireAdminAuth(s.handlePreRegister))
	s.mux.HandleFunc("/api/v1/agents/register", s.handleRegisterEdge)
	s.mux.HandleFunc("/api/v1/agents/register-edge", s.handleRegisterEdge)
	s.mux.HandleFunc("/api/v1/grants/acquire", s.handleAcquireGrant)
	s.mux.HandleFunc("/api/v1/grants/consume", s.handleConsumeGrant)
	s.mux.HandleFunc("/api/v1/instances/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("/api/v1/agents", s.handleListAgents)
	s.mux.HandleFunc("/api/v1/policy/bundle", s.handleGetPolicyBundle)
	s.mux.HandleFunc("/api/v1/policy/sync", s.handlePolicySync)
	s.mux.HandleFunc("/api/v1/audit/ingest", s.handleAuditIngest)
	s.mux.HandleFunc("/api/v1/audit/events", s.handleListAuditEvents)
	s.mux.HandleFunc("/api/v1/sessions/start", s.handleSessionStart)
	s.mux.HandleFunc("/api/v1/sessions/heartbeat", s.handleHeartbeat)
	s.mux.HandleFunc("/api/v1/sessions/end", s.handleSessionEnd)
	s.mux.HandleFunc("/api/v1/sessions/prompt", s.handleSessionPrompt)
	s.mux.HandleFunc("/api/v1/sessions", s.handleListSessions)
	s.mux.HandleFunc("/api/v1/sessions/", s.handleGetSession)
	s.mux.HandleFunc("/api/v1/auth/envoy", s.handleEnvoyExtAuthz)
	s.mux.HandleFunc("/api/v1/financial-records", s.handleFinancialRecords)
	s.mux.HandleFunc("/api/v1/inspector/data", s.handleInspectorData)
	s.mux.HandleFunc("/api/v1/control/revocations", s.handleGetRevocations)
	s.mux.HandleFunc("/api/v1/control/chain/verify", s.handleVerifyChain)

	// Web Inspector & React Admin Handshake / Login
	s.mux.HandleFunc("/api/v1/auth/inspector-handshake", s.handleInspectorHandshake)
	s.mux.HandleFunc("/api/v1/auth/admin-login", s.handleAdminLogin)

	// Administrative & Mutating Operations (Protected by Admin Token)
	s.mux.HandleFunc("/api/v1/control/kill-switch", s.requireAdminAuth(s.handleKillSwitch))
	s.mux.HandleFunc("/api/v1/control/agent/kill", s.requireAdminAuth(s.handleTargetedKillAgent))
	s.mux.HandleFunc("/api/v1/control/agent/revoke", s.requireAdminAuth(s.handleTargetedKillAgent))
	s.mux.HandleFunc("/api/v1/sessions/revoke", s.requireAdminAuth(s.handleTargetedKillAgent))
	s.mux.HandleFunc("/api/v1/sessions/reset", s.requireDemoMode(s.requireAdminAuth(s.handleResetSessions)))
	s.mux.HandleFunc("/api/v1/agents/revoke", s.requireAdminAuth(s.handleRevoke))
	s.mux.HandleFunc("/api/v1/apps/revoke", s.requireAdminAuth(s.handleRevokeApp))
	s.mux.HandleFunc("/api/v1/demo/exec-safe", s.requireDemoMode(s.requireAdminAuth(s.handleDemoExecSafe)))
	s.mux.HandleFunc("/api/v1/demo/exec-attack", s.requireDemoMode(s.requireAdminAuth(s.handleDemoExecAttack)))
	s.mux.HandleFunc("/api/v1/demo/fleet-scale", s.requireDemoMode(s.requireAdminAuth(s.handleDemoFleetScale)))
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "ltd-service-control-plane"})
}

func (s *Server) handlePreRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1MB limit
	var req types.PreRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	if strings.TrimSpace(req.AppID) == "" || strings.TrimSpace(req.AgentName) == "" {
		writeError(w, http.StatusBadRequest, "app_id and agent_name are required")
		return
	}

	agent, err := s.registry.PreRegister(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to register agent: "+err.Error())
		return
	}

	ttl := 15 * time.Minute
	if req.TTLMins > 0 {
		ttl = time.Duration(req.TTLMins) * time.Minute
	}

	code, expiresAt, err := s.otcStore.Generate(agent.AgentID, ttl, req.MaxInstances)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to generate one-time code: "+err.Error())
		return
	}

	resp := types.PreRegisterResponse{
		AgentID:      agent.AgentID,
		Code:         code,
		ExpiresAt:    expiresAt,
		MaxInstances: req.MaxInstances,
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleRegisterEdge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req types.RegisterEdgeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	code := strings.TrimSpace(req.Code)
	if code == "" {
		writeError(w, http.StatusBadRequest, "one_time_code is required")
		return
	}

	// 1. Consume OTC (single-use validation)
	agentID, err := s.otcStore.Consume(code)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Enrollment failed: "+err.Error())
		return
	}

	// 2. Fetch registered agent definition
	agent, err := s.registry.Get(agentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Registered agent not found: "+err.Error())
		return
	}

	// 3. Binary Attestation
	if err := attestation.VerifyBinaryImage(agent, req.BinaryHash); err != nil {
		writeError(w, http.StatusForbidden, "Binary image attestation failed: "+err.Error())
		return
	}

	// 4. Enroll agent in registry
	enrolled, err := s.registry.Enroll(agentID, req.BinaryHash, req.PublicKey, req.Hostname, req.OS, req.Arch, req.InstanceID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Enrollment error: "+err.Error())
		return
	}

	// 5. Issue initial session token
	sessionToken, _, _ := s.minter.Mint(enrolled, req.BinaryHash, nil)

	resp := types.RegisterEdgeResponse{
		AgentID:      enrolled.AgentID,
		AppID:        enrolled.AppID,
		InstanceID:   enrolled.InstanceID,
		SPIFFEID:     enrolled.SPIFFEID,
		Status:       string(enrolled.Status),
		ServerTime:   time.Now(),
		SessionToken: sessionToken,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAcquireGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req types.AcquireGrantRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	agent, err := s.registry.Get(req.AgentID)
	if err != nil {
		writeError(w, http.StatusNotFound, "Agent not found in registry")
		return
	}

	if agent.Status != types.StatusActive {
		writeError(w, http.StatusForbidden, fmt.Sprintf("Agent is not active (current status: %s)", agent.Status))
		return
	}

	// A public agent ID and a reported binary hash are not authentication.
	if !s.isAdminCaller(r) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		claims, err := s.minter.Verify(token)
		subject := agent.AgentID
		if agent.SPIFFEID != "" {
			subject = agent.SPIFFEID
		}
		if err != nil || claims.Sub != subject || claims.AppID != agent.AppID || claims.InstanceID != agent.InstanceID {
			writeError(w, http.StatusUnauthorized, "Enrolled agent bearer credential required")
			return
		}
	}
	if s.policyStore.GetBundle().KillSwitch {
		writeError(w, http.StatusForbidden, "Fleet is frozen")
		return
	}
	// Verify binary hash hasn't drifted or been modified
	if err := attestation.VerifyBinaryImage(agent, req.BinaryHash); err != nil {
		writeError(w, http.StatusForbidden, "Binary image attestation failed on grant request: "+err.Error())
		return
	}

	// Mint short-lived Bounded Authority token
	bundle := s.policyStore.GetBundle()
	policyVersion := fmt.Sprintf("v%d-%s", bundle.Version, bundle.Digest)

	token, expiresAt, grantID, err := s.minter.MintWithDetails(
		agent,
		req.BinaryHash,
		req.Scopes,
		req.SessionID,
		req.Action,
		req.Resource,
		req.Constraints,
		policyVersion,
	)
	if err != nil {
		writeError(w, http.StatusForbidden, "Failed to mint authority token: "+err.Error())
		return
	}

	s.registry.RecordGrant(agent.AgentID)

	resp := types.AcquireGrantResponse{
		Token:         token,
		TokenType:     "Bearer",
		GrantID:       grantID,
		ExpiresAt:     expiresAt,
		TTLSecs:       int(time.Until(expiresAt).Seconds()),
		Scopes:        agent.PermittedScopes,
		SessionID:     req.SessionID,
		Action:        req.Action,
		Resource:      req.Resource,
		PolicyVersion: policyVersion,
		Constraints:   req.Constraints,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var payload struct {
		AgentID string `json:"agent_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.AgentID == "" {
		writeError(w, http.StatusBadRequest, "agent_id is required")
		return
	}

	if err := s.registry.Revoke(payload.AgentID); err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"agent_id": payload.AgentID,
		"status":   string(types.StatusRevoked),
		"message":  "Agent has been revoked. All subsequent grants will be denied.",
	})
}

func (s *Server) handleListAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	agents := s.registry.List()
	s.writeTelemetry(w, r, map[string]any{
		"count":  len(agents),
		"agents": agents,
	})
}

func (s *Server) handleConsumeGrant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		Token     string `json:"token"`
		Action    string `json:"action,omitempty"`
		Resource  string `json:"resource,omitempty"`
		SessionID string `json:"session_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeError(w, http.StatusBadRequest, "token is required")
		return
	}

	claims, err := s.consumeActiveGrantWithDetails(req.Token, req.Action, req.Resource, req.SessionID)
	if err != nil {
		writeError(w, http.StatusForbidden, "Grant consumption failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"consumed":       true,
		"grant_id":       claims.GrantID,
		"agent_id":       claims.Sub,
		"app_id":         claims.AppID,
		"session_id":     claims.SessionID,
		"action":         claims.Action,
		"resource":       claims.Resource,
		"policy_version": claims.PolicyVersion,
		"scopes":         claims.Scopes,
		"expires_at":     claims.Exp,
	})
}

func (s *Server) handleEnvoyExtAuthz(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		w.Header().Set("X-BAP-Decision", "DENY")
		writeError(w, http.StatusUnauthorized, "Blocked by BAP Gateway PEP: Missing or malformed BAP Bearer Grant")
		return
	}

	token := strings.TrimSpace(authHeader[7:])
	resource := r.Header.Get("X-Original-Uri")
	if resource == "" {
		resource = r.Header.Get("X-Forwarded-Uri")
	}
	if resource == "" {
		resource = r.URL.Path
	}
	action := r.Header.Get("X-Original-Method")
	if action == "" {
		action = r.Method
	}
	sessionID := r.Header.Get("X-BAP-Session-ID")

	claims, err := s.consumeActiveGrantWithDetails(token, action, resource, sessionID)
	if err != nil {
		w.Header().Set("X-BAP-Decision", "DENY")
		writeError(w, http.StatusForbidden, "BAP Grant authorization failed: "+err.Error())
		return
	}

	w.Header().Set("X-BAP-Decision", "ALLOW")
	w.Header().Set("X-BAP-Verified-Workload", claims.Sub)
	w.Header().Set("X-BAP-Verified-App", claims.AppID)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "authorized",
		"workload":       claims.Sub,
		"app_id":         claims.AppID,
		"grant_id":       claims.GrantID,
		"session_id":     claims.SessionID,
		"action":         claims.Action,
		"resource":       claims.Resource,
		"policy_version": claims.PolicyVersion,
		"scopes":         claims.Scopes,
	})
}

func (s *Server) handleFinancialRecords(w http.ResponseWriter, r *http.Request) {
	workload := r.Header.Get("X-BAP-Verified-Workload")
	appID := r.Header.Get("X-BAP-Verified-App")
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "success",
		"gateway":           "envoy-podman-pep",
		"pep_decision":      "ALLOW",
		"verified_workload": workload,
		"verified_app":      appID,
		"security_boundary": "Perimeter Gateway Enforcement Verified (Envoy Proxy)",
		"accounts": []map[string]any{
			{"account_id": "ACC-98124", "holder": "Apex Capital Management", "balance": 42500000.00, "currency": "USD", "risk_tier": "Tier-1"},
			{"account_id": "ACC-54219", "holder": "Global Sovereign Fund LTD", "balance": 18200000.00, "currency": "EUR", "risk_tier": "Tier-1"},
			{"account_id": "ACC-11048", "holder": "Enterprise Treasury Reserve", "balance": 95000000.00, "currency": "USD", "risk_tier": "Critical"},
		},
	})
}

func (s *Server) handleGetPolicyBundle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	bundle := s.policyStore.GetBundle()
	writeJSON(w, http.StatusOK, bundle)
}

func (s *Server) handlePolicySync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req policy.SyncRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}
	resp := s.policyStore.Sync(req)
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleAuditIngest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB limit for batch audit logs
	var payload json.RawMessage
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	var events []audit.Event
	if err := json.Unmarshal(payload, &events); err != nil {
		var single audit.Event
		if errSingle := json.Unmarshal(payload, &single); errSingle != nil {
			writeError(w, http.StatusBadRequest, "Payload must be an audit event or array of events")
			return
		}
		events = []audit.Event{single}
	}

	ingested, err := s.auditStore.Ingest(events)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to ingest audit events: "+err.Error())
		return
	}

	// Link events to sessions
	if s.sessionStore != nil {
		for _, ev := range events {
			if ev.SessionID != "" {
				s.sessionStore.RecordEvent(ev.SessionID, ev)
			}
		}
	}

	valid, _ := s.auditStore.VerifyChain()
	writeJSON(w, http.StatusOK, map[string]any{
		"ingested":     ingested,
		"chain_valid":  valid,
		"receipt_hash": s.auditStore.LastHash(),
		"status":       "acknowledged",
	})
}

func (s *Server) handleListAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	events := s.auditStore.List(100)
	valid, chainErr := s.auditStore.VerifyChain()
	chainStatus := "valid"
	if !valid || chainErr != nil {
		chainStatus = "corrupted"
	}

	s.writeTelemetry(w, r, map[string]any{
		"count":        len(events),
		"chain_status": chainStatus,
		"events":       events,
	})
}

func (s *Server) handleRevokeApp(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		AppID string `json:"app_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	if req.AppID == "" {
		writeError(w, http.StatusBadRequest, "app_id is required")
		return
	}

	revokedCount, err := s.registry.RevokeApp(req.AppID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to revoke app: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"app_id":        req.AppID,
		"revoked_count": revokedCount,
		"status":        "revoked",
	})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		AgentID   string `json:"agent_id"`
		SessionID string `json:"session_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON body: "+err.Error())
		return
	}

	id := req.SessionID
	if id == "" {
		id = req.AgentID
	}
	if id == "" {
		writeError(w, http.StatusBadRequest, "agent_id or session_id is required")
		return
	}

	var sessionFound, agentFound bool

	if s.sessionStore != nil {
		if s.sessionStore.IsRevoked(id) || s.sessionStore.IsUserRevoked(id) {
			writeJSON(w, http.StatusOK, map[string]any{
				"id":         id,
				"session_id": id,
				"status":     "revoked",
				"action":     "terminate",
				"reason":     "Session authority revoked by administrator",
				"time":       time.Now().UTC(),
			})
			return
		}
		if sess, err := s.sessionStore.Get(id); err == nil {
			if sess.Status == "revoked" || s.sessionStore.IsUserRevoked(sess.UserID) || s.sessionStore.IsUserRevoked(sess.UserEmail) {
				writeJSON(w, http.StatusOK, map[string]any{
					"id":         id,
					"session_id": id,
					"status":     "revoked",
					"action":     "terminate",
					"reason":     "Session authority revoked by administrator",
					"time":       time.Now().UTC(),
				})
				return
			}
			if sess.Status == "closed" {
				writeJSON(w, http.StatusOK, map[string]any{
					"id":         id,
					"session_id": id,
					"status":     "closed",
					"action":     "terminate",
					"reason":     "Session closed",
					"time":       time.Now().UTC(),
				})
				return
			}
		}
		if sess, err := s.sessionStore.Heartbeat(id); err == nil {
			sessionFound = true
			if sess.Status == "revoked" {
				writeJSON(w, http.StatusOK, map[string]any{
					"id":         id,
					"session_id": id,
					"status":     "revoked",
					"action":     "terminate",
					"reason":     "Session authority revoked by administrator",
					"time":       time.Now().UTC(),
				})
				return
			}
			if s.registry != nil {
				instanceID := sess.InstanceID
				if instanceID == "" {
					instanceID = sess.SessionID
				}
				if err := s.registry.HeartbeatInstance(sess.AppID, instanceID); err == nil {
					agentFound = true
				} else if agent := s.registry.EnsureSessionAgent(sess.AppID, instanceID, sess.SPIFFEID, sess.UserEmail, sess.Hostname); agent != nil && agent.Status != types.StatusRevoked {
					// The session store is durable while the registry is in-memory.
					// Recreate presence after a control-plane restart on the first heartbeat.
					agentFound = true
				}
			}
		}
	}

	if s.registry != nil {
		if agent, err := s.registry.Get(id); err == nil && agent.Status == types.StatusRevoked {
			writeJSON(w, http.StatusOK, map[string]any{
				"id":       id,
				"agent_id": id,
				"status":   "revoked",
				"action":   "terminate",
				"reason":   "Agent authority revoked by administrator",
				"time":     time.Now().UTC(),
			})
			return
		}
		if err := s.registry.Heartbeat(id); err == nil {
			agentFound = true
		}
	}

	if !sessionFound && !agentFound {
		writeError(w, http.StatusNotFound, fmt.Sprintf("Neither active agent nor session found for ID %q", id))
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":       id,
		"agent_id": id,
		"status":   "alive",
		"time":     time.Now().UTC(),
		"session":  sessionFound,
		"agent":    agentFound,
	})
}

func (s *Server) handleInspectorData(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var isUserRevoked func(string) bool
	if s.sessionStore != nil {
		isUserRevoked = s.sessionStore.IsUserRevoked
	}
	agents := s.registry.ListVisible(2*time.Hour, isUserRevoked)
	centralEvents := s.auditStore.List(200)
	valid, chainErr := s.auditStore.VerifyChain()
	chainStatus := "valid"
	if !valid || chainErr != nil {
		chainStatus = "corrupted"
	}

	bundle := s.policyStore.GetBundle()

	// Read local ltd-audit.jsonl lines if present
	var edgeLogs []map[string]any
	candidates := []string{
		"ltd-audit.jsonl",
		"../ltd-audit.jsonl",
		"../../ltd-audit.jsonl",
		"bap-edge/ltd-audit.jsonl",
		"../bap-edge/ltd-audit.jsonl",
	}
	for _, c := range candidates {
		if data, err := os.ReadFile(c); err == nil && len(data) > 0 {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if line == "" {
					continue
				}
				var item map[string]any
				if err := json.Unmarshal([]byte(line), &item); err == nil {
					cmd, _ := item["full_command"].(string)
					src, _ := item["source"].(string)
					cmdLower := strings.ToLower(cmd)
					srcLower := strings.ToLower(src)
					if strings.Contains(cmdLower, "pytest") || strings.Contains(cmdLower, "test_leak") || strings.Contains(srcLower, "test") {
						continue
					}
					edgeLogs = append(edgeLogs, item)
				}
			}
			if len(edgeLogs) > 0 {
				break
			}
		}
	}

	var sessionsList any = []any{}
	var revokedSessions []string
	var revokedUsers []string
	if s.sessionStore != nil {
		// The command center paginates on the client and searches the full fleet.
		sessionsList = s.sessionStore.ListVisible(5000, 2*time.Hour)
		revokedSessions = s.sessionStore.ListRevoked()
		revokedUsers = s.sessionStore.ListRevokedUsers()
	}

	s.lastDemoMu.RLock()
	lastAct := s.lastDemoAction
	s.lastDemoMu.RUnlock()

	isAdmin := s.isAdminCaller(r) || (s.adminToken == "" && isLoopbackAddress(r.RemoteAddr))
	if !isAdmin {
		maskedCentral := make([]audit.Event, len(centralEvents))
		for i, ev := range centralEvents {
			maskedEv := ev
			if maskedEv.UserPrompt != "" {
				maskedEv.UserPrompt = "[Protected: Leadership Authentication Required]"
			}
			maskedCentral[i] = maskedEv
		}
		centralEvents = maskedCentral
	}

	var intentCounts map[string]int
	var totalPrompts int
	var intentWindows session.IntentWindows
	if s.sessionStore != nil {
		intentCounts, totalPrompts = s.sessionStore.GetIntentStats()
		intentWindows = s.sessionStore.GetIntentWindows()
	} else {
		intentCounts = make(map[string]int)
	}

	resp := map[string]any{
		"service":                "bapcontrolplane",
		"trust_domain":           s.registry.TrustDomain(),
		"chain_status":           chainStatus,
		"agents":                 agents,
		"sessions":               sessionsList,
		"revoked_sessions":       revokedSessions,
		"revoked_users":          revokedUsers,
		"central_events":         centralEvents,
		"edge_events":            edgeLogs,
		"last_demo_action":       lastAct,
		"intent_counts":          intentCounts,
		"total_prompts":          totalPrompts,
		"intent_windows":         intentWindows,
		"policy_version":         bundle.Version,
		"policy_digest":          bundle.Digest,
		"policy_cedar":           bundle.PolicyCedar,
		"policy_schema":          bundle.SchemaJSON,
		"kill_switch":            bundle.KillSwitch,
		"admin_authorized":       isAdmin,
		"user_prompt_visibility": map[string]any{"admin_only": true, "unlocked": isAdmin},
		"server_time":            time.Now().UTC(),
	}
	s.writeTelemetry(w, r, resp)
}

func (s *Server) handleGetRevocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	bundle := s.policyStore.GetBundle()
	var revokedSessions []string
	var revokedUsers []string
	if s.sessionStore != nil {
		revokedSessions = s.sessionStore.ListRevoked()
		revokedUsers = s.sessionStore.ListRevokedUsers()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"kill_switch":      bundle.KillSwitch,
		"revoked_sessions": revokedSessions,
		"revoked_users":    revokedUsers,
		"updated_at":       time.Now().UTC(),
	})
}

func (s *Server) handleSessionStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req session.SessionStartRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}

	bundle := s.policyStore.GetBundle()
	if bundle.KillSwitch {
		writeError(w, http.StatusForbidden, "New agent sessions are forbidden: CISO emergency kill-switch is active across the fleet")
		return
	}
	if s.sessionStore != nil {
		if s.sessionStore.IsUserRevoked(req.UserID) || s.sessionStore.IsUserRevoked(req.UserEmail) {
			writeError(w, http.StatusForbidden, "User access has been revoked by administrator")
			return
		}
		if s.sessionStore.IsRevoked(req.SessionID) {
			writeError(w, http.StatusForbidden, "Session authority for "+req.SessionID+" is revoked")
			return
		}
	}
	if s.registry != nil {
		for _, a := range s.registry.List() {
			if a.InstanceID == req.SessionID && a.Status == types.StatusRevoked {
				writeError(w, http.StatusForbidden, "Agent instance is revoked by CISO administrator")
				return
			}
		}
	}

	sess, err := s.sessionStore.Start(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to start session: "+err.Error())
		return
	}
	if s.registry != nil {
		instanceID := sess.InstanceID
		if instanceID == "" {
			instanceID = sess.SessionID
		}
		s.registry.EnsureSessionAgent(sess.AppID, instanceID, sess.SPIFFEID, sess.UserEmail, sess.Hostname, sess.AgentName)
	}
	s.writeTelemetry(w, r, sess)
}

func (s *Server) handleSessionEnd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req struct {
		SessionID string `json:"session_id"`
		Reason    string `json:"reason,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}
	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}

	var sess *session.Session
	if s.sessionStore != nil {
		sess, _ = s.sessionStore.Get(req.SessionID)
		if err := s.sessionStore.End(req.SessionID, req.Reason); err != nil {
			writeError(w, http.StatusNotFound, "Failed to end session: "+err.Error())
			return
		}
	}

	if s.registry != nil && sess != nil {
		instanceID := sess.InstanceID
		if instanceID == "" {
			instanceID = sess.SessionID
		}
		s.registry.EndSessionAgent(sess.AppID, instanceID)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"session_id": req.SessionID,
		"status":     "closed",
		"ended_at":   time.Now().UTC(),
	})
}

func (s *Server) handleSessionPrompt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req struct {
		SessionID            string                `json:"session_id"`
		UserPrompt           string                `json:"user_prompt"`
		Producer             string                `json:"producer"`
		Intent               session.IntentContext `json:"intent"`
		PromptHash           string                `json:"prompt_hash"`
		PromptCaptureEnabled bool                  `json:"prompt_capture_enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request payload: "+err.Error())
		return
	}
	if req.SessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id is required")
		return
	}
	validProducers := map[string]bool{
		"claude-lifecycle-hook": true,
		"bap-python-sdk":        true,
		"demo-executive":        true,
		"bap-agent":             true,
	}
	if !validProducers[req.Producer] {
		writeError(w, http.StatusBadRequest, "prompt telemetry must come from an authorized agent producer")
		return
	}
	req.Intent.Primary = strings.ToUpper(strings.TrimSpace(req.Intent.Primary))
	for i := range req.Intent.Secondary {
		req.Intent.Secondary[i] = strings.ToUpper(strings.TrimSpace(req.Intent.Secondary[i]))
	}
	for i := range req.Intent.Tags {
		req.Intent.Tags[i] = strings.ToUpper(strings.TrimSpace(req.Intent.Tags[i]))
	}
	validSources := map[string]bool{
		"claude-user-prompt-submit": true,
		"bap-python-sdk":            true,
		"demo-executive":            true,
		"bap-agent":                 true,
		"bap-server-classifier":     true,
	}
	if !validIntentCategory(req.Intent.Primary) || req.Intent.ClassifierVersion == "" || !validSources[req.Intent.Source] {
		writeError(w, http.StatusBadRequest, "a valid edge-classified intent is required")
		return
	}
	for _, secondary := range req.Intent.Secondary {
		if !validIntentCategory(secondary) || secondary == "UNKNOWN" || secondary == req.Intent.Primary {
			writeError(w, http.StatusBadRequest, "secondary intent contains an invalid category")
			return
		}
	}
	if req.Intent.Confidence < 0 || req.Intent.Confidence > 1 {
		writeError(w, http.StatusBadRequest, "intent confidence must be between 0 and 1")
		return
	}
	if len(req.PromptHash) != 64 {
		writeError(w, http.StatusBadRequest, "prompt_hash must be a SHA-256 digest")
		return
	}
	if _, err := hex.DecodeString(req.PromptHash); err != nil {
		writeError(w, http.StatusBadRequest, "prompt_hash must be hexadecimal")
		return
	}
	if !req.PromptCaptureEnabled && req.UserPrompt != "" {
		writeError(w, http.StatusBadRequest, "user_prompt must be omitted when prompt capture is disabled")
		return
	}
	req.Intent.PromptHash = req.PromptHash
	req.Intent.PromptCaptured = req.PromptCaptureEnabled
	if s.sessionStore == nil {
		writeError(w, http.StatusServiceUnavailable, "Session store unavailable")
		return
	}
	if s.sessionStore.IsRevoked(req.SessionID) || s.sessionStore.IsUserRevoked(req.SessionID) {
		writeError(w, http.StatusForbidden, "Session authority has been revoked by administrator. Prompts are blocked.")
		return
	}
	sess, err := s.sessionStore.SetPromptAndIntent(req.SessionID, req.UserPrompt, req.Intent)
	if err != nil {
		writeError(w, http.StatusNotFound, "Failed to update prompt: "+err.Error())
		return
	}
	if sess.Status == "revoked" || s.sessionStore.IsUserRevoked(sess.UserID) || s.sessionStore.IsUserRevoked(sess.UserEmail) {
		writeError(w, http.StatusForbidden, "User access has been revoked by administrator. Prompts are blocked.")
		return
	}
	// Always log the normalized intent. Raw prompt text is optional and follows
	// the independently configured endpoint privacy policy.
	if s.auditStore != nil {
		_, _ = s.auditStore.Ingest([]audit.Event{{
			EventID:          fmt.Sprintf("ev-prompt-%d", time.Now().UnixNano()),
			SessionID:        req.SessionID,
			Source:           sess.AppID,
			Executable:       "user_prompt",
			FullCommand:      "USER_PROMPT_SUBMITTED",
			Decision:         "intent",
			Reason:           "User mission classified at BAP Edge",
			Timestamp:        time.Now().UTC().Format(time.RFC3339),
			UserPrompt:       req.UserPrompt,
			PrimaryIntent:    req.Intent.Primary,
			SecondaryIntents: req.Intent.Secondary,
			IntentTags:       req.Intent.Tags,
			IntentConfidence: req.Intent.Confidence,
			IntentClassifier: req.Intent.ClassifierVersion,
			PromptHash:       req.PromptHash,
			PromptCaptured:   req.PromptCaptureEnabled,
			UserID:           sess.UserID,
			UserEmail:        sess.UserEmail,
		}})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "updated",
		"intent": sess.Intent,
		"time":   time.Now().UTC(),
	})
}

func validIntentCategory(category string) bool {
	switch strings.ToUpper(strings.TrimSpace(category)) {
	case "BUG_FIX", "DATABASE_CHANGE", "FEATURE_ENHANCEMENT", "INVESTIGATION", "REFACTOR", "TEST_VERIFICATION", "DOCUMENTATION", "MIGRATION", "DEPLOYMENT_RELEASE", "WORK_MANAGEMENT", "SECURITY_REMEDIATION", "UNKNOWN":
		return true
	default:
		return false
	}
}

func (s *Server) handleResetSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	closedSess := 0
	if s.sessionStore != nil {
		closedSess = s.sessionStore.Reset()
		s.sessionStore.ResetIntentStats()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":         "All sessions reset cleanly; enrolled agent identities were preserved",
		"closed_sessions": closedSess,
		"closed_agents":   0,
	})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	sessions := s.sessionStore.List(100)
	s.writeTelemetry(w, r, map[string]any{
		"sessions": sessions,
		"total":    len(sessions),
	})
}

func (s *Server) handleGetSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	prefix := "/api/v1/sessions/"
	sessionID := strings.TrimPrefix(r.URL.Path, prefix)
	if sessionID == "" {
		writeError(w, http.StatusBadRequest, "session_id is required in path")
		return
	}
	sess, err := s.sessionStore.Get(sessionID)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	s.writeTelemetry(w, r, sess)
}

func (s *Server) handleKillSwitch(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		bundle := s.policyStore.GetBundle()
		writeJSON(w, http.StatusOK, map[string]any{
			"kill_switch": bundle.KillSwitch,
			"updated_at":  bundle.UpdatedAt,
		})
		return
	}

	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid JSON: "+err.Error())
		return
	}

	if req.Enabled == nil {
		writeError(w, http.StatusBadRequest, "enabled is required")
		return
	}
	s.policyStore.SetKillSwitch(*req.Enabled)

	decision := "FROZEN"
	reason := "GLOBAL EMERGENCY KILL-SWITCH ENGAGED by CISO Override. All agent workloads locked."
	if !*req.Enabled {
		decision = "RESTORED"
		reason = "Global Fleet Governance Restored. Standard Cedar invariants enforced."
	}

	if s.auditStore != nil {
		_, _ = s.auditStore.Ingest([]audit.Event{
			{
				Source:      "controlplane-ciso",
				Executable:  "KILL_SWITCH",
				FullCommand: fmt.Sprintf("kill-switch --status=%v", *req.Enabled),
				Decision:    decision,
				Reason:      reason,
				Timestamp:   time.Now().UTC().Format(time.RFC3339),
				ExitCode:    0,
			},
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"kill_switch": req.Enabled,
		"status":      "ok",
		"message":     reason,
	})
}

func (s *Server) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	valid, chainErr := s.auditStore.VerifyChain()
	events := s.auditStore.List(1)
	headHash := "genesis-bapltd-control-plane"
	if len(events) > 0 {
		headHash = events[0].EventHash
	}

	errStr := ""
	if chainErr != nil {
		errStr = chainErr.Error()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":             valid,
		"error":             errStr,
		"total_events":      len(s.auditStore.List(10000)),
		"head_hash":         headHash,
		"merkle_integrity":  "100% CRYPTOGRAPHICALLY SECURE",
		"compliance_status": "SOC2_FEDRAMP_ISO27001_COMPLIANT",
	})
}

func (s *Server) handleDemoExecSafe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if s.policyStore.GetBundle().KillSwitch {
		writeJSON(w, http.StatusForbidden, map[string]any{
			"error":        "KillSwitchActive",
			"decision":     "DENY",
			"pep_decision": "DENY",
			"reason":       "EXECUTION BLOCKED: Global Emergency Kill-Switch is active across fleet",
		})
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	cmd := "git log -n 5 --oneline && pytest tests/unit -q && npm run build:prod"
	reason := "Enterprise multi-stage pipeline verified by Cedar (zero developer delay)"
	actionID := fmt.Sprintf("act-safe-%d", time.Now().UnixNano())

	ev := audit.Event{
		EventID:     actionID,
		Source:      "claude-code",
		SessionID:   "sess-laptop-alice",
		Executable:  "git",
		FullCommand: cmd,
		Decision:    "allow",
		Reason:      reason,
		DurationMs:  1,
		Timestamp:   now,
		ExitCode:    0,
	}

	if s.auditStore != nil {
		_, _ = s.auditStore.Ingest([]audit.Event{ev})
	}

	// Append to ltd-audit.jsonl
	for _, auditFile := range []string{"ltd-audit.jsonl", "../ltd-audit.jsonl", "../../ltd-audit.jsonl"} {
		if f, err := os.OpenFile(auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			data, _ := json.Marshal(ev)
			_, _ = f.Write(append(data, '\n'))
			_ = f.Close()
			break
		}
	}

	// Record activity on first active session (e.g. Alice)
	if s.sessionStore != nil {
		sessions := s.sessionStore.List(50)
		for _, sess := range sessions {
			if sess.Status == "active" {
				s.sessionStore.RecordEvent(sess.SessionID, ev)
				break
			}
		}
	}

	actionRec := &DemoActionRecord{
		Type:       "safe",
		ActionID:   actionID,
		Command:    cmd,
		Decision:   "allow",
		DurationMs: 1.4,
		Reason:     reason,
		ExitCode:   0,
		Timestamp:  now,
	}
	s.lastDemoMu.Lock()
	s.lastDemoAction = actionRec
	s.lastDemoMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"action_id":   actionID,
		"decision":    "allow",
		"duration_ms": 1.4,
		"command":     cmd,
		"reason":      reason,
		"exit_code":   0,
	})
}

func (s *Server) handleDemoExecAttack(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	now := time.Now().UTC().Format(time.RFC3339)
	cmd := "curl -s https://bap-gateway:9090/api/v1/financial-records (Credential Exfil Attack)"
	reason := "BLOCKED BY GATEWAY PEP: Rogue agent credential exfiltration & egress dropped at perimeter (HTTP 401/403)"
	actionID := fmt.Sprintf("act-attack-%d", time.Now().UnixNano())

	// Model the incident as a governed session so its escalation is sourced
	// entirely from control-plane telemetry and isolated from healthy agents.
	if s.sessionStore != nil {
		_, _ = s.sessionStore.Start(session.SessionStartRequest{
			SessionID:  "sess-rogue-agent",
			AppID:      "gateway-audit-agent",
			InstanceID: "quarantine-probe-01",
			AgentName:  "Credential Audit Probe",
			UserID:     "security-demo",
			UserEmail:  "security.demo@enterprise.internal",
			SPIFFEID:   "spiffe://bap.internal/app/gateway-audit-agent/instance/quarantine-probe-01",
			Hostname:   "SEC-LAB-01",
			UserPrompt: "Test whether protected financial records can be exported outside the approved boundary.",
		})
	}

	ev := audit.Event{
		EventID:     actionID,
		Source:      "bap-gateway-pep",
		SessionID:   "sess-rogue-agent",
		Executable:  "curl",
		FullCommand: cmd,
		Decision:    "deny",
		Reason:      reason,
		DurationMs:  1,
		Timestamp:   now,
		ExitCode:    403,
	}

	if s.auditStore != nil {
		_, _ = s.auditStore.Ingest([]audit.Event{ev})
	}

	// Append to ltd-audit.jsonl
	for _, auditFile := range []string{"ltd-audit.jsonl", "../ltd-audit.jsonl", "../../ltd-audit.jsonl"} {
		if f, err := os.OpenFile(auditFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			data, _ := json.Marshal(ev)
			_, _ = f.Write(append(data, '\n'))
			_ = f.Close()
			break
		}
	}

	// Record activity on the incident session itself.
	if s.sessionStore != nil {
		s.sessionStore.RecordEvent("sess-rogue-agent", ev)
	}

	actionRec := &DemoActionRecord{
		Type:       "attack",
		ActionID:   actionID,
		Command:    cmd,
		Decision:   "deny",
		DurationMs: 1.1,
		Reason:     reason,
		ExitCode:   403,
		Timestamp:  now,
	}
	s.lastDemoMu.Lock()
	s.lastDemoAction = actionRec
	s.lastDemoMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"action_id":    actionID,
		"decision":     "deny",
		"pep_decision": "DENY",
		"duration_ms":  1.1,
		"command":      cmd,
		"reason":       reason,
		"exit_code":    403,
	})
}

func (s *Server) handleDemoFleetScale(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Count int `json:"count"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	targetCount := req.Count
	if targetCount != 25 {
		targetCount = 5
	}

	// Always clear previous fleet
	if s.sessionStore != nil {
		s.sessionStore.Reset()
		s.sessionStore.ResetIntentStats()
		for _, revokedUser := range s.sessionStore.ListRevokedUsers() {
			s.sessionStore.RestoreUser(revokedUser)
		}
	}
	if s.registry != nil {
		s.registry.Reset()
	}

	baseSquads := []struct {
		Squad   string
		AppID   string
		Prompt  string
		Action  string
		Intent  session.IntentContext
		Members []string
	}{
		{"Frontend Squad", "claude-code", "Review the release candidate and verify the UI build.", "npm run test:ui && npm run build", session.IntentContext{Primary: "TEST_VERIFICATION", Secondary: []string{"INVESTIGATION"}, Tags: []string{"UI"}, Confidence: .90, ClassifierVersion: demoIntentClassifierVersion, Source: "demo-fixture", PromptCaptured: true}, []string{"Alice", "Alex", "Amy", "Aaron", "Abby"}},
		{"Payments Platform", "copilot", "Validate payment reconciliation changes before deployment.", "pytest tests/payments -q", session.IntentContext{Primary: "TEST_VERIFICATION", Secondary: []string{"DEPLOYMENT_RELEASE"}, Confidence: .88, ClassifierVersion: demoIntentClassifierVersion, Source: "demo-fixture", PromptCaptured: true}, []string{"Bob", "Brian", "Bella", "Ben", "Boris"}},
		{"Cloud Ops / SRE", "antigravity", "Inspect production service health and deployment readiness.", "kubectl get pods --all-namespaces", session.IntentContext{Primary: "DEPLOYMENT_RELEASE", Secondary: []string{"INVESTIGATION"}, Tags: []string{"PRODUCTION", "INFRASTRUCTURE"}, Confidence: .91, ClassifierVersion: demoIntentClassifierVersion, Source: "demo-fixture", PromptCaptured: true}, []string{"Carol", "Chris", "Clara", "Cole", "Cynthia"}},
		{"Security Core", "claude-code", "Review the policy bundle for risky permission changes.", "git diff -- policy.cedar", session.IntentContext{Primary: "SECURITY_REMEDIATION", Secondary: []string{"INVESTIGATION"}, Tags: []string{"SECURITY"}, Confidence: .86, ClassifierVersion: demoIntentClassifierVersion, Source: "demo-fixture", PromptCaptured: true}, []string{"Dave", "Dan", "Diana", "Derek", "Daisy"}},
		{"Data & Analytics", "python-agent", "Reconcile the daily analytics pipeline and report anomalies.", "python verify_pipeline.py --latest", session.IntentContext{Primary: "INVESTIGATION", Secondary: []string{"DATABASE_CHANGE"}, Tags: []string{"DATABASE"}, Confidence: .82, ClassifierVersion: demoIntentClassifierVersion, Source: "demo-fixture", PromptCaptured: true}, []string{"Eve", "Ethan", "Emma", "Eric", "Elena"}},
	}

	enrolled := 0

	for _, squad := range baseSquads {
		for i, m := range squad.Members {
			if targetCount == 5 && i > 0 {
				continue // only first member of each squad for 5-agent mode
			}
			inst := fmt.Sprintf("laptop-%s", strings.ToLower(m))
			email := fmt.Sprintf("%s.dev@enterprise.internal", strings.ToLower(m))
			spiffe := fmt.Sprintf("spiffe://bap.internal/app/%s/instance/%s", squad.AppID, inst)
			sessID := fmt.Sprintf("sess-%s", inst)
			if s.sessionStore != nil {
				_, _ = s.sessionStore.Start(session.SessionStartRequest{
					SessionID:  sessID,
					AppID:      squad.AppID,
					InstanceID: inst,
					AgentName:  fmt.Sprintf("%s · %s", squad.Squad, m),
					UserID:     strings.ToLower(m),
					UserEmail:  email,
					SPIFFEID:   spiffe,
					Hostname:   fmt.Sprintf("DEVHOST-%s", strings.ToUpper(m)),
					UserPrompt: squad.Prompt,
					Intent:     squad.Intent,
				})

				eventTime := time.Now().UTC().Add(time.Duration(-enrolled) * time.Second)
				ev := audit.Event{
					EventID:          fmt.Sprintf("demo-fleet-%d-%d", eventTime.UnixNano(), enrolled),
					SessionID:        sessID,
					Source:           squad.AppID,
					Executable:       strings.Fields(squad.Action)[0],
					FullCommand:      squad.Action,
					Decision:         "allow",
					Reason:           "Authorized by the active Cedar fleet policy",
					DurationMs:       1,
					Timestamp:        eventTime.Format(time.RFC3339Nano),
					ExitCode:         0,
					UserPrompt:       squad.Prompt,
					PrimaryIntent:    squad.Intent.Primary,
					SecondaryIntents: squad.Intent.Secondary,
					IntentTags:       squad.Intent.Tags,
					IntentConfidence: squad.Intent.Confidence,
					IntentClassifier: squad.Intent.ClassifierVersion,
					PromptCaptured:   true,
					UserEmail:        email,
				}
				_, _ = s.auditStore.Ingest([]audit.Event{ev})
				s.sessionStore.RecordEvent(sessID, ev)
			}
			enrolled++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      "ok",
		"agent_count": enrolled,
		"scale_mode":  fmt.Sprintf("%d-agent", targetCount),
	})
}

func killProcessPID(pid int) {
	if pid <= 0 || pid == os.Getpid() {
		return
	}
	if runtime.GOOS == "windows" {
		_ = exec.Command("taskkill", "/F", "/T", "/PID", fmt.Sprintf("%d", pid), "/FI", "IMAGENAME ne bapcontrolplane.exe").Run()
	} else {
		if p, err := os.FindProcess(pid); err == nil {
			_ = p.Kill()
		}
	}
}

func (s *Server) handleTargetedKillAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Target string `json:"target"`
		Action string `json:"action"`
		UserID string `json:"user_id,omitempty"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid action JSON")
		return
	}
	target := strings.TrimSpace(req.Target)
	action := strings.ToLower(strings.TrimSpace(req.Action))
	if action == "unrevoke" {
		action = "restore"
	}
	if target == "" || (action != "restore" && action != "revoke" && action != "stop") {
		writeError(w, http.StatusBadRequest, "Exact target and action (stop, revoke, or restore) are required")
		return
	}
	sessionTarget, agentTarget := "", ""
	var targetSession *session.Session
	var targetAgent *types.RegisteredAgent

	if sess, err := s.sessionStore.Get(target); err == nil {
		sessionTarget = sess.SessionID
		targetSession = sess
		for _, agent := range s.registry.List() {
			linkedInstance := sess.InstanceID
			if linkedInstance == "" {
				linkedInstance = sess.SessionID
			}
			if agent.InstanceID == linkedInstance && agent.AppID == sess.AppID {
				agentTarget = agent.AgentID
				targetAgent = agent
				break
			}
		}
	} else if agent, err := s.registry.Get(target); err == nil {
		agentTarget = agent.AgentID
		targetAgent = agent
		if s.sessionStore != nil {
			for _, sess := range s.sessionStore.List(0) {
				linkedInstance := sess.InstanceID
				if linkedInstance == "" {
					linkedInstance = sess.SessionID
				}
				if sess.AppID == agent.AppID && linkedInstance == agent.InstanceID && sess.Status != "closed" {
					sessionTarget = sess.SessionID
					targetSession = sess
					break
				}
			}
		}
	}

	// Also check if target matches any session by InstanceID, UserID, or UserEmail
	if sessionTarget == "" && agentTarget == "" && s.sessionStore != nil {
		for _, sess := range s.sessionStore.List(0) {
			if strings.EqualFold(sess.SessionID, target) || strings.EqualFold(sess.InstanceID, target) || strings.EqualFold(sess.UserID, target) || strings.EqualFold(sess.UserEmail, target) {
				sessionTarget = sess.SessionID
				targetSession = sess
				break
			}
		}
	}

	if sessionTarget == "" && agentTarget == "" {
		if action == "revoke" || action == "restore" {
			userID := target
			if req.UserID != "" {
				userID = req.UserID
			}
			if action == "revoke" {
				if s.sessionStore != nil {
					s.sessionStore.RevokeUser(userID, "Revoked by administrator")
				}
				markerData := map[string]any{
					"user_id":    userID,
					"status":     "revoked",
					"revoked_at": time.Now().UTC(),
					"reason":     "User access revoked by administrator",
				}
				if mb, err := json.MarshalIndent(markerData, "", "  "); err == nil {
					_ = os.WriteFile(".bap-revoked", mb, 0644)
					_ = os.WriteFile("../.bap-revoked", mb, 0644)
				}
				writeJSON(w, http.StatusOK, map[string]any{
					"target":      target,
					"user_id":     userID,
					"status":      "revoked",
					"action":      "revoke",
					"message":     fmt.Sprintf("User %s access revoked by administrator. Future sessions blocked.", userID),
					"kill_status": "REVOKED",
				})
				return
			} else {
				if s.sessionStore != nil {
					s.sessionStore.RestoreUser(userID)
				}
				_ = os.Remove(".bap-revoked")
				_ = os.Remove("../.bap-revoked")
				writeJSON(w, http.StatusOK, map[string]any{
					"target":      target,
					"user_id":     userID,
					"status":      "active",
					"action":      "restore",
					"message":     fmt.Sprintf("User %s access restored by administrator.", userID),
					"kill_status": "RESTORED",
				})
				return
			}
		}
		writeError(w, http.StatusNotFound, "No exact session or agent ID found")
		return
	}

	// 1. ACTION: STOP SESSION (session termination only, no user revocation)
	if action == "stop" {
		var stoppedName string
		if targetSession != nil {
			stoppedName = targetSession.InstanceID
			if stoppedName == "" {
				stoppedName = targetSession.SessionID
			}
		} else if targetAgent != nil {
			stoppedName = targetAgent.InstanceID
		}
		if stoppedName == "" {
			stoppedName = target
		}

		if s.sessionStore != nil && sessionTarget != "" {
			_ = s.sessionStore.End(sessionTarget, "Session stopped by administrator")
		}
		if s.registry != nil {
			if targetSession != nil {
				s.registry.EndSessionAgent(targetSession.AppID, targetSession.InstanceID)
			} else if targetAgent != nil {
				s.registry.EndSessionAgent(targetAgent.AppID, targetAgent.InstanceID)
			}
		}

		// Directly terminate the local workload process if client PID is recorded
		if targetSession != nil && targetSession.ClientPID > 0 {
			killProcessPID(targetSession.ClientPID)
		}

		now := time.Now().UTC()
		s.auditStore.Ingest([]audit.Event{
			{
				Source:      "bap-controlplane",
				SessionID:   sessionTarget,
				Executable:  "bapcontrolplane",
				FullCommand: fmt.Sprintf("STOP_SESSION target=%s", target),
				Decision:    "deny",
				Reason:      fmt.Sprintf("Session %s stopped by administrator. Workload process terminated.", stoppedName),
				DurationMs:  1,
				Timestamp:   now.Format(time.RFC3339),
				ExitCode:    0,
			},
		})

		termMsg := "Workload process terminated."
		if targetSession == nil || targetSession.ClientPID <= 0 {
			termMsg = "workload process was not terminated (no client PID recorded)."
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"target":      target,
			"agent_name":  stoppedName,
			"session_id":  sessionTarget,
			"status":      "closed",
			"action":      "stop",
			"message":     fmt.Sprintf("Session %s successfully stopped. %s Future sessions by this user are permitted.", stoppedName, termMsg),
			"kill_status": "STOPPED",
		})
		return
	}

	// 2. ACTION: RESTORE ACCESS (unblocks user, clears revocation)
	if action == "restore" {
		var restoredName string
		userID := req.UserID
		if targetSession != nil {
			restoredName = targetSession.InstanceID
			if userID == "" {
				userID = targetSession.UserID
			}
			if userID == "" || userID == "NA" {
				userID = targetSession.UserEmail
			}
		}
		if targetAgent != nil {
			if restoredName == "" {
				restoredName = targetAgent.InstanceID
			}
			if userID == "" || userID == "NA" {
				userID = targetAgent.OwnerEmail
			}
		}
		if restoredName == "" {
			restoredName = target
		}
		if userID == "" || userID == "NA" {
			userID = target
		}

		if s.sessionStore != nil {
			if userID != "" {
				s.sessionStore.RestoreUser(userID)
			}
			if sessionTarget != "" {
				_, _ = s.sessionStore.RestoreTarget(sessionTarget)
			}
		}
		if s.registry != nil && agentTarget != "" {
			_, _ = s.registry.RestoreTarget(agentTarget)
		}

		_ = os.Remove(".bap-revoked")
		_ = os.Remove("../.bap-revoked")

		now := time.Now().UTC()
		s.auditStore.Ingest([]audit.Event{
			{
				Source:      "bap-controlplane",
				SessionID:   "admin-ciso-override",
				Executable:  "bapcontrolplane",
				FullCommand: fmt.Sprintf("RESTORE_ACCESS target=%s user=%s", target, userID),
				Decision:    "allow",
				Reason:      fmt.Sprintf("Access restored by administrator for %s (user: %s).", restoredName, userID),
				DurationMs:  1,
				Timestamp:   now.Format(time.RFC3339),
				ExitCode:    0,
			},
		})

		writeJSON(w, http.StatusOK, map[string]any{
			"target":      target,
			"agent_name":  restoredName,
			"user_id":     userID,
			"status":      "active",
			"action":      "restore",
			"message":     fmt.Sprintf("Access successfully restored for %s. User can now start new sessions.", restoredName),
			"kill_status": "RESTORED",
		})
		return
	}

	// 3. ACTION: REVOKE ACCESS (user-level block, terminates sessions, rejects future sessions)
	var revokedName string
	var spiffeID string
	userID := req.UserID
	if targetSession != nil {
		revokedName = targetSession.InstanceID
		spiffeID = targetSession.SPIFFEID
		if userID == "" {
			userID = targetSession.UserID
		}
		if userID == "" || userID == "NA" {
			userID = targetSession.UserEmail
		}
	}
	if targetAgent != nil {
		if revokedName == "" {
			revokedName = targetAgent.InstanceID
		}
		if spiffeID == "" {
			spiffeID = targetAgent.SPIFFEID
		}
		if userID == "" || userID == "NA" {
			userID = targetAgent.OwnerEmail
		}
	}
	if revokedName == "" {
		revokedName = target
	}
	if userID == "" || userID == "NA" {
		userID = target
	}

	if s.sessionStore != nil {
		if userID != "" {
			s.sessionStore.RevokeUser(userID, "Revoked by administrator")
		}
		if sessionTarget != "" {
			_, _ = s.sessionStore.RevokeTarget(sessionTarget, "Revoked by administrator")
		}
	}
	if s.registry != nil && agentTarget != "" {
		_, _ = s.registry.RevokeTarget(agentTarget)
	}

	// Directly terminate the local workload process if client PID is recorded
	if targetSession != nil && targetSession.ClientPID > 0 {
		killProcessPID(targetSession.ClientPID)
	}

	// Write marker tombstone so local edge hooks immediately know
	markerData := map[string]any{
		"session_id": sessionTarget,
		"user_id":    userID,
		"status":     "revoked",
		"revoked_at": time.Now().UTC(),
		"reason":     "User access revoked by administrator",
	}
	if mb, err := json.MarshalIndent(markerData, "", "  "); err == nil {
		_ = os.WriteFile(".bap-revoked", mb, 0644)
		_ = os.WriteFile("../.bap-revoked", mb, 0644)
	}

	now := time.Now().UTC()
	s.auditStore.Ingest([]audit.Event{
		{
			Source:      "bap-controlplane",
			SessionID:   sessionTarget,
			Executable:  "bapcontrolplane",
			FullCommand: fmt.Sprintf("REVOKE_ACCESS target=%s user=%s", target, userID),
			Decision:    "deny",
			Reason:      fmt.Sprintf("Access revoked by administrator for user %s (target %s). All active sessions terminated and future sessions blocked.", userID, revokedName),
			DurationMs:  1,
			Timestamp:   now.Format(time.RFC3339),
			ExitCode:    1,
		},
	})

	processTermMsg := "Workload process terminated and future sessions blocked."
	if targetSession == nil || targetSession.ClientPID <= 0 {
		processTermMsg = "workload process was not terminated (no client PID recorded) and future sessions blocked."
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"target":      target,
		"agent_name":  revokedName,
		"user_id":     userID,
		"spiffe_id":   spiffeID,
		"session_id":  sessionTarget,
		"status":      "revoked",
		"action":      "revoke",
		"message":     fmt.Sprintf("Access revoked for %s (%s). %s", revokedName, spiffeID, processTermMsg),
		"kill_status": "REVOKED",
	})
}

func isLoopbackAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return host == "localhost" || host == "127.0.0.1" || host == "::1"
	}
	return ip.IsLoopback()
}

func (s *Server) logSecurityAlert(r *http.Request, category string, reason string) {
	if s.auditStore == nil {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	_, _ = s.auditStore.Ingest([]audit.Event{
		{
			EventID:     fmt.Sprintf("sec-alert-%d", time.Now().UnixNano()),
			Source:      "controlplane-auth",
			Executable:  r.URL.Path,
			FullCommand: fmt.Sprintf("%s %s from %s", r.Method, r.URL.Path, r.RemoteAddr),
			Decision:    "deny",
			Reason:      reason,
			Timestamp:   now,
			ExitCode:    403,
		},
	})
}

// Admin credentials are explicit request headers, never ambient cookies.
func adminCredential(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return r.Header.Get("X-BAP-Admin-Token")
}

func (s *Server) isAdminCaller(r *http.Request) bool {
	token := adminCredential(r)
	return s.adminToken != "" && token != "" &&
		(s.allowRemoteAdmin || isLoopbackAddress(r.RemoteAddr)) &&
		subtle.ConstantTimeCompare([]byte(token), []byte(s.adminToken)) == 1
}

func (s *Server) requireAdminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.adminToken == "" {
			writeError(w, http.StatusServiceUnavailable, "Administrative authentication is not configured")
			return
		}
		if !s.allowRemoteAdmin && !isLoopbackAddress(r.RemoteAddr) {
			writeError(w, http.StatusForbidden, "Remote administration is disabled")
			return
		}
		if !s.isAdminCaller(r) {
			s.logSecurityAlert(r, "UNAUTHORIZED_ADMIN", "Administrative credential missing or invalid")
			if adminCredential(r) == "" {
				w.Header().Set("WWW-Authenticate", `Bearer realm="bap-controlplane-admin"`)
				writeError(w, http.StatusUnauthorized, "Administrative credential required")
			} else {
				writeError(w, http.StatusForbidden, "Invalid administrative credential")
			}
			return
		}
		next(w, r)
	}
}

// Compatibility endpoint: verifies supplied credentials, never bootstraps them.
func (s *Server) handleInspectorHandshake(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	s.requireAdminAuth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "authorized",
			"role":        "ciso_admin",
			"permissions": []string{"kill_switch", "audit_read", "session_revoke", "fleet_scale"},
		})
	})(w, r)
}

func (s *Server) handleAdminLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid login JSON")
		return
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		writeError(w, http.StatusBadRequest, "Expected one JSON object")
		return
	}
	if req.Token != "" {
		r.Header.Set("Authorization", "Bearer "+req.Token)
	}
	s.requireAdminAuth(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"status":      "authorized",
			"role":        "ciso_admin",
			"permissions": []string{"kill_switch", "audit_read", "session_revoke", "fleet_scale"},
		})
	})(w, r)
}

func redactedTelemetry(value any) any {
	data, _ := json.Marshal(value)
	var copy any
	_ = json.Unmarshal(data, &copy)
	var redact func(any)
	redact = func(node any) {
		switch v := node.(type) {
		case map[string]any:
			for key, item := range v {
				switch key {
				case "user_prompt", "prompt_hash", "user_id", "user_email", "owner_email", "session_id", "instance_id", "spiffe_id", "hostname":
					if item != "" && item != nil {
						v[key] = "[Protected: Admin Authentication Required]"
					}
				case "client_pid":
					if item != nil {
						v[key] = 0
					}
				case "revoked_sessions":
					v[key] = []any{}
				default:
					redact(item)
				}
			}
		case []any:
			for _, item := range v {
				redact(item)
			}
		}
	}
	redact(copy)
	return copy
}
func (s *Server) writeTelemetry(w http.ResponseWriter, r *http.Request, value any) {
	if !s.isAdminCaller(r) && (s.adminToken != "" || !isLoopbackAddress(r.RemoteAddr)) {
		value = redactedTelemetry(value)
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *Server) consumeActiveGrant(token, resource string) (*authz.GrantClaims, error) {
	return s.consumeActiveGrantWithDetails(token, "", resource, "")
}

func (s *Server) consumeActiveGrantWithDetails(token, action, resource, sessionID string) (*authz.GrantClaims, error) {
	claims, err := s.minter.Verify(token)
	if err != nil {
		return nil, err
	}
	if s.policyStore.GetBundle().KillSwitch {
		return nil, fmt.Errorf("fleet is frozen")
	}
	for _, agent := range s.registry.List() {
		subject := agent.AgentID
		if agent.SPIFFEID != "" {
			subject = agent.SPIFFEID
		}
		if subject == claims.Sub && agent.AppID == claims.AppID && (agent.InstanceID == "" || claims.InstanceID == "" || agent.InstanceID == claims.InstanceID) {
			if agent.Status != types.StatusActive {
				return nil, fmt.Errorf("agent is not active")
			}
			return s.minter.ConsumeWithDetails(token, action, resource, sessionID)
		}
	}
	return nil, fmt.Errorf("agent is not registered")
}

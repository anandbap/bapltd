package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"bap-controlplane/internal/audit"
	"bap-controlplane/pkg/types"
)

var (
	// Permitted standard scopes per target audience
	permittedAudienceScopes = map[string][]string{
		"github": {
			"repo", "repo:status", "repo_deployment", "public_repo", "repo:invite",
			"security_events", "repo:read", "repo:push", "pull_request:write",
			"issues:write", "read:org", "read:user", "user:email", "workflow",
		},
		"aws": {
			"s3:read", "s3:write", "logs:write", "ecr:read", "cloudwatch:read",
		},
		"railway": {
			"deploy:write", "service:read", "env:read", "logs:read",
		},
		"jira": {
			"read:jira-work", "write:jira-work", "read:jira-user",
		},
		"salesforce": {
			"api", "refresh_token", "read",
		},
		"stripe": {
			"read", "charges:read", "customers:read",
		},
	}

	// Strictly forbidden privilege escalation scopes
	forbiddenAudienceScopes = map[string][]string{
		"github": {
			"admin:org", "admin:enterprise", "delete_repo", "repo:delete",
			"site_admin", "admin:repo_hook", "admin:org_hook",
		},
		"aws": {
			"iam:*", "organizations:*", "sts:AssumeRoleWithWebIdentity:*",
		},
		"railway": {
			"billing:admin", "workspace:delete",
		},
	}
)

// handleSTSToken implements RFC 8693 OAuth 2.0 Security Token Service (STS) endpoint (BAP-810)
func (s *Server) handleSTSToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req types.RFC8693TokenExchangeRequest
	contentType := r.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Failed to parse form: "+err.Error())
			return
		}
		req.GrantType = r.FormValue("grant_type")
		req.Resource = r.FormValue("resource")
		req.Audience = r.FormValue("audience")
		req.Scope = r.FormValue("scope")
		req.RequestedTokenType = r.FormValue("requested_token_type")
		req.SubjectToken = r.FormValue("subject_token")
		req.SubjectTokenType = r.FormValue("subject_token_type")
		req.ActorToken = r.FormValue("actor_token")
		req.ActorTokenType = r.FormValue("actor_token_type")
		req.SessionID = r.FormValue("session_id")
		if muStr := r.FormValue("max_uses"); muStr != "" {
			if mu, err := strconv.Atoi(muStr); err == nil {
				req.MaxUses = mu
			}
		}
	} else {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Invalid JSON: "+err.Error())
			return
		}
	}

	// 1. Validate Grant Type (RFC 8693)
	if req.GrantType != types.RFC8693GrantTypeTokenExchange {
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type",
			"grant_type must be "+types.RFC8693GrantTypeTokenExchange)
		return
	}

	// 2. Validate Subject Token
	trimmedSubject := strings.TrimSpace(req.SubjectToken)
	if trimmedSubject == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "subject_token is required")
		return
	}

	// 3. Resolve Session ID and User from Subject Token
	sessionID, userEmail, appID := s.resolveSessionFromSubjectToken(trimmedSubject, req.SessionID)
	if sessionID == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "Unable to resolve active session ID from subject_token")
		return
	}

	// 4. Validate Session Liveness and Anti-Tamper Status
	if s.sessionStore != nil {
		if s.sessionStore.IsRevoked(sessionID) {
			s.recordSTSRejection(req, sessionID, userEmail, "session_revoked", "Session is revoked")
			writeOAuthError(w, http.StatusForbidden, "access_denied", "Attested session has been revoked")
			return
		}
		if userEmail != "" && s.sessionStore.IsUserRevoked(userEmail) {
			s.recordSTSRejection(req, sessionID, userEmail, "user_revoked", "User is revoked")
			writeOAuthError(w, http.StatusForbidden, "access_denied", "Attested user has been revoked")
			return
		}
		if sess, err := s.sessionStore.Get(sessionID); err == nil && sess != nil {
			if userEmail == "" && sess.UserEmail != "" {
				userEmail = sess.UserEmail
			}
			if appID == "" && sess.AppID != "" {
				appID = sess.AppID
			}
		}
	}

	if userEmail == "" {
		userEmail = "operator@bap.local"
	}
	if appID == "" {
		appID = "bap-agent"
	}

	// 5. Audience & Scope Policy Enforcement (Cedar Invariants)
	audience := strings.ToLower(strings.TrimSpace(req.Audience))
	if audience == "" {
		audience = "github"
	}

	requestedScopes := strings.Fields(req.Scope)
	if len(requestedScopes) == 0 {
		requestedScopes = []string{"repo:read"}
	}

	// Check for forbidden privilege escalation
	if forbidden, exists := forbiddenAudienceScopes[audience]; exists {
		for _, reqScope := range requestedScopes {
			for _, f := range forbidden {
				if strings.EqualFold(reqScope, f) {
					reason := fmt.Sprintf("Privilege escalation blocked: scope %q is strictly forbidden for audience %q", reqScope, audience)
					s.recordSTSRejection(req, sessionID, userEmail, "invalid_scope", reason)
					writeOAuthError(w, http.StatusForbidden, "invalid_scope", reason)
					return
				}
			}
		}
	}

	// Monotonic Scope Attenuation: ensure requested scopes are within permitted policy boundary
	attenuatedScopes := make([]string, 0)
	if permitted, exists := permittedAudienceScopes[audience]; exists {
		permMap := make(map[string]bool)
		for _, p := range permitted {
			permMap[strings.ToLower(p)] = true
		}
		for _, reqScope := range requestedScopes {
			if permMap[strings.ToLower(reqScope)] {
				attenuatedScopes = append(attenuatedScopes, reqScope)
			}
		}
		if len(attenuatedScopes) == 0 {
			reason := fmt.Sprintf("Scope escalation denied: none of requested scopes %v are permitted for audience %q", requestedScopes, audience)
			s.recordSTSRejection(req, sessionID, userEmail, "invalid_scope", reason)
			writeOAuthError(w, http.StatusForbidden, "invalid_scope", reason)
			return
		}
	} else {
		// General audience fallback
		attenuatedScopes = requestedScopes
	}

	// 6. Single-Use Replay Attack Protection
	if req.MaxUses == 1 || strings.HasPrefix(trimmedSubject, "grant-") {
		if burned, status, err := s.saasTokenMgr.BurnGrantOnce(trimmedSubject); !burned || err != nil {
			s.recordSTSRejection(req, sessionID, userEmail, "invalid_grant", "Replay attack detected: "+status)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_grant", "Grant token already consumed: "+err.Error())
			return
		}
	}

	// 7. Bind Downstream Ephemeral Credential
	ttl := 5 * time.Minute // Bounded 5-minute TTL invariant
	binding, err := s.saasTokenMgr.BindToken(audience, "", sessionID, appID, userEmail, attenuatedScopes, ttl)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "Failed to bind downstream token: "+err.Error())
		return
	}
	if req.MaxUses > 0 {
		binding.MaxUses = req.MaxUses
	}

	// 8. Record OBO Exchange Event for Ladder & Cockpit Inspection
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	exchangeID := fmt.Sprintf("obo-%s-%s", audience, hex.EncodeToString(b))

	exchangeRecord := &types.OBOTokenExchangeRecord{
		ExchangeID:      exchangeID,
		Timestamp:       time.Now().UTC(),
		SubjectSVID:     trimmedSubject,
		ActorSVID:       req.ActorToken,
		UserEmail:       userEmail,
		Audience:        audience,
		RequestedScope:  req.Scope,
		AttenuatedScope: strings.Join(attenuatedScopes, " "),
		BoundSessionID:  sessionID,
		TokenID:         binding.TokenID,
		Status:          "ACTIVE",
	}
	s.saasTokenMgr.RecordExchange(exchangeRecord)

	// 9. Audit Event Ingestion
	if s.auditStore != nil {
		s.auditStore.Ingest([]audit.Event{{
			EventID:     fmt.Sprintf("evt-sts-%d", time.Now().UnixNano()),
			AgentID:     appID,
			SessionID:   sessionID,
			UserEmail:   userEmail,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Source:      "sts_token_exchange",
			Executable:  "sts_token",
			FullCommand: fmt.Sprintf("rfc8693 token exchange audience=%s requested_scope=%q attenuated_scope=%q token=%s", audience, req.Scope, exchangeRecord.AttenuatedScope, binding.TokenID),
			Decision:    "ALLOW",
			Reason:      "RFC 8693 OBO Token Exchange successfully evaluated and bound to active session",
		}})
	}

	// 10. Return RFC 8693 Compliant JSON Response
	issuedTokenType := req.RequestedTokenType
	if issuedTokenType == "" {
		issuedTokenType = types.RFC8693TokenTypeAccessToken
	}

	writeJSON(w, http.StatusOK, types.RFC8693TokenExchangeResponse{
		AccessToken:     binding.TokenID,
		IssuedTokenType: issuedTokenType,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		Scope:           strings.Join(attenuatedScopes, " "),
	})
}

// resolveSessionFromSubjectToken extracts the session ID, user email, and app ID from various token formats
func (s *Server) resolveSessionFromSubjectToken(subjectToken, fallbackSessionID string) (sessionID, userEmail, appID string) {
	sessionID = fallbackSessionID

	// Handle SPIFFE SVID URI format:
	// spiffe://bap.internal/workstation/{ws}/session/{sessionID}
	// spiffe://bap.local/agent/{appID}/{sessionID}
	if strings.HasPrefix(subjectToken, "spiffe://") {
		parts := strings.Split(subjectToken, "/")
		for i, p := range parts {
			if (p == "session" || p == "agent") && i+1 < len(parts) {
				sessionID = parts[i+1]
				break
			}
		}
		if sessionID == "" && len(parts) > 0 {
			sessionID = parts[len(parts)-1]
		}
	} else if strings.HasPrefix(subjectToken, "urn:bap:session:") {
		sessionID = strings.TrimPrefix(subjectToken, "urn:bap:session:")
	} else if strings.HasPrefix(subjectToken, "sess-") {
		sessionID = subjectToken
	}

	// Try validating with minter if it's a signed BAP JWT
	if s.minter != nil {
		if claims, err := s.minter.Verify(subjectToken); err == nil && claims != nil {
			if claims.SessionID != "" {
				sessionID = claims.SessionID
			}
			if claims.UserEmail != "" {
				userEmail = claims.UserEmail
			}
			if claims.AgentID != "" {
				appID = claims.AgentID
			}
		}
	}

	return sessionID, userEmail, appID
}

// recordSTSRejection emits audit and inspector records for denied STS requests
func (s *Server) recordSTSRejection(req types.RFC8693TokenExchangeRequest, sessionID, userEmail, errCode, reason string) {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	exchangeID := fmt.Sprintf("obo-denied-%s", hex.EncodeToString(b))

	if s.saasTokenMgr != nil {
		s.saasTokenMgr.RecordExchange(&types.OBOTokenExchangeRecord{
			ExchangeID:      exchangeID,
			Timestamp:       time.Now().UTC(),
			SubjectSVID:     req.SubjectToken,
			ActorSVID:       req.ActorToken,
			UserEmail:       userEmail,
			Audience:        req.Audience,
			RequestedScope:  req.Scope,
			AttenuatedScope: "",
			BoundSessionID:  sessionID,
			TokenID:         "",
			Status:          "DENIED",
			DecisionReason:  reason,
		})
	}

	if s.auditStore != nil {
		s.auditStore.Ingest([]audit.Event{{
			EventID:     fmt.Sprintf("evt-sts-deny-%d", time.Now().UnixNano()),
			SessionID:   sessionID,
			UserEmail:   userEmail,
			Timestamp:   time.Now().UTC().Format(time.RFC3339),
			Source:      "sts_token_exchange",
			Executable:  "sts_token",
			FullCommand: fmt.Sprintf("rfc8693 token exchange audience=%s scope=%q", req.Audience, req.Scope),
			Decision:    "DENY",
			Reason:      fmt.Sprintf("%s: %s", errCode, reason),
		}})
	}
}

// handleSTSInspector returns all active SaaS bindings and OBO token exchange history
func (s *Server) handleSTSInspector(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	exchanges := s.saasTokenMgr.ListExchanges()
	bindings := s.saasTokenMgr.ListBindings()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"exchanges":     exchanges,
		"active_tokens": bindings,
		"total_count":   len(exchanges),
	})
}

// writeOAuthError writes standard RFC 6749 / RFC 8693 OAuth 2.0 error responses
func writeOAuthError(w http.ResponseWriter, status int, errorCode, description string) {
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

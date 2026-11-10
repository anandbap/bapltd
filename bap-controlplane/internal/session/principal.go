package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"bap-controlplane/pkg/types"
)

// GeneratePrincipalID returns an explicit identifiable URN for an agent principal (BAP-911).
func GeneratePrincipalID(clientType string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	cleanClient := strings.ToLower(strings.TrimSpace(clientType))
	if cleanClient == "" {
		cleanClient = "agent"
	}
	return fmt.Sprintf("urn:bap:principal:agent:%s-%s", cleanClient, hex.EncodeToString(b))
}

// RegisterPrincipal registers an explicit agent principal distinct from its human owner (BAP-911).
func (s *Store) RegisterPrincipal(p types.AgentPrincipal) (*types.AgentPrincipal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.principals == nil {
		s.principals = make(map[string]*types.AgentPrincipal)
	}
	if s.sessionPrincipals == nil {
		s.sessionPrincipals = make(map[string]string)
	}

	if p.PrincipalID == "" {
		p.PrincipalID = GeneratePrincipalID(p.ClientType)
	}
	if p.PrincipalSVID == "" {
		p.PrincipalSVID = fmt.Sprintf("spiffe://bap.internal/principal/%s", p.PrincipalID)
	}
	if p.Status == "" {
		p.Status = "active"
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.LastActiveAt = now

	stored := p
	s.principals[p.PrincipalID] = &stored

	if p.AgentSessionID != "" {
		s.sessionPrincipals[p.AgentSessionID] = p.PrincipalID
		// Also update the session record if it exists
		if sess := s.sessions[p.AgentSessionID]; sess != nil {
			sess.PrincipalID = p.PrincipalID
			sess.PrincipalSVID = p.PrincipalSVID
		}
	}

	return &stored, nil
}

// GetPrincipal looks up an agent principal by ID (BAP-911).
func (s *Store) GetPrincipal(principalID string) (*types.AgentPrincipal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.principals == nil {
		return nil, false
	}
	p, ok := s.principals[principalID]
	if !ok {
		return nil, false
	}
	copy := *p
	return &copy, true
}

// GetSessionPrincipal retrieves the agent principal bound to a session (BAP-911).
func (s *Store) GetSessionPrincipal(sessionID string) (*types.AgentPrincipal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.sessionPrincipals == nil || s.principals == nil {
		return nil, false
	}
	pid, ok := s.sessionPrincipals[sessionID]
	if !ok {
		return nil, false
	}
	p, exists := s.principals[pid]
	if !exists {
		return nil, false
	}
	copy := *p
	return &copy, true
}

// ListPrincipals returns all registered agent principals (BAP-911).
func (s *Store) ListPrincipals() []types.AgentPrincipal {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]types.AgentPrincipal, 0, len(s.principals))
	for _, p := range s.principals {
		res = append(res, *p)
	}
	return res
}

// UpdatePrincipalStatus updates the operational lifecycle state of an agent principal.
func (s *Store) UpdatePrincipalStatus(principalID string, status string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.principals == nil {
		return fmt.Errorf("principal not found: %s", principalID)
	}
	p, ok := s.principals[principalID]
	if !ok {
		return fmt.Errorf("principal not found: %s", principalID)
	}
	p.Status = status
	p.LastActiveAt = time.Now().UTC()
	return nil
}

package registry

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"bap-controlplane/pkg/types"
)

type Store struct {
	mu            sync.RWMutex
	trustDomain   string
	agents        map[string]*types.RegisteredAgent
	identityIndex map[string][]*types.RegisteredAgent
}

func NewStore(trustDomain string) *Store {
	if trustDomain == "" {
		trustDomain = "bap.internal"
	}
	return &Store{
		trustDomain: trustDomain,
		agents:      make(map[string]*types.RegisteredAgent),
	}
}

func (s *Store) PreRegister(req types.PreRegisterRequest) (*types.RegisteredAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	idBytes := make([]byte, 6)
	if _, err := rand.Read(idBytes); err != nil {
		return nil, err
	}
	agentID := fmt.Sprintf("agent-%s-%s", strings.ToLower(req.AppID), hex.EncodeToString(idBytes))

	profile := req.EnvProfile
	if profile == "" {
		profile = types.ProfileDev
	}

	agent := &types.RegisteredAgent{
		AgentID:             agentID,
		AppID:               req.AppID,
		TrustDomain:         s.trustDomain,
		OwnerEmail:          req.OwnerEmail,
		AgentName:           req.AgentName,
		EnvProfile:          profile,
		Status:              types.StatusPendingEnrollment,
		AllowedBinaryHashes: req.AllowedBinaryHashes,
		PermittedScopes:     req.PermittedScopes,
		CreatedAt:           time.Now(),
	}

	s.agents[agentID] = agent
	s.indexIdentityLocked(agent)
	return agent, nil
}

func (s *Store) Get(agentID string) (*types.RegisteredAgent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agent, exists := s.agents[agentID]
	if !exists {
		return nil, fmt.Errorf("agent %q not found in registry", agentID)
	}
	copy := *agent
	copy.AllowedBinaryHashes = append([]string(nil), agent.AllowedBinaryHashes...)
	copy.PermittedScopes = append([]string(nil), agent.PermittedScopes...)
	copy.Subagents = append([]string(nil), agent.Subagents...)
	if copy.Status == types.StatusActive {
		lastAct := copy.CreatedAt
		if copy.LastHeartbeatAt != nil {
			lastAct = *copy.LastHeartbeatAt
		}
		elapsed := time.Since(lastAct)
		if elapsed > 15*time.Minute {
			copy.Status = types.StatusOffline
		}
	}
	return &copy, nil
}

func (s *Store) Enroll(agentID string, binaryHash, pubKey, hostname, osName, arch, instanceID string) (*types.RegisteredAgent, error) {
	return s.EnrollWithVersion(agentID, binaryHash, pubKey, hostname, osName, arch, instanceID, "", 0)
}

func (s *Store) EnrollWithVersion(agentID string, binaryHash, pubKey, hostname, osName, arch, instanceID, agentVersion string, protocolVersion int) (*types.RegisteredAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	parentAgent, exists := s.agents[agentID]
	if !exists {
		return nil, fmt.Errorf("agent %q not found", agentID)
	}

	if parentAgent.Status == types.StatusRevoked {
		return nil, fmt.Errorf("cannot enroll revoked agent %q", agentID)
	}

	now := time.Now()

	if instanceID == "" {
		idBytes := make([]byte, 4)
		_, _ = rand.Read(idBytes)
		if hostname != "" {
			instanceID = fmt.Sprintf("%s-%s", strings.ToLower(hostname), hex.EncodeToString(idBytes))
		} else {
			instanceID = fmt.Sprintf("inst-%s", hex.EncodeToString(idBytes))
		}
	}

	spiffeID := fmt.Sprintf("spiffe://%s/app/%s/instance/%s", s.trustDomain, strings.ToLower(parentAgent.AppID), instanceID)

	// If the parent agent is pending enrollment, or is re-enrolling/re-activating on the same workstation:
	isSameWorkstation := (instanceID != "" && parentAgent.InstanceID == instanceID) || (hostname != "" && strings.EqualFold(parentAgent.Hostname, hostname))
	if parentAgent.Status == types.StatusPendingEnrollment || parentAgent.Status == types.StatusDeregistered || isSameWorkstation {
		parentAgent.Status = types.StatusActive
		parentAgent.RevokedAt = nil
		s.removeIdentityLocked(parentAgent)
		parentAgent.InstanceID = instanceID
		s.indexIdentityLocked(parentAgent)
		parentAgent.SPIFFEID = spiffeID
		parentAgent.TrustDomain = s.trustDomain
		parentAgent.EnrolledBinaryHash = binaryHash
		parentAgent.PublicKey = pubKey
		if hostname != "" {
			parentAgent.Hostname = hostname
		}
		if osName != "" {
			parentAgent.OS = osName
		}
		if arch != "" {
			parentAgent.Arch = arch
		}
		if agentVersion != "" {
			parentAgent.AgentVersion = agentVersion
		}
		if protocolVersion != 0 {
			parentAgent.ProtocolVersion = protocolVersion
		}
		parentAgent.EnrolledAt = &now
		parentAgent.LastHeartbeatAt = &now
		return parentAgent, nil
	}

	// For multi-instance enrollment under the same fleet, spawn a unique instance entry
	instanceAgentID := fmt.Sprintf("%s-%s", parentAgent.AgentID, instanceID)
	agentInstance := &types.RegisteredAgent{
		AgentID:             instanceAgentID,
		AppID:               parentAgent.AppID,
		InstanceID:          instanceID,
		SPIFFEID:            spiffeID,
		TrustDomain:         s.trustDomain,
		OwnerEmail:          parentAgent.OwnerEmail,
		AgentName:           parentAgent.AgentName,
		EnvProfile:          parentAgent.EnvProfile,
		Status:              types.StatusActive,
		AllowedBinaryHashes: parentAgent.AllowedBinaryHashes,
		EnrolledBinaryHash:  binaryHash,
		PublicKey:           pubKey,
		Hostname:            hostname,
		OS:                  osName,
		Arch:                arch,
		AgentVersion:        agentVersion,
		ProtocolVersion:     protocolVersion,
		CreatedAt:           parentAgent.CreatedAt,
		EnrolledAt:          &now,
		LastHeartbeatAt:     &now,
		PermittedScopes:     parentAgent.PermittedScopes,
	}
	s.agents[instanceAgentID] = agentInstance
	s.indexIdentityLocked(agentInstance)
	return agentInstance, nil
}

// EnrollWithClaims enrolls an agent and attaches verified corporate identity claims (OIDC / IdP).
func (s *Store) EnrollWithClaims(
	agentID, binaryHash, pubKey, hostname, osName, arch, instanceID string,
	userEmail, department string, groups []string, authMode, idpProvider string,
) (*types.RegisteredAgent, error) {
	agent, err := s.Enroll(agentID, binaryHash, pubKey, hostname, osName, arch, instanceID)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if userEmail != "" {
		agent.UserEmail = userEmail
	}
	if department != "" {
		agent.Department = department
	}
	if len(groups) > 0 {
		agent.Groups = groups
	}
	if authMode != "" {
		agent.AuthMode = authMode
	}
	if idpProvider != "" {
		agent.IdPProvider = idpProvider
	}
	return agent, nil
}

func (s *Store) Revoke(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, exists := s.agents[agentID]
	if !exists {
		return fmt.Errorf("agent %q not found", agentID)
	}

	now := time.Now()
	agent.Status = types.StatusRevoked
	agent.RevokedAt = &now
	return nil
}

// IsRevoked checks if an agent has been revoked (BAP-532).
func (s *Store) IsRevoked(agentID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	agent, exists := s.agents[agentID]
	if !exists {
		return false
	}
	return agent.Status == types.StatusRevoked
}

func (s *Store) RevokeApp(appID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	count := 0
	for _, agent := range s.agents {
		if strings.EqualFold(agent.AppID, appID) && agent.Status != types.StatusRevoked {
			agent.Status = types.StatusRevoked
			agent.RevokedAt = &now
			count++
		}
	}
	if count == 0 {
		return 0, fmt.Errorf("no active instances found for app_id %q", appID)
	}
	return count, nil
}

func (s *Store) RevokeTarget(target string) (*types.RegisteredAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	now := time.Now()
	for _, a := range s.agents {
		if a.AgentID == target {
			a.Status = types.StatusRevoked
			a.RevokedAt = &now
			return a, nil
		}
	}
	return nil, fmt.Errorf("no agent found matching %q", target)
}

func (s *Store) RestoreTarget(target string) (*types.RegisteredAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	for _, a := range s.agents {
		if a.AgentID == target || a.InstanceID == target {
			if a.Status == types.StatusDeregistered {
				return nil, fmt.Errorf("agent %q is permanently deregistered and logged out; cannot restore, user must run 'bap login' to re-enroll", target)
			}
			a.Status = types.StatusActive
			a.RevokedAt = nil
			return a, nil
		}
	}
	return nil, fmt.Errorf("no agent found matching %q", target)
}

// Deregister marks an agent or instance as deregistered (e.g. via 'bap logout').
func (s *Store) Deregister(target string) (*types.RegisteredAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	now := time.Now()
	var matched *types.RegisteredAgent
	for _, a := range s.agents {
		if a.AgentID == target || a.InstanceID == target || (a.OwnerEmail != "" && strings.EqualFold(a.OwnerEmail, target)) || (a.UserEmail != "" && strings.EqualFold(a.UserEmail, target)) {
			a.Status = types.StatusDeregistered
			a.RevokedAt = &now
			if matched == nil {
				matched = a
			}
		}
	}
	if matched != nil {
		return matched, nil
	}
	return nil, fmt.Errorf("no agent found matching %q", target)
}

// FindWorkstationAgent locates an existing agent registered for this workstation resource (hostname and user/owner email).
// This guarantees that a developer's machine is represented as a single persistent agent across logins/logouts.
func (s *Store) FindWorkstationAgent(appID, email, hostname string) *types.RegisteredAgent {
	s.mu.Lock()
	defer s.mu.Unlock()

	if hostname == "" && email == "" {
		return nil
	}

	for _, a := range s.agents {
		matchHost := hostname != "" && a.Hostname != "" && strings.EqualFold(a.Hostname, hostname)
		matchEmail := email != "" && ((a.OwnerEmail != "" && strings.EqualFold(a.OwnerEmail, email)) || (a.UserEmail != "" && strings.EqualFold(a.UserEmail, email)))
		if matchHost && (matchEmail || email == "") {
			return a
		}
	}
	return nil
}

// SupersedeWorkstationAgent preserves the primary workstation agent and marks any secondary duplicates as deregistered.
func (s *Store) SupersedeWorkstationAgent(appID, email, hostname string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if hostname == "" && email == "" {
		return
	}

	now := time.Now()
	var primary *types.RegisteredAgent
	for _, a := range s.agents {
		matchHost := hostname != "" && a.Hostname != "" && strings.EqualFold(a.Hostname, hostname)
		matchEmail := email != "" && ((a.OwnerEmail != "" && strings.EqualFold(a.OwnerEmail, email)) || (a.UserEmail != "" && strings.EqualFold(a.UserEmail, email)))
		if matchHost && (matchEmail || email == "") {
			if primary == nil {
				primary = a
			} else {
				a.Status = types.StatusDeregistered
				a.RevokedAt = &now
			}
		}
	}
}

func (s *Store) Heartbeat(agentID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	agent, exists := s.agents[agentID]
	if !exists {
		return fmt.Errorf("agent %q not found", agentID)
	}
	if agent.Status == types.StatusRevoked {
		return fmt.Errorf("agent %q is revoked", agentID)
	}
	now := time.Now()
	agent.LastHeartbeatAt = &now
	return nil
}

func (s *Store) RecordGrant(agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if agent, exists := s.agents[agentID]; exists {
		now := time.Now()
		agent.LastGrantAt = &now
	}
}

func (s *Store) List() []*types.RegisteredAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	list := make([]*types.RegisteredAgent, 0, len(s.agents))
	for _, a := range s.agents {
		copy := *a
		copy.AllowedBinaryHashes = append([]string(nil), a.AllowedBinaryHashes...)
		copy.PermittedScopes = append([]string(nil), a.PermittedScopes...)
		copy.Subagents = append([]string(nil), a.Subagents...)
		if copy.Status == types.StatusActive {
			lastAct := copy.CreatedAt
			if copy.LastHeartbeatAt != nil {
				lastAct = *copy.LastHeartbeatAt
			}
			elapsed := now.Sub(lastAct)
			if elapsed > 15*time.Minute {
				copy.Status = types.StatusOffline
			}
		}
		list = append(list, &copy)
	}
	return list
}

// ListVisible returns registered agents, pruning non-revoked agents older than maxAge.
// Revoked agents are NEVER pruned so administrators can inspect and restore them.
func (s *Store) ListVisible(maxAge time.Duration, isUserRevoked func(string) bool) []*types.RegisteredAgent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	list := make([]*types.RegisteredAgent, 0, len(s.agents))
	for _, a := range s.agents {
		isRevoked := a.Status == types.StatusRevoked || a.Status == types.StatusQuarantined || (isUserRevoked != nil && isUserRevoked(a.OwnerEmail))
		if !isRevoked && maxAge > 0 {
			lastAct := a.CreatedAt
			if a.LastHeartbeatAt != nil {
				lastAct = *a.LastHeartbeatAt
			}
			if now.Sub(lastAct) > maxAge {
				continue
			}
		}
		copy := *a
		copy.AllowedBinaryHashes = append([]string(nil), a.AllowedBinaryHashes...)
		copy.PermittedScopes = append([]string(nil), a.PermittedScopes...)
		copy.Subagents = append([]string(nil), a.Subagents...)
		if copy.Status == types.StatusActive {
			lastAct := copy.CreatedAt
			if copy.LastHeartbeatAt != nil {
				lastAct = *copy.LastHeartbeatAt
			}
			elapsed := now.Sub(lastAct)
			if elapsed > 15*time.Minute {
				copy.Status = types.StatusOffline
			}
		}
		list = append(list, &copy)
	}
	return list
}

// QuarantineTarget marks an agent or instance as quarantined
func (s *Store) QuarantineTarget(target, reason string) (*types.RegisteredAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	for _, a := range s.agents {
		if a.AgentID == target || a.AppID == target || (a.InstanceID != "" && a.InstanceID == target) {
			a.Status = types.StatusQuarantined
			now := time.Now()
			a.RevokedAt = &now
			return a, nil
		}
	}
	return nil, fmt.Errorf("no agent found matching %q", target)
}

// UnquarantineTarget restores an agent or instance from quarantine
func (s *Store) UnquarantineTarget(target string) (*types.RegisteredAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("target is required")
	}
	for _, a := range s.agents {
		if a.AgentID == target || a.AppID == target || (a.InstanceID != "" && a.InstanceID == target) {
			if a.Status == types.StatusDeregistered {
				return nil, fmt.Errorf("agent %q is permanently deregistered and logged out; cannot restore, user must run 'bap login' to re-enroll", target)
			}
			a.Status = types.StatusActive
			a.RevokedAt = nil
			return a, nil
		}
	}
	return nil, fmt.Errorf("no agent found matching %q", target)
}

func (s *Store) TrustDomain() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.trustDomain
}

// EnsureSessionAgent guarantees that any active agent session is tracked in the registry.
// Stable instance ID is derived when not provided, avoiding agent sprawl across sessions.
func (s *Store) EnsureSessionAgent(appID, instanceID, spiffeID, userEmail, hostname string, agentNames ...string) *types.RegisteredAgent {
	s.mu.Lock()
	defer s.mu.Unlock()

	customName := ""
	if len(agentNames) > 0 && agentNames[0] != "" {
		customName = agentNames[0]
	}

	now := time.Now()
	if instanceID == "" {
		return nil
	}

	// If a workstation agent exists for this machine resource, record appID as a subagent under that 1 master agent
	s.buildIdentityIndexLocked()
	for _, a := range s.identityIndex["instance\x00"+instanceID] {
		matchInstance := instanceID != "" && (a.InstanceID == instanceID || a.AgentID == instanceID)
		if matchInstance {
			sub := appID
			if customName != "" {
				sub = customName
			}
			hasSub := false
			for _, ex := range a.Subagents {
				if strings.EqualFold(ex, sub) {
					hasSub = true
					break
				}
			}
			if !hasSub && sub != "" && !strings.EqualFold(sub, a.AppID) {
				a.Subagents = append(a.Subagents, sub)
			}
			a.LastHeartbeatAt = &now
			if a.Status != types.StatusRevoked && a.Status != types.StatusQuarantined && a.Status != types.StatusDeregistered {
				a.Status = types.StatusActive
			}
			return a
		}
	}

	agentID := fmt.Sprintf("agent-%s-%s", strings.ToLower(appID), instanceID)
	if previous, ok := s.agents[agentID]; ok && previous.InstanceID != instanceID {
		agentID = fmt.Sprintf("agent-session-%x", sha256.Sum256([]byte(appID+"\x00"+instanceID)))
	}
	if existing, found := s.agents[agentID]; found {
		if existing.Status == types.StatusRevoked {
			return existing
		}
		existing.Status = types.StatusActive
		existing.LastHeartbeatAt = &now
		if customName != "" && (existing.AgentName == "" || existing.AgentName == existing.AppID) {
			existing.AgentName = customName
		}
		if spiffeID != "" && spiffeID != "NA" {
			existing.SPIFFEID = spiffeID
		}
		if userEmail != "" && userEmail != "NA" {
			existing.OwnerEmail = userEmail
		}
		if hostname != "" {
			existing.Hostname = hostname
		}
		return existing
	}

	name := appID
	if customName != "" {
		name = customName
	}

	agent := &types.RegisteredAgent{
		AgentID:         agentID,
		AppID:           appID,
		RecoveryOnly:    true,
		InstanceID:      instanceID,
		SPIFFEID:        spiffeID,
		TrustDomain:     s.trustDomain,
		OwnerEmail:      userEmail,
		AgentName:       name,
		EnvProfile:      types.ProfileDev,
		Status:          types.StatusActive,
		Hostname:        hostname,
		CreatedAt:       now,
		EnrolledAt:      &now,
		LastHeartbeatAt: &now,
	}
	s.agents[agentID] = agent
	s.indexIdentityLocked(agent)
	return agent
}

// HeartbeatInstance records liveness for the exact app/instance identity linked
// to a session. Administrative revocation is never cleared by a heartbeat.
func (s *Store) HeartbeatInstance(appID, instanceID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if appID == "" || instanceID == "" {
		return fmt.Errorf("app_id and instance_id are required")
	}
	now := time.Now()
	s.buildIdentityIndexLocked()
	for _, a := range s.identityIndex["instance\x00"+instanceID] {
		if a.InstanceID == instanceID || a.AgentID == instanceID {
			if a.Status == types.StatusRevoked || a.Status == types.StatusQuarantined || a.Status == types.StatusDeregistered {
				return fmt.Errorf("agent %q is administratively blocked", a.AgentID)
			}
			a.Status = types.StatusActive
			a.LastHeartbeatAt = &now
			return nil
		}
	}
	return fmt.Errorf("agent instance %q/%q not found", appID, instanceID)
}

// EndSessionAgent updates the registry status when an ephemeral session closes.
// Workstation agents (enrolled via OIDC / device flow) remain enrolled permanently unless explicitly deregistered via 'bap logout'.
func (s *Store) EndSessionAgent(appID, instanceID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, a := range s.agents {
		if strings.EqualFold(a.AppID, appID) {
			if a.Status == types.StatusRevoked || a.Status == types.StatusDeregistered {
				continue
			}
			isWorkstation := strings.Contains(strings.ToLower(a.AppID), "workstation") || a.DeviceType != "" || a.AuthMode == "oidc"
			if instanceID != "" && (a.InstanceID == instanceID || a.AgentID == instanceID) {
				if isWorkstation {
					a.Status = types.StatusOffline
				} else {
					a.Status = types.StatusDeregistered
				}
				a.LastHeartbeatAt = &now
			}
		}
	}
}

// PurgeStale marks active agents whose last heartbeat/activity exceeds maxIdle.
// Workstation agents are transitioned to offline, while ephemeral session agents are deregistered.
func (s *Store) PurgeStale(maxIdle time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	count := 0
	for _, a := range s.agents {
		if a.Status == types.StatusActive {
			lastAct := a.CreatedAt
			if a.LastHeartbeatAt != nil {
				lastAct = *a.LastHeartbeatAt
			}
			if now.Sub(lastAct) > maxIdle {
				if a.Status == types.StatusRevoked || a.Status == types.StatusDeregistered {
					continue
				}
				isWorkstation := strings.Contains(strings.ToLower(a.AppID), "workstation") || a.DeviceType != "" || a.AuthMode == "oidc"
				if isWorkstation {
					a.Status = types.StatusOffline
				} else {
					a.Status = types.StatusDeregistered
				}
				a.LastHeartbeatAt = &now
				count++
			}
		}
	}
	return count
}

// Reset marks all active agents as deregistered.
func (s *Store) Reset() int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	count := 0
	for _, a := range s.agents {
		if a.Status == types.StatusActive {
			if a.Status == types.StatusRevoked {
				continue
			}
			a.Status = "deregistered"
			a.LastHeartbeatAt = &now
			count++
		}
	}
	return count
}

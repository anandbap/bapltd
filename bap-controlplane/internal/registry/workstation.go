package registry

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"bap-controlplane/pkg/types"
)

func workstationApp(app string) bool {
	return strings.Contains(strings.ToLower(app), "workstation") || strings.EqualFold(app, "bapedge")
}

func sameWorkstation(a *types.RegisteredAgent, req types.RegisteredAgent) bool {
	if req.Hostname == "" || req.UserEmail == "" ||
		!strings.EqualFold(strings.TrimSpace(a.Hostname), strings.TrimSpace(req.Hostname)) {
		return false
	}
	email := a.UserEmail
	if email == "" {
		email = a.OwnerEmail
	}
	if !strings.EqualFold(strings.TrimSpace(email), strings.TrimSpace(req.UserEmail)) {
		return false
	}
	return strings.EqualFold(a.AppID, req.AppID) ||
		(workstationApp(req.AppID) && (workstationApp(a.AppID) || a.AuthMode == "oidc" || a.DeviceType != ""))
}

// EnrollWorkstation updates one stable workstation identity across client
// upgrades and logout/login cycles. Lookup, selection and update share a lock.
// The caller must supply identity claims verified by the device authorization flow.
func (s *Store) EnrollWorkstation(req types.RegisteredAgent) (*types.RegisteredAgent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var primary *types.RegisteredAgent
	var matches []*types.RegisteredAgent
	for _, a := range s.agents {
		if !sameWorkstation(a, req) {
			continue
		}
		if a.Status == types.StatusRevoked || a.Status == types.StatusQuarantined {
			return nil, fmt.Errorf("workstation is administratively blocked")
		}
		matches = append(matches, a)
		if a.SupersededBy != "" {
			continue
		}
		if primary == nil || (primary.RecoveryOnly && !a.RecoveryOnly) ||
			(primary.RecoveryOnly == a.RecoveryOnly &&
				(a.CreatedAt.Before(primary.CreatedAt) || (a.CreatedAt.Equal(primary.CreatedAt) && a.AgentID < primary.AgentID))) {
			primary = a
		}
	}
	now := time.Now()
	if primary == nil {
		id := make([]byte, 6)
		if _, err := rand.Read(id); err != nil {
			return nil, err
		}
		primary = &types.RegisteredAgent{
			AgentID: fmt.Sprintf("agent-%s-%s", strings.ToLower(req.AppID), hex.EncodeToString(id)),
			AppID:   req.AppID, CreatedAt: now, EnvProfile: types.ProfileDev,
			PermittedScopes: append([]string(nil), req.PermittedScopes...),
		}
	}
	if primary.InstanceID == "" {
		id := make([]byte, 4)
		if _, err := rand.Read(id); err != nil {
			return nil, err
		}
		primary.InstanceID = fmt.Sprintf("%s-%s", strings.ToLower(req.Hostname), hex.EncodeToString(id))
	}
	s.removeIdentityLocked(primary)
	primary.SPIFFEID = fmt.Sprintf("spiffe://%s/app/%s/instance/%s", s.trustDomain, strings.ToLower(primary.AppID), primary.InstanceID)
	primary.TrustDomain = s.trustDomain
	primary.AgentName = req.AgentName
	primary.Hostname = req.Hostname
	primary.OS, primary.Arch = req.OS, req.Arch
	primary.DeviceType, primary.IPAddress = req.DeviceType, req.IPAddress
	primary.OwnerEmail, primary.UserEmail = req.UserEmail, req.UserEmail
	primary.Department = req.Department
	primary.Groups = append([]string(nil), req.Groups...)
	primary.AuthMode, primary.IdPProvider = "oidc", req.IdPProvider
	primary.EnrolledBinaryHash = req.EnrolledBinaryHash
	primary.Status, primary.RevokedAt = types.StatusActive, nil
	primary.EnrolledAt, primary.LastHeartbeatAt = &now, &now
	if primary.RecoveryOnly {
		primary.PermittedScopes = append([]string(nil), req.PermittedScopes...)
	}
	primary.RecoveryOnly = false
	primary.SupersededBy = ""
	s.agents[primary.AgentID] = primary
	s.indexIdentityLocked(primary)
	for _, a := range matches {
		if a.AgentID != primary.AgentID {
			a.Status, a.RevokedAt, a.SupersededBy = types.StatusDeregistered, &now, primary.AgentID
		}
	}
	result := *primary
	result.Groups = append([]string(nil), primary.Groups...)
	result.PermittedScopes = append([]string(nil), primary.PermittedScopes...)
	return &result, nil
}

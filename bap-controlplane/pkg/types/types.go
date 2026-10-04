package types

import "time"

type EnvProfile string

const (
	ProfileDev  EnvProfile = "development"
	ProfileProd EnvProfile = "production"
)

type AgentStatus string

const (
	StatusPendingEnrollment AgentStatus = "pending_enrollment"
	StatusActive            AgentStatus = "active"
	StatusRevoked           AgentStatus = "revoked"
)

type RegisteredAgent struct {
	AgentID             string      `json:"agent_id"`
	AppID               string      `json:"app_id"`
	InstanceID          string      `json:"instance_id,omitempty"`
	SPIFFEID            string      `json:"spiffe_id,omitempty"`
	TrustDomain         string      `json:"trust_domain,omitempty"`
	OwnerEmail          string      `json:"owner_email"`
	AgentName           string      `json:"agent_name"`
	EnvProfile          EnvProfile  `json:"env_profile"`
	Status              AgentStatus `json:"status"`
	AllowedBinaryHashes []string    `json:"allowed_binary_hashes,omitempty"`
	EnrolledBinaryHash  string      `json:"enrolled_binary_hash,omitempty"`
	PublicKey           string      `json:"public_key,omitempty"`
	Hostname            string      `json:"hostname,omitempty"`
	OS                  string      `json:"os,omitempty"`
	Arch                string      `json:"arch,omitempty"`
	CreatedAt           time.Time   `json:"created_at"`
	EnrolledAt          *time.Time  `json:"enrolled_at,omitempty"`
	LastGrantAt         *time.Time  `json:"last_grant_at,omitempty"`
	LastHeartbeatAt     *time.Time  `json:"last_heartbeat_at,omitempty"`
	RevokedAt           *time.Time  `json:"revoked_at,omitempty"`
	PermittedScopes     []string    `json:"permitted_scopes,omitempty"`
}

type PreRegisterRequest struct {
	AppID               string     `json:"app_id"`
	OwnerEmail          string     `json:"owner_email"`
	AgentName           string     `json:"agent_name"`
	EnvProfile          EnvProfile `json:"env_profile"`
	AllowedBinaryHashes []string   `json:"allowed_binary_hashes,omitempty"`
	PermittedScopes     []string   `json:"permitted_scopes,omitempty"`
	TTLMins             int        `json:"ttl_minutes,omitempty"`
	MaxInstances        int        `json:"max_instances,omitempty"`
}

type PreRegisterResponse struct {
	AgentID      string    `json:"agent_id"`
	Code         string    `json:"one_time_code"`
	ExpiresAt    time.Time `json:"expires_at"`
	MaxInstances int       `json:"max_instances,omitempty"`
}

type RegisterEdgeRequest struct {
	Code       string `json:"one_time_code"`
	BinaryHash string `json:"binary_hash"`
	PublicKey  string `json:"public_key"`
	Hostname   string `json:"hostname,omitempty"`
	OS         string `json:"os,omitempty"`
	Arch       string `json:"arch,omitempty"`
	InstanceID string `json:"instance_id,omitempty"`
}

type RegisterEdgeResponse struct {
	AgentID      string    `json:"agent_id"`
	AppID        string    `json:"app_id"`
	InstanceID   string    `json:"instance_id,omitempty"`
	SPIFFEID     string    `json:"spiffe_id,omitempty"`
	Status       string    `json:"status"`
	ServerTime   time.Time `json:"server_time"`
	SessionToken string    `json:"session_token"`
}

type GrantConstraints struct {
	MaxUses   int `json:"max_uses,omitempty"`
	MaxAmount int `json:"max_amount,omitempty"`
}

type AcquireGrantRequest struct {
	AgentID     string            `json:"agent_id"`
	BinaryHash  string            `json:"binary_hash"`
	Signature   string            `json:"signature,omitempty"`
	Timestamp   int64             `json:"timestamp"`
	SessionID   string            `json:"session_id,omitempty"`
	Action      string            `json:"action,omitempty"`
	Resource    string            `json:"resource,omitempty"`
	Constraints *GrantConstraints `json:"constraints,omitempty"`
	Scopes      []string          `json:"scopes,omitempty"`
}

type AcquireGrantResponse struct {
	Token         string            `json:"token"`
	TokenType     string            `json:"token_type"`
	GrantID       string            `json:"grant_id,omitempty"`
	ExpiresAt     time.Time         `json:"expires_at"`
	TTLSecs       int               `json:"expires_in"`
	Scopes        []string          `json:"scopes"`
	SessionID     string            `json:"session_id,omitempty"`
	Action        string            `json:"action,omitempty"`
	Resource      string            `json:"resource,omitempty"`
	PolicyVersion string            `json:"policy_version,omitempty"`
	Constraints   *GrantConstraints `json:"constraints,omitempty"`
}

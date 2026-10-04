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
	UserEmail           string      `json:"user_email,omitempty"`
	Department          string      `json:"department,omitempty"`
	Groups              []string    `json:"groups,omitempty"`
	AuthMode            string      `json:"auth_mode,omitempty"`   // "otc" or "oidc"
	IdPProvider         string      `json:"idp_provider,omitempty"` // "entra", "okta", "generic"
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

// DevOTCRequest allows unauthenticated developers in dev mode to request an instant OTC.
type DevOTCRequest struct {
	AppID      string `json:"app_id,omitempty"`
	OwnerEmail string `json:"owner_email,omitempty"`
	AgentName  string `json:"agent_name,omitempty"`
}

type DevOTCResponse struct {
	AgentID   string    `json:"agent_id"`
	Code      string    `json:"one_time_code"`
	ExpiresAt time.Time `json:"expires_at"`
	Mode      string    `json:"mode"`
}

// OIDC Device Flow Types (RFC 8628)
type OIDCDeviceCodeRequest struct {
	ClientID   string `json:"client_id"`
	Scope      string `json:"scope,omitempty"`
	Provider   string `json:"provider,omitempty"` // "entra", "okta", "generic"
	Hostname   string `json:"hostname,omitempty"`
	BinaryHash string `json:"binary_hash,omitempty"`
	AppID      string `json:"app_id,omitempty"`
}

type OIDCDeviceCodeResponse struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type OIDCDeviceTokenRequest struct {
	DeviceCode string `json:"device_code"`
}

type OIDCDeviceTokenResponse struct {
	Status       string    `json:"status"` // "pending", "authorized", "expired"
	Error        string    `json:"error,omitempty"`
	IDToken      string    `json:"id_token,omitempty"`
	AccessToken  string    `json:"access_token,omitempty"`
	UserEmail    string    `json:"user_email,omitempty"`
	Department   string    `json:"department,omitempty"`
	Groups       []string  `json:"groups,omitempty"`
	AgentID      string    `json:"agent_id,omitempty"`
	AppID        string    `json:"app_id,omitempty"`
	InstanceID   string    `json:"instance_id,omitempty"`
	SessionToken string    `json:"session_token,omitempty"`
	ExpiresIn    int       `json:"expires_in,omitempty"`
	Provider     string    `json:"provider,omitempty"`
}

type OIDCDeviceVerifyRequest struct {
	UserCode   string   `json:"user_code"`
	UserEmail  string   `json:"user_email"`
	Department string   `json:"department"`
	Groups     []string `json:"groups"`
	Provider   string   `json:"provider,omitempty"`
}

// OIDCConfig defines configurable Enterprise Identity Provider parameters.
type OIDCConfig struct {
	Enabled         bool     `json:"enabled"`
	Provider        string   `json:"provider"`                 // "entra", "okta", "generic"
	IssuerURL       string   `json:"issuer_url,omitempty"`      // e.g. https://login.microsoftonline.com/{tenant_id}/v2.0
	ClientID        string   `json:"client_id,omitempty"`       // OAuth2 client_id
	ClientSecret    string   `json:"client_secret,omitempty"`   // Optional for confidential clients
	DeviceAuthURL   string   `json:"device_auth_url,omitempty"` // Device Authorization Endpoint
	TokenURL        string   `json:"token_url,omitempty"`       // Token Endpoint
	VerificationURI string   `json:"verification_uri,omitempty"`// User verification web page
	Scopes          []string `json:"scopes,omitempty"`          // e.g. ["openid", "profile", "email", "groups"]
	TenantID        string   `json:"tenant_id,omitempty"`       // Entra Tenant ID or Okta org
	AllowedDomains  []string `json:"allowed_domains,omitempty"` // e.g. ["corp.com", "enterprise.org"]
	ClaimDepartment string   `json:"claim_department,omitempty"`// Claim key for department (default: "department")
	ClaimGroups     string   `json:"claim_groups,omitempty"`    // Claim key for groups (default: "groups")
	ClaimEmail      string   `json:"claim_email,omitempty"`     // Claim key for email (default: "email")
}



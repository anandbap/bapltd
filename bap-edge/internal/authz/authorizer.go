package authz

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
	"github.com/cedar-policy/cedar-go/x/exp/schema"
)

// PrincipalIdentity encapsulates the authenticated corporate identity (OIDC / Entra / Okta or OTC).
type PrincipalIdentity struct {
	UserEmail  string   `json:"user_email"`
	Department string   `json:"department"`
	Groups     []string `json:"groups"`
	AgentID    string   `json:"agent_id"`
	AuthMode   string   `json:"auth_mode"`
}

// Authorizer evaluates execution requests against Cedar policies and schemas.
type Authorizer struct {
	policySet *cedar.PolicySet
	schema    *schema.Schema
	identity  PrincipalIdentity
}

// SetIdentity explicitly sets the authenticated engineer's corporate identity.
func (a *Authorizer) SetIdentity(identity PrincipalIdentity) {
	a.identity = identity
}

// GetIdentity returns the current authenticated corporate identity.
func (a *Authorizer) GetIdentity() PrincipalIdentity {
	return a.identity
}

// NewAuthorizer loads the Cedar policy and optional schema from specified or standard locations.
func NewAuthorizer(policyPath string) (*Authorizer, error) {
	resolvedPolicyPath, err := findFile(policyPath, "policy.cedar")
	if err != nil {
		return nil, err
	}

	// Check if kill-switch is active in policy-state.json
	policyDir := filepath.Dir(resolvedPolicyPath)
	candidates := []string{
		filepath.Join(policyDir, ".bap", "policy-state.json"),
		filepath.Join(policyDir, "policy-state.json"),
		filepath.Join(".bap", "policy-state.json"),
		"policy-state.json",
	}
	for _, statePath := range candidates {
		if stateData, stateErr := os.ReadFile(statePath); stateErr == nil {
			var state struct {
				KillSwitch bool `json:"kill_switch"`
			}
			if json.Unmarshal(stateData, &state) == nil && state.KillSwitch {
				return nil, fmt.Errorf("emergency kill-switch is active; all executions are blocked")
			}
		}
	}

	policyData, err := os.ReadFile(resolvedPolicyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read policy file %s: %w", resolvedPolicyPath, err)
	}

	ps, err := cedar.NewPolicySetFromBytes(resolvedPolicyPath, policyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Cedar policy file %s: %w", resolvedPolicyPath, err)
	}

	authz := &Authorizer{policySet: ps}

	// Load authenticated corporate identity from ~/.ltd/credentials.json if enrolled
	if home, err := os.UserHomeDir(); err == nil {
		credsCandidate := filepath.Join(home, ".ltd", "credentials.json")
		if data, err := os.ReadFile(credsCandidate); err == nil {
			var creds struct {
				UserEmail  string   `json:"user_email"`
				Department string   `json:"department"`
				Groups     []string `json:"groups"`
				AgentID    string   `json:"agent_id"`
				AuthMode   string   `json:"auth_mode"`
			}
			if json.Unmarshal(data, &creds) == nil {
				authz.identity = PrincipalIdentity{
					UserEmail:  creds.UserEmail,
					Department: creds.Department,
					Groups:     creds.Groups,
					AgentID:    creds.AgentID,
					AuthMode:   creds.AuthMode,
				}
			}
		}
	}

	// Try loading schema.json from the same directory or standard locations
	schemaPathCandidate := filepath.Join(policyDir, "schema.json")
	if resolvedSchemaPath, err := findFile(schemaPathCandidate, "schema.json"); err == nil {
		if schemaData, err := os.ReadFile(resolvedSchemaPath); err == nil {
			var s schema.Schema
			if err := s.UnmarshalJSON(schemaData); err == nil {
				if _, err := s.Resolve(); err == nil {
					authz.schema = &s
					if os.Getenv("BAP_DEBUG") != "" {
						fmt.Fprintf(os.Stderr, "[authz] Loaded and validated Cedar schema from %s\n", resolvedSchemaPath)
					}
				} else {
					fmt.Fprintf(os.Stderr, "[authz] Warning: Failed to resolve schema %s: %v\n", resolvedSchemaPath, err)
				}
			} else {
				fmt.Fprintf(os.Stderr, "[authz] Warning: Failed to parse schema %s: %v\n", resolvedSchemaPath, err)
			}
		}
	}

	return authz, nil
}

// Evaluate checks whether executing the given command is permitted.
// The Cedar schema specifies:
// - Principal: Agent::"Local"
// - Action:    Action::"Execute"
// - Resource:  Command::"CLI"
func (a *Authorizer) Evaluate(executable, fullCommand, args string) (bool, string, error) {
	return a.EvaluateWithWorkspace(executable, fullCommand, args, GetWorkspaceRoot())
}

// EvaluateWithWorkspace evaluates whether executing the given command is permitted
// within the specified workspaceRoot directory boundary.
func (a *Authorizer) EvaluateWithWorkspace(executable, fullCommand, args, workspaceRoot string) (bool, string, error) {
	normalizedExec := strings.ToLower(executable)
	normalizedFull := strings.ToLower(fullCommand)
	normalizedArgs := strings.ToLower(args)

	escapesWorkspace := false
	if workspaceRoot != "" {
		escapesWorkspace = CheckCommandWorkspaceEscape(workspaceRoot, fullCommand)
	}

	principalUID := cedar.NewEntityUID("Agent", "Local")

	// Construct Principal attributes record including authenticated corporate identity claims
	principalAttrs := cedar.RecordMap{
		cedar.String("department"): cedar.String(a.identity.Department),
		cedar.String("email"):      cedar.String(a.identity.UserEmail),
	}
	if len(a.identity.Groups) > 0 {
		var groupVals []types.Value
		for _, g := range a.identity.Groups {
			groupVals = append(groupVals, cedar.String(g))
		}
		principalAttrs[cedar.String("groups")] = cedar.NewSet(groupVals...)
	} else {
		principalAttrs[cedar.String("groups")] = cedar.NewSet()
	}

	entities := types.EntityMap{
		principalUID: types.Entity{
			UID:        principalUID,
			Attributes: cedar.NewRecord(principalAttrs),
		},
	}

	contextMap := cedar.RecordMap{
		cedar.String("executable"):        cedar.String(normalizedExec),
		cedar.String("full_command"):      cedar.String(normalizedFull),
		cedar.String("args"):              cedar.String(normalizedArgs),
		cedar.String("escapes_workspace"): cedar.Boolean(escapesWorkspace),
		cedar.String("department"):        cedar.String(a.identity.Department),
		cedar.String("user_email"):        cedar.String(a.identity.UserEmail),
	}

	req := cedar.Request{
		Principal: principalUID,
		Action:    cedar.NewEntityUID("Action", "Execute"),
		Resource:  cedar.NewEntityUID("Command", "CLI"),
		Context:   cedar.NewRecord(contextMap),
	}

	decision, diag := cedar.Authorize(a.policySet, entities, req)

	if decision == cedar.Allow {
		return true, "", nil
	}

	var reason string
	if len(diag.Reasons) > 0 {
		var reasonList []string
		for _, r := range diag.Reasons {
			reasonList = append(reasonList, fmt.Sprintf("policy %s", r.PolicyID))
		}
		reason = fmt.Sprintf("Denial triggered by: %s", strings.Join(reasonList, ", "))
	} else if len(diag.Errors) > 0 {
		var errList []string
		for _, e := range diag.Errors {
			errList = append(errList, e.Message)
		}
		reason = fmt.Sprintf("Policy evaluation error: %s", strings.Join(errList, "; "))
	} else {
		reason = "Explicit deny or default deny (no permit policy matched)"
	}

	return false, reason, nil
}

// findFile resolves a file path by checking:
// 1. Specified custom path (if non-empty and exists)
// 2. Current working directory
// 3. Executable's directory
func findFile(customPath, defaultName string) (string, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath, nil
		}
	}

	// 1. Current directory
	cwdFile := defaultName
	if _, err := os.Stat(cwdFile); err == nil {
		return cwdFile, nil
	}

	// 2. Executable directory
	exe, err := os.Executable()
	if err == nil {
		exeDirFile := filepath.Join(filepath.Dir(exe), defaultName)
		if _, err := os.Stat(exeDirFile); err == nil {
			return exeDirFile, nil
		}
	}

	// 3. User cached policy directory (~/.ltd/policy/ or ~/.bap/policy/)
	if home, err := os.UserHomeDir(); err == nil {
		ltdCache := filepath.Join(home, ".ltd", "policy", defaultName)
		if _, err := os.Stat(ltdCache); err == nil {
			return ltdCache, nil
		}
		bapCache := filepath.Join(home, ".bap", "policy", defaultName)
		if _, err := os.Stat(bapCache); err == nil {
			return bapCache, nil
		}
	}

	return "", fmt.Errorf("%s not found in custom path, current directory, executable directory, or ~/.ltd/policy/", defaultName)
}

// CheckSessionRevocation checks if the given sessionID or system is blocked by local or cached policy state.
func CheckSessionRevocation(policyPath, sessionID string) error {
	resolvedPolicyPath, err := findFile(policyPath, "policy.cedar")
	if err != nil {
		// Fallback to checking local policy-state.json
		resolvedPolicyPath = "policy.cedar"
	}
	policyDir := filepath.Dir(resolvedPolicyPath)
	candidates := []string{
		filepath.Join(policyDir, ".bap", "policy-state.json"),
		filepath.Join(policyDir, "policy-state.json"),
		filepath.Join(".bap", "policy-state.json"),
		"policy-state.json",
	}

	for _, statePath := range candidates {
		stateData, err := os.ReadFile(statePath)
		if err != nil {
			continue
		}

		var state struct {
			KillSwitch      bool     `json:"kill_switch"`
			RevokedSessions []string `json:"revoked_sessions"`
		}
		if err := json.Unmarshal(stateData, &state); err != nil {
			continue
		}

		if state.KillSwitch {
			return fmt.Errorf("emergency kill-switch is active; all executions are blocked")
		}

		if sessionID != "" {
			sessLower := strings.ToLower(sessionID)
			for _, rev := range state.RevokedSessions {
				revLower := strings.ToLower(strings.TrimSpace(rev))
				if revLower == "" {
					continue
				}
				if strings.Contains(sessLower, revLower) || strings.Contains(revLower, sessLower) {
					return fmt.Errorf("session %q has been revoked by CISO administrator; execution blocked", sessionID)
				}
			}
		}
	}

	return nil
}

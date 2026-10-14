package authz

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// PathPermission represents user-authorized access to a cross-folder directory or file.
type PathPermission struct {
	Path      string    `json:"path"`
	Actions   []string  `json:"actions"` // "write", "delete", "all"
	Scope     string    `json:"scope"`   // "once", "session", "project", "global"
	GrantedAt time.Time `json:"granted_at"`
	GrantedBy string    `json:"granted_by"`
	SessionID string    `json:"session_id,omitempty"`
}

// PermissionsStore encapsulates persistent trusted paths for a scope.
type PermissionsStore struct {
	TrustedPaths []PathPermission `json:"trusted_paths"`
}

// GetGlobalPermissionsPath returns the path to the machine-wide permissions file (~/.bap/global_permissions.json).
func GetGlobalPermissionsPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".bap", "global_permissions.json")
	}
	return filepath.Join(home, ".bap", "global_permissions.json")
}

// GetProjectPermissionsPath returns the path to the workspace-level permissions file (<workspace>/.bap/project_permissions.json).
func GetProjectPermissionsPath(workspaceRoot string) string {
	if workspaceRoot == "" {
		workspaceRoot = GetWorkspaceRoot()
	}
	return filepath.Join(workspaceRoot, ".bap", "project_permissions.json")
}

// GetSessionPermissionsPath returns the path to the session-scoped approvals file.
func GetSessionPermissionsPath(workspaceRoot, sessionID string) string {
	if workspaceRoot == "" {
		workspaceRoot = GetWorkspaceRoot()
	}
	if sessionID == "" {
		sessionID = "default"
	}
	safeID := strings.ReplaceAll(sessionID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	safeID = strings.ReplaceAll(safeID, "\\", "_")
	return filepath.Join(workspaceRoot, ".bap", fmt.Sprintf("approvals_%s.json", safeID))
}

func readPermissionsFile(filePath string) []PathPermission {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil
	}

	var store PermissionsStore
	if err := json.Unmarshal(data, &store); err == nil && len(store.TrustedPaths) > 0 {
		return store.TrustedPaths
	}

	// Also support legacy session approval schema: { "approved_commands": {...}, "approved_paths": [...] }
	var legacy struct {
		ApprovedPaths []PathPermission `json:"approved_paths"`
	}
	if err := json.Unmarshal(data, &legacy); err == nil && len(legacy.ApprovedPaths) > 0 {
		return legacy.ApprovedPaths
	}

	return nil
}

func writePermissionsFile(filePath string, perms []PathPermission) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	store := PermissionsStore{TrustedPaths: perms}
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filePath, data, 0600)
}

// IsPathCovered checks if targetPath is covered by trustedPath (exact match or subdirectory).
func IsPathCovered(trustedPath, targetPath string) bool {
	if trustedPath == "" || targetPath == "" {
		return false
	}
	cleanTrusted := filepath.Clean(trustedPath)
	cleanTarget := filepath.Clean(targetPath)

	if strings.EqualFold(cleanTrusted, cleanTarget) {
		return true
	}

	rel, err := filepath.Rel(cleanTrusted, cleanTarget)
	if err != nil {
		return false
	}
	if rel == "." || (!strings.HasPrefix(rel, "..") && !strings.HasPrefix(rel, "/") && !strings.HasPrefix(rel, "\\")) {
		return true
	}
	return false
}

// IsTargetAuthorized checks whether cross-folder operations on targetPath with action are authorized
// across Session, Project, or Global scopes.
func IsTargetAuthorized(workspaceRoot, sessionID, targetPath, action string) (bool, string) {
	if targetPath == "" {
		return false, ""
	}
	normAction := strings.ToLower(strings.TrimSpace(action))
	if normAction == "" {
		normAction = "write"
	}

	cleanTarget := filepath.Clean(targetPath)

	// 1. Check Session Scope
	if sessionID != "" {
		sessionFile := GetSessionPermissionsPath(workspaceRoot, sessionID)
		for _, p := range readPermissionsFile(sessionFile) {
			if IsPathCovered(p.Path, cleanTarget) && actionMatches(p.Actions, normAction) {
				return true, "session"
			}
		}
	}

	// 2. Check Project Scope
	projectFile := GetProjectPermissionsPath(workspaceRoot)
	for _, p := range readPermissionsFile(projectFile) {
		if IsPathCovered(p.Path, cleanTarget) && actionMatches(p.Actions, normAction) {
			return true, "project"
		}
	}

	// 3. Check Global Scope
	globalFile := GetGlobalPermissionsPath()
	for _, p := range readPermissionsFile(globalFile) {
		if IsPathCovered(p.Path, cleanTarget) && actionMatches(p.Actions, normAction) {
			return true, "global"
		}
	}

	return false, ""
}

func actionMatches(actions []string, requested string) bool {
	if len(actions) == 0 {
		return true
	}
	for _, a := range actions {
		lower := strings.ToLower(strings.TrimSpace(a))
		if lower == "all" || lower == "*" || lower == requested {
			return true
		}
		if (requested == "write" || requested == "delete") && lower == "modify" {
			return true
		}
	}
	return false
}

// GrantPermission records authorization for a target path under the specified scope.
// Scope: "session", "project", or "global".
func GrantPermission(workspaceRoot, sessionID, targetPath, scope string, actions []string) error {
	if targetPath == "" {
		return fmt.Errorf("target path cannot be empty")
	}
	cleanPath, err := filepath.Abs(targetPath)
	if err != nil {
		cleanPath = filepath.Clean(targetPath)
	}

	if len(actions) == 0 {
		actions = []string{"write", "delete"}
	}

	perm := PathPermission{
		Path:      cleanPath,
		Actions:   actions,
		Scope:     scope,
		GrantedAt: time.Now().UTC(),
		GrantedBy: "user_override",
		SessionID: sessionID,
	}

	var filePath string
	switch strings.ToLower(scope) {
	case "session":
		filePath = GetSessionPermissionsPath(workspaceRoot, sessionID)
	case "project":
		filePath = GetProjectPermissionsPath(workspaceRoot)
	case "global":
		filePath = GetGlobalPermissionsPath()
	default:
		return fmt.Errorf("invalid permission scope %q (must be 'session', 'project', or 'global')", scope)
	}

	existing := readPermissionsFile(filePath)
	updated := false
	for i, p := range existing {
		if strings.EqualFold(filepath.Clean(p.Path), cleanPath) {
			existing[i] = perm
			updated = true
			break
		}
	}
	if !updated {
		existing = append(existing, perm)
	}

	return writePermissionsFile(filePath, existing)
}

// RevokePermission removes authorization for targetPath from the specified scope.
func RevokePermission(workspaceRoot, sessionID, targetPath, scope string) error {
	cleanPath, err := filepath.Abs(targetPath)
	if err != nil {
		cleanPath = filepath.Clean(targetPath)
	}

	var filePath string
	switch strings.ToLower(scope) {
	case "session":
		filePath = GetSessionPermissionsPath(workspaceRoot, sessionID)
	case "project":
		filePath = GetProjectPermissionsPath(workspaceRoot)
	case "global":
		filePath = GetGlobalPermissionsPath()
	default:
		return fmt.Errorf("invalid permission scope %q (must be 'session', 'project', or 'global')", scope)
	}

	existing := readPermissionsFile(filePath)
	var filtered []PathPermission
	for _, p := range existing {
		if !strings.EqualFold(filepath.Clean(p.Path), cleanPath) {
			filtered = append(filtered, p)
		}
	}

	return writePermissionsFile(filePath, filtered)
}

// ListAllPermissions returns all granted cross-folder permissions across Session, Project, and Global scopes.
func ListAllPermissions(workspaceRoot, sessionID string) []PathPermission {
	var all []PathPermission

	if sessionID != "" {
		for _, p := range readPermissionsFile(GetSessionPermissionsPath(workspaceRoot, sessionID)) {
			p.Scope = "session"
			all = append(all, p)
		}
	}
	for _, p := range readPermissionsFile(GetProjectPermissionsPath(workspaceRoot)) {
		p.Scope = "project"
		all = append(all, p)
	}
	for _, p := range readPermissionsFile(GetGlobalPermissionsPath()) {
		p.Scope = "global"
		all = append(all, p)
	}

	return all
}

// RecordLegacySessionCommandApproval updates session approval files for CLI commands.
func RecordLegacySessionCommandApproval(sessionID, fullCommand, executable, approvalType string) {
	if sessionID == "" {
		sessionID = "default"
	}
	safeID := strings.ReplaceAll(sessionID, ":", "_")
	safeID = strings.ReplaceAll(safeID, "/", "_")
	safeID = strings.ReplaceAll(safeID, "\\", "_")
	path := filepath.Join(GetWorkspaceRoot(), ".bap", fmt.Sprintf("approvals_%s.json", safeID))
	_ = os.MkdirAll(filepath.Dir(path), 0700)

	type legacyRecord struct {
		SessionID           string            `json:"session_id"`
		ApprovedCommands    map[string]string `json:"approved_commands"`
		ApprovedExecutables map[string]bool   `json:"approved_executables"`
		TrustedPaths        []PathPermission  `json:"trusted_paths,omitempty"`
	}

	var rec legacyRecord
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &rec)
	}
	rec.SessionID = sessionID
	if rec.ApprovedCommands == nil {
		rec.ApprovedCommands = make(map[string]string)
	}
	if rec.ApprovedExecutables == nil {
		rec.ApprovedExecutables = make(map[string]bool)
	}
	cmdHash := fmt.Sprintf("%x", sha256.Sum256([]byte(strings.TrimSpace(fullCommand))))
	rec.ApprovedCommands[cmdHash] = approvalType
	if approvalType == "session" {
		normExec := strings.ToLower(strings.TrimSpace(executable))
		if normExec != "" {
			rec.ApprovedExecutables[normExec] = true
		}
	}
	if b, err := json.MarshalIndent(rec, "", "  "); err == nil {
		_ = os.WriteFile(path, b, 0600)
	}
}

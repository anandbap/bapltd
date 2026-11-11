package authz

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"bap-edge/internal/identity"
	"bap-edge/pkg/types"
)

type persistedPrincipal struct {
	SVID          types.CryptographicAgentSVID `json:"svid"`
	PrivateKeyHex string                       `json:"private_key_hex"`
	PublicKeyHex  string                       `json:"public_key_hex"`
}

// ZSPStatusReport captures the cryptographic principal, zero-standing-privilege posture,
// and active/burned grants for a session (BAP-915, BAP-916, BAP-917, BAP-918).
type ZSPStatusReport struct {
	SessionID          string                        `json:"session_id"`
	Principal          *types.CryptographicAgentSVID `json:"principal,omitempty"`
	StandingPrivileges string                        `json:"standing_privileges"`
	ActiveGrants       []types.TaskGrant             `json:"active_grants"`
	BurnedOrExpired    []types.TaskGrant             `json:"burned_or_expired_grants,omitempty"`
	RecentLineage      []types.AuditLineageProof     `json:"recent_lineage,omitempty"`
}

var unsafeSessionChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func sanitizeZSPKey(s string) string {
	clean := unsafeSessionChars.ReplaceAllString(strings.TrimSpace(s), "_")
	if clean == "" {
		return "default-session"
	}
	return clean
}

// ResolveZSPDir returns the workspace-local or user-home directory used for persistent ZSP state.
func ResolveZSPDir() string {
	if env := strings.TrimSpace(os.Getenv("BAP_ZSP_DIR")); env != "" {
		return filepath.Clean(env)
	}
	if ws := GetWorkspaceRoot(); ws != "" && ws != "." {
		return filepath.Join(ws, ".bapstate", "zsp")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, ".bapstate", "zsp")
	}
	return filepath.Join(".bapstate", "zsp")
}

// IsZSPEnforced returns true unless ZSP has been explicitly disabled for isolated legacy testing.
func IsZSPEnforced() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_ZSP")))
	if v == "0" || v == "false" || v == "off" || v == "disabled" {
		return false
	}
	return true
}

// IsZSPControlCommand returns true if fullCommand is a single atomic BAP ZSP/status/why
// control-channel invocation without shell chaining or redirections.
// Agents start with 0 standing privileges and must be able to invoke the ZSP PEP directly
// to submit a signed 4-tuple TaskAuthorizationEnvelope or inspect their status.
func IsZSPControlCommand(fullCommand string) bool {
	trimmed := strings.TrimSpace(fullCommand)
	if trimmed == "" || strings.ContainsAny(trimmed, "\r\n|;&><`") || strings.Contains(trimmed, "$(") {
		return false
	}
	pipe, err := ParseAST(trimmed)
	if err != nil || pipe == nil || len(pipe.Nodes) != 1 || len(pipe.Nodes[0].SubCommands) > 0 {
		return false
	}
	tokens := tokenizeCommand(trimmed)
	if len(tokens) < 2 {
		return false
	}
	execBase := strings.ToLower(filepath.Base(strings.Trim(tokens[0], "\"'")))
	switch execBase {
	case "bapedge", "bapedge.exe", "bap", "bap.exe", "ltd-agent", "ltd-agent.exe":
	default:
		return false
	}
	sub := strings.ToLower(strings.Trim(tokens[1], "\"'"))
	switch sub {
	case "zsp", "status", "why", "version":
		return true
	default:
		return false
	}
}

func loadOrCreatePEPSecret(zspDir string) (string, error) {
	if err := os.MkdirAll(zspDir, 0700); err != nil {
		return "", err
	}
	keyPath := filepath.Join(zspDir, "pepper.key")
	if data, err := os.ReadFile(keyPath); err == nil {
		secret := strings.TrimSpace(string(data))
		if len(secret) >= 32 {
			return secret, nil
		}
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	secret := hex.EncodeToString(buf)
	if err := os.WriteFile(keyPath, []byte(secret+"\n"), 0600); err != nil {
		return "", err
	}
	return secret, nil
}

func resolveWorkstationOwner() (workstationID, ownerEmail, oidcSub string) {
	host, _ := os.Hostname()
	if host == "" {
		host = "local-host"
	}
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	if user == "" {
		user = "developer"
	}
	h := sha256.Sum256([]byte(host + ":" + user))
	workstationID = fmt.Sprintf("wkstn-%s-%s", hex.EncodeToString(h[:4]), user)
	ownerEmail = fmt.Sprintf("%s@%s.local", user, strings.ToLower(host))
	oidcSub = "local-workstation:" + user

	var candidates []string
	if envCred := os.Getenv("BAP_CREDENTIALS"); envCred != "" {
		candidates = append(candidates, envCred)
	}
	if ws := GetWorkspaceRoot(); ws != "" {
		candidates = append(candidates,
			filepath.Join(ws, ".bapstate", "credentials.json"),
			filepath.Join(ws, ".bap", "credentials.json"),
		)
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".bapstate", "credentials.json"),
			filepath.Join(home, ".bap", "credentials.json"),
		)
	}
	for _, cp := range candidates {
		data, err := os.ReadFile(cp)
		if err != nil {
			continue
		}
		var creds struct {
			UserEmail string `json:"user_email"`
			Email     string `json:"email"`
			UserID    string `json:"user_id"`
			OIDCSub   string `json:"oidc_sub"`
			Subject   string `json:"sub"`
		}
		if json.Unmarshal(data, &creds) == nil {
			if creds.UserEmail != "" {
				ownerEmail = creds.UserEmail
			} else if creds.Email != "" {
				ownerEmail = creds.Email
			} else if creds.UserID != "" {
				ownerEmail = creds.UserID
			}
			if creds.OIDCSub != "" {
				oidcSub = creds.OIDCSub
			} else if creds.Subject != "" {
				oidcSub = creds.Subject
			}
			break
		}
	}
	return workstationID, ownerEmail, oidcSub
}

// EnsureSessionPrincipal loads or mints a persisted cryptographic Ed25519 Agent SVID
// anchored to the workstation human owner. Calling this initializes the session with 0 grants.
func EnsureSessionPrincipal(zspDir, sessionID, clientType string) (*types.CryptographicAgentSVID, *identity.AgentKeypair, *identity.WorkstationIdentityMinter, string, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	if sessionID == "" {
		sessionID = "default-session"
	}
	if clientType == "" {
		clientType = "claude-code"
	}

	pepSecret, err := loadOrCreatePEPSecret(zspDir)
	if err != nil {
		return nil, nil, nil, "", err
	}
	minter := identity.NewWorkstationIdentityMinter(pepSecret, "bap.local")

	principalsDir := filepath.Join(zspDir, "principals")
	if err := os.MkdirAll(principalsDir, 0700); err != nil {
		return nil, nil, nil, "", err
	}
	pPath := filepath.Join(principalsDir, sanitizeZSPKey(sessionID)+".json")
	if data, err := os.ReadFile(pPath); err == nil {
		var pp persistedPrincipal
		if json.Unmarshal(data, &pp) == nil && minter.VerifyAgentSVID(&pp.SVID) == nil {
			privBytes, err1 := hex.DecodeString(pp.PrivateKeyHex)
			pubBytes, err2 := hex.DecodeString(pp.PublicKeyHex)
			if err1 == nil && err2 == nil && len(privBytes) == ed25519.PrivateKeySize && len(pubBytes) == ed25519.PublicKeySize {
				kp := &identity.AgentKeypair{
					PublicKey:  ed25519.PublicKey(pubBytes),
					PrivateKey: ed25519.PrivateKey(privBytes),
				}
				return &pp.SVID, kp, minter, pepSecret, nil
			}
		}
	}

	kp, err := identity.GenerateAgentKeypair()
	if err != nil {
		return nil, nil, nil, "", err
	}
	workstationID, ownerEmail, oidcSub := resolveWorkstationOwner()
	svid, err := minter.MintAgentSVID(kp, ownerEmail, oidcSub, workstationID, sessionID, clientType, 8*time.Hour)
	if err != nil {
		return nil, nil, nil, "", err
	}

	pp := persistedPrincipal{
		SVID:          *svid,
		PrivateKeyHex: hex.EncodeToString(kp.PrivateKey),
		PublicKeyHex:  hex.EncodeToString(kp.PublicKey),
	}
	if encoded, err := json.MarshalIndent(pp, "", "  "); err == nil {
		_ = os.WriteFile(pPath, encoded, 0600)
	}
	return svid, kp, minter, pepSecret, nil
}

// SubmitTaskEnvelope constructs, cryptographically signs, evaluates via ZSPEngine,
// and persists a least-privilege ephemeral TaskGrant for sessionID (BAP-916 & BAP-917).
func SubmitTaskEnvelope(
	zspDir, sessionID, clientType, mission, goal, promptText string,
	actions, resources []string,
	authorizedBy string,
	maxUses int,
	ttl time.Duration,
) (*types.TaskGrant, *types.TaskAuthorizationEnvelope, error) {
	svid, kp, minter, pepSecret, err := EnsureSessionPrincipal(zspDir, sessionID, clientType)
	if err != nil {
		return nil, nil, err
	}
	if len(actions) == 0 {
		return nil, nil, fmt.Errorf("%w: permission ask requires at least one action", ErrInvalidEnvelope)
	}
	if len(resources) == 0 {
		resources = []string{"workspace://current"}
	}
	if mission == "" {
		mission = "TASK_EXECUTION"
	}
	if goal == "" {
		goal = "Declared agent task"
	}
	if promptText == "" {
		promptText = goal
	}

	promptDigest := sha256.Sum256([]byte(promptText))
	deleg := types.DelegationIdentity{
		DelegationType: "human_interactive_prompt",
		ApproverEmail:  svid.HumanOwner,
	}
	if authorizedBy != "" {
		deleg.ApproverEmail = authorizedBy
	}
	intent := types.TaskIntent{
		PrimaryMission: strings.ToUpper(strings.TrimSpace(mission)),
		DeclaredGoal:   goal,
		PromptHash:     hex.EncodeToString(promptDigest[:]),
	}
	perms := types.PermissionAsk{
		Actions:   actions,
		Resources: resources,
	}

	b := make([]byte, 4)
	_, _ = rand.Read(b)
	envID := fmt.Sprintf("env-%s-%s", time.Now().UTC().Format("150405"), hex.EncodeToString(b))
	envHash := identity.ComputeEnvelopeHash(*svid, deleg, intent, perms)
	hashBytes, err := hex.DecodeString(envHash)
	if err != nil {
		return nil, nil, err
	}
	sig := hex.EncodeToString(kp.Sign(hashBytes))

	env := &types.TaskAuthorizationEnvelope{
		EnvelopeID:     envID,
		Identity:       *svid,
		AuthorizedBy:   deleg,
		Intent:         intent,
		PermissionAsk:  perms,
		EnvelopeHash:   envHash,
		AgentSignature: sig,
		Timestamp:      time.Now().UTC(),
	}

	engine := NewZSPEngine(minter, pepSecret)
	grant, err := engine.AuthorizeTaskEnvelope(env, maxUses, ttl)
	if err != nil {
		return nil, env, err
	}

	if err := saveSessionGrant(zspDir, sessionID, grant); err != nil {
		return nil, env, err
	}
	return grant, env, nil
}

func grantsDirForSession(zspDir, sessionID string) string {
	return filepath.Join(zspDir, "grants", sanitizeZSPKey(sessionID))
}

func saveSessionGrant(zspDir, sessionID string, g *types.TaskGrant) error {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	dir := grantsDirForSession(zspDir, sessionID)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, sanitizeZSPKey(g.GrantID)+".json"), data, 0600)
}

func loadSessionGrants(zspDir, sessionID string, engine *ZSPEngine) ([]*types.TaskGrant, error) {
	dir := grantsDirForSession(zspDir, sessionID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var loaded []*types.TaskGrant
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var g types.TaskGrant
		if err := json.Unmarshal(data, &g); err != nil {
			continue
		}
		if engine != nil {
			if err := engine.LoadGrant(&g); err != nil {
				continue
			}
		}
		loaded = append(loaded, &g)
	}
	sort.Slice(loaded, func(i, j int) bool {
		return loaded[i].IssuedAt.After(loaded[j].IssuedAt)
	})
	return loaded, nil
}

func appendZSPProof(zspDir string, proof *types.AuditLineageProof) {
	if proof == nil {
		return
	}
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	_ = os.MkdirAll(zspDir, 0700)
	line, err := json.Marshal(proof)
	if err != nil {
		return
	}
	f, err := os.OpenFile(filepath.Join(zspDir, "lineage.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(line, '\n'))
}

// VerifyOrConsumeSessionZSP enforces Zero Standing Privileges against persisted TaskGrants
// for sessionID. If consume is false (e.g. --decision-only), it verifies matching grant scope
// without decrementing RemainingUses; if true, it burns one use and persists an AuditLineageProof.
func VerifyOrConsumeSessionZSP(
	zspDir, sessionID, clientType, action, canonicalResource, fullCommand, workspaceRoot string,
	escapesWorkspace, consume bool,
	processAncestry []string,
) (*types.CryptographicAgentSVID, *types.TaskGrant, *types.AuditLineageProof, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	svid, _, minter, pepSecret, err := EnsureSessionPrincipal(zspDir, sessionID, clientType)
	if err != nil {
		return nil, nil, nil, err
	}

	engine := NewZSPEngine(minter, pepSecret)
	grants, err := loadSessionGrants(zspDir, sessionID, engine)
	if err != nil {
		return svid, nil, nil, err
	}

	effectiveResource := canonicalResource
	if escapesWorkspace {
		if effectiveResource == "" || strings.HasPrefix(effectiveResource, "workspace://") || effectiveResource == "repo:local" {
			effectiveResource = "outside-workspace://unescaped"
		}
	} else if workspaceRoot != "" && !strings.HasPrefix(effectiveResource, "system://") && !strings.HasPrefix(effectiveResource, "http") {
		// In-workspace targets (repo:local, dir://..., file://...) map cleanly to workspace://current
		// when no escape occurred.
		effectiveResource = "workspace://current"
	}
	if effectiveResource == "" {
		effectiveResource = "workspace://current"
	}

	if len(grants) == 0 {
		return svid, nil, nil, fmt.Errorf(
			"%w: agent principal %s has ZERO standing privileges (signed 4-tuple TaskAuthorizationEnvelope required)",
			ErrZeroStandingPrivilegeViolation, svid.Subject,
		)
	}

	var firstErr error
	for _, g := range grants {
		if consume {
			proof, consumeErr := engine.ConsumeTaskGrant(g.GrantID, action, effectiveResource, fullCommand, processAncestry)
			if consumeErr == nil {
				updated, _ := engine.GetGrant(g.GrantID)
				if updated != nil {
					_ = saveSessionGrant(zspDir, sessionID, updated)
				}
				appendZSPProof(zspDir, proof)
				return svid, updated, proof, nil
			}
			// Persist expiration burn if newly expired
			if errors.Is(consumeErr, ErrGrantExpired) {
				if updated, ok := engine.GetGrant(g.GrantID); ok {
					_ = saveSessionGrant(zspDir, sessionID, updated)
				}
			}
			if firstErr == nil {
				firstErr = consumeErr
			}
		} else {
			checked, checkErr := engine.CheckTaskGrant(g.GrantID, action, effectiveResource)
			if checkErr == nil {
				return svid, checked, nil, nil
			}
			if firstErr == nil {
				firstErr = checkErr
			}
		}
	}

	if firstErr == nil {
		firstErr = ErrZeroStandingPrivilegeViolation
	}
	return svid, nil, nil, fmt.Errorf("%w (principal %s)", firstErr, svid.Subject)
}

// ResolveZSPActionAndResource normalizes a CLI command or native tool invocation into a canonical
// ZSP action, canonical resource, and workspace-escape indicator.
func ResolveZSPActionAndResource(fullCommand, executable, args, toolName, targetPath, workspaceRoot string) (string, string, bool) {
	normTool := strings.ToLower(strings.TrimSpace(toolName))
	if fullCommand == "" && normTool != "" {
		canonRes := "workspace://current"
		escapes := false
		if targetPath != "" {
			canon := ResolveCanonicalPath(targetPath, workspaceRoot)
			canonRes = "file://" + filepath.ToSlash(canon)
			if workspaceRoot != "" && IsPathOutsideWorkspaceCanonical(workspaceRoot, canon) {
				escapes = true
			}
			if IsFilesystemRootTarget(targetPath) || IsFilesystemRootTarget(canon) {
				escapes = true
			}
		}
		switch normTool {
		case "write", "edit", "multi_edit", "replace_file_content", "write_to_file":
			return "fs:file:write", canonRes, escapes
		case "read", "view", "view_file", "grep", "grep_search", "glob", "find_by_name", "ls", "list_dir", "listdirectory":
			return "fs:read", canonRes, escapes
		default:
			return "tool:" + normTool, canonRes, escapes
		}
	}

	decomp := Decompose(executable, fullCommand, args)
	action := decomp.CanonicalAction
	if strings.EqualFold(executable, "git") {
		for _, tok := range strings.Fields(args) {
			if strings.HasPrefix(tok, "-") {
				continue
			}
			sub := strings.ToLower(tok)
			switch sub {
			case "status", "log", "diff", "show", "branch":
				action = "git:" + sub
			}
			break
		}
	}
	if action == "" {
		action = strings.ToLower(executable)
	}
	res := decomp.CanonicalResource
	escapes := CheckCommandWorkspaceEscape(workspaceRoot, fullCommand) || HasFilesystemRootEscape(workspaceRoot, fullCommand)
	if !escapes && workspaceRoot != "" && decomp.TargetEntity != "" && decomp.TargetEntity != "local" && decomp.TargetEntity != "stdin" &&
		(decomp.ActionType == "read" || decomp.ActionType == "write" || decomp.ActionType == "delete") {
		canon := ResolveCanonicalPath(decomp.TargetEntity, workspaceRoot)
		if IsPathOutsideWorkspaceCanonical(workspaceRoot, canon) {
			escapes = true
			res = "file://" + filepath.ToSlash(canon)
		}
	}
	if escapes && (res == "" || res == "repo:local" || strings.HasPrefix(res, "workspace://")) {
		escaping := FindEscapingTargets(workspaceRoot, fullCommand)
		if len(escaping) > 0 {
			res = "file://" + filepath.ToSlash(escaping[0])
		} else {
			res = "outside-workspace://root"
		}
	}
	return action, res, escapes
}

// ListSessionZSPStatus inspects the ZSP cryptographic posture and grant ledger for a session.
func ListSessionZSPStatus(zspDir, sessionID, clientType string) (*ZSPStatusReport, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	svid, _, minter, pepSecret, err := EnsureSessionPrincipal(zspDir, sessionID, clientType)
	if err != nil {
		return nil, err
	}
	engine := NewZSPEngine(minter, pepSecret)
	grants, err := loadSessionGrants(zspDir, sessionID, engine)
	if err != nil {
		return nil, err
	}
	report := &ZSPStatusReport{
		SessionID:          sessionID,
		Principal:          svid,
		StandingPrivileges: "NONE (Starting Permission Set: ZERO / ZSP Active)",
		ActiveGrants:       []types.TaskGrant{},
	}
	now := time.Now().UTC()
	for _, g := range grants {
		if !g.IsBurned && g.RemainingUses > 0 && now.Before(g.ExpiresAt) {
			report.ActiveGrants = append(report.ActiveGrants, *g)
		} else {
			report.BurnedOrExpired = append(report.BurnedOrExpired, *g)
		}
	}

	if data, err := os.ReadFile(filepath.Join(zspDir, "lineage.jsonl")); err == nil {
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		start := 0
		if len(lines) > 10 {
			start = len(lines) - 10
		}
		for _, ln := range lines[start:] {
			var p types.AuditLineageProof
			if json.Unmarshal([]byte(ln), &p) == nil && (sessionID == "" || p.SessionID == sessionID) {
				report.RecentLineage = append(report.RecentLineage, p)
			}
		}
	}
	return report, nil
}

// RevokeSessionZSPGrants burns one specific grant or all grants in sessionID immediately.
func RevokeSessionZSPGrants(zspDir, sessionID, grantID string) (int, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	grants, err := loadSessionGrants(zspDir, sessionID, nil)
	if err != nil {
		return 0, err
	}
	revoked := 0
	for _, g := range grants {
		if grantID != "" && g.GrantID != grantID {
			continue
		}
		if !g.IsBurned {
			g.IsBurned = true
			g.RemainingUses = 0
			g.BurnReason = "Revoked by operator"
			if saveErr := saveSessionGrant(zspDir, sessionID, g); saveErr == nil {
				revoked++
			}
		}
	}
	return revoked, nil
}

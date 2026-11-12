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
	"sync"
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

// ResolveZSPDir returns the canonical directory used for persistent ZSP state.
// Precedence: BAP_ZSP_DIR -> BAP_STATE_DIR/zsp -> ~/bin/.bapstate/zsp.
func ResolveZSPDir() string {
	if env := strings.TrimSpace(os.Getenv("BAP_ZSP_DIR")); env != "" {
		return filepath.Clean(env)
	}
	if envState := strings.TrimSpace(os.Getenv("BAP_STATE_DIR")); envState != "" {
		return filepath.Join(filepath.Clean(envState), "zsp")
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return filepath.Join(home, "bin", ".bapstate", "zsp")
	}
	return filepath.Join(os.TempDir(), "bapstate", "zsp")
}

// IsZSPEnforced returns true unless ZSP has been explicitly disabled for isolated legacy testing.
func IsZSPEnforced() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("BAP_ZSP")))
	if v == "0" || v == "false" || v == "off" || v == "disabled" {
		return false
	}
	return true
}

// HasUnquotedControlOperator returns true when cmd contains shell chaining/redirection
// operators outside single or double quotes, subshell markers, newlines, or unclosed quotes.
func HasUnquotedControlOperator(cmd string) bool {
	if strings.ContainsAny(cmd, "\r\n`") || strings.Contains(cmd, "$(") {
		return true
	}
	inSingle := false
	inDouble := false
	for i := 0; i < len(cmd); i++ {
		ch := cmd[i]
		if ch == '\'' && !inDouble {
			inSingle = !inSingle
		} else if ch == '"' && !inSingle {
			inDouble = !inDouble
		} else if !inSingle && !inDouble {
			switch ch {
			case ';', '|', '&', '>', '<':
				return true
			}
		}
	}
	return inSingle || inDouble
}

func isBAPControlExecutable(token string) bool {
	execBase := strings.ToLower(filepath.Base(strings.ReplaceAll(strings.Trim(token, `"'`), `\`, "/")))
	switch execBase {
	case "bapedge", "bapedge.exe", "bap", "bap.exe", "ltd-agent", "ltd-agent.exe":
		return true
	default:
		return false
	}
}

// StripLeadingPowerShellCallOperator removes a leading PowerShell `&` call
// operator only when it invokes a BAP executable (e.g. `& "C:\Program Files\BAP\bapedge.exe" ...`),
// preserving any remaining shell text so downstream chaining checks still inspect it.
func StripLeadingPowerShellCallOperator(fullCommand string) (string, bool) {
	trimmed := strings.TrimSpace(fullCommand)
	if len(trimmed) < 2 || trimmed[0] != '&' || (trimmed[1] != ' ' && trimmed[1] != '\t') {
		return trimmed, false
	}
	rest := strings.TrimSpace(trimmed[1:])
	if rest == "" {
		return trimmed, false
	}
	tokens := tokenizeCommand(rest)
	if len(tokens) == 0 {
		return trimmed, false
	}
	if isBAPControlExecutable(tokens[0]) {
		return rest, true
	}
	return trimmed, false
}

// IsZSPControlCommand returns true if fullCommand is a single atomic BAP ZSP/status/why
// control-channel invocation without shell chaining or redirections.
// Agents start with 0 standing privileges and must be able to invoke the ZSP PEP directly
// to submit a signed 4-tuple TaskAuthorizationEnvelope or inspect their status.
func IsZSPControlCommand(fullCommand string) bool {
	trimmed, _ := StripLeadingPowerShellCallOperator(fullCommand)
	if trimmed == "" || HasUnquotedControlOperator(trimmed) {
		return false
	}
	pipe, err := ParseAST(trimmed)
	if err != nil || pipe == nil || len(pipe.Nodes) != 1 || len(pipe.Nodes[0].SubCommands) > 0 || len(pipe.Nodes[0].Redirections) > 0 {
		return false
	}
	tokens := tokenizeCommand(trimmed)
	if len(tokens) < 2 {
		return false
	}
	if !isBAPControlExecutable(tokens[0]) {
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

var (
	zspProcessMu    sync.Mutex
	zspSessionLocks = make(map[string]*sync.Mutex)
)

func sessionLockMutex(zspDir, key string) *sync.Mutex {
	mapKey := filepath.Clean(zspDir) + "|" + sanitizeZSPKey(key)
	zspProcessMu.Lock()
	defer zspProcessMu.Unlock()
	mu, ok := zspSessionLocks[mapKey]
	if !ok {
		mu = &sync.Mutex{}
		zspSessionLocks[mapKey] = mu
	}
	return mu
}

// withZSPStoreLock serializes access to ZSP state across both in-process goroutines
// and concurrent OS processes (e.g., parallel tool executions calling bapedge exec).
func withZSPStoreLock(zspDir, lockKey string, fn func() error) error {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	mu := sessionLockMutex(zspDir, lockKey)
	mu.Lock()
	defer mu.Unlock()

	locksDir := filepath.Join(zspDir, "locks")
	if err := os.MkdirAll(locksDir, 0700); err != nil {
		return err
	}
	lockPath := filepath.Join(locksDir, sanitizeZSPKey(lockKey)+".lock")
	deadline := time.Now().Add(5 * time.Second)
	var lockFile *os.File
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			lockFile = f
			break
		}
		if !os.IsExist(err) {
			return err
		}
		if info, statErr := os.Stat(lockPath); statErr == nil && time.Since(info.ModTime()) > 15*time.Second {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timed out waiting for ZSP store lock %s", lockPath)
		}
		time.Sleep(10 * time.Millisecond)
	}
	_, _ = fmt.Fprintf(lockFile, "%d\n", os.Getpid())
	_ = lockFile.Close()
	defer os.Remove(lockPath)

	return fn()
}

func writeFileAtomic(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(targetPath)+".*.tmp")
	if err != nil {
		return os.WriteFile(targetPath, data, perm)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

// ValidateZSPActionName verifies that a ZSP action uses non-empty canonical token syntax
// without whitespace (for example "git:status", "fs:read", or "exec").
func ValidateZSPActionName(action string) error {
	trimmed := strings.TrimSpace(action)
	if trimmed == "" {
		return fmt.Errorf("%w: empty action name", ErrInvalidEnvelope)
	}
	if strings.ContainsAny(trimmed, " \t\r\n") {
		parts := strings.Fields(trimmed)
		suggestion := strings.ToLower(strings.Join(parts, ":"))
		return fmt.Errorf(
			"%w: invalid action %q (contains whitespace); use canonical colon notation without spaces (e.g. %q)",
			ErrInvalidEnvelope, trimmed, suggestion,
		)
	}
	if strings.HasPrefix(trimmed, ":") || strings.HasSuffix(trimmed, ":") || strings.Contains(trimmed, "::") {
		return fmt.Errorf(
			"%w: malformed canonical action %q; expected non-empty segments like \"git:status\"",
			ErrInvalidEnvelope, trimmed,
		)
	}
	return nil
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
	var out string
	err := withZSPStoreLock(zspDir, "__pep__", func() error {
		if data, err := os.ReadFile(keyPath); err == nil {
			secret := strings.TrimSpace(string(data))
			if len(secret) >= 32 {
				out = secret
				return nil
			}
		}
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		out = hex.EncodeToString(buf)
		return writeFileAtomic(keyPath, []byte(out+"\n"), 0600)
	})
	return out, err
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
	loadExistingPrincipal := func() (*types.CryptographicAgentSVID, *identity.AgentKeypair, bool) {
		data, readErr := os.ReadFile(pPath)
		if readErr != nil {
			return nil, nil, false
		}
		var pp persistedPrincipal
		if json.Unmarshal(data, &pp) != nil || minter.VerifyAgentSVID(&pp.SVID) != nil {
			return nil, nil, false
		}
		privBytes, err1 := hex.DecodeString(pp.PrivateKeyHex)
		pubBytes, err2 := hex.DecodeString(pp.PublicKeyHex)
		if err1 != nil || err2 != nil || len(privBytes) != ed25519.PrivateKeySize || len(pubBytes) != ed25519.PublicKeySize {
			return nil, nil, false
		}
		kp := &identity.AgentKeypair{
			PublicKey:  ed25519.PublicKey(pubBytes),
			PrivateKey: ed25519.PrivateKey(privBytes),
		}
		return &pp.SVID, kp, true
	}
	if svid, kp, ok := loadExistingPrincipal(); ok {
		return svid, kp, minter, pepSecret, nil
	}

	var (
		svid *types.CryptographicAgentSVID
		kp   *identity.AgentKeypair
	)
	lockErr := withZSPStoreLock(zspDir, "principal-"+sessionID, func() error {
		if existingSVID, existingKP, ok := loadExistingPrincipal(); ok {
			svid = existingSVID
			kp = existingKP
			return nil
		}
		genKP, genErr := identity.GenerateAgentKeypair()
		if genErr != nil {
			return genErr
		}
		workstationID, ownerEmail, oidcSub := resolveWorkstationOwner()
		minted, mintErr := minter.MintAgentSVID(genKP, ownerEmail, oidcSub, workstationID, sessionID, clientType, 8*time.Hour)
		if mintErr != nil {
			return mintErr
		}
		pp := persistedPrincipal{
			SVID:          *minted,
			PrivateKeyHex: hex.EncodeToString(genKP.PrivateKey),
			PublicKeyHex:  hex.EncodeToString(genKP.PublicKey),
		}
		if encoded, mErr := json.MarshalIndent(pp, "", "  "); mErr == nil {
			_ = writeFileAtomic(pPath, encoded, 0600)
		}
		svid = minted
		kp = genKP
		return nil
	})
	if lockErr != nil {
		return nil, nil, nil, "", lockErr
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
	return SubmitTaskEnvelopeWithDelegation(
		zspDir, sessionID, clientType, mission, goal, promptText,
		actions, resources, authorizedBy, "human_interactive_prompt", maxUses, ttl,
	)
}

// SubmitTaskEnvelopeWithDelegation creates, signs, evaluates, and persists a 4-Tuple Task Authorization
// Envelope with an explicit delegation type (e.g. "human_interactive_oob" for out-of-band HITL approval).
func SubmitTaskEnvelopeWithDelegation(
	zspDir, sessionID, clientType, mission, goal, promptText string,
	actions, resources []string,
	authorizedBy, delegationType string,
	maxUses int,
	ttl time.Duration,
) (*types.TaskGrant, *types.TaskAuthorizationEnvelope, error) {
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	svid, kp, minter, pepSecret, err := EnsureSessionPrincipal(zspDir, sessionID, clientType)
	if err != nil {
		return nil, nil, err
	}
	if len(actions) == 0 {
		return nil, nil, fmt.Errorf("%w: permission ask requires at least one action", ErrInvalidEnvelope)
	}
	for _, act := range actions {
		if valErr := ValidateZSPActionName(act); valErr != nil {
			return nil, nil, valErr
		}
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
	if strings.TrimSpace(delegationType) == "" {
		delegationType = "human_interactive_prompt"
	}
	deleg := types.DelegationIdentity{
		DelegationType: delegationType,
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

	if err := withZSPStoreLock(zspDir, "grants-"+sessionID, func() error {
		return saveSessionGrant(zspDir, sessionID, grant)
	}); err != nil {
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
	data, err := json.MarshalIndent(g, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, sanitizeZSPKey(g.GrantID)+".json"), data, 0600)
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
	line, err := json.Marshal(proof)
	if err != nil {
		return
	}
	_ = withZSPStoreLock(zspDir, "lineage", func() error {
		if mkErr := os.MkdirAll(zspDir, 0700); mkErr != nil {
			return mkErr
		}
		f, openErr := os.OpenFile(filepath.Join(zspDir, "lineage.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
		if openErr != nil {
			return openErr
		}
		defer f.Close()
		_, writeErr := f.Write(append(line, '\n'))
		return writeErr
	})
}

// ZSPActionCheck represents a normalized ZSP action/resource check for a command node or native tool.
type ZSPActionCheck struct {
	Action            string
	CanonicalResource string
	EscapesWorkspace  bool
}

func effectiveZSPResource(canonicalResource, workspaceRoot string, escapesWorkspace bool) string {
	effectiveResource := canonicalResource
	if escapesWorkspace {
		if effectiveResource == "" || strings.HasPrefix(effectiveResource, "workspace://") || effectiveResource == "repo:local" {
			return "outside-workspace://unescaped"
		}
		return effectiveResource
	}
	if workspaceRoot != "" && !strings.HasPrefix(effectiveResource, "system://") && !strings.HasPrefix(effectiveResource, "http") {
		// In-workspace targets (repo:local, dir://..., file://...) map cleanly to workspace://current
		// when no escape occurred.
		return "workspace://current"
	}
	if effectiveResource == "" {
		return "workspace://current"
	}
	return effectiveResource
}

func isInWorkspaceNavBuiltin(execName string) bool {
	switch strings.ToLower(strings.Trim(execName, "\"'")) {
	case "cd", "chdir", "pushd", "popd", "set-location", "sl":
		return true
	default:
		return false
	}
}

func collectAtomicZSPNodes(nodes []*ASTNode) []*ASTNode {
	var out []*ASTNode
	for _, n := range nodes {
		if n == nil {
			continue
		}
		if len(n.Args) > 0 {
			out = append(out, n)
		}
		if len(n.SubCommands) > 0 {
			out = append(out, collectAtomicZSPNodes(n.SubCommands)...)
		}
	}
	return out
}

// ResolveZSPCommandChecks decomposes a shell command (including chained statements and subcommands)
// or native tool call into every ZSP action/resource check that must be authorized.
func ResolveZSPCommandChecks(fullCommand, executable, args, toolName, targetPath, workspaceRoot string) []ZSPActionCheck {
	if strings.TrimSpace(fullCommand) == "" && strings.TrimSpace(toolName) != "" {
		act, res, esc := ResolveZSPActionAndResource(fullCommand, executable, args, toolName, targetPath, workspaceRoot)
		return []ZSPActionCheck{{Action: act, CanonicalResource: res, EscapesWorkspace: esc}}
	}
	if strings.TrimSpace(fullCommand) != "" {
		if pipe, err := ParseAST(fullCommand); err == nil && pipe != nil {
			atomicNodes := collectAtomicZSPNodes(pipe.Nodes)
			if len(atomicNodes) > 0 {
				var checks []ZSPActionCheck
				for _, node := range atomicNodes {
					nodeExec := node.Args[0]
					nodeArgs := strings.Join(node.Args[1:], " ")
					act, res, esc := ResolveZSPActionAndResource(node.FullCommand, nodeExec, nodeArgs, "", "", workspaceRoot)
					if len(atomicNodes) > 1 && !esc && isInWorkspaceNavBuiltin(nodeExec) {
						continue
					}
					checks = append(checks, ZSPActionCheck{
						Action:            act,
						CanonicalResource: res,
						EscapesWorkspace:  esc,
					})
				}
				if len(checks) > 0 {
					return checks
				}
			}
		}
	}
	act, res, esc := ResolveZSPActionAndResource(fullCommand, executable, args, toolName, targetPath, workspaceRoot)
	return []ZSPActionCheck{{Action: act, CanonicalResource: res, EscapesWorkspace: esc}}
}

// SummarizeZSPActions formats a deduplicated comma-separated list of ZSP actions in order.
func SummarizeZSPActions(checks []ZSPActionCheck) string {
	seen := make(map[string]struct{}, len(checks))
	var actions []string
	for _, c := range checks {
		act := strings.TrimSpace(c.Action)
		if act == "" {
			continue
		}
		key := strings.ToLower(act)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		actions = append(actions, act)
	}
	return strings.Join(actions, ",")
}

// FormatZSPAgentSuggestion builds an actionable ZSP authorization hint telling the agent
// to submit a standalone `bapedge zsp authorize` request to the BAP PEP rather than delegating to the user.
func FormatZSPAgentSuggestion(principal, sessionID, goal, actions string, checkCount int) string {
	maxUsesArg := ""
	if checkCount > 1 {
		maxUsesArg = fmt.Sprintf(" --max-uses %d", checkCount)
	}
	return fmt.Sprintf(
		"Agent principal %s has ZERO standing privileges. Declare your task intent and request a policy-evaluated JIT TaskGrant by running this standalone command yourself via your shell tool (without &&, ;, or |) — bapedge zsp authorize submits your envelope to the BAP Policy Enforcement Point for Cedar verification (it is NOT self-approval): bapedge zsp authorize --session-id %q --mission TASK_EXECUTION --goal %q --actions %q --resources workspace://current%s",
		principal, sessionID, goal, actions, maxUsesArg,
	)
}

// VerifyOrConsumeSessionZSP enforces Zero Standing Privileges against persisted TaskGrants
// for sessionID. If consume is false (e.g. --decision-only), it verifies matching grant scope
// without decrementing RemainingUses; if true, it burns one use and persists an AuditLineageProof.
func VerifyOrConsumeSessionZSP(
	zspDir, sessionID, clientType, action, canonicalResource, fullCommand, workspaceRoot string,
	escapesWorkspace, consume bool,
	processAncestry []string,
) (*types.CryptographicAgentSVID, *types.TaskGrant, *types.AuditLineageProof, error) {
	return VerifyOrConsumeSessionZSPChecks(
		zspDir,
		sessionID,
		clientType,
		[]ZSPActionCheck{{
			Action:            action,
			CanonicalResource: canonicalResource,
			EscapesWorkspace:  escapesWorkspace,
		}},
		fullCommand,
		workspaceRoot,
		consume,
		processAncestry,
	)
}

// VerifyOrConsumeSessionZSPChecks enforces Zero Standing Privileges across every action/resource
// check resolved from an invocation. A single command execution burns one grant use only after
// every sub-action passes verification.
func VerifyOrConsumeSessionZSPChecks(
	zspDir, sessionID, clientType string,
	checks []ZSPActionCheck,
	fullCommand, workspaceRoot string,
	consume bool,
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
	if len(checks) == 0 {
		checks = []ZSPActionCheck{{Action: "exec", CanonicalResource: "workspace://current"}}
	}

	var (
		matchedGrant *types.TaskGrant
		consumedProof *types.AuditLineageProof
		firstErr      error
	)
	lockErr := withZSPStoreLock(zspDir, "grants-"+sessionID, func() error {
		grants, loadErr := loadSessionGrants(zspDir, sessionID, engine)
		if loadErr != nil {
			return loadErr
		}
		if len(grants) == 0 {
			firstErr = fmt.Errorf(
				"%w: agent principal %s has ZERO standing privileges (signed 4-tuple TaskAuthorizationEnvelope required)",
				ErrZeroStandingPrivilegeViolation, svid.Subject,
			)
			return nil
		}

		checkGrantCoversAll := func(g *types.TaskGrant) (*types.TaskGrant, error) {
			var checked *types.TaskGrant
			for _, chk := range checks {
				res := effectiveZSPResource(chk.CanonicalResource, workspaceRoot, chk.EscapesWorkspace)
				cg, checkErr := engine.CheckTaskGrant(g.GrantID, chk.Action, res)
				if checkErr != nil {
					return nil, checkErr
				}
				checked = cg
			}
			return checked, nil
		}

		for _, g := range grants {
			checked, checkErr := checkGrantCoversAll(g)
			if checkErr == nil {
				if !consume {
					matchedGrant = checked
					return nil
				}
				primaryRes := effectiveZSPResource(checks[0].CanonicalResource, workspaceRoot, checks[0].EscapesWorkspace)
				proof, consumeErr := engine.ConsumeTaskGrant(g.GrantID, checks[0].Action, primaryRes, fullCommand, processAncestry)
				if consumeErr == nil {
					updated, _ := engine.GetGrant(g.GrantID)
					if updated != nil {
						_ = saveSessionGrant(zspDir, sessionID, updated)
					}
					matchedGrant = updated
					consumedProof = proof
					return nil
				}
				if errors.Is(consumeErr, ErrGrantExpired) {
					if updated, ok := engine.GetGrant(g.GrantID); ok {
						_ = saveSessionGrant(zspDir, sessionID, updated)
					}
				}
				if firstErr == nil {
					firstErr = consumeErr
				}
				continue
			}
			if errors.Is(checkErr, ErrGrantExpired) {
				if updated, ok := engine.GetGrant(g.GrantID); ok {
					updated.IsBurned = true
					updated.BurnReason = "TTL Expired"
					_ = saveSessionGrant(zspDir, sessionID, updated)
				}
			}
			if firstErr == nil {
				firstErr = checkErr
			}
		}
		return nil
	})
	if lockErr != nil {
		return svid, nil, nil, lockErr
	}
	if matchedGrant != nil {
		if consumedProof != nil {
			appendZSPProof(zspDir, consumedProof)
		}
		return svid, matchedGrant, consumedProof, nil
	}
	if firstErr == nil {
		firstErr = ErrZeroStandingPrivilegeViolation
	}
	if errors.Is(firstErr, ErrZeroStandingPrivilegeViolation) && strings.Contains(firstErr.Error(), svid.Subject) {
		return svid, nil, nil, firstErr
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
	revoked := 0
	err := withZSPStoreLock(zspDir, "grants-"+sessionID, func() error {
		grants, loadErr := loadSessionGrants(zspDir, sessionID, nil)
		if loadErr != nil {
			return loadErr
		}
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
		return nil
	})
	if err != nil {
		return 0, err
	}
	return revoked, nil
}

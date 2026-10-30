package authz

import (
	"bap-edge/internal/state"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
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
	sessionID string
}

// SetIdentity explicitly sets the authenticated engineer's corporate identity.
func (a *Authorizer) SetIdentity(identity PrincipalIdentity) {
	a.identity = identity
}

// SetSessionID sets the active session identifier for scoped permissions lookup.
func (a *Authorizer) SetSessionID(sessionID string) {
	a.sessionID = sessionID
}

// GetIdentity returns the current authenticated corporate identity.
func (a *Authorizer) GetIdentity() PrincipalIdentity {
	return a.identity
}

// NewAuthorizer loads the Cedar policy and optional schema from specified or standard locations.
func NewAuthorizer(policyPath string) (*Authorizer, error) {
	resolvedPolicyPath, err := findFile(policyPath, "policy.cedar")
	var policyData []byte
	if err == nil {
		policyData, _ = os.ReadFile(resolvedPolicyPath)
	}
	if len(policyData) == 0 {
		return nil, fmt.Errorf("policy.cedar not available: zero-trust policy file missing; bapedge fail-closed")
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

	ps, err := cedar.NewPolicySetFromBytes(resolvedPolicyPath, policyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Cedar policy file %s: %w", resolvedPolicyPath, err)
	}

	authz := &Authorizer{policySet: ps}

	// Load authenticated corporate identity from .bapstate/credentials.json if enrolled
	credsCandidate := state.CredentialsPath()
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

	// Try loading schema.json from the same directory or standard locations
	schemaPathCandidate := filepath.Join(policyDir, "schema.json")
	var schemaData []byte
	if resolvedSchemaPath, err := findFile(schemaPathCandidate, "schema.json"); err == nil {
		schemaData, _ = os.ReadFile(resolvedSchemaPath)
	}
	if len(schemaData) == 0 {
		schemaData = []byte(defaultBaselineSchema)
	}
	var s schema.Schema
	if err := s.UnmarshalJSON(schemaData); err == nil {
		if _, err := s.Resolve(); err == nil {
			authz.schema = &s
			if os.Getenv("BAP_DEBUG") != "" {
				fmt.Fprintf(os.Stderr, "[authz] Loaded and validated Cedar schema\n")
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
// within the specified workspaceRoot directory boundary using AST parsing and canonical symlink resolution.
func (a *Authorizer) EvaluateWithWorkspace(executable, fullCommand, args, workspaceRoot string) (bool, string, error) {
	cmdToParse := fullCommand
	if cmdToParse == "" && executable != "" {
		cmdToParse = executable
		if args != "" {
			cmdToParse = executable + " " + args
		}
	}

	pipeline, err := ParseAST(cmdToParse)
	if err != nil || pipeline == nil || len(pipeline.Nodes) == 0 {
		return a.evaluateAtomicNode(executable, fullCommand, args, workspaceRoot, "", CheckCommandWorkspaceEscape(workspaceRoot, fullCommand))
	}

	cleanRoot := filepath.Clean(workspaceRoot)
	currentDir := cleanRoot
	overallEscapes := false
	if workspaceRoot != "" {
		overallEscapes = CheckCommandWorkspaceEscape(workspaceRoot, cmdToParse)
	}

	var evaluateNode func(n *ASTNode) (bool, string, error)
	evaluateNode = func(n *ASTNode) (bool, string, error) {
		// 1. Evaluate nested subcommands in command substitutions $(...) and `...`
		for _, sub := range n.SubCommands {
			allowed, reason, err := evaluateNode(sub)
			if err != nil {
				return false, "", err
			}
			if !allowed {
				return false, fmt.Sprintf("Denial in subshell '%s': %s", sub.FullCommand, reason), nil
			}
		}

		nodeExec := n.Executable
		if nodeExec == "" {
			nodeExec = executable
		}
		nodeFull := n.FullCommand
		nodeArgs := ""
		if len(n.Args) > 1 {
			nodeArgs = strings.Join(n.Args[1:], " ")
		}

		nodeEscapes := overallEscapes

		// Track directory changes across pipeline (cd, chdir, pushd)
		first := strings.ToLower(nodeExec)
		if first == "cd" || first == "chdir" || first == "pushd" {
			if len(n.Args) >= 2 {
				target := strings.Trim(n.Args[1], "\"'")
				if strings.EqualFold(target, "/d") && len(n.Args) >= 3 {
					target = strings.Trim(n.Args[2], "\"'")
				}
				if target == "" || target == "~" {
					nodeEscapes = true
				} else {
					var nextAbs string
					if filepath.IsAbs(target) {
						nextAbs = filepath.Clean(target)
					} else {
						nextAbs = filepath.Clean(filepath.Join(currentDir, target))
					}
					if IsPathOutsideWorkspace(cleanRoot, nextAbs) {
						nodeEscapes = true
					} else {
						currentDir = nextAbs
						nodeEscapes = false
					}
				}
			}
		}

		var canonicalTarget string
		for i, arg := range n.Args {
			if i == 0 || isCommandFlag(arg) {
				continue
			}

			canonical := ResolveCanonicalPath(arg, currentDir)
			if canonicalTarget == "" {
				canonicalTarget = canonical
			}

			// Canonical workspace escape check (e.g., symlink pointing outside workspace)
			if workspaceRoot != "" && IsPathOutsideWorkspaceCanonical(workspaceRoot, canonical) {
				nodeEscapes = true
			}

			// Secret path inspection (.env, .ssh, ~/.aws, /etc/shadow)
			if isForbidden, secretReason := IsForbiddenSecretPath(canonical); isForbidden {
				if nodeExec != "ls" && nodeExec != "dir" {
					return false, fmt.Sprintf("Denial on '%s': %s", arg, secretReason), nil
				}
			}
		}

		// 2. Evaluate Redirections
		for _, r := range n.Redirections {
			if r.Target == "" {
				continue
			}
			canonical := ResolveCanonicalPath(r.Target, currentDir)
			if workspaceRoot != "" && IsPathOutsideWorkspaceCanonical(workspaceRoot, canonical) {
				if authorized, _ := IsTargetAuthorized(workspaceRoot, a.sessionID, canonical, "write"); !authorized {
					return false, fmt.Sprintf("Denial on redirection target '%s': Path escapes workspace boundary", r.Target), nil
				}
			}
			if isForbidden, secretReason := IsForbiddenSecretPath(canonical); isForbidden {
				return false, fmt.Sprintf("Denial on redirection target '%s': %s", r.Target, secretReason), nil
			}
		}

		// 3. Evaluate Cedar policy on the atomic command
		allowed, reason, err := a.evaluateAtomicNode(nodeExec, nodeFull, nodeArgs, workspaceRoot, canonicalTarget, nodeEscapes)
		if err != nil {
			return false, "", err
		}
		if !allowed {
			return false, fmt.Sprintf("Denial on '%s': %s", nodeFull, reason), nil
		}

		return true, "", nil
	}

	for _, n := range pipeline.Nodes {
		allowed, reason, err := evaluateNode(n)
		if err != nil {
			return false, "", err
		}
		if !allowed {
			// Fail-closed on first violating node in the pipeline
			return false, reason, nil
		}
	}

	return true, "", nil
}

func (a *Authorizer) evaluateAtomicNode(executable, fullCommand, args, workspaceRoot, canonicalTarget string, escapesWorkspace bool) (bool, string, error) {
	// 0. Skip empty or comment lines
	trimmedFull := strings.TrimSpace(fullCommand)
	if trimmedFull == "" || strings.HasPrefix(trimmedFull, "#") || strings.HasPrefix(trimmedFull, "//") || strings.HasPrefix(strings.ToLower(trimmedFull), "rem ") {
		return true, "", nil
	}

	cleanExec := executable
	if strings.HasPrefix(executable, "(") {
		cleanExec = strings.TrimLeft(executable, "([{\"'$@&")
		if idx := strings.IndexAny(cleanExec, ")."); idx != -1 {
			cleanExec = cleanExec[:idx]
		}
	}
	normExec := strings.ReplaceAll(cleanExec, "\\", "/")
	normalizedExec := strings.ToLower(path.Base(strings.TrimSuffix(normExec, ".exe")))
	if strings.HasPrefix(normalizedExec, "---") || strings.HasPrefix(normalizedExec, "===") ||
		strings.HasPrefix(normalizedExec, "***") || strings.HasPrefix(normalizedExec, "###") ||
		strings.Contains(normalizedExec, " ") {
		normalizedExec = "write-output"
	}
	normalizedFull := strings.ToLower(fullCommand)
	normalizedArgs := strings.ToLower(args)

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

	decomp := Decompose(executable, fullCommand, args)
	if decomp.TargetEntity != "" && decomp.TargetEntity != "local" && decomp.TargetEntity != "stdin" && (decomp.ActionType == "read" || decomp.ActionType == "write" || decomp.ActionType == "delete") {
		resolved := ResolveCanonicalPath(decomp.TargetEntity, workspaceRoot)
		if resolved != "" {
			canonicalTarget = resolved
		}
	}
	if canonicalTarget != "" && (decomp.ActionType == "read" || decomp.ActionType == "write" || decomp.ActionType == "delete") {
		decomp.TargetEntity = canonicalTarget
		decomp.CanonicalResource = "file://" + filepath.ToSlash(canonicalTarget)
	}

	effectiveEscapesWorkspace := escapesWorkspace
	checkTarget := canonicalTarget
	if checkTarget == "" {
		checkTarget = decomp.TargetEntity
	}
	if checkTarget != "" && !filepath.IsAbs(checkTarget) && workspaceRoot != "" {
		checkTarget = filepath.Clean(filepath.Join(workspaceRoot, checkTarget))
	}
	if escapesWorkspace && checkTarget != "" && (decomp.ActionType == "write" || decomp.ActionType == "delete") {
		if authorized, _ := IsTargetAuthorized(workspaceRoot, a.sessionID, checkTarget, decomp.ActionType); authorized {
			effectiveEscapesWorkspace = false
		}
	}
	if effectiveEscapesWorkspace {
		if parts := strings.Split(fullCommand, ">"); len(parts) > 1 {
			redirTarget := strings.TrimSpace(strings.Trim(parts[len(parts)-1], "\"'`"))
			if redirTarget != "" {
				absRedir := ResolveCanonicalPath(redirTarget, workspaceRoot)
				if auth, _ := IsTargetAuthorized(workspaceRoot, a.sessionID, absRedir, "write"); auth {
					effectiveEscapesWorkspace = false
				}
			}
		}
	}

	contextMap := cedar.RecordMap{
		cedar.String("executable"):         cedar.String(normalizedExec),
		cedar.String("full_command"):       cedar.String(normalizedFull),
		cedar.String("args"):               cedar.String(normalizedArgs),
		cedar.String("escapes_workspace"):  cedar.Boolean(effectiveEscapesWorkspace),
		cedar.String("department"):         cedar.String(a.identity.Department),
		cedar.String("user_email"):         cedar.String(a.identity.UserEmail),
		cedar.String("action_canonical"):   cedar.String(decomp.CanonicalAction),
		cedar.String("resource_canonical"): cedar.String(decomp.CanonicalResource),
		cedar.String("action_type"):        cedar.String(decomp.ActionType),
		cedar.String("target_entity"):      cedar.String(decomp.TargetEntity),
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

// isCommandFlag returns true if arg represents a command-line switch rather than a file path.
func isCommandFlag(arg string) bool {
	if strings.HasPrefix(arg, "-") {
		return true
	}
	if strings.HasPrefix(arg, "/") {
		if arg == "/" || strings.HasPrefix(arg, "//") || strings.Contains(arg[1:], "/") || strings.Contains(arg[1:], "\\") || strings.HasPrefix(arg, "/.") {
			return false // Path, not a flag
		}
		// Known root-level directories
		lower := strings.ToLower(arg[1:])
		switch lower {
		case "etc", "tmp", "var", "home", "root", "bin", "usr", "opt", "mnt", "proc", "dev", "sys", "lib", "lib64", "srv", "windows", "program files", "users":
			return false // Path, not a flag
		}
		// Single-letter switch flags (e.g. /c, /d, /s, /b, /q, /y) on Windows are flags
		if len(arg) == 2 {
			return true
		}
		if runtime.GOOS != "windows" {
			return false
		}
		return true
	}
	return false
}

// findFile resolves a file path by checking:
// FindFile locates a configuration or policy asset across canonical release and runtime locations:
// 1. Explicit custom path (if provided)
// 2. Executable directory (where bapedge resides in bin/ alongside release policy.cedar)
// 3. User standard bin directory (~/bin or ~/.local/bin)
// 4. User cached policy directory (.bapstate/policy/ or ~/.bap/policy/)
// 5. Workspace-specific sandbox (.bap/<defaultName>)
// 6. Current working directory
// 7. Parent directories (fallback for development / test suites)
func FindFile(customPath, defaultName string) (string, error) {
	if customPath != "" {
		if _, err := os.Stat(customPath); err == nil {
			return customPath, nil
		}
	}

	// 1. Current workspace root or CWD (canonical repository policy)
	if ws := GetWorkspaceRoot(); ws != "" {
		wsFile := filepath.Join(ws, defaultName)
		if fi, err := os.Stat(wsFile); err == nil && fi.Size() > 0 {
			return wsFile, nil
		}
	}
	if fi, err := os.Stat(defaultName); err == nil && fi.Size() > 0 {
		return defaultName, nil
	}

	// 2. Executable directory (canonical location: release binaries & policy live together in bin/)
	exe, err := os.Executable()
	if err == nil {
		exeDirFile := filepath.Join(filepath.Dir(exe), defaultName)
		if _, err := os.Stat(exeDirFile); err == nil {
			return exeDirFile, nil
		}
	}

	// 3. User standard bin and state directories
	if home, err := os.UserHomeDir(); err == nil {
		userBinFile := filepath.Join(home, "bin", defaultName)
		if _, err := os.Stat(userBinFile); err == nil {
			return userBinFile, nil
		}
		localBinFile := filepath.Join(home, ".local", "bin", defaultName)
		if _, err := os.Stat(localBinFile); err == nil {
			return localBinFile, nil
		}
		stateCache := filepath.Join(state.PolicyDir(), defaultName)
		if _, err := os.Stat(stateCache); err == nil {
			return stateCache, nil
		}
		bapCache := filepath.Join(home, ".bap", "policy", defaultName)
		if _, err := os.Stat(bapCache); err == nil {
			return bapCache, nil
		}
	}

	// 4. Workspace-specific .bap directory
	bapLocal := filepath.Join(".bap", defaultName)
	if _, err := os.Stat(bapLocal); err == nil {
		return bapLocal, nil
	}

	// 5. Parent directories (development / test fallback)
	for _, parent := range []string{"..", "../..", "../../..", "../../../.."} {
		parentFile := filepath.Join(parent, defaultName)
		if _, err := os.Stat(parentFile); err == nil {
			return parentFile, nil
		}
	}

	exeDir := ""
	if err == nil {
		exeDir = filepath.Dir(exe)
	}
	return "", fmt.Errorf("%s not found in executable directory (%s), user bin, policy cache, or workspace", defaultName, exeDir)
}

func findFile(customPath, defaultName string) (string, error) {
	return FindFile(customPath, defaultName)
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
			Frozen          bool     `json:"frozen"`
			RevokedSessions []string `json:"revoked_sessions"`
		}
		if err := json.Unmarshal(stateData, &state); err != nil {
			continue
		}

		if state.KillSwitch {
			return fmt.Errorf("emergency kill-switch is active; all executions are blocked")
		}

		if state.Frozen {
			return fmt.Errorf("workstation is currently FROZEN (quarantined) by central administrator; all executions blocked")
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

const defaultBaselinePolicy = `
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    [
        "pytest", "python", "python3", "py", "pip", "pip3",
        "go", "npm", "npx", "yarn", "pnpm", "node",
        "mvn", "gradle", "cargo", "git",
        "java", "javac",
        "ls", "dir", "mkdir", "echo", "pwd", "cat", "type", "printenv", "whoami",
        "cd", "chdir", "pushd", "popd", "exit",
        "cmd", "powershell", "pwsh", "bash", "sh", "zsh",
        "grep", "findstr", "head", "tail", "wc", "sort", "uniq", "more",
        "sed", "awk", "cut", "tr", "diff", "patch", "tee", "touch",
        "cp", "mv", "copy", "move", "rm", "del", "rmdir", "erase",
        "find", "which", "where", "less",
        "clear", "cls", "true", "false", "test", "date", "uname", "hostname", "env",
        "tar", "zip", "unzip", "gzip", "gunzip",
        "select-object", "where-object", "select-string", "sort-object", "measure-object", "get-content", "out-string",
        "taskkill", "kill", "pkill", "killall",
        "bapedge", "ltd-agent"
    ].contains(context.executable)
};

forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.escapes_workspace == true
};

forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.full_command like "*curl*" ||
    context.full_command like "*wget*" ||
    context.full_command like "nc *" ||
    context.full_command like "* nc *" ||
    context.full_command like "*~/.aws*" ||
    context.full_command like "*~\\.aws*" ||
    context.full_command like "*~/.ssh*" ||
    context.full_command like "*~\\.ssh*" ||
    context.full_command like "*.env*"
};
`

const defaultBaselineSchema = `{
  "": {
    "entityTypes": {
      "Agent": {
        "memberOfTypes": [],
        "shape": {
          "type": "Record",
          "attributes": {
            "department": { "type": "String", "required": false },
            "email": { "type": "String", "required": false },
            "groups": { "type": "Set", "element": { "type": "String" }, "required": false }
          }
        }
      },
      "Command": { "memberOfTypes": [] }
    },
    "actions": {
      "Execute": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["Command"],
          "context": {
            "type": "Record",
            "attributes": {
              "executable": { "type": "String", "required": true },
              "full_command": { "type": "String", "required": true },
              "args": { "type": "String", "required": false },
              "escapes_workspace": { "type": "Boolean", "required": false },
              "department": { "type": "String", "required": false },
              "user_email": { "type": "String", "required": false },
              "groups": { "type": "Set", "element": { "type": "String" }, "required": false }
            }
          }
        }
      }
    }
  }
}`


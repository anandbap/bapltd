package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"bap-edge/pkg/types"
)

func batchCommandHash(command string) string {
	sum := sha256.Sum256([]byte(command))
	return hex.EncodeToString(sum[:])
}

func canonicalBatchWorkspace(root string) string {
	if root == "" {
		return ""
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return ""
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	return filepath.Clean(abs)
}

func batchPolicyHash(policy *PermissionPolicy) string {
	raw, _ := json.Marshal(policy)
	return batchCommandHash(string(raw))
}

func batchShell(shell []string) string {
	if len(shell) == 0 || strings.TrimSpace(shell[0]) == "" {
		return "auto"
	}
	return strings.ToLower(strings.TrimSpace(shell[0]))
}

func IsAutomaticBatchCandidate(command, workspace string, shell ...string) bool {
	if os.Getenv("BAP_ZSP_AUTO_GRANTS") == "0" {
		return false
	}
	_, ok := automaticBatchChecks(command, workspace, shell...)
	return ok
}

// automaticBatchChecks is deliberately narrower than manual task authorization.
// Unrecognized shell syntax/options always fall back to the existing grant flow.
func automaticBatchChecks(command, workspace string, shell ...string) ([]ZSPActionCheck, bool) {
	if workspace == "" || strings.TrimSpace(command) == "" || len(command) > 32768 {
		return nil, false
	}
	if strings.ContainsAny(command, "`$(){}\r\n") {
		return nil, false
	}
	// The general parser accepts incomplete quotes; auto-authorization must not.
	var quote rune
	for _, ch := range command {
		if ch == '\'' || ch == '"' {
			if quote == 0 {
				quote = ch
			} else if quote == ch {
				quote = 0
			}
		}
	}
	if quote != 0 {
		return nil, false
	}
	pipe, err := ParseAST(command)
	if err != nil || pipe == nil || len(pipe.Nodes) == 0 || len(pipe.Nodes) > 64 {
		return nil, false
	}
	approved := approvedEffectSet()
	var checks []ZSPActionCheck
	for _, node := range pipe.Nodes {
		if len(node.Args) == 0 || len(node.SubCommands) > 0 || node.Operator == "&" {
			return nil, false
		}
		for _, redir := range node.Redirections {
			if !automaticNullRedirection(redir, batchShell(shell)) {
				return nil, false
			}
		}
		// Percent syntax is literal only in recognized Git format arguments,
		// and never automatically authorized when CMD could expand it.
		for i, arg := range node.Args {
			if i > 0 && (LooksLikeCredentialPath(arg) || isCredentialStorePath(ResolveCanonicalPath(arg, workspace))) {
				return nil, false
			}
			if strings.Contains(arg, "%") && (i < 2 || node.Args[0] != "git" || node.Args[1] != "log" ||
				(!strings.HasPrefix(arg, "--format=") && !strings.HasPrefix(arg, "--pretty=")) ||
				batchShell(shell) == "cmd" || (batchShell(shell) == "auto" && runtime.GOOS == "windows")) {
				return nil, false
			}
		}
		// Independently validated null stderr redirection needs no write scope.
		analysisCommand := joinArgsQuoted(node.Args)
		executable := strings.ToLower(node.Args[0])
		if executable == "git" || executable == "git.exe" {
			if !automaticGitInspection(node.Args) {
				return nil, false
			}
		} else {
			// Only simple inspection tools or explicitly machine-approved effects.
			action, _, _ := ResolveZSPActionAndResource(analysisCommand, node.Args[0], strings.Join(node.Args[1:], " "), "", "", workspace)
			switch executable {
			case "cat", "type", "head", "tail", "wc", "ls", "dir", "grep", "findstr":
				if !isLocalReadAction(action) {
					return nil, false
				}
			default:
				if !approved[action] {
					return nil, false
				}
			}
		}
		atomic := ResolveZSPCommandChecks(analysisCommand, node.Args[0], strings.Join(node.Args[1:], " "), "", "", workspace)
		if len(atomic) != 1 {
			return nil, false
		}
		check := atomic[0]
		if check.EscapesWorkspace || IsHighRiskEscalationAction(check.Action) || isCredentialStorePath(check.CanonicalResource) {
			return nil, false
		}
		checks = append(checks, check)
	}
	return checks, true
}

func automaticNullRedirection(r Redirection, shell string) bool {
	if r.Operator != "2>" {
		return false
	}
	posix := shell == "bash" || shell == "sh" || shell == "zsh" || (shell == "auto" && runtime.GOOS != "windows")
	if posix {
		return r.Target == "/dev/null"
	}
	return runtime.GOOS == "windows" && (shell == "cmd" || shell == "auto" || shell == "powershell" || shell == "pwsh") && strings.EqualFold(r.Target, "NUL")
}

func automaticGitInspection(args []string) bool {
	if len(args) < 2 {
		return false
	}
	switch args[1] {
	case "add", "stage":
		for _, arg := range args[2:] {
			if strings.HasPrefix(arg, "-") && arg != "-A" && arg != "--all" && arg != "-u" && arg != "--update" {
				return false
			}
		}
		return true
	case "status":
		for _, arg := range args[2:] {
			switch arg {
			case "--short", "--branch", "-s", "-b", "-sb", "-bs", "--porcelain", "--porcelain=1", "--porcelain=2",
				"-u", "-uno", "-unormal", "-uall", "--untracked-files", "--ignored":
			default:
				if strings.HasPrefix(arg, "-") {
					return false
				}
			}
		}
	case "remote":
		if len(args) > 2 {
			switch strings.ToLower(args[2]) {
			case "add", "rename", "remove", "rm", "set-head", "set-branches", "set-url", "prune":
				return false
			}
		}
		return true
	case "symbolic-ref":
		nonFlags := 0
		for _, arg := range args[2:] {
			if !strings.HasPrefix(arg, "-") {
				nonFlags++
			}
		}
		if nonFlags > 1 {
			return false
		}
		return true
	case "rev-parse", "merge-base", "describe":
		for _, arg := range args[2:] {
			if strings.HasPrefix(arg, "--output") || strings.HasPrefix(arg, "-O") {
				return false
			}
		}
		return true
	case "branch":
		for _, arg := range args[2:] {
			switch arg {
			case "-v", "-vv", "-a", "--all", "-r", "--remotes", "--list", "--show-current":
			default:
				if strings.HasPrefix(arg, "-") {
					return false
				}
			}
		}
	case "diff":
		for _, arg := range args[2:] {
			if strings.HasPrefix(arg, "--output") || strings.HasPrefix(arg, "-O") {
				return false
			}
		}
	case "show":
		for _, arg := range args[2:] {
			if strings.HasPrefix(arg, "--output") || strings.HasPrefix(arg, "-O") {
				return false
			}
		}
	case "log":
		for i := 2; i < len(args); i++ {
			arg := args[i]
			switch arg {
			case "--oneline", "--graph", "--all", "--no-decorate", "--decorate", "--no-patch":
			case "-n", "--max-count":
				i++
				if i >= len(args) {
					return false
				}
				n, err := strconv.Atoi(args[i])
				if err != nil || n < 1 || n > 10000 {
					return false
				}
			default:
				if strings.HasPrefix(arg, "--format=") || strings.HasPrefix(arg, "--pretty=") {
					continue
				}
				if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
					if n, err := strconv.Atoi(arg[1:]); err == nil && n >= 1 && n <= 10000 {
						continue
					}
				}
				if !strings.HasPrefix(arg, "--max-count=") {
					return false
				}
				n, err := strconv.Atoi(strings.TrimPrefix(arg, "--max-count="))
				if err != nil || n < 1 || n > 10000 {
					return false
				}
			}
		}
	default:
		return false
	}
	return true
}

// AuthorizeSessionCommandBatch reuses existing authority before trying an exact,
// single-use automatic grant. It never raises an approval or auto-grants a mixed
// allow/approve batch. Cedar/invariant evaluation must succeed before calling it.
func AuthorizeSessionCommandBatch(zspDir, sessionID, clientType, command, workspace string, checks []ZSPActionCheck, consume bool, ancestry []string, shell ...string) (*types.CryptographicAgentSVID, *types.TaskGrant, *types.AuditLineageProof, error) {
	svid, grant, proof, originalErr := VerifyOrConsumeSessionZSPChecks(zspDir, sessionID, clientType, checks, command, workspace, consume, ancestry, shell...)
	if originalErr == nil {
		return svid, grant, proof, nil
	}
	// A local flag can only restrict this path, never expand policy permissions.
	if os.Getenv("BAP_ZSP_AUTO_GRANTS") == "0" {
		return svid, grant, proof, originalErr
	}
	derived, eligible := automaticBatchChecks(command, workspace, shell...)
	if !eligible {
		return svid, grant, proof, originalErr
	}
	if zspDir == "" {
		zspDir = ResolveZSPDir()
	}
	_, _, _, secret, err := EnsureSessionPrincipal(zspDir, sessionID, clientType)
	if err != nil {
		return svid, nil, nil, err
	}
	policy, err := LoadPermissionPolicy(zspDir, secret)
	if err != nil {
		return svid, nil, nil, err
	}
	actions, resources := []string{}, []string{}
	for _, check := range derived {
		resource := resolveZSPCheckResource(check, workspace, sessionID)
		decision := policy.Evaluate([]string{check.Action}, []string{resource})
		if !policy.InBoundary(resource) || len(decision.Denied) != 0 || len(decision.NeedsApproval) != 0 {
			return svid, nil, nil, originalErr
		}
		if !containsExact(actions, check.Action) {
			actions = append(actions, check.Action)
		}
		if !containsExact(resources, resource) {
			resources = append(resources, resource)
		}
	}
	// Serialize mint/recheck/consume across concurrent identical requests. Grant
	// persistence itself uses the shared session lock and existing mint ceilings.
	err = withZSPStoreLock(zspDir, "auto-"+sessionID+"-"+batchCommandHash(batchShell(shell)+"\x00"+command), func() error {
		var checkErr error
		svid, grant, proof, checkErr = VerifyOrConsumeSessionZSPChecks(zspDir, sessionID, clientType, derived, command, workspace, consume, ancestry, shell...)
		if checkErr == nil {
			return nil
		}
		binding := &types.TaskGrant{CommandHash: batchCommandHash(command), WorkspaceRoot: canonicalBatchWorkspace(workspace), PolicyHash: batchPolicyHash(policy)}
		binding.Shell = batchShell(shell)
		grant, _, err = submitTaskEnvelopeBound(zspDir, sessionID, clientType, "TASK_EXECUTION", "Policy-authorized command batch", command, actions, resources, "", "policy_automatic_batch", 1, 30*time.Second, binding)
		if err != nil {
			return err
		}
		svid, grant, proof, err = VerifyOrConsumeSessionZSPChecks(zspDir, sessionID, clientType, derived, command, workspace, consume, ancestry, shell...)
		return err
	})
	return svid, grant, proof, err
}

func containsExact(values []string, value string) bool {
	for _, current := range values {
		if current == value {
			return true
		}
	}
	return false
}

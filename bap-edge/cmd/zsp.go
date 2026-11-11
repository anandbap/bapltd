package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/internal/authz"
	"bap-edge/internal/state"
)

func collectAncestorPIDs(ppid int, processes []agentProcess) []int {
	seen := make(map[int]struct{})
	var pids []int
	add := func(pid int) {
		if pid <= 0 {
			return
		}
		if _, ok := seen[pid]; ok {
			return
		}
		seen[pid] = struct{}{}
		pids = append(pids, pid)
	}

	byPID := make(map[int]agentProcess, len(processes))
	for _, p := range processes {
		byPID[p.PID] = p
	}
	if observed, ok := observedCaller(ppid, processes); ok && observed.PID > 0 {
		add(observed.PID)
	}
	curr := ppid
	for depth := 0; depth < 12 && curr > 0; depth++ {
		add(curr)
		p, ok := byPID[curr]
		if !ok || p.ParentPID <= 0 || p.ParentPID == curr {
			break
		}
		curr = p.ParentPID
	}
	return pids
}

func resolveSessionIDFromPIDMarkers(pids ...int) string {
	dirs := []string{state.SessionsDir(), filepath.Join(".bap", "sessions")}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		dirs = append(dirs,
			filepath.Join(home, ".bapstate", "sessions"),
			filepath.Join(home, ".bap", "sessions"),
		)
	}
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		fileName := fmt.Sprintf("pid-%d.json", pid)
		for _, dir := range dirs {
			if dir == "" {
				continue
			}
			if data, err := os.ReadFile(filepath.Join(dir, fileName)); err == nil {
				var info struct {
					SessionID string `json:"session_id"`
				}
				if json.Unmarshal(data, &info) == nil && info.SessionID != "" {
					return info.SessionID
				}
			}
		}
	}
	return ""
}

func resolveDefaultZSPSessionID(explicit string) string {
	if explicit != "" {
		return explicit
	}
	if s := strings.TrimSpace(os.Getenv("BAP_SESSION_ID")); s != "" {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("LTD_SESSION_ID")); s != "" {
		return s
	}
	ppid := os.Getppid()
	processes, err := listAgentProcesses()
	var observed agentProcess
	var hasObserved bool
	if err == nil {
		observed, hasObserved = observedCaller(ppid, processes)
	}
	if sid := resolveSessionIDFromPIDMarkers(collectAncestorPIDs(ppid, processes)...); sid != "" {
		return sid
	}
	if hasObserved && observed.PID > 0 {
		if sid := observedSessionID(observationHost(), observed); sid != "" {
			return sid
		}
	}
	for _, cand := range []string{".bap-session.json", "../.bap-session.json"} {
		if data, err := os.ReadFile(cand); err == nil {
			var info struct {
				SessionID string `json:"session_id"`
			}
			if json.Unmarshal(data, &info) == nil && info.SessionID != "" {
				return info.SessionID
			}
		}
	}
	return fmt.Sprintf("sess-agent-pid-%d", ppid)
}

func splitCSVFlags(raw string) []string {
	var out []string
	for _, part := range strings.Split(raw, ",") {
		p := strings.TrimSpace(part)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// RunZSP manages Cryptographic Agent Principals, 4-Tuple Task Authorization Envelopes,
// and Zero Standing Privileges JIT TaskGrants (BAP-915, BAP-916, BAP-917, BAP-918).
func RunZSP(args []string) error {
	if len(args) == 0 {
		printZSPUsage()
		return nil
	}

	sub := strings.ToLower(strings.TrimSpace(args[0]))
	rest := args[1:]

	switch sub {
	case "init":
		fs := flag.NewFlagSet("zsp init", flag.ContinueOnError)
		sessFlag := fs.String("session-id", "", "Session ID")
		clientFlag := fs.String("client", "claude-code", "Agent client type")
		jsonFlag := fs.Bool("json", false, "JSON output")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		sessionID := resolveDefaultZSPSessionID(*sessFlag)
		svid, _, _, _, err := authz.EnsureSessionPrincipal(authz.ResolveZSPDir(), sessionID, *clientFlag)
		if err != nil {
			return err
		}
		if *jsonFlag {
			data, _ := json.MarshalIndent(map[string]any{
				"status":              "initialized",
				"session_id":          sessionID,
				"principal":           svid,
				"standing_privileges": "NONE (Starting Permission Set: ZERO)",
			}, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Printf("[BAP ZERO-TRUST] Cryptographic Principal SVID initialized: %s\n", svid.Subject)
		fmt.Printf("  Human Owner:         %s (%s)\n", svid.HumanOwner, svid.HumanOIDCSUB)
		fmt.Printf("  Standing Privileges: NONE (Starting Permission Set: ZERO / ZSP Active)\n")
		return nil

	case "status", "list":
		fs := flag.NewFlagSet("zsp status", flag.ContinueOnError)
		sessFlag := fs.String("session-id", "", "Session ID")
		clientFlag := fs.String("client", "claude-code", "Agent client type")
		jsonFlag := fs.Bool("json", false, "JSON output")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		sessionID := resolveDefaultZSPSessionID(*sessFlag)
		rep, err := authz.ListSessionZSPStatus(authz.ResolveZSPDir(), sessionID, *clientFlag)
		if err != nil {
			return err
		}
		if *jsonFlag {
			data, _ := json.MarshalIndent(rep, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Println("================================================================================")
		fmt.Println("  [BAP ZERO-TRUST] Agent Principal & ZSP Task Grant Ledger")
		fmt.Println("================================================================================")
		if rep.Principal != nil {
			fmt.Printf("  Agent Principal SVID: %s\n", rep.Principal.Subject)
			fmt.Printf("  Human Owner Identity: %s (%s)\n", rep.Principal.HumanOwner, rep.Principal.HumanOIDCSUB)
			fmt.Printf("  Workstation ID:       %s\n", rep.Principal.WorkstationID)
			fmt.Printf("  Public Key (Ed25519): %s...\n", rep.Principal.PublicKeyHex[:minInt(16, len(rep.Principal.PublicKeyHex))])
		}
		fmt.Printf("  Session ID:           %s\n", rep.SessionID)
		fmt.Printf("  Standing Privileges:  %s\n", rep.StandingPrivileges)
		fmt.Printf("  Active JIT Grants:    %d\n", len(rep.ActiveGrants))
		for _, g := range rep.ActiveGrants {
			fmt.Printf("    - %s | actions=%v | resources=%v | uses=%d/%d | exp=%s\n",
				g.GrantID, g.AllowedActions, g.AllowedResources, g.RemainingUses, g.MaxUses, g.ExpiresAt.Format(time.RFC3339))
		}
		fmt.Printf("  Recent Lineage Proofs:%d\n", len(rep.RecentLineage))
		fmt.Println("================================================================================")
		return nil

	case "authorize", "request":
		fs := flag.NewFlagSet("zsp authorize", flag.ContinueOnError)
		sessFlag := fs.String("session-id", "", "Session ID")
		clientFlag := fs.String("client", "claude-code", "Agent client type")
		missionFlag := fs.String("mission", "TASK_EXECUTION", "Primary mission (e.g. CODE_INSPECTION, BUG_FIX)")
		goalFlag := fs.String("goal", "", "Declared task goal")
		promptFlag := fs.String("prompt", os.Getenv("BAP_USER_PROMPT"), "Originating prompt")
		actionsFlag := fs.String("actions", "", "Comma-separated canonical actions requested (e.g. git:status,git:log)")
		resourcesFlag := fs.String("resources", "workspace://current", "Comma-separated resource scopes (default: workspace://current)")
		authByFlag := fs.String("authorized-by", "", "Approver/human owner email")
		maxUsesFlag := fs.Int("max-uses", 1, "Maximum ephemeral execution uses before grant burns")
		ttlFlag := fs.Duration("ttl", 300*time.Second, "Grant TTL (e.g. 300s)")
		jsonFlag := fs.Bool("json", false, "JSON output")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		maxUsesSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "max-uses" {
				maxUsesSet = true
			}
		})
		sessionID := resolveDefaultZSPSessionID(*sessFlag)
		actions := splitCSVFlags(*actionsFlag)
		resources := splitCSVFlags(*resourcesFlag)
		if len(actions) == 0 {
			return fmt.Errorf("--actions is required (e.g. --actions git:status,git:log)")
		}
		for _, act := range actions {
			if valErr := authz.ValidateZSPActionName(act); valErr != nil {
				return valErr
			}
		}
		maxUses := *maxUsesFlag
		if !maxUsesSet && len(actions) > 1 {
			maxUses = len(actions)
		}
		if maxUses <= 0 {
			return fmt.Errorf("--max-uses must be at least 1")
		}
		grant, env, err := authz.SubmitTaskEnvelope(
			authz.ResolveZSPDir(),
			sessionID,
			*clientFlag,
			*missionFlag,
			*goalFlag,
			*promptFlag,
			actions,
			resources,
			*authByFlag,
			maxUses,
			*ttlFlag,
		)
		if err != nil {
			if *jsonFlag {
				data, _ := json.MarshalIndent(map[string]any{
					"allowed": false,
					"error":   err.Error(),
				}, "", "  ")
				fmt.Println(string(data))
			}
			return err
		}
		if *jsonFlag {
			data, _ := json.MarshalIndent(map[string]any{
				"allowed":     true,
				"grant":       grant,
				"envelope_id": env.EnvelopeID,
			}, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Printf("[BAP ZERO-TRUST] 4-Tuple Task Envelope Authorized -> JIT TaskGrant Minted\n")
		fmt.Printf("  Grant ID:          %s\n", grant.GrantID)
		fmt.Printf("  Envelope ID:       %s\n", env.EnvelopeID)
		fmt.Printf("  Principal SVID:    %s\n", grant.PrincipalSVID)
		fmt.Printf("  Human Owner:       %s\n", grant.HumanOwner)
		fmt.Printf("  Allowed Actions:   %v\n", grant.AllowedActions)
		fmt.Printf("  Allowed Resources: %v\n", grant.AllowedResources)
		fmt.Printf("  Max Uses / TTL:    %d uses | expires %s\n", grant.MaxUses, grant.ExpiresAt.Format(time.RFC3339))
		return nil

	case "check":
		fs := flag.NewFlagSet("zsp check", flag.ContinueOnError)
		sessFlag := fs.String("session-id", "", "Session ID")
		clientFlag := fs.String("client", "claude-code", "Agent client type")
		actionFlag := fs.String("action", "", "Canonical action")
		resFlag := fs.String("resource", "workspace://current", "Canonical resource")
		cmdFlag := fs.String("command", "", "Command executed")
		consumeFlag := fs.Bool("consume", false, "Burn one grant use if authorized")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		sessionID := resolveDefaultZSPSessionID(*sessFlag)
		svid, grant, proof, err := authz.VerifyOrConsumeSessionZSP(
			authz.ResolveZSPDir(), sessionID, *clientFlag, *actionFlag, *resFlag, *cmdFlag,
			authz.GetWorkspaceRoot(), false, *consumeFlag, nil,
		)
		out := map[string]any{
			"allowed":   err == nil,
			"principal": svid,
			"grant":     grant,
			"proof":     proof,
		}
		if err != nil {
			out["reason"] = err.Error()
		}
		data, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(data))
		return err

	case "revoke":
		fs := flag.NewFlagSet("zsp revoke", flag.ContinueOnError)
		sessFlag := fs.String("session-id", "", "Session ID")
		grantFlag := fs.String("grant-id", "", "Specific Grant ID to revoke (default: all in session)")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		sessionID := resolveDefaultZSPSessionID(*sessFlag)
		n, err := authz.RevokeSessionZSPGrants(authz.ResolveZSPDir(), sessionID, *grantFlag)
		if err != nil {
			return err
		}
		fmt.Printf("[BAP ZERO-TRUST] Revoked %d JIT TaskGrant(s) for session %s.\n", n, sessionID)
		return nil

	default:
		printZSPUsage()
		return fmt.Errorf("unknown zsp subcommand: %s", sub)
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func printZSPUsage() {
	fmt.Println(`Usage: bapedge zsp <subcommand> [flags]

Subcommands:
  init       Initialize cryptographic Agent Principal SVID with 0 standing privileges
  status     Inspect cryptographic principal, standing privilege posture, and JIT grants
  authorize  Submit signed 4-Tuple Task Authorization Envelope and mint least-privilege JIT TaskGrant
  check      Verify (or consume) a TaskGrant for a specific action & resource
  revoke     Immediately burn one or all TaskGrants in a session`)
}

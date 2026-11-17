package cmd

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"bap-edge/internal/audit"
	"bap-edge/internal/authz"
	"bap-edge/internal/config"
	"bap-edge/internal/state"
	"bap-edge/pkg/types"
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
			filepath.Join(home, "bin", ".bapstate", "sessions"),
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
	if existing := findActiveNativeSession("", ppid); existing != "" {
		return existing
	}
	for _, cand := range []string{state.WorkspaceSessionPath(), filepath.Join(".bap", "session.json"), ".bap-session.json", "../.bap-session.json"} {
		if data, err := os.ReadFile(cand); err == nil {
			var info struct {
				SessionID string `json:"session_id"`
			}
			if json.Unmarshal(data, &info) == nil && info.SessionID != "" {
				return info.SessionID
			}
		}
	}
	if hasObserved && observed.PID > 0 {
		if sid := observedSessionID(observationHost(), observed); sid != "" {
			return sid
		}
	}
	return fmt.Sprintf("sess-agent-%d", ppid)
}

func resolveRequestingSessionID(targetSession, clientType string) string {
	if s := strings.TrimSpace(os.Getenv("BAP_SESSION_ID")); s != "" && s != targetSession {
		return s
	}
	if s := strings.TrimSpace(os.Getenv("LTD_SESSION_ID")); s != "" && s != targetSession {
		return s
	}
	ppid := os.Getppid()
	if existing := findActiveNativeSession(clientType, ppid); existing != "" && existing != targetSession {
		return existing
	}
	for _, cand := range []string{state.WorkspaceSessionPath(), filepath.Join(".bap", "session.json")} {
		if data, err := os.ReadFile(cand); err == nil {
			var info struct {
				SessionID string `json:"session_id"`
			}
			if json.Unmarshal(data, &info) == nil && info.SessionID != "" && info.SessionID != targetSession {
				return info.SessionID
			}
		}
	}
	return targetSession
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
		svid, _, _, _, err := authz.EnsureSessionPrincipal(authz.ResolveZSPDir(), sessionID, normalizeZSPClientType(*clientFlag))
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

	case "status", "list", "grants":
		fs := flag.NewFlagSet("zsp status", flag.ContinueOnError)
		sessFlag := fs.String("session-id", "", "Session ID")
		clientFlag := fs.String("client", "claude-code", "Agent client type")
		jsonFlag := fs.Bool("json", false, "JSON output")
		allFlag := fs.Bool("all", false, "Show all grants including burned/used and expired")
		allSessionsFlag := fs.Bool("all-sessions", false, "Show grants across all sessions on this workstation")
		if err := fs.Parse(rest); err != nil {
			return err
		}

		// Workstation-wide inspection if requested or if no session specified and default has 0 grants
		if *allSessionsFlag {
			allG, err := authz.CollectAllWorkstationGrants(authz.ResolveZSPDir())
			if err != nil {
				return err
			}
			if *jsonFlag {
				data, _ := json.MarshalIndent(map[string]any{
					"standing_privileges": "NONE (Starting Permission Set: ZERO / ZSP Active)",
					"total_grants":        len(allG),
					"grants":              allG,
				}, "", "  ")
				fmt.Println(string(data))
				return nil
			}
			fmt.Println("================================================================================")
			fmt.Println("  [BAP ZERO-TRUST] Workstation ZSP Task Grant Ledger (All Sessions)")
			fmt.Println("================================================================================")
			fmt.Printf("  Total Recorded Grants: %d\n", len(allG))
			for idx, g := range allG {
				mode := "AUTOMATIC (Cedar Policy)"
				if strings.Contains(strings.ToLower(g.DelegationType), "oob") ||
					strings.Contains(strings.ToLower(g.DelegationType), "prompt") ||
					strings.Contains(strings.ToLower(g.DelegationType), "step_up") ||
					strings.Contains(strings.ToLower(g.DelegationType), "manual") {
					mode = "MANUAL (HITL Challenge)"
				}
				statusStr := "ACTIVE"
				if g.IsBurned || g.RemainingUses < g.MaxUses {
					statusStr = fmt.Sprintf("1x USED & BURNED (%s)", g.BurnReason)
				} else if time.Now().After(g.ExpiresAt) {
					statusStr = "EXPIRED UNUSED"
				}
				fmt.Printf("  [%d] %s [%s]\n", idx+1, g.GrantID, mode)
				fmt.Printf("      Session/Agent: %s (%s)\n", g.SessionID, g.ClientType)
				if g.RequestingSessionID != "" && g.RequestingSessionID != g.SessionID {
					fmt.Printf("      Requesting:    %s\n", g.RequestingSessionID)
				}
				if len(g.LinkedSessionIDs) > 1 {
					fmt.Printf("      Linked:        %v\n", g.LinkedSessionIDs)
				}
				fmt.Printf("      Scopes:        actions=%v, resources=%v\n", g.AllowedActions, g.AllowedResources)
				fmt.Printf("      Lifecycle:     %s\n", statusStr)
				if g.ConsumedCmd != "" {
					fmt.Printf("      Consumed:      %s (Receipt: %s)\n", g.ConsumedCmd, g.ReceiptID)
				}
			}
			fmt.Println("================================================================================")
			return nil
		}

		sessionID := resolveDefaultZSPSessionID(*sessFlag)
		rep, err := authz.ListSessionZSPStatus(authz.ResolveZSPDir(), sessionID, normalizeZSPClientType(*clientFlag))
		if err != nil {
			return err
		}

		// Fallback: If caller didn't pass explicit session and default session is empty, check workstation-wide grants
		if *sessFlag == "" && len(rep.ActiveGrants) == 0 && len(rep.BurnedOrExpired) == 0 {
			if allG, err := authz.CollectAllWorkstationGrants(authz.ResolveZSPDir()); err == nil && len(allG) > 0 {
				for _, g := range allG {
					if !g.IsBurned && g.RemainingUses > 0 && time.Now().Before(g.ExpiresAt) {
						rep.ActiveGrants = append(rep.ActiveGrants, *g)
					} else {
						rep.BurnedOrExpired = append(rep.BurnedOrExpired, *g)
					}
				}
			}
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
			mode := "AUTOMATIC (Cedar Policy)"
			if strings.Contains(strings.ToLower(g.DelegationType), "oob") ||
				strings.Contains(strings.ToLower(g.DelegationType), "prompt") ||
				strings.Contains(strings.ToLower(g.DelegationType), "step_up") {
				mode = "MANUAL (HITL Challenge)"
			}
			fmt.Printf("    - %s [%s]\n", g.GrantID, mode)
			fmt.Printf("      Status:    ACTIVE EPHEMERAL (remaining: %d/%d, exp: %s)\n", g.RemainingUses, g.MaxUses, g.ExpiresAt.Format("15:04:05Z"))
			fmt.Printf("      Scopes:    actions=%v, resources=%v\n", g.AllowedActions, g.AllowedResources)
		}

		now := time.Now().UTC()
		var burnedGrants []types.TaskGrant
		var expiredGrants []types.TaskGrant
		for _, g := range rep.BurnedOrExpired {
			if g.IsBurned || g.RemainingUses < g.MaxUses {
				burnedGrants = append(burnedGrants, g)
			} else if now.After(g.ExpiresAt) {
				expiredGrants = append(expiredGrants, g)
			}
		}

		showHistory := *allFlag || sub == "grants" || len(rep.ActiveGrants) == 0
		if showHistory && len(burnedGrants) > 0 {
			fmt.Printf("  Used & Burned Grants: %d (Zero Standing Privilege Expended)\n", len(burnedGrants))
			for _, g := range burnedGrants {
				mode := "AUTOMATIC (Cedar Policy)"
				if strings.Contains(strings.ToLower(g.DelegationType), "oob") ||
					strings.Contains(strings.ToLower(g.DelegationType), "prompt") ||
					strings.Contains(strings.ToLower(g.DelegationType), "step_up") {
					mode = "MANUAL (HITL Challenge)"
				}
				consumedCmd := g.ConsumedCmd
				receiptID := g.ReceiptID
				if consumedCmd == "" {
					for _, lin := range rep.RecentLineage {
						if lin.GrantID == g.GrantID {
							consumedCmd = lin.CommandExecuted
							receiptID = lin.ProofID
							break
						}
					}
				}
				fmt.Printf("    - %s [%s]\n", g.GrantID, mode)
				fmt.Printf("      Status:    1x USED & BURNED (%s)\n", g.BurnReason)
				fmt.Printf("      Scopes:    actions=%v, resources=%v\n", g.AllowedActions, g.AllowedResources)
				if consumedCmd != "" {
					fmt.Printf("      Consumed:  %s (Receipt: %s)\n", consumedCmd, receiptID)
				}
			}
		}

		if showHistory && len(expiredGrants) > 0 {
			fmt.Printf("  Expired Unused Grants:%d\n", len(expiredGrants))
			for _, g := range expiredGrants {
				fmt.Printf("    - %s [EXPIRED UNUSED] actions=%v exp=%s\n", g.GrantID, g.AllowedActions, g.ExpiresAt.Format("15:04:05Z"))
			}
		}

		fmt.Printf("  Recent Lineage Proofs:%d\n", len(rep.RecentLineage))
		fmt.Println("================================================================================")
		return nil

	case "playback":
		fs := flag.NewFlagSet("zsp playback", flag.ContinueOnError)
		limitFlag := fs.Int("limit", 50, "Max grants to playback")
		jsonFlag := fs.Bool("json", false, "Output playback in JSON format")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		grants, err := authz.CollectAllWorkstationGrants(authz.ResolveZSPDir())
		if err != nil {
			return err
		}
		sort.Slice(grants, func(i, j int) bool {
			return grants[i].IssuedAt.Before(grants[j].IssuedAt)
		})
		if len(grants) > *limitFlag {
			grants = grants[len(grants)-*limitFlag:]
		}
		if *jsonFlag {
			data, _ := json.MarshalIndent(grants, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		fmt.Println("================================================================================")
		fmt.Println("  [BAP ZERO-TRUST] 🎬 ZSP Grant Lifecycle Playback & Policy Tuning Feed")
		fmt.Println("================================================================================")
		if len(grants) == 0 {
			fmt.Println("  (No ZSP task grants recorded on this workstation yet)")
			fmt.Println("================================================================================")
			return nil
		}
		autoCount, manualCount := 0, 0
		for idx, g := range grants {
			mode := "AUTOMATIC (Cedar Policy)"
			if strings.Contains(strings.ToLower(g.DelegationType), "oob") ||
				strings.Contains(strings.ToLower(g.DelegationType), "prompt") ||
				strings.Contains(strings.ToLower(g.DelegationType), "step_up") ||
				strings.Contains(strings.ToLower(g.DelegationType), "manual") {
				mode = "MANUAL (HITL Challenge)"
				manualCount++
			} else {
				autoCount++
			}
			statusStr := "ACTIVE"
			if g.IsBurned || g.RemainingUses < g.MaxUses {
				statusStr = fmt.Sprintf("1x USED & BURNED (%s)", g.BurnReason)
			} else if time.Now().After(g.ExpiresAt) {
				statusStr = "EXPIRED UNUSED"
			}
			fmt.Printf("  [%d] %s | %s [%s]\n", idx+1, g.IssuedAt.Format("15:04:05 UTC"), g.GrantID, mode)
			fmt.Printf("      Agent/Session: %s (%s)\n", g.ClientType, g.SessionID)
			fmt.Printf("      Scopes:        actions=%v, resources=%v\n", g.AllowedActions, g.AllowedResources)
			fmt.Printf("      Lifecycle:     %s\n", statusStr)
			if g.ConsumedCmd != "" {
				rcpt := g.ReceiptID
				if rcpt == "" {
					rcpt = "verified-receipt"
				}
				fmt.Printf("      Execution:     %s (Receipt: %s)\n", g.ConsumedCmd, rcpt)
			}
		}
		total := autoCount + manualCount
		autoPct := 0.0
		if total > 0 {
			autoPct = float64(autoCount) / float64(total) * 100.0
		}
		fmt.Println("--------------------------------------------------------------------------------")
		fmt.Printf("  PLAYBACK SUMMARY FOR POLICY TUNING:\n")
		fmt.Printf("    Total Grants Replayed: %d (%d Automatic, %d Step-Up HITL)\n", total, autoCount, manualCount)
		fmt.Printf("    Automation Velocity:   %.1f%% automated by Cedar invariants\n", autoPct)
		if autoCount > 3 {
			fmt.Printf("    Policy Recommendation: Recurring safe routine grants qualify for permanent Cedar rules.\n")
		}
		fmt.Println("================================================================================")
		return nil

	case "authorize", "request":
		fs := flag.NewFlagSet("zsp authorize", flag.ContinueOnError)
		sessFlag := fs.String("session-id", "", "Session ID")
		reqSessFlag := fs.String("requesting-session-id", "", "Requesting agent session ID")
		clientFlag := fs.String("client", "claude-code", "Agent client type")
		missionFlag := fs.String("mission", "TASK_EXECUTION", "Primary mission (e.g. CODE_INSPECTION, BUG_FIX)")
		goalFlag := fs.String("goal", "", "Declared task goal")
		promptFlag := fs.String("prompt", os.Getenv("BAP_USER_PROMPT"), "Originating prompt")
		actionsFlag := fs.String("actions", "", "Comma-separated canonical actions requested (e.g. git:status,git:log)")
		resourcesFlag := fs.String("resources", "workspace://current", "Comma-separated resource scopes (default: workspace://current)")
		authByFlag := fs.String("authorized-by", "", "Approver/human owner email")
		maxUsesFlag := fs.Int("max-uses", 1, "Maximum ephemeral execution uses before grant burns")
		ttlFlag := fs.Duration("ttl", 300*time.Second, "Grant TTL (e.g. 300s)")
		oobApproveFlag := fs.Bool("oob-approve", false, "Out-of-band human operator approval (forbidden inside agent broker)")
		jsonFlag := fs.Bool("json", false, "JSON output")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		inBroker := strings.TrimSpace(os.Getenv("BAP_IN_BROKER")) != ""
		if *oobApproveFlag && inBroker {
			return fmt.Errorf("%w: --oob-approve cannot be invoked from inside an agent broker sandbox; a human operator must approve out-of-band", authz.ErrHighRiskApprovalRequired)
		}
		maxUsesSet := false
		fs.Visit(func(f *flag.Flag) {
			if f.Name == "max-uses" {
				maxUsesSet = true
			}
		})
		sessionID := resolveDefaultZSPSessionID(*sessFlag)
		requestingSessionID := strings.TrimSpace(*reqSessFlag)
		if requestingSessionID == "" {
			requestingSessionID = resolveRequestingSessionID(sessionID, *clientFlag)
		}
		clientType := normalizeZSPClientType(*clientFlag)
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
		delegationType := "human_interactive_prompt"
		if *oobApproveFlag && !inBroker {
			// BAP-926: the flag alone proves nothing. A human must answer a fresh one-time challenge on a real terminal.
			if !humanApprovalChallenge(sessionID, actions, resources, *goalFlag) {
				return fmt.Errorf("%w: interactive human approval challenge failed or no terminal is attached", authz.ErrHighRiskApprovalRequired)
			}
			delegationType = "human_interactive_oob"
		}
		if delegationType == "human_interactive_prompt" {
				// A human opened a developer override window: policy-tier approvals are paused for its
				// duration. Governance escalations (policy:, grant:, admin:, ...) are still refused by the
				// engine, and the grant carries a distinct delegation type so the audit trail shows it.
				if active, banner := devOverrideActive(); active {
					fmt.Fprintln(os.Stderr, banner)
					delegationType = authz.DelegationDevOverride
				} else if on, until, _ := authz.AutoApproveStatus(authz.ResolveZSPDir()); on {
					// BAP-1100: a human enabled step-up auto-approve for a bounded window.
					fmt.Fprintf(os.Stderr, "[BAP ZSP AUTO-APPROVE ON until %s] Approve-tier requests are granted without a prompt; policy denies and governance escalations still apply.\n", until.Format(time.RFC3339))
					delegationType = authz.DelegationAutoApprove
				}
			}
			var pendingReq *authz.PendingApproval
		grant, _, err := authz.SubmitTaskEnvelopeWithDelegation(
			authz.ResolveZSPDir(),
			sessionID,
			clientType,
			*missionFlag,
			*goalFlag,
			*promptFlag,
			actions,
			resources,
			*authByFlag,
			delegationType,
			maxUses,
			*ttlFlag,
			requestingSessionID,
		)
		if err != nil && errors.Is(err, authz.ErrHighRiskApprovalRequired) && !inBroker && isTerminal(os.Stdin) {
			fmt.Fprintf(os.Stderr, "\n[BAP HITL ESCALATION] %v\n", err)
			if humanApprovalChallenge(sessionID, actions, resources, *goalFlag) {
				grant, _, err = authz.SubmitTaskEnvelopeWithDelegation(
					authz.ResolveZSPDir(),
					sessionID,
					clientType,
					*missionFlag,
					*goalFlag,
					*promptFlag,
					actions,
					resources,
					*authByFlag,
					"human_interactive_oob",
					maxUses,
					*ttlFlag,
					requestingSessionID,
				)
			}
		}
		// A human already approved an earlier request and its grant is still live and covers this ask:
		// hand that grant back instead of raising a second request for the same thing.
		reusedApprovedGrant := false
		if err != nil && errors.Is(err, authz.ErrHighRiskApprovalRequired) {
			if g, _ := authz.FindLiveApprovedGrant(authz.ResolveZSPDir(), sessionID, clientType, actions, resources, time.Now()); g != nil {
				grant, err, reusedApprovedGrant = g, nil, true
			}
		}
		if err != nil {
			// Every refusal is an audit event with a specific concept and the real reason (BAP-931), so the
			// calls report shows a denied authorize as a denial rather than an opaque "exit status 1".
			if concept := zspDenialConcept(err); concept != "" {
				recordZSPAuditEvent(sessionID, clientType, actions, nil, false, "", "", "deny", err.Error(), concept)
			}
			// Anti-spin: count identical refusals; from the third, tell the agent plainly to stop (BAP-936).
			if zspDenialConcept(err) != "" {
				if n := authz.RecordDenial(authz.ResolveZSPDir(), sessionID, authz.AuthorizeDenialKey(actions, resources)); n >= authz.DenialWarnAfter {
					fmt.Fprintln(os.Stderr, authz.RepeatedDenialNotice(n))
				}
			}
			// An approve-tier refusal is not a dead end: raise a reviewable HITL request (BAP-936).
			if errors.Is(err, authz.ErrHighRiskApprovalRequired) {
				pendingReq = raiseHITLRequest(sessionID, clientType, *missionFlag, *goalFlag, actions, resources, maxUses, *ttlFlag, err)
			}
			if *jsonFlag {
				data, _ := json.MarshalIndent(map[string]any{
					"allowed": false,
					"error":   err.Error(),
				}, "", "  ")
				fmt.Println(string(data))
			} else if errors.Is(err, authz.ErrHighRiskApprovalRequired) {
				fmt.Fprintf(os.Stderr, "[BAP ZERO-TRUST] High-Risk Escalation Blocked (Out-of-Band Interactive Human Approval Required)\n")
				fmt.Fprintf(os.Stderr, "  Requested Actions: %v\n", actions)
				fmt.Fprintf(os.Stderr, "  Reason:            %v\n", err)
				printHITLNextStep(pendingReq, sessionID, *actionsFlag, *resourcesFlag)
			}
			return err
		}
		decision := "allow"
		zspConcept := "ZSP_GRANT_MINTED"
			if delegationType == authz.DelegationDevOverride {
				zspConcept = "ZSP_DEV_OVERRIDE_GRANT"
			}
			if delegationType == authz.DelegationAutoApprove {
				zspConcept = "ZSP_AUTO_APPROVE_GRANT"
			}
		if reusedApprovedGrant {
			zspConcept = "ZSP_APPROVED_GRANT_REUSED"
		}
		if grant.NarrowingApplied {
			decision = "ALLOWED-LIMITED"
			zspConcept = "ZSP_SCOPE_NARROWED"
		}
		recordZSPAuditEvent(sessionID, clientType, grant.RequestedActions, grant.AllowedActions, grant.NarrowingApplied, grant.NarrowingReason, grant.GrantID, decision, grant.NarrowingReason, zspConcept, requestingSessionID, grant.LinkedSessionIDs)
		if *jsonFlag {
			data, _ := json.MarshalIndent(map[string]any{
				"allowed":           true,
				"decision":          decision,
				"grant":             grant,
				"envelope_id":       grant.EnvelopeID,
				"reused_approved":   reusedApprovedGrant,
				"narrowing_applied": grant.NarrowingApplied,
				"narrowing_reason":  grant.NarrowingReason,
			}, "", "  ")
			fmt.Println(string(data))
			return nil
		}
		if grant.NarrowingApplied {
			fmt.Printf("[BAP ZERO-TRUST] Decision: ALLOWED-LIMITED (Policy Narrowing Applied: Monotonic Scope Attenuation)\n")
			fmt.Printf("  Requested Actions: %v -> Attenuated: %v\n", grant.RequestedActions, grant.AllowedActions)
			fmt.Printf("  Reason:            %s\n", grant.NarrowingReason)
		}
		if reusedApprovedGrant {
			fmt.Printf("[BAP ZERO-TRUST] Human-approved grant is still live and covers this request; reusing it (no new request raised)\n")
			fmt.Printf("  Run your command now. The grant expires soon and has limited uses.\n")
		} else {
			fmt.Printf("[BAP ZERO-TRUST] 4-Tuple Task Envelope Authorized -> JIT TaskGrant Minted\n")
		}
		fmt.Printf("  Grant ID:          %s\n", grant.GrantID)
		fmt.Printf("  Envelope ID:       %s\n", grant.EnvelopeID)
		fmt.Printf("  Session ID:        %s\n", grant.SessionID)
		if grant.RequestingSessionID != "" && grant.RequestingSessionID != grant.SessionID {
			fmt.Printf("  Requesting Session:%s\n", grant.RequestingSessionID)
		}
		if len(grant.LinkedSessionIDs) > 1 {
			fmt.Printf("  Linked Sessions:   %v\n", grant.LinkedSessionIDs)
		}
		fmt.Printf("  Principal SVID:    %s\n", grant.PrincipalSVID)
		fmt.Printf("  Human Owner:       %s\n", grant.HumanOwner)
		fmt.Printf("  Allowed Actions:   %v\n", grant.AllowedActions)
		fmt.Printf("  Allowed Resources: %v\n", grant.AllowedResources)
		fmt.Printf("  Max Uses / TTL:    %d uses | expires %s\n", grant.MaxUses, grant.ExpiresAt.Format(time.RFC3339))
		return nil

	case "approvals", "requests":
		return runZSPApprovals()

	case "approve":
		return runZSPDecide(true, rest)

	case "deny":
		return runZSPDecide(false, rest)

	case "autoapprove":
		return runZSPAutoApprove(rest)

	case "policy-sign":
		// BAP-925: install an administrator permission-policy override, HMAC-signed with the PEP secret.
		if strings.TrimSpace(os.Getenv("BAP_IN_BROKER")) != "" {
			return fmt.Errorf("%w: policy-sign is a human-operator action and cannot run inside an agent session", authz.ErrHighRiskApprovalRequired)
		}
		fs := flag.NewFlagSet("zsp policy-sign", flag.ContinueOnError)
		fileFlag := fs.String("file", "", "Permission policy JSON to validate, sign and install")
		if err := fs.Parse(rest); err != nil {
			return err
		}
		if strings.TrimSpace(*fileFlag) == "" {
			return fmt.Errorf("--file is required")
		}
		if err := authz.InstallSignedPermissionPolicy(authz.ResolveZSPDir(), *fileFlag); err != nil {
			return err
		}
		fmt.Printf("[BAP ZERO-TRUST] Permission policy validated, signed and installed in %s\n", authz.ResolveZSPDir())
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
			authz.ResolveZSPDir(), sessionID, normalizeZSPClientType(*clientFlag), *actionFlag, *resFlag, *cmdFlag,
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

func recordZSPAuditEvent(
	sessionID, clientType string,
	requestedActions, allowedActions []string,
	narrowingApplied bool,
	narrowingReason, grantID, decision, reason, zspConcept string,
	optSess ...any,
) {
	requestingSessionID := ""
	var linkedSessions []string
	if len(optSess) > 0 {
		if s, ok := optSess[0].(string); ok {
			requestingSessionID = s
		}
	}
	if len(optSess) > 1 {
		if ls, ok := optSess[1].([]string); ok {
			linkedSessions = ls
		}
	}

	fullCmd := fmt.Sprintf("bapedge zsp authorize --actions %s", strings.Join(requestedActions, ","))
	if narrowingApplied {
		fullCmd = fmt.Sprintf("bapedge zsp authorize --actions %s [NARROWED -> %s]", strings.Join(requestedActions, ","), strings.Join(allowedActions, ","))
	}
	entry := audit.AuditEntry{
		EventID:             fmt.Sprintf("zsp-%d", time.Now().UnixNano()),
		ReportingLayer:      "broker",
		SessionID:           sessionID,
		RequestingSessionID: requestingSessionID,
		LinkedSessionIDs:    linkedSessions,
		Timestamp:           time.Now().UTC(),
		Source:              clientType,
		ClientPID:           os.Getppid(),
		Executable:          "bapedge",
		Arguments:           "zsp authorize",
		FullCommand:         fullCmd,
		Decision:            decision,
		Reason:              reason,
		CanonicalAction:     "zsp:authorize",
		CanonicalResource:   "workspace://current",
		GrantID:             grantID,
		NarrowingApplied:    narrowingApplied,
		NarrowingReason:     narrowingReason,
		RequestedActions:    requestedActions,
		AllowedActions:      allowedActions,
		ZSPConcept:          zspConcept,
	}
	if reason == "" {
		entry.Reason = fmt.Sprintf("TaskGrant %s minted (%v)", grantID, allowedActions)
	}
	_ = audit.Log(&entry, "")
	if requestingSessionID != "" && requestingSessionID != sessionID {
		reqEntry := entry
		reqEntry.EventID = fmt.Sprintf("zsp-req-%d", time.Now().UnixNano())
		reqEntry.SessionID = requestingSessionID
		_ = audit.Log(&reqEntry, "")
	}
	ep := config.ResolveEndpoints()
	if ep.ControlPlaneURL != "" {
		_, _, _ = audit.Transmit(entry, ep.ControlPlaneURL, "")
	}
}

func normalizeZSPClientType(client string) string {
	trimmed := strings.TrimSpace(client)
	if isClaudeSource(trimmed) {
		return "claude-code"
	}
	if trimmed == "" {
		return "claude-code"
	}
	return trimmed
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
  playback   Replay full chronological grant lifecycle, modes (auto vs HITL) and policy recommendations
  authorize  Submit signed 4-Tuple Task Authorization Envelope and mint least-privilege JIT TaskGrant
  check      Verify (or consume) a TaskGrant for a specific action & resource
  revoke     Immediately burn one or all TaskGrants in a session
  approvals  List pending human-approval requests (alias: requests)
  approve    Approve a pending request by id (human only, one-time code)
  deny       Deny a pending request by id (human only)
  autoapprove on|off|status   Optional bounded auto-approve of approve-tier requests (on is human only)
  policy-sign  Validate, sign and install a permission-policy override (human only)`)
}

package cmd

import (
	"bap-edge/internal/config"
	"bap-edge/internal/httptransport"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

// RunDelegate handles the 'delegate' / 'subagent' CLI command (BAP-532).
func RunDelegate(args []string) error {
	if len(args) == 0 {
		printDelegateUsage()
		return nil
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "mint":
		return runDelegateMint(subArgs)
	case "run":
		return runDelegateRun(subArgs)
	case "status", "tree":
		return runDelegateStatus(subArgs)
	case "help", "-h", "--help":
		printDelegateUsage()
		return nil
	default:
		// If first arg isn't a known subcommand, check if it's "run" flags or print usage
		printDelegateUsage()
		return fmt.Errorf("unknown delegate subcommand %q", sub)
	}
}

func printDelegateUsage() {
	fmt.Println("Usage: bapedge delegate <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  mint        Request an attenuated child grant from control plane")
	fmt.Println("  run         Execute a subagent command under an attenuated grant and delegation lineage")
	fmt.Println("  status      Display current delegation lineage and hierarchy")
	fmt.Println("\nExamples:")
	fmt.Println("  bapedge delegate mint --child-agent subagent-worker --scopes fs:read")
	fmt.Println("  bapedge delegate run --child-agent subagent-worker --scopes fs:read -- python worker.py")
	fmt.Println("  bapedge delegate status")
}

// DelegateResponse represents the JSON returned by /api/v1/grants/delegate.
type DelegateResponse struct {
	Token         string   `json:"token"`
	TokenType     string   `json:"token_type"`
	GrantID       string   `json:"grant_id"`
	ParentGrantID string   `json:"parent_grant_id"`
	RootGrantID   string   `json:"root_grant_id"`
	RootAgentID   string   `json:"root_agent_id"`
	ParentAgentID string   `json:"parent_agent_id"`
	Lineage       []string `json:"lineage"`
	LineageTree   string   `json:"lineage_tree"`
	ExpiresAt     time.Time `json:"expires_at"`
	TTLSecs       int      `json:"ttl_secs"`
	Scopes        []string `json:"scopes"`
	SessionID     string   `json:"session_id"`
	Action        string   `json:"action"`
	Resource      string   `json:"resource"`
	Depth         int      `json:"depth"`
	Error         string   `json:"error,omitempty"`
	Message       string   `json:"message,omitempty"`
}

// VerifyLocalAttenuation validates monotonic narrowing of authority locally.
func VerifyLocalAttenuation(parentScopes, childScopes []string, parentResource, childResource, parentAction, childAction string) error {
	if len(parentScopes) > 0 {
		if len(childScopes) == 0 {
			return fmt.Errorf("PrivilegeEscalationBlocked: child subagent requested empty scopes while parent has bounded scopes")
		}
		for _, cs := range childScopes {
			allowed := false
			for _, ps := range parentScopes {
				if ps == "*" || ps == "admin:all" {
					allowed = true
					break
				}
				if ps == cs {
					allowed = true
					break
				}
				if strings.HasSuffix(ps, "*") && strings.HasPrefix(cs, strings.TrimSuffix(ps, "*")) {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("PrivilegeEscalationBlocked: child subagent requested scope %q which is outside parent boundary %v", cs, parentScopes)
			}
		}
	}

	if parentResource != "" && parentResource != "*" {
		if childResource == "" || childResource == "*" {
			return fmt.Errorf("PrivilegeEscalationBlocked: child subagent cannot broaden resource from %q to wildcard or empty", parentResource)
		}
		if strings.HasSuffix(parentResource, "/*") {
			base := strings.TrimSuffix(parentResource, "/*")
			if !strings.HasPrefix(childResource, base) {
				return fmt.Errorf("PrivilegeEscalationBlocked: child subagent resource %q violates parent boundary %q", childResource, parentResource)
			}
		} else if strings.HasSuffix(parentResource, "*") {
			base := strings.TrimSuffix(parentResource, "*")
			if !strings.HasPrefix(childResource, base) {
				return fmt.Errorf("PrivilegeEscalationBlocked: child subagent resource %q violates parent boundary %q", childResource, parentResource)
			}
		} else {
			if childResource != parentResource && !strings.HasPrefix(childResource, parentResource+"/") {
				return fmt.Errorf("PrivilegeEscalationBlocked: child subagent resource %q exceeds parent resource boundary %q", childResource, parentResource)
			}
		}
	}

	if parentAction != "" && parentAction != "*" {
		if childAction == "" || childAction == "*" {
			return fmt.Errorf("PrivilegeEscalationBlocked: child subagent cannot broaden action from %q to wildcard", parentAction)
		}
		if !strings.EqualFold(parentAction, childAction) {
			return fmt.Errorf("PrivilegeEscalationBlocked: child subagent action %q exceeds parent action %q", childAction, parentAction)
		}
	}

	return nil
}

func runDelegateMint(args []string) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	parentTokenFlag := fs.String("parent-token", "", "Parent BAP grant token (default: BAP_GRANT_TOKEN env)")
	childAgentFlag := fs.String("child-agent", "subagent", "Child subagent ID or name")
	childAppFlag := fs.String("child-app", "subagent", "Child subagent application ID")
	sessionFlag := fs.String("session", "", "Subagent session ID")
	scopesFlag := fs.String("scopes", "", "Comma-separated attenuated scopes requested for child")
	actionFlag := fs.String("action", "", "Attenuated action (e.g. exec, read)")
	resourceFlag := fs.String("resource", "", "Attenuated resource pattern")
	ttlFlag := fs.Int("ttl", 15, "Grant validity in minutes")
	serverFlag := fs.String("server", "", "BAP Control Plane URL")
	jsonFlag := fs.Bool("json", false, "Output structured JSON response")

	if err := fs.Parse(args); err != nil {
		return err
	}

	parentToken := *parentTokenFlag
	if parentToken == "" {
		parentToken = os.Getenv("BAP_GRANT_TOKEN")
		if parentToken == "" {
			parentToken = os.Getenv("BAP_TOKEN")
		}
	}

	serverURL := *serverFlag
	if serverURL == "" {
		serverURL = config.ResolveEndpoints().ControlPlaneURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	sessionID := *sessionFlag
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-sub-%x-%d", time.Now().UnixNano()%0xFFFF, os.Getpid())
	}

	var scopes []string
	if *scopesFlag != "" {
		for _, s := range strings.Split(*scopesFlag, ",") {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				scopes = append(scopes, trimmed)
			}
		}
	}

	reqBody := map[string]any{
		"parent_token":     parentToken,
		"child_agent_id":   *childAgentFlag,
		"child_app_id":     *childAppFlag,
		"session_id":       sessionID,
		"requested_scopes": scopes,
		"action":           *actionFlag,
		"resource":         *resourceFlag,
		"ttl_mins":         *ttlFlag,
	}

	resp, err := callDelegateAPI(serverURL, reqBody)
	if err != nil {
		if strings.Contains(err.Error(), "PrivilegeEscalationBlocked") {
			fmt.Fprintf(os.Stderr, "[BLOCKED] 403 Forbidden: %v\n", err)
			return err
		}
		return fmt.Errorf("delegation request failed: %w", err)
	}

	if *jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
		return nil
	}

	fmt.Printf("[BAP DELEGATION] Attenuated Grant Minted Successfully\n")
	fmt.Printf("  Grant ID     : %s\n", resp.GrantID)
	fmt.Printf("  Parent Grant : %s\n", resp.ParentGrantID)
	fmt.Printf("  Root Agent   : %s\n", resp.RootAgentID)
	fmt.Printf("  Lineage Tree : %s\n", resp.LineageTree)
	fmt.Printf("  Scopes       : %v\n", resp.Scopes)
	fmt.Printf("  Expires At   : %s (TTL: %ds)\n", resp.ExpiresAt.Format(time.RFC3339), resp.TTLSecs)
	fmt.Printf("  Token        : %s\n", resp.Token)
	return nil
}

func runDelegateRun(args []string) error {
	// Parse flags up to "--" delimiter
	var flagArgs []string
	var cmdArgs []string
	dashDashFound := false
	for i, a := range args {
		if a == "--" {
			flagArgs = args[:i]
			cmdArgs = args[i+1:]
			dashDashFound = true
			break
		}
	}
	if !dashDashFound {
		flagArgs = args
	}

	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	parentTokenFlag := fs.String("parent-token", "", "Parent BAP grant token")
	childAgentFlag := fs.String("child-agent", "subagent", "Child subagent ID or name")
	childAppFlag := fs.String("child-app", "subagent", "Child subagent application ID")
	sessionFlag := fs.String("session", "", "Subagent session ID")
	scopesFlag := fs.String("scopes", "", "Comma-separated attenuated scopes")
	actionFlag := fs.String("action", "", "Attenuated action")
	resourceFlag := fs.String("resource", "", "Attenuated resource pattern")
	ttlFlag := fs.Int("ttl", 15, "Grant validity in minutes")
	serverFlag := fs.String("server", "", "BAP Control Plane URL")

	if err := fs.Parse(flagArgs); err != nil {
		return err
	}

	if len(cmdArgs) == 0 && len(fs.Args()) > 0 {
		cmdArgs = fs.Args()
	}
	if len(cmdArgs) == 0 {
		return fmt.Errorf("no command provided to delegate run. Usage: bapedge delegate run [options] -- <command...>")
	}

	parentToken := *parentTokenFlag
	if parentToken == "" {
		parentToken = os.Getenv("BAP_GRANT_TOKEN")
		if parentToken == "" {
			parentToken = os.Getenv("BAP_TOKEN")
		}
	}

	serverURL := *serverFlag
	if serverURL == "" {
		serverURL = config.ResolveEndpoints().ControlPlaneURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	sessionID := *sessionFlag
	if sessionID == "" {
		sessionID = fmt.Sprintf("sess-sub-%x-%d", time.Now().UnixNano()%0xFFFF, os.Getpid())
	}

	var scopes []string
	if *scopesFlag != "" {
		for _, s := range strings.Split(*scopesFlag, ",") {
			trimmed := strings.TrimSpace(s)
			if trimmed != "" {
				scopes = append(scopes, trimmed)
			}
		}
	}

	// 1. Request attenuated child grant from control plane
	reqBody := map[string]any{
		"parent_token":     parentToken,
		"child_agent_id":   *childAgentFlag,
		"child_app_id":     *childAppFlag,
		"session_id":       sessionID,
		"requested_scopes": scopes,
		"action":           *actionFlag,
		"resource":         *resourceFlag,
		"ttl_mins":         *ttlFlag,
	}

	delResp, err := callDelegateAPI(serverURL, reqBody)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[DELEGATION ERROR] %v\n", err)
		return err
	}

	// 2. Prepare child subprocess environment with delegation lineage
	subCmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
	subCmd.Stdin = os.Stdin
	subCmd.Stdout = os.Stdout
	subCmd.Stderr = os.Stderr

	env := os.Environ()
	env = append(env,
		"BAP_GRANT_TOKEN="+delResp.Token,
		"BAP_SESSION_ID="+delResp.SessionID,
		"BAP_GRANT_ID="+delResp.GrantID,
		"BAP_PARENT_GRANT_ID="+delResp.ParentGrantID,
		"BAP_ROOT_AGENT_ID="+delResp.RootAgentID,
		"BAP_DELEGATION_LINEAGE="+strings.Join(delResp.Lineage, ","),
		"BAP_LINEAGE_TREE="+delResp.LineageTree,
		fmt.Sprintf("BAP_DELEGATION_DEPTH=%d", delResp.Depth),
	)
	subCmd.Env = env

	fmt.Fprintf(os.Stderr, "[BAP] Spawning child subagent process (Lineage: %s)\n", delResp.LineageTree)
	if err := subCmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		return err
	}
	return nil
}

func runDelegateStatus(args []string) error {
	lineageTree := os.Getenv("BAP_LINEAGE_TREE")
	lineageRaw := os.Getenv("BAP_DELEGATION_LINEAGE")
	rootAgent := os.Getenv("BAP_ROOT_AGENT_ID")
	parentGrant := os.Getenv("BAP_PARENT_GRANT_ID")
	grantID := os.Getenv("BAP_GRANT_ID")

	if lineageTree == "" && lineageRaw == "" {
		fmt.Println("[BAP DELEGATION] Current process is running as root authority (no delegation lineage active).")
		return nil
	}

	fmt.Println("[BAP DELEGATION STATUS]")
	fmt.Printf("  Lineage Tree : %s\n", lineageTree)
	fmt.Printf("  Root Agent   : %s\n", rootAgent)
	fmt.Printf("  Parent Grant : %s\n", parentGrant)
	fmt.Printf("  Current Grant: %s\n", grantID)
	fmt.Printf("  Lineage Path : %s\n", lineageRaw)
	return nil
}

func callDelegateAPI(serverURL string, payload map[string]any) (*DelegateResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to encode request: %w", err)
	}

	client := httptransport.New(5 * time.Second)
	req, err := http.NewRequest(http.MethodPost, serverURL+"/api/v1/grants/delegate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection to control plane failed (%s): %w", serverURL, err)
	}
	defer resp.Body.Close()

	respBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		var errData struct {
			Error   string `json:"error"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(respBytes, &errData)
		if errData.Error == "PrivilegeEscalationBlocked" {
			return nil, fmt.Errorf("PrivilegeEscalationBlocked: %s", errData.Message)
		}
		if errData.Message != "" {
			return nil, fmt.Errorf("server error (HTTP %d): %s", resp.StatusCode, errData.Message)
		}
		return nil, fmt.Errorf("server returned error (HTTP %d): %s", resp.StatusCode, string(respBytes))
	}

	var delResp DelegateResponse
	if err := json.Unmarshal(respBytes, &delResp); err != nil {
		return nil, fmt.Errorf("failed to parse response JSON: %w", err)
	}
	return &delResp, nil
}

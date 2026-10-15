package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"bap-edge/internal/config"
	"bap-edge/internal/mcp"
)

const mcpUsage = `bapmcp - BAP Model Context Protocol (MCP) Execution & Policy Broker
(Integrated into Claude Code, GitHub Copilot, Cursor, Antigravity)

Usage:
  bapmcp [command] [flags]
  (Alias: bapedge mcp [command] [flags])

Available Commands:
  serve, --stdio  Run MCP stdio JSON-RPC server (default when launched by an MCP client)
  status          Inspect MCP server configuration, policy rules, and audit status
  help            Display MCP configuration and onboarding instructions

Exposed Zero-Trust MCP Tools:
  • bap_execute         Evaluate and execute command within sandboxed kernel isolation
  • bap_explain_policy  Simulate and explain Cedar policy decisions without executing
  • bap_status          Inspect local daemon health, active sessions, and policy cache

Integration Configurations:
  Claude Code (~/.claude/settings.json or claude mcp add):
    claude mcp add bap-zero-trust -- bapedge mcp
    (or: claude mcp add bap-zero-trust -- bapmcp)

  Antigravity / Gemini CLI:
    ~/.gemini/antigravity/mcp/bap-zero-trust/

  Cursor IDE (~/.cursor/mcp.json):
    {
      "mcpServers": {
        "bap-zero-trust": {
          "command": "bapmcp",
          "args": ["--stdio"]
        }
      }
    }

Examples:
  bapmcp --stdio
  bapmcp status
  bapedge mcp --stdio
`

// RunMCP handles the 'mcp' subcommand to run BAP as a Model Context Protocol stdio server.
func RunMCP(args []string) error {
	if len(args) > 0 {
		cmdName := strings.ToLower(args[0])
		if cmdName == "help" || cmdName == "--help" || cmdName == "-h" {
			fmt.Print(mcpUsage)
			return nil
		}
		if cmdName == "status" {
			return runMCPStatus(args[1:])
		}
		if cmdName == "serve" {
			args = args[1:]
		}
	} else if isTerminal(os.Stdin) {
		// When run interactively in a console without piped input or arguments, display help
		fmt.Print(mcpUsage)
		return nil
	}

	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "Path to policy.cedar file (defaults to ./policy.cedar)")
	auditLogFlag := fs.String("audit-log", "", "Path to audit log file in JSON lines (defaults to .bapstate/audit.jsonl or LTD_AUDIT_LOG)")
	_ = fs.Bool("stdio", false, "Run in stdio JSON-RPC mode")

	defaultSession := os.Getenv("BAP_SESSION_ID")
	if defaultSession == "" {
		defaultSession = os.Getenv("LTD_SESSION_ID")
	}
	sessionFlag := fs.String("session-id", defaultSession, "Session identifier for grouping agent actions")

	epCfg := config.ResolveEndpoints()
	serverFlag := fs.String("server", epCfg.ControlPlaneURL, "Central control plane URL for telemetry streaming")
	modeFlag := fs.String("mode", epCfg.EnforcementMode, "Enforcement mode: 'enforce' (default) or 'audit'/'shadow'")

	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg := mcp.ServerConfig{
		PolicyPath:       *policyPath,
		ServerURL:        *serverFlag,
		SessionID:        *sessionFlag,
		AuditLogPath:     *auditLogFlag,
		EnforcementMode:  strings.ToLower(strings.TrimSpace(*modeFlag)),
		IdentityResolver: resolveLocalIdentity,
	}

	return mcp.StartServer(cfg)
}

func runMCPStatus(args []string) error {
	epCfg := config.ResolveEndpoints()
	fmt.Println("================================================================================")
	fmt.Println("  [BAP MCP SERVER] 🛡️  Model Context Protocol Bridge Status")
	fmt.Println("================================================================================")
	fmt.Printf("  Transport:        Standard I/O (JSON-RPC 2.0)\n")
	fmt.Printf("  Enforcement Mode: %s\n", strings.ToUpper(epCfg.EnforcementMode))
	fmt.Printf("  Control Plane:    %s\n", epCfg.ControlPlaneURL)
	fmt.Printf("  Gateway PEP:      %s\n", epCfg.GatewayURL)

	policyCandidates := []string{"policy.cedar", "bap-edge/policy.cedar"}
	foundPolicy := "Using embedded fallback"
	for _, p := range policyCandidates {
		if _, err := os.Stat(p); err == nil {
			foundPolicy = p
			break
		}
	}
	fmt.Printf("  Cedar Policy:     %s\n", foundPolicy)
	fmt.Println("\n  EXPOSED ZERO-TRUST TOOLS:")
	fmt.Println("    • bap_execute:         Sandboxed command execution governed by Cedar")
	fmt.Println("    • bap_explain_policy:  Zero-trust decision explanation & invariant query")
	fmt.Println("    • bap_status:          Local agent lifecycle and policy telemetry")
	fmt.Println("================================================================================")
	return nil
}

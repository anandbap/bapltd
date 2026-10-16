package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"bap-edge/cmd"
)

const usage = `bapedge - BAP Local Trusted Daemon (LTD) & Zero-Trust Execution Broker
(Alias: ltd-agent)

Usage:
  bapedge <command> [arguments]

Service & Daemon Lifecycle:
  start        Start background supervisor daemon (or 'bapedge start -foreground')
  stop         Gracefully terminate background daemon
  status       Inspect local active sessions, daemon state, policy cache, and spool backlog
  restart      Restart background supervisor daemon
  enable       Enable zero-trust governance and configure developer workstation (1-click setup)
  daemon       Manage supervisor daemon subsystem (start, stop, status)

Zero-Trust Governance & HITL Authorization:
  trust        Authorize cross-folder write/delete operations for a path (session/project/global)
  untrust      Revoke cross-folder mutation authorization for a path
  permissions  List all active cross-folder authorizations across session, project, and global scopes
  why          Explain Cedar policy decision for a command directly in the terminal
  rollback     Forensically revert file mutations to pre-execution cryptographic checkpoints (BAP-538)
  pin          Cryptographically pin, verify, and re-attest skills, prompts, and MCP tools (BAP-531)
  scan         Audit workspace skills, prompt templates, and configs for prompt injection & drift (BAP-536)
  adapter      Unified multi-harness adapter for Cursor, Gemini CLI, Browser, and SaaS agents (BAP-539)

Execution & Protocol Integration:
  exec         Evaluate command against Cedar policy and run in sandboxed kernel namespace
  check        Evaluate command against Cedar policy in decision-only mode (zero execution side effects)
  mcp          Run as Model Context Protocol (MCP) server for Claude Code, Copilot, Cursor, Antigravity
  serve        Start the zero-trust attestation server on domain socket / named pipe
  sweep        Clean sweep orphaned sessions, purge dead process locks, and flush offline audit

Identity & Central Control Plane:
  setup        1-click workstation onboarding for Claude Code & AI agents (BAP-471)
  login        Authenticate developer identity via enterprise OIDC/OAuth2 device flow (Okta/Entra)
  register     Enroll edge LTD with central BAP Control Plane using one-time code (OTC)
  sync         Synchronize or inspect local policy cache from control plane (with offline fallback)
  config       View or update central control plane and gateway host URLs
  attest       Client test command: connect to attestation server and request OBO JWT
  verify-log   Verify cryptographic integrity and anti-tamper hash-chain of local audit log
  version      Display semantic version, git commit, build date, and platform metadata (-v, --version, --json)
  help         Display help information

Examples:
  bapedge start
  bapedge status
  bapedge stop
  bapedge exec "echo hello world"
  bapedge why "rm -rf /"
  bapedge trust --path C:\Users\User\pyprj\other --scope session --ops write,delete
  bapedge permissions
  bapedge untrust --path C:\Users\User\pyprj\other
  bapedge rollback --checkpoint-id chk-xxx
  bapedge pin verify
  bapedge mcp --stdio
  bapedge setup --app claude-code
`

func main() {
	if len(os.Args) < 2 {
		// If invoked as bapmcp.exe or containing "mcp", default to running the MCP server
		if strings.Contains(strings.ToLower(os.Args[0]), "mcp") {
			if err := cmd.RunMCP(nil); err != nil {
				fmt.Fprintf(os.Stderr, "Error running MCP server: %v\n", err)
				os.Exit(1)
			}
			return
		}
		if strings.Contains(strings.ToLower(os.Args[0]), "daemon") {
			if err := cmd.RunDaemon([]string{"status"}); err != nil {
				fmt.Fprintf(os.Stderr, "Error running daemon: %v\n", err)
				os.Exit(1)
			}
			return
		}
		fmt.Print(usage)
		os.Exit(0)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
	case "start":
		if err := cmd.RunDaemon(append([]string{"start"}, args...)); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting daemon: %v\n", err)
			os.Exit(1)
		}
	case "stop":
		if err := cmd.RunDaemon(append([]string{"stop"}, args...)); err != nil {
			fmt.Fprintf(os.Stderr, "Error stopping daemon: %v\n", err)
			os.Exit(1)
		}
	case "restart":
		_ = cmd.RunDaemon([]string{"stop"})
		time.Sleep(300 * time.Millisecond)
		if err := cmd.RunDaemon(append([]string{"start"}, args...)); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting daemon: %v\n", err)
			os.Exit(1)
		}
	case "enable":
		if err := cmd.RunSetup(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error enabling workstation governance: %v\n", err)
			os.Exit(1)
		}
	case "setup":
		if err := cmd.RunSetup(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error in setup: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if err := cmd.RunStatus(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error inspecting status: %v\n", err)
			os.Exit(1)
		}
	case "why", "explain":
		if err := cmd.RunWhy(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error explaining policy: %v\n", err)
			os.Exit(1)
		}
	case "sweep", "clean-sweep":
		if err := cmd.RunSweep(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error running clean sweep: %v\n", err)
			os.Exit(1)
		}
	case "login":
		if err := cmd.RunLogin(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error authenticating: %v\n", err)
			os.Exit(1)
		}
	case "register":
		if err := cmd.RunRegister(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error registering agent: %v\n", err)
			os.Exit(1)
		}
	case "sync":
		if err := cmd.RunSync(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error synchronizing policy: %v\n", err)
			os.Exit(1)
		}
	case "serve":
		if err := cmd.RunServe(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error running server: %v\n", err)
			os.Exit(1)
		}
	case "exec":
		cmd.RunExec(args)
	case "check", "authorize":
		cmd.RunCheck(args)
	case "mcp":
		if err := cmd.RunMCP(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error running MCP server: %v\n", err)
			os.Exit(1)
		}
	case "daemon":
		if err := cmd.RunDaemon(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error running daemon: %v\n", err)
			os.Exit(1)
		}
	case "pin":
		if err := cmd.RunPin(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error in pin: %v\n", err)
			os.Exit(1)
		}
	case "scan":
		if err := cmd.RunScan(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error in scan: %v\n", err)
			os.Exit(1)
		}
	case "adapter":
		if err := cmd.RunAdapter(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error in adapter: %v\n", err)
			os.Exit(1)
		}
	case "delegate", "subagent":
		if err := cmd.RunDelegate(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error in delegation: %v\n", err)
			os.Exit(1)
		}
	case "rollback":
		if err := cmd.RunRollback(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error in rollback: %v\n", err)
			os.Exit(1)
		}
	case "trust":
		if err := cmd.RunTrust(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error granting trust: %v\n", err)
			os.Exit(1)
		}
	case "untrust":
		if err := cmd.RunUntrust(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error revoking trust: %v\n", err)
			os.Exit(1)
		}
	case "permissions":
		if err := cmd.RunPermissions(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error listing permissions: %v\n", err)
			os.Exit(1)
		}
	case "attest":
		if err := cmd.RunAttest(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error running attestation client: %v\n", err)
			os.Exit(1)
		}
	case "config":
		if err := cmd.RunConfig(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error managing configuration: %v\n", err)
			os.Exit(1)
		}
	case "watch":
		if err := cmd.RunWatch(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error running watcher: %v\n", err)
			os.Exit(1)
		}
	case "session-start":
		if err := cmd.RunSessionStart(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error starting session: %v\n", err)
			os.Exit(1)
		}
	case "session-end":
		if err := cmd.RunSessionEnd(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error ending session: %v\n", err)
			os.Exit(1)
		}
	case "verify-log":
		if err := cmd.RunVerifyLog(args); err != nil {
			os.Exit(1)
		}
	case "version", "-v", "--version":
		if err := cmd.RunVersion(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error displaying version: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n%s", command, usage)
		os.Exit(1)
	}
}

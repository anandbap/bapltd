package main

import (
	"fmt"
	"os"
	"strings"

	"bap-edge/cmd"
)

const usage = `bapedge - BAP Local Trusted Daemon (LTD) & Zero-Trust Execution Broker
(Alias: ltd-agent)

Usage:
  bapedge <command> [arguments]

Available Commands:
  config    View or update central control plane and gateway host URLs
  login     Authenticate developer identity via enterprise OIDC/OAuth2 device flow (Okta/Entra)
  register  Enroll edge LTD with central BAP Control Plane using one-time code (OTC)
  setup     1-click workstation onboarding for Claude Code & AI agents (BAP-471)
  status    Inspect local active sessions, Cedar policy cache, layers, and spool backlog (BAP-472)
  why       Explain Cedar policy decision for a command directly in the terminal (BAP-472)
  sweep     Clean sweep orphaned sessions, purge dead process locks, and flush offline audit (BAP-470)
  sync      Synchronize or inspect local policy cache from control plane (with offline fallback)
  serve     Start the zero-trust attestation server on Unix domain socket
  exec      Evaluate command against Cedar policy and run in sandboxed kernel namespace
  check     Evaluate command against Cedar policy in decision-only mode (zero execution side effects)
  mcp       Run as Model Context Protocol (MCP) stdio server for Claude, Copilot, and Cursor
  daemon    Start, stop, or query background supervisor daemon (bap-daemon)
  pin       Cryptographically pin, verify, and re-attest skills, prompt instructions, and MCP tools (BAP-531)
  delegate  Mint attenuated child grants and execute subagents with delegation lineage (BAP-532)
  attest      Client test command: connect to attestation server and request OBO JWT
  verify-log  Verify cryptographic integrity and anti-tamper hash-chain of local audit log
  help        Display help information

Examples:
  bapedge setup --app claude-code
  bapedge status
  bapedge daemon start
  bapedge daemon status
  bapedge daemon stop
  bapedge why "rm -rf /"
  bapedge why "git status"
  bapedge sweep
  bapedge register --server http://localhost:8080 --code LTD-OTC-XXXX-XXXX
  bapedge sync --server http://localhost:8080
  bapedge exec "echo hello world"
  bapedge exec "rm -rf /"

  bapedge serve --socket /tmp/ltd.sock
  bapedge attest --socket /tmp/ltd.sock
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
		os.Exit(1)
	}

	command := os.Args[1]
	args := os.Args[2:]

	switch command {
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
	case "delegate", "subagent":
		if err := cmd.RunDelegate(args); err != nil {
			fmt.Fprintf(os.Stderr, "Error in delegation: %v\n", err)
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
	case "help", "-h", "--help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command %q\n\n%s", command, usage)
		os.Exit(1)
	}
}

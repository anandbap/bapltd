package cmd

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"bap-edge/internal/config"
	"bap-edge/internal/coverage"
)

type governedAgentSpec struct {
	Client                                    string
	Executables, WindowsScripts, POSIXScripts []string
}

func governedAgent(client string) (governedAgentSpec, bool) {
	switch normalizeClientAppID(client) {
	case "codex":
		return governedAgentSpec{"codex", []string{"codex", "codex.exe", "codex.cmd"}, []string{"run_codex_cli_bap.ps1", "run_codex_cli_bap.bat"}, []string{"run_codex_cli_bap.sh"}}, true
	case "antigravity":
		return governedAgentSpec{"antigravity", []string{"agy", "antigravity", "agy.exe", "agy.cmd"}, []string{"run_antigravity_cli_bap.ps1", "run_antigravity_cli_bap.bat"}, []string{"run_antigravity_cli_bap.sh"}}, true
	case "copilot":
		return governedAgentSpec{"copilot", []string{"copilot", "copilot.exe", "copilot.cmd"}, []string{"run_copilot_cli_bap.ps1", "run_copilot_cli_bap.bat"}, []string{"run_copilot_cli_bap.sh"}}, true
	case "opencode":
		return governedAgentSpec{"opencode", []string{"opencode", "opencode.exe", "opencode.cmd"}, []string{"run_opencode_cli_bap.ps1", "run_opencode_cli_bap.bat"}, []string{"run_opencode_cli_bap.sh"}}, true
	}
	return governedAgentSpec{}, false
}

// All supported non-Claude entry points share session identity, offline
// startup behavior and teardown. Native adapters remain client-specific.
func runGovernedAgent(client string, args []string) error {
	spec, ok := governedAgent(client)
	if !ok {
		return fmt.Errorf("unsupported coding client %q", client)
	}
	if handled, err := reexecUnderWinpty(spec.Client, args); handled {
		return err
	}
	downstream, disabled, _, server, err := parseLauncherArgs(args)
	if err != nil {
		return err
	}
	if !disabled {
		repairClaudeLaunchEnvironment()
	}
	if server == "" {
		server = config.ResolveEndpoints().ControlPlaneURL
	}
	if server == "" {
		server = config.DefaultControlPlaneURL
	}
	scripts := spec.POSIXScripts
	if runtime.GOOS == "windows" {
		scripts = spec.WindowsScripts
	}
	var child *exec.Cmd
	if script := resolveLauncherScript(scripts); script != "" {
		child = buildLauncherCommand(script, server, downstream)
	} else {
		binary := findExecutable(spec.Executables)
		if binary == "" {
			return fmt.Errorf("%s executable not found", spec.Client)
		}
		child = exec.Command(binary, downstream...)
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	session := "sess-" + spec.Client + "-" + hex.EncodeToString(nonce)
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = append(os.Environ(), "LTD_SOURCE="+spec.Client, "BAP_SESSION_ID="+session, "BAP_SERVER_URL="+server, "BAP_CONTROL_PLANE_URL="+server, "BAP_BOUNDARY_GUIDANCE="+coverage.Guidance)
	if disabled {
		child.Env = append(child.Env, "BAP_HOOKS=false", "BAP_DISABLE_HOOKS=1")
	}
	fmt.Fprintln(os.Stderr, coverage.Guidance)
	PrintClientDefenseLayers(os.Stderr, ".", spec.Client)
	if err := EnsureSessionStarted(session, spec.Client, os.Getpid(), ""); err != nil {
		return err
	}
	defer func() { _ = EnsureSessionEnded(session, "coding client process exited") }()
	return child.Run()
}

func RunCodex(args []string) error       { return runGovernedAgent("codex", args) }
func RunAntigravity(args []string) error { return runGovernedAgent("antigravity", args) }
func RunCopilot(args []string) error     { return runGovernedAgent("copilot", args) }
func RunOpenCode(args []string) error    { return runGovernedAgent("opencode", args) }

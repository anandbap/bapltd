package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"bap-edge/internal/authz"
	"bap-edge/pkg/version"
)

// parseLauncherArgs extracts BAP launcher flags and returns the filtered downstream args for the agent CLI.
func parseLauncherArgs(args []string) (downstreamArgs []string, hooksDisabled bool, forceFix bool, serverURL string, err error) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--no-hooks" || a == "--disable-hooks" || a == "--hooks-disabled" || a == "--unmonitored" || a == "--bap-hooks=false" || a == "--prompt-only":
			if !version.DevOverridesAllowed() {
				return nil, false, false, "", fmt.Errorf("[BAP ZERO-TRUST SECURITY VIOLATION] Dev-override and hook bypass flags ('%s') are strictly disabled in Enterprise Production builds.", a)
			}
			hooksDisabled = true
		case a == "--fix" || a == "-Fix" || a == "--remediate":
			forceFix = true
		case strings.HasPrefix(a, "--server="):
			serverURL = strings.TrimPrefix(a, "--server=")
		case strings.HasPrefix(a, "--server-url="):
			serverURL = strings.TrimPrefix(a, "--server-url=")
		case a == "--server" || a == "--server-url":
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return nil, false, false, "", fmt.Errorf("missing value for %s", a)
			}
			i++
			serverURL = args[i]
		default:
			downstreamArgs = append(downstreamArgs, a)
		}
	}
	return downstreamArgs, hooksDisabled, forceFix, serverURL, nil
}

// resolveLauncherScript finds a launcher script matching one of the given names
// across current directory, repo root, and standard BAP user directories.
func resolveLauncherScript(scriptNames []string) string {
	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)

	candidateDirs := []string{
		exeDir,
		filepath.Join(exeDir, "launchers"),
		filepath.Join(home, "bin"),
		filepath.Join(home, "bin", "launchers"),
		filepath.Join(home, ".bap", "launchers"),
		filepath.Join(home, ".bap"),
		cwd,
		filepath.Join(cwd, "bap"),
		filepath.Join(cwd, "bap", "launchers"),
		filepath.Join(cwd, "scripts"),
	}

	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		candidateDirs = append(candidateDirs, filepath.Join(localAppData, "BAP", "launchers"))
		candidateDirs = append(candidateDirs, filepath.Join(localAppData, "BAP"))
	}
	if appData := os.Getenv("APPDATA"); appData != "" {
		candidateDirs = append(candidateDirs, filepath.Join(appData, "BAP", "launchers"))
		candidateDirs = append(candidateDirs, filepath.Join(appData, "BAP"))
	}

	// Check workspace root if known
	if ws := authz.GetWorkspaceRoot(); ws != "" {
		candidateDirs = append(candidateDirs, ws, filepath.Join(ws, "scripts"), filepath.Join(ws, "bap"))
	}

	// Walk up to find git root from cwd
	for dir := cwd; dir != "" && dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			candidateDirs = append(candidateDirs, dir, filepath.Join(dir, "scripts"), filepath.Join(dir, "bap"))
			break
		}
	}

	for _, dir := range candidateDirs {
		for _, name := range scriptNames {
			p := filepath.Join(dir, name)
			if info, err := os.Stat(p); err == nil && !info.IsDir() {
				return p
			}
		}
	}
	return ""
}

// firstInPath returns the first of names found on PATH, or "" if none is.
func firstInPath(names ...string) string {
	for _, n := range names {
		if p, err := exec.LookPath(n); err == nil {
			return p
		}
	}
	return ""
}

// buildLauncherCommand builds the OS-appropriate command for a BAP launcher script.
//
// PowerShell and cmd launchers (Windows only) understand the --server flag. POSIX
// shell launchers receive the control-plane URL through the environment instead:
// anything placed in argv is forwarded to the agent CLI (claude / codex / agy),
// which rejects an unknown "--server=..." option and exits with an error.
func buildLauncherCommand(script, serverURL string, downstreamArgs []string) *exec.Cmd {
	lower := strings.ToLower(script)
	serverArg := "--server=" + serverURL

	switch {
	case strings.HasSuffix(lower, ".ps1"):
		// powershell.exe is Windows PowerShell; pwsh covers PowerShell 7-only hosts.
		ps := firstInPath("powershell.exe", "pwsh.exe", "pwsh")
		if ps == "" {
			ps = "powershell.exe"
		}
		args := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script, serverArg}, downstreamArgs...)
		return exec.Command(ps, args...)
	case strings.HasSuffix(lower, ".bat"), strings.HasSuffix(lower, ".cmd"):
		return exec.Command("cmd.exe", append([]string{"/c", script, serverArg}, downstreamArgs...)...)
	default:
		sh := firstInPath("bash", "bash.exe", "sh")
		if sh == "" {
			sh = "bash"
		}
		return exec.Command(sh, append([]string{script}, downstreamArgs...)...)
	}
}

// findExecutable searches for a command across candidate names and paths.
func findExecutable(names []string) string {
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	home, _ := os.UserHomeDir()
	var extraPaths []string
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		localAppData := os.Getenv("LOCALAPPDATA")
		extraPaths = []string{
			filepath.Join(appData, "npm"),
			filepath.Join(localAppData, "Programs"),
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".claude", "local"),
			filepath.Join(home, ".cargo", "bin"),
		}
	} else {
		// A GUI-launched or non-login shell on macOS often lacks Homebrew / npm-global /
		// native-installer directories on PATH, so probe them explicitly.
		extraPaths = []string{
			"/opt/homebrew/bin",
			"/usr/local/bin",
			"/usr/bin",
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".claude", "local"),
			filepath.Join(home, ".npm-global", "bin"),
			filepath.Join(home, ".bun", "bin"),
			filepath.Join(home, ".volta", "bin"),
			filepath.Join(home, ".cargo", "bin"),
		}
		// nvm-managed Node installs global CLIs under a per-version bin directory.
		if nvmBins, err := filepath.Glob(filepath.Join(home, ".nvm", "versions", "node", "*", "bin")); err == nil {
			extraPaths = append(extraPaths, nvmBins...)
		}
	}

	for _, p := range extraPaths {
		for _, name := range names {
			candidate := filepath.Join(p, name)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate
			}
		}
	}
	return ""
}

// reexecUnderWinpty re-runs "bapedge <subcmd> <args>" under winpty when started from Git Bash's
// default terminal (mintty). Mintty hands native Windows programs a pipe instead of a console, so
// Node-based agent CLIs (claude / codex / agy) think they are non-interactive and drop into
// --print mode ("Input must be provided either through stdin or as a prompt argument").
// winpty ships with Git for Windows and supplies a real console. It is a no-op everywhere else
// (PowerShell, cmd, Windows Terminal, macOS, Linux) and can be disabled with BAP_NO_WINPTY=1.
func reexecUnderWinpty(subcmd string, args []string) (handled bool, err error) {
	if runtime.GOOS != "windows" || os.Getenv("BAP_NO_WINPTY") != "" || os.Getenv("BAP_UNDER_WINPTY") != "" {
		return false, nil
	}
	if os.Getenv("MSYSTEM") == "" || !strings.EqualFold(os.Getenv("TERM_PROGRAM"), "mintty") {
		return false, nil
	}
	if fi, statErr := os.Stdin.Stat(); statErr == nil && fi.Mode()&os.ModeCharDevice != 0 {
		return false, nil // already a real console
	}
	winpty, lookErr := exec.LookPath("winpty")
	if lookErr != nil {
		return false, nil
	}
	exe, exeErr := os.Executable()
	if exeErr != nil {
		return false, nil
	}
	cmd := exec.Command(winpty, append([]string{exe, subcmd}, args...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(), "BAP_UNDER_WINPTY=1")
	return true, cmd.Run()
}

// RunReview launches the interactive session reviewer and performance inspector.
func RunReview(args []string) error {
	var script string
	if runtime.GOOS == "windows" {
		script = resolveLauncherScript([]string{"review_session.ps1", "scripts/review_session.ps1"})
		if script != "" {
			cmd := exec.Command("powershell.exe", append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script}, args...)...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}
	} else {
		script = resolveLauncherScript([]string{"review_session.sh", "scripts/review_session.sh"})
		if script != "" {
			cmd := exec.Command("bash", append([]string{script}, args...)...)
			cmd.Stdin = os.Stdin
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			return cmd.Run()
		}
	}
	return fmt.Errorf("review_session script not found.\nTo install session review and debugging scripts, run: bap install --debug")
}

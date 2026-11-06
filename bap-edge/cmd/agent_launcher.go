package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// resolveLauncherScript finds a launcher script matching one of the given names
// across current directory, repo root, and standard BAP user directories.
func resolveLauncherScript(scriptNames []string) string {
	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)

	candidateDirs := []string{
		cwd,
		filepath.Join(cwd, "bap"),
		filepath.Join(cwd, "bap", "launchers"),
		filepath.Join(cwd, "scripts"),
		exeDir,
		filepath.Join(exeDir, "launchers"),
		filepath.Join(home, ".bap", "launchers"),
		filepath.Join(home, ".bap"),
	}

	if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
		candidateDirs = append(candidateDirs, filepath.Join(localAppData, "BAP", "launchers"))
		candidateDirs = append(candidateDirs, filepath.Join(localAppData, "BAP"))
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
			filepath.Join(home, ".cargo", "bin"),
		}
	} else {
		extraPaths = []string{
			"/usr/local/bin",
			filepath.Join(home, ".local", "bin"),
			filepath.Join(home, ".cargo", "bin"),
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

// RunClaude launches Claude Code in active BAP Zero-Trust Governance.
func RunClaude(args []string) error {
	// First check for dedicated BAP launcher scripts
	var script string
	if runtime.GOOS == "windows" {
		script = resolveLauncherScript([]string{"run_claude_bap.ps1", "run_claude_bap.bat", "run_claude_cli_bap.ps1"})
	} else {
		script = resolveLauncherScript([]string{"run_claude_bap.sh", "run_claude_cli_bap.sh"})
	}

	if script != "" {
		var cmd *exec.Cmd
		if strings.HasSuffix(strings.ToLower(script), ".ps1") {
			psArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script}, args...)
			cmd = exec.Command("powershell.exe", psArgs...)
		} else if strings.HasSuffix(strings.ToLower(script), ".bat") || strings.HasSuffix(strings.ToLower(script), ".cmd") {
			cmd = exec.Command("cmd.exe", append([]string{"/c", script}, args...)...)
		} else {
			cmd = exec.Command("bash", append([]string{script}, args...)...)
		}
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		return cmd.Run()
	}

	// Fallback: look for claude binary on PATH
	claudeNames := []string{"claude"}
	if runtime.GOOS == "windows" {
		claudeNames = []string{"claude.cmd", "claude.bat", "claude.exe", "claude"}
	}
	claudeBin := findExecutable(claudeNames)
	if claudeBin == "" {
		return fmt.Errorf("Claude Code CLI ('claude') not found on PATH or standard directories.\nPlease install with 'npm install -g @anthropic-ai/claude-code' or run 'bap setup --app=claude-code'.")
	}

	// Check if native plugin directory exists
	cwd, _ := os.Getwd()
	pluginDir := filepath.Join(cwd, "plugins", "claude")
	claudeArgs := args
	hasPluginFlag := false
	for _, a := range args {
		if strings.HasPrefix(a, "--plugin-dir") {
			hasPluginFlag = true
			break
		}
	}
	if !hasPluginFlag {
		if info, err := os.Stat(pluginDir); err == nil && info.IsDir() {
			claudeArgs = append([]string{"--plugin-dir", pluginDir}, args...)
		}
	}

	sessionID := fmt.Sprintf("sess-claude-%d-%d", os.Getpid(), time.Now().Unix())
	cmd := exec.Command(claudeBin, claudeArgs...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"LTD_SOURCE=claude-code",
		"BAP_SESSION_ID="+sessionID,
	)
	return cmd.Run()
}

// RunCodex launches OpenAI Codex CLI in active BAP Zero-Trust Governance.
func RunCodex(args []string) error {
	var script string
	if runtime.GOOS == "windows" {
		script = resolveLauncherScript([]string{"run_codex_cli_bap.ps1", "run_codex_cli_bap.bat"})
	} else {
		script = resolveLauncherScript([]string{"run_codex_cli_bap.sh"})
	}

	if script != "" {
		var cmd *exec.Cmd
		if strings.HasSuffix(strings.ToLower(script), ".ps1") {
			psArgs := append([]string{"-NoProfile", "-ExecutionPolicy", "Bypass", "-File", script}, args...)
			cmd = exec.Command("powershell.exe", psArgs...)
		} else if strings.HasSuffix(strings.ToLower(script), ".bat") || strings.HasSuffix(strings.ToLower(script), ".cmd") {
			cmd = exec.Command("cmd.exe", append([]string{"/c", script}, args...)...)
		} else {
			cmd = exec.Command("bash", append([]string{script}, args...)...)
		}
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = os.Environ()
		return cmd.Run()
	}

	// Fallback: look for codex binary on PATH
	codexNames := []string{"codex"}
	if runtime.GOOS == "windows" {
		codexNames = []string{"codex.cmd", "codex.bat", "codex.exe", "codex"}
	}
	codexBin := findExecutable(codexNames)
	if codexBin == "" {
		return fmt.Errorf("OpenAI Codex CLI ('codex') not found on PATH or standard directories.\nPlease install with 'npm install -g @openai/codex' or run 'bap setup --app=codex'.")
	}

	sessionID := fmt.Sprintf("sess-codex-%d-%d", os.Getpid(), time.Now().Unix())
	cmd := exec.Command(codexBin, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		"LTD_SOURCE=codex",
		"BAP_SESSION_ID="+sessionID,
	)
	return cmd.Run()
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
	return fmt.Errorf("review_session script not found in current directory or scripts/")
}

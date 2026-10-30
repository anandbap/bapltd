package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// InjectedOBOToken is the corporate on-behalf-of token injected into the sandboxed process.
const InjectedOBOToken = "mock_secret_token_123"

// CleanCommandString normalizes shell escaping and strips outer wrapping quotes
// so commands like 'java -Dapp="Foo Bar" -version' or "git status" parse cleanly.
func CleanCommandString(s string) string {
	s = strings.TrimSpace(s)
	// Strip shell escaping artifacts (e.g. \"cmd, \ cmd, ^cmd)
	s = strings.TrimLeft(s, "\\^ \t")
	s = strings.TrimRight(s, "\\^ \t")
	s = strings.TrimSpace(s)

	// Strip outer single quotes if user wrapped the whole command in single quotes
	if strings.HasPrefix(s, "'") && strings.HasSuffix(s, "'") && len(s) >= 2 {
		s = strings.TrimSpace(s[1 : len(s)-1])
	}

	// Strip outer double quotes if user wrapped the whole command in double quotes
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") && len(s) >= 2 {
		inner := strings.TrimSpace(s[1 : len(s)-1])
		if !strings.HasPrefix(inner, "\"") {
			parts := strings.Fields(inner)
			if len(parts) >= 1 {
				s = inner
			}
		}
	}

	return s
}

// ParseCommand parses a raw command line string into an executable name and its arguments string.
// It normalizes quoted paths, directory paths, file extensions (e.g., C:\...\pytest.exe -> pytest),
// and recognizes Python module invocations (e.g., python -m pytest -> pytest).
func ParseCommand(cmdStr string) (string, string) {
	trimmed := CleanCommandString(cmdStr)
	if trimmed == "" {
		return "", ""
	}

	var rawExec, args string
	if strings.HasPrefix(trimmed, "\"") {
		endIdx := strings.Index(trimmed[1:], "\"")
		if endIdx != -1 {
			candidate := trimmed[1 : endIdx+1]
			lowerCand := strings.ToLower(candidate)
			if strings.Contains(candidate, " ") && !strings.HasSuffix(lowerCand, ".exe") && !strings.ContainsAny(candidate, "/\\") {
				parts := strings.Fields(candidate)
				rawExec = parts[0]
				rest := strings.TrimSpace(candidate[len(parts[0]):])
				args = strings.TrimSpace(rest + " " + trimmed[endIdx+2:])
			} else {
				rawExec = candidate
				args = strings.TrimSpace(trimmed[endIdx+2:])
			}
		} else {
			rawExec = strings.Trim(trimmed, "\"")
		}
	} else if strings.HasPrefix(trimmed, "'") {
		endIdx := strings.Index(trimmed[1:], "'")
		if endIdx != -1 {
			candidate := trimmed[1 : endIdx+1]
			lowerCand := strings.ToLower(candidate)
			if strings.Contains(candidate, " ") && !strings.HasSuffix(lowerCand, ".exe") && !strings.ContainsAny(candidate, "/\\") {
				parts := strings.Fields(candidate)
				rawExec = parts[0]
				rest := strings.TrimSpace(candidate[len(parts[0]):])
				args = strings.TrimSpace(rest + " " + trimmed[endIdx+2:])
			} else {
				rawExec = candidate
				args = strings.TrimSpace(trimmed[endIdx+2:])
			}
		} else {
			rawExec = strings.Trim(trimmed, "'")
		}
	} else {
		parts := strings.Fields(trimmed)
		rawExec = parts[0]
		if len(trimmed) > len(rawExec) {
			args = strings.TrimSpace(trimmed[len(rawExec):])
		}
	}

	// Normalize directory separators and extract base executable name
	normalized := strings.ReplaceAll(rawExec, "\\", "/")
	base := path.Base(normalized)

	// Strip shell escape artifacts or quotes (e.g. \"git, \git, ^git)
	base = strings.Trim(base, "\"'\\^")

	// Strip .exe extension (case-insensitive)
	lower := strings.ToLower(base)
	if strings.HasSuffix(lower, ".exe") {
		base = base[:len(base)-4]
	}

	// Strip leading parenthesis, wrapper syntax or quotes: (Get-ChildItem -Filter ...).FullName
	if strings.HasPrefix(base, "(") {
		clean := strings.TrimLeft(base, "([{\"'$@&")
		if idx := strings.IndexAny(clean, ")."); idx != -1 {
			clean = clean[:idx]
		}
		if clean != "" {
			base = clean
		}
	}
	baseLower := strings.ToLower(base)
	if strings.HasPrefix(baseLower, "---") || strings.HasPrefix(baseLower, "===") ||
		strings.HasPrefix(baseLower, "***") || strings.HasPrefix(baseLower, "###") ||
		strings.HasPrefix(baseLower, "#") || strings.HasPrefix(baseLower, "//") {
		return "write-output", args
	}
	if baseLower == "python" || baseLower == "python3" || baseLower == "py" {
		argParts := strings.Fields(args)
		if len(argParts) >= 2 && argParts[0] == "-m" && argParts[1] == "pytest" {
			return "pytest", args
		}
	}

	// If invoked via "cmd /c <command>" or "cmd.exe /c <command>", evaluate inner command
	if baseLower == "cmd" {
		argParts := strings.Fields(args)
		if len(argParts) >= 2 && (strings.EqualFold(argParts[0], "/c") || strings.EqualFold(argParts[0], "/k")) {
			innerCmd := strings.TrimSpace(args[len(argParts[0]):])
			return ParseCommand(innerCmd)
		}
	}

	return strings.ToLower(base), args
}

// isPowerShellCommand determines if a command line string is PowerShell syntax or uses PowerShell cmdlets.
func isPowerShellCommand(trimmed, executable string) bool {
	execLower := strings.ToLower(executable)
	switch execLower {
	case "get-childitem", "gci", "select-object", "where-object", "foreach-object",
		"format-table", "ft", "format-list", "fl", "format-wide", "fw",
		"out-string", "select-string", "sls", "get-content", "gc", "test-path",
		"set-content", "sc", "add-content", "ac", "new-item", "ni", "remove-item", "ri",
		"copy-item", "cpi", "move-item", "mi", "write-host", "write-output",
		"measure-object", "group-object", "get-process", "gps", "start-sleep",
		"clear-host", "get-item", "gi", "get-command", "gcm", "get-help",
		"convertfrom-json", "convertto-json", "invoke-webrequest", "iwr",
		"invoke-restmethod", "irm", "new-object":
		return true
	}

	lower := strings.ToLower(trimmed)
	if strings.Contains(lower, "select-object") || strings.Contains(lower, "format-table") ||
		strings.Contains(lower, "where-object") || strings.Contains(lower, "get-childitem") ||
		strings.Contains(lower, "get-content") || strings.Contains(lower, "select-string") ||
		strings.Contains(lower, "$_") || strings.Contains(lower, "@{") ||
		strings.Contains(lower, "$env:") || strings.Contains(lower, "[math]") ||
		strings.Contains(lower, "[system.") || strings.Contains(lower, " -recurse") ||
		strings.Contains(lower, " -filter ") || strings.Contains(lower, " -property ") ||
		strings.Contains(lower, " -expandproperty ") || strings.Contains(lower, " -eq ") ||
		strings.Contains(lower, " -ne ") || strings.Contains(lower, " -gt ") ||
		strings.Contains(lower, " -lt ") || strings.Contains(lower, " -like ") ||
		strings.Contains(lower, " -match ") || strings.HasPrefix(trimmed, "$") {
		return true
	}

	return false
}

// BuildExecCmd creates an *exec.Cmd appropriate for the host OS.
func BuildExecCmd(cmdStr string) *exec.Cmd {
	return BuildExecCmdWithShell(cmdStr, "auto")
}

// BuildExecCmdWithShell creates an *exec.Cmd appropriate for the host OS and requested shell.
func BuildExecCmdWithShell(cmdStr, shell string) *exec.Cmd {
	trimmed := CleanCommandString(cmdStr)
	if runtime.GOOS == "windows" {
		executable, args := ParseCommand(trimmed)

		// Direct invocation of powershell or pwsh with smart -Command payload preservation
		if executable == "powershell" || executable == "pwsh" {
			psExe := executable + ".exe"
			lower := strings.ToLower(args)
			cmdIdx := -1
			cmdFlagLen := 0
			for _, flag := range []string{"-command ", "-c "} {
				if idx := strings.Index(lower, flag); idx != -1 {
					cmdIdx = idx
					cmdFlagLen = len(flag)
					break
				}
			}
			if cmdIdx != -1 {
				prefix := strings.TrimSpace(args[:cmdIdx])
				code := strings.TrimSpace(args[cmdIdx+cmdFlagLen:])
				// Strip outer quotes if the code was wrapped in quotes
				if (strings.HasPrefix(code, "\"") && strings.HasSuffix(code, "\"") && len(code) >= 2) ||
					(strings.HasPrefix(code, "'") && strings.HasSuffix(code, "'") && len(code) >= 2) {
					code = code[1 : len(code)-1]
				}
				prefixParts := strings.Fields(prefix)
				cmdArgs := append(prefixParts, "-Command", code)
				return exec.Command(psExe, cmdArgs...)
			}
			argParts := strings.Fields(args)
			return exec.Command(psExe, argParts...)
		}
		if executable == "cmd" {
			return exec.Command("cmd.exe", strings.Fields(args)...)
		}

		// Explicit shell or detected PowerShell command
		if strings.EqualFold(shell, "powershell") || strings.EqualFold(shell, "pwsh") ||
			(shell != "cmd" && isPowerShellCommand(trimmed, executable)) {
			psExe := "powershell.exe"
			if pwshPath, err := exec.LookPath("pwsh.exe"); err == nil && pwshPath != "" {
				psExe = pwshPath
			}
			return exec.Command(psExe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", trimmed)
		}

		// If command uses shell features (pipes, chaining, redirection), execute via cmd.exe /c
		if strings.ContainsAny(trimmed, "|&><;") {
			return exec.Command("cmd.exe", "/c", trimmed)
		}

		parts := strings.Fields(trimmed)

		// Fast direct resolution for "ls"
		if len(parts) > 0 && parts[0] == "ls" {
			if lsPath, err := exec.LookPath("ls"); err == nil {
				return exec.Command(lsPath, parts[1:]...)
			}
			gitLs := `C:\Program Files\Git\usr\bin\ls.exe`
			if _, err := os.Stat(gitLs); err == nil {
				return exec.Command(gitLs, parts[1:]...)
			}
			if len(parts) == 1 {
				return exec.Command("cmd.exe", "/c", "dir /b")
			}
			return exec.Command("cmd.exe", "/c", "dir /b "+strings.TrimSpace(trimmed[2:]))
		}
		if len(parts) > 0 && parts[0] == "printenv" {
			if pePath, err := exec.LookPath("printenv"); err == nil {
				return exec.Command(pePath, parts[1:]...)
			}
			gitPe := `C:\Program Files\Git\usr\bin\printenv.exe`
			if _, err := os.Stat(gitPe); err == nil {
				return exec.Command(gitPe, parts[1:]...)
			}
		}
		return exec.Command("cmd.exe", "/c", trimmed)
	}
	// Use /bin/sh -c for Linux, macOS, and POSIX
	return exec.Command("/bin/sh", "-c", cmdStr)
}

// CleanOutput normalizes line endings, strips trailing whitespace per line,
// and collapses multiple consecutive blank lines.
func CleanOutput(raw string) string {
	s := strings.ReplaceAll(raw, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = strings.TrimRight(line, " \t")
	}
	s = strings.Join(lines, "\n")
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(s)
}

// ExecResult encapsulates full execution telemetry including exit code, output, and process ancestry.
type ExecResult struct {
	Output      string
	ExitCode    int
	Error       error
	ParentPID   int
	ProcessPID  int
	ProcessTree []string
}

// RunSandboxedCommandWithDetails executes the shell command in an isolated sandbox,
// capturing combined stdout/stderr, exit code, and complete process tree ancestry (BAP-534).
func RunSandboxedCommandWithDetails(cmdStr string) ExecResult {
	return RunSandboxedCommandWithShell(cmdStr, "auto")
}

// RunSandboxedCommandWithShell executes the shell command in an isolated sandbox with the target shell,
// capturing combined stdout/stderr, exit code, and complete process tree ancestry.
func RunSandboxedCommandWithShell(cmdStr, shell string) ExecResult {
	cmd := BuildExecCmdWithShell(cmdStr, shell)

	// Apply platform-specific sandbox attributes
	cleanup := ConfigureSandbox(cmd)
	if cleanup != nil {
		defer cleanup()
	}

	// Prepare environment and scrub ambient credentials (BAP-535)
	env := ScrubEnvironment(os.Environ())
	if runtime.GOOS == "windows" {
		// Ensure standard utilities from Git (ls, grep, head, tail, etc.) are reachable in cmd.exe
		gitUsrBin := `C:\Program Files\Git\usr\bin`
		if _, err := os.Stat(gitUsrBin); err == nil {
			for i, e := range env {
				if strings.HasPrefix(strings.ToUpper(e), "PATH=") {
					env[i] = e + ";" + gitUsrBin
					break
				}
			}
		}
	}

	// Inject CORP_OBO_TOKEN and broker marker environment variables
	cmd.Env = append(env, fmt.Sprintf("CORP_OBO_TOKEN=%s", InjectedOBOToken))
	cmd.Env = append(cmd.Env, "BAP_IN_BROKER=1")

	// Inject Corporate Mirror Supply-Chain Environment (Nexus / Artifactory)
	nexusMaven := os.Getenv("BAP_NEXUS_MAVEN_URL")
	if nexusMaven == "" {
		nexusMaven = "http://nexus.corp.internal/repository/maven-public/"
	}
	nexusNPM := os.Getenv("BAP_NEXUS_NPM_URL")
	if nexusNPM == "" {
		nexusNPM = "http://nexus.corp.internal/repository/npm-group/"
	}
	nexusPyPI := os.Getenv("BAP_NEXUS_PYPI_URL")
	if nexusPyPI == "" {
		nexusPyPI = "http://nexus.corp.internal/repository/pypi-group/simple"
	}

	cmd.Env = append(cmd.Env,
		fmt.Sprintf("PIP_INDEX_URL=%s", nexusPyPI),
		fmt.Sprintf("NPM_CONFIG_REGISTRY=%s", nexusNPM),
		"NPM_CONFIG_STRICT_SSL=true",
	)

	// If mirrors settings.xml or pip.ini exist, point to them
	for _, mDir := range []string{".bapstate/mirrors", "../.bapstate/mirrors"} {
		if absM, err := filepath.Abs(mDir); err == nil {
			mSettings := filepath.Join(absM, "settings.xml")
			if _, err := os.Stat(mSettings); err == nil {
				cmd.Env = append(cmd.Env, fmt.Sprintf("MAVEN_ARGS=-s \"%s\"", mSettings))
			}
			mPip := filepath.Join(absM, "pip.ini")
			if _, err := os.Stat(mPip); err == nil {
				cmd.Env = append(cmd.Env, fmt.Sprintf("PIP_CONFIG_FILE=%s", mPip))
			}
			mNpm := filepath.Join(absM, ".npmrc")
			if _, err := os.Stat(mNpm); err == nil {
				cmd.Env = append(cmd.Env, fmt.Sprintf("NPM_CONFIG_USERCONFIG=%s", mNpm))
			}
		}
	}

	var b bytes.Buffer
	cmd.Stdout = &b
	cmd.Stderr = &b

	err := cmd.Start()
	if err != nil {
		return ExecResult{
			Output:   "",
			ExitCode: 1,
			Error:    err,
		}
	}

	childPID := cmd.Process.Pid
	parentPID := os.Getppid()
	brokerPID := os.Getpid()
	tree := []string{
		fmt.Sprintf("parent:%d", parentPID),
		fmt.Sprintf("broker:%d", brokerPID),
		fmt.Sprintf("child:%d", childPID),
	}

	postCleanup := PostStartProcess(cmd)
	if postCleanup != nil {
		defer postCleanup()
	}

	timeoutSec := 120
	if toStr := os.Getenv("BAP_EXEC_TIMEOUT_SEC"); toStr != "" {
		if val, err := strconv.Atoi(toStr); err == nil && val > 0 {
			timeoutSec = val
		}
	}

	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	var waitErr error
	select {
	case waitErr = <-done:
	case <-time.After(time.Duration(timeoutSec) * time.Second):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		waitErr = fmt.Errorf("Execution timed out after %d seconds (Process Terminated by Resource Quota)", timeoutSec)
	}
	// Redact sensitive keys/tokens from stdout and stderr output (BAP-535)
	cleaned := CleanOutput(RedactSecrets(b.String()))
	exitCode := 0
	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return ExecResult{
		Output:      cleaned,
		ExitCode:    exitCode,
		Error:       waitErr,
		ParentPID:   parentPID,
		ProcessPID:  childPID,
		ProcessTree: tree,
	}
}

// RunSandboxedCommandWithExitCode executes the shell command in an isolated sandbox,
// injecting CORP_OBO_TOKEN and capturing combined stdout and stderr along with the integer exit code.
func RunSandboxedCommandWithExitCode(cmdStr string) (string, int, error) {
	res := RunSandboxedCommandWithDetails(cmdStr)
	return res.Output, res.ExitCode, res.Error
}

// RunSandboxedCommand executes the shell command in an isolated sandbox,
// injecting CORP_OBO_TOKEN and capturing combined stdout and stderr.
func RunSandboxedCommand(cmdStr string) (string, error) {
	out, _, err := RunSandboxedCommandWithExitCode(cmdStr)
	return out, err
}

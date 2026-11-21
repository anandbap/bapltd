package sandbox

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// ToolShell preserves the tool's language through the decision and execution hops.
// Generic terminal tools retain auto detection; explicit languages never fall back
// to a different shell when the requested interpreter is unavailable.
func ToolShell(tool string) string {
	switch strings.ToLower(strings.TrimSpace(tool)) {
	case "bash", "sh", "zsh", "powershell", "pwsh", "cmd", "bapsh":
		return strings.ToLower(strings.TrimSpace(tool))
	case "cmd.exe":
		return "cmd"
	}
	return "auto"
}

func explicitShellCommand(command, shell string) *exec.Cmd {
	shell = strings.ToLower(strings.TrimSpace(shell))
	var names, args []string
	switch shell {
	case "bash", "zsh", "sh":
		names = []string{shell}
		args = []string{"-c", command}
		if runtime.GOOS == "windows" {
			// Prefer Git's native POSIX shell over the Windows WSL launcher.
			if git, err := exec.LookPath("git.exe"); err == nil {
				for _, rel := range []string{"../bin", "../usr/bin", "."} {
					names = append([]string{filepath.Clean(filepath.Join(filepath.Dir(git), rel, shell+".exe"))}, names...)
				}
			}
		}
	case "powershell":
		if runtime.GOOS == "windows" {
			names = []string{"powershell.exe", "pwsh.exe"}
		} else {
			names = []string{"pwsh", "powershell"}
		}
		args = []string{"-NoProfile", "-NonInteractive", "-Command", command}
	case "pwsh":
		names = []string{"pwsh"}
		args = []string{"-NoProfile", "-NonInteractive", "-Command", command}
	case "cmd":
		if runtime.GOOS == "windows" {
			names = []string{"cmd.exe"}
		}
		args = []string{"/d", "/s", "/c", command}
	}
	for _, name := range names {
		if path, err := exec.LookPath(name); err == nil {
			return exec.Command(path, args...)
		}
	}
	cmd := exec.Command(shell)
	cmd.Err = fmt.Errorf("requested shell %q is unavailable or unsupported on %s; no alternate shell was used", shell, runtime.GOOS)
	return cmd
}

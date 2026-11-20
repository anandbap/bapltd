package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestExplicitShellPreservesCommandAndLanguage(t *testing.T) {
	for _, shell := range []string{"bash", "sh", "zsh", "powershell", "pwsh", "cmd"} {
		t.Run(shell, func(t *testing.T) {
			input := "git log -1 --format=%B; ls; head -c 1500 README.md GEMINI.md package.json 2>/dev/null"
			cmd := BuildExecCmdWithShell(input, shell)
			if cmd.Err != nil {
				if !strings.Contains(cmd.Err.Error(), "no alternate shell") {
					t.Fatal(cmd.Err)
				}
				return
			}
			base := strings.TrimSuffix(strings.ToLower(filepath.Base(cmd.Path)), ".exe")
			if base != shell && !(shell == "powershell" && base == "pwsh") {
				t.Fatalf("%s silently became %s", shell, cmd.Path)
			}
			if cmd.Args[len(cmd.Args)-1] != input {
				t.Fatalf("command rewritten: %q", cmd.Args)
			}
		})
	}
	for _, shell := range []string{"not-a-shell", "bash -c", "../shell"} {
		cmd := BuildExecCmdWithShell("echo should-not-run", shell)
		if cmd.Err == nil || cmd.Run() == nil {
			t.Fatalf("unsupported shell executed: %q", shell)
		}
	}
}

func TestNativeShellSemantics(t *testing.T) {
	for _, shell := range []string{"bash", "sh", "zsh", "powershell", "pwsh", "cmd"} {
		t.Run(shell, func(t *testing.T) {
			input := `printf '%s\n' 'first; literal'; printf '%s\n' second 2>/dev/null`
			if shell == "powershell" || shell == "pwsh" {
				input = `Write-Output 'first; literal'; Write-Output second`
			}
			if shell == "cmd" {
				input = `echo first-literal&&echo second`
			}
			cmd := BuildExecCmdWithShell(input, shell)
			if cmd.Err != nil {
				required := shell == "bash" || (runtime.GOOS != "windows" && shell == "sh") ||
					(runtime.GOOS == "windows" && (shell == "cmd" || shell == "powershell")) ||
					(runtime.GOOS == "darwin" && shell == "zsh")
				if os.Getenv("BAP_REQUIRE_NATIVE_SHELLS") == "1" && required {
					t.Fatal(cmd.Err)
				}
				t.Skip(cmd.Err)
			}
			out, err := cmd.CombinedOutput()
			if err != nil {
				if runtime.GOOS == "windows" && (strings.Contains(string(out), "0xC0000022") || strings.Contains(string(out), "NtCreateDirectoryObject")) {
					t.Skipf("msys2 restricted sandbox environment on Windows: %s", out)
				}
				t.Fatalf("native %s failed: %v\n%s", shell, err, out)
			}
			want := "first; literal"
			if shell == "cmd" {
				want = "first-literal"
			}
			if !strings.Contains(string(out), want) || !strings.Contains(string(out), "second") {
				t.Fatalf("shell semantics lost: %q", out)
			}
		})
	}
}

func TestUnavailableExplicitShellNeverFallsBack(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	for _, shell := range []string{"bash", "sh", "zsh", "powershell", "pwsh", "cmd"} {
		cmd := BuildExecCmdWithShell("echo should-not-execute", shell)
		if cmd.Err == nil || cmd.Run() == nil {
			t.Fatalf("missing %s fell back: %q", shell, cmd.Args)
		}
	}
}

func TestFirstTurnCommandRunsInBash(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	ws := t.TempDir()
	// Fixture data and missing optional files are intentionally ordinary project paths.
	git := exec.Command("git", "-c", "init.templateDir=", "init", ws)
	if out, err := git.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v %s", err, out)
	}
	git = exec.Command("git", "-C", ws, "-c", "user.name=Pilot", "-c", "user.email=pilot@example.test", "-c", "commit.gpgsign=false", "-c", "core.hooksPath="+filepath.Join(ws, "no-hooks"), "commit", "--allow-empty", "-m", "first commit")
	if out, err := git.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v %s", err, out)
	}
	// An absent optional file makes head return nonzero even though the command
	// ran correctly; test that behavior separately from broker/shell startup.
	cmd := BuildExecCmdWithShell("git log -1 --format=%B; ls; head -c 1500 README.md GEMINI.md package.json 2>/dev/null", "bash")
	if cmd.Err != nil {
		t.Skip(cmd.Err)
	}
	cmd.Dir = ws
	out, err := cmd.CombinedOutput()
	if err != nil && runtime.GOOS == "windows" && (strings.Contains(string(out), "0xC0000022") || strings.Contains(string(out), "NtCreateDirectoryObject")) {
		t.Skipf("msys2 restricted sandbox environment on Windows: %s", out)
	}
	if !strings.Contains(string(out), "first commit") {
		t.Fatalf("first turn lost Git output on %s: %q", runtime.GOOS, out)
	}
}

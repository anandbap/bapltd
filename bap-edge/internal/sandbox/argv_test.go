package sandbox

import (
	"os/exec"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestSplitArgv(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   []string
		wantOK bool
	}{
		{"plain", `git status`, []string{"git", "status"}, true},
		{"extra whitespace", "  git \t log   -1 ", []string{"git", "log", "-1"}, true},
		{"empty", ``, nil, true},
		{"single quoted message", `git commit -m 'Fix the bug'`, []string{"git", "commit", "-m", "Fix the bug"}, true},
		{"double quoted message", `git commit -m "Fix the bug"`, []string{"git", "commit", "-m", "Fix the bug"}, true},
		{"semicolon inside single quotes", `git commit -m 'a; b'`, []string{"git", "commit", "-m", "a; b"}, true},
		{"operators inside single quotes", `echo 'a | b && c > d < e'`, []string{"echo", "a | b && c > d < e"}, true},
		{"angle brackets in trailer", `git commit -m 'Co-Authored-By: X <x@example.com>'`, []string{"git", "commit", "-m", "Co-Authored-By: X <x@example.com>"}, true},
		{"single quote inside double quotes is literal", `git commit -m "it's fine"`, []string{"git", "commit", "-m", "it's fine"}, true},
		{"double quote inside single quotes is literal", `git commit -m 'say "hi"'`, []string{"git", "commit", "-m", `say "hi"`}, true},
		{"escaped quote inside double quotes", `git commit -m "say \"hi\""`, []string{"git", "commit", "-m", `say "hi"`}, true},
		// Windows rules: backslashes are literal unless they directly precede a double quote.
		{"backslashes not before a quote stay literal", `echo "a\\b"`, []string{"echo", `a\\b`}, true},
		{"single backslash stays literal", `echo a\b`, []string{"echo", `a\b`}, true},
		{"even backslash run before closing quote", `echo "a\\"`, []string{"echo", `a\`}, true},
		{"odd backslash run before quote is a literal quote", `echo "a\\\"b"`, []string{"echo", `a\"b`}, true},
		{
			// Regression: TestBAP200 handoff. "\\b" must not collapse to "\b" (a backspace in Python).
			"python string literal with quotes and a double backslash",
			`python -c "print('\"quotes\" and \\backslash')"`,
			[]string{"python", "-c", `print('"quotes" and \\backslash')`},
			true,
		},
		{"empty quoted argument is kept", `git commit -m ''`, []string{"git", "commit", "-m", ""}, true},
		{"adjacent quoted segments join", `echo 'a'"b"c`, []string{"echo", "abc"}, true},
		{"windows path unquoted", `C:\tools\git.exe status`, []string{`C:\tools\git.exe`, "status"}, true},
		{"windows path with spaces quoted", `"C:\Program Files\Git\bin\git.exe" status`, []string{`C:\Program Files\Git\bin\git.exe`, "status"}, true},
		{"unterminated single quote", `git commit -m 'oops`, nil, false},
		{"unterminated double quote", `git commit -m "oops`, nil, false},
		// A trailing backslash before the closing quote reads as an escaped quote, so the string is
		// unterminated and the caller keeps the conservative cmd.exe path instead of guessing.
		{"windows trailing backslash is not guessed", `"C:\dir\" status`, nil, false},
		{
			"the full multi-paragraph commit that originally failed",
			`git commit -m 'Default control plane to prod and require admin auth on telemetry read routes' -m 'Make --mode default to prod; an explicit --mode now overrides BAP_MODE/BAP_ENVIRONMENT. Add requireAdminViewer and apply it to agents, sessions, audit events, risky events, inspector, STS inspector and activity read routes, sharing the invalid-credential throttle. URL tokens remain accepted only on /stream paths.' -m 'Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>'`,
			[]string{
				"git", "commit",
				"-m", "Default control plane to prod and require admin auth on telemetry read routes",
				"-m", "Make --mode default to prod; an explicit --mode now overrides BAP_MODE/BAP_ENVIRONMENT. Add requireAdminViewer and apply it to agents, sessions, audit events, risky events, inspector, STS inspector and activity read routes, sharing the invalid-credential throttle. URL tokens remain accepted only on /stream paths.",
				"-m", "Co-Authored-By: Claude Sonnet 5.5 <noreply@anthropic.com>",
			},
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := splitArgv(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("splitArgv(%q) ok=%v, want %v", tc.in, ok, tc.wantOK)
			}
			if !tc.wantOK {
				return
			}
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("splitArgv(%q)\n got  %q\n want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestHasUnquotedShellOperator(t *testing.T) {
	// Operators in quoted arguments are data and must not force the shell path.
	quoted := []string{
		`git status`,
		`git commit -m 'a; b'`,
		`git commit -m "a; b"`,
		`git commit -m 'a | b'`,
		`git commit -m 'a && b'`,
		`git commit -m 'a > b'`,
		`git commit -m 'Co-Authored-By: X <x@example.com>'`,
		`git commit -m "Co-Authored-By: X <x@example.com>"`,
		`git commit -m "say \"hi\"; bye"`,
		`git log --format='[%h] [%s]'`,
		`echo ''`,
	}
	for _, in := range quoted {
		if hasUnquotedShellOperator(in) {
			t.Errorf("hasUnquotedShellOperator(%q) = true, want false (operator is quoted)", in)
		}
	}

	// Real operators, and anything ambiguous, must keep the conservative shell path.
	operators := []string{
		`git status; calc`,
		`git status && calc`,
		`git status || calc`,
		`git status | findstr x`,
		`git status > out.txt`,
		`git status 2> out.txt`,
		`cat < in.txt`,
		`git status & calc`,
		"git status\ncalc",
		"git status\r\ncalc",
		`git commit -m 'safe' ; calc`,
		`git commit -m "safe" && calc`,
		// An escaped backslash closes the string, so the following operator is real.
		`echo "a\\" ; calc`,
		// Quote state must not leak across segments.
		`echo 'a' ; echo 'b'`,
		// Unterminated quotes are never trusted.
		`git commit -m 'oops; calc`,
		`git commit -m "oops; calc`,
	}
	for _, in := range operators {
		if !hasUnquotedShellOperator(in) {
			t.Errorf("hasUnquotedShellOperator(%q) = false, want true (real operator or ambiguous quoting)", in)
		}
	}
}

// A quoted operator that is closed by an escaped quote must stay quoted, not terminate early.
func TestEscapedQuoteDoesNotEndQuotedRegion(t *testing.T) {
	in := `git commit -m "a\" ; calc"`
	if hasUnquotedShellOperator(in) {
		t.Fatalf("%q: the ';' is inside the quoted message and must not count as an operator", in)
	}
	argv, ok := splitArgv(in)
	if !ok || len(argv) != 4 || argv[3] != `a" ; calc` {
		t.Fatalf("splitArgv(%q) = %q ok=%v, want the whole message as one argument", in, argv, ok)
	}
}

func TestBuildExecCmdQuotedArgumentsOnWindows(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("cmd.exe routing only applies on Windows")
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not on PATH")
	}

	t.Run("quoted operators run directly with exact argv", func(t *testing.T) {
		cmd := BuildExecCmdWithShell(`git commit -m 'a; b' -m 'Co-Authored-By: X <x@example.com>'`, "auto")
		if strings.EqualFold(baseName(cmd.Path), "cmd.exe") {
			t.Fatalf("quoted arguments were routed through cmd.exe: %q", cmd.Args)
		}
		want := []string{gitPath, "commit", "-m", "a; b", "-m", "Co-Authored-By: X <x@example.com>"}
		if len(cmd.Args) != len(want) {
			t.Fatalf("argv = %q, want %q", cmd.Args, want)
		}
		for i := 1; i < len(want); i++ {
			if cmd.Args[i] != want[i] {
				t.Fatalf("argv[%d] = %q, want %q (full: %q)", i, cmd.Args[i], want[i], cmd.Args)
			}
		}
	})

	t.Run("real operators still use the shell", func(t *testing.T) {
		for _, in := range []string{`git status && echo done`, `git status ; echo done`, `git status | findstr x`, `git status > nul`} {
			cmd := BuildExecCmdWithShell(in, "auto")
			if !strings.EqualFold(baseName(cmd.Path), "cmd.exe") {
				t.Errorf("%q should still run through cmd.exe, got %q", in, cmd.Args)
			}
		}
	})

	t.Run("a quoted operator cannot smuggle a second command", func(t *testing.T) {
		// The ';' sits outside the quotes, so this is two commands and must go through the shell path
		// (which the policy layer has already evaluated), never be flattened into one git argv.
		cmd := BuildExecCmdWithShell(`git commit -m 'safe' ; calc`, "auto")
		if !strings.EqualFold(baseName(cmd.Path), "cmd.exe") {
			t.Fatalf("compound command was executed directly: %q", cmd.Args)
		}
	})

	t.Run("unterminated quote falls back instead of guessing", func(t *testing.T) {
		cmd := BuildExecCmdWithShell(`git commit -m 'oops`, "auto")
		if !strings.EqualFold(baseName(cmd.Path), "cmd.exe") {
			t.Fatalf("unterminated quote was executed directly: %q", cmd.Args)
		}
	})

	t.Run("unquoted commands keep their existing cmd.exe behaviour", func(t *testing.T) {
		for _, in := range []string{`echo hello`, `git status`, `dir`} {
			cmd := BuildExecCmdWithShell(in, "auto")
			if !strings.EqualFold(baseName(cmd.Path), "cmd.exe") {
				t.Errorf("%q should still run via cmd.exe, got %q", in, cmd.Args)
			}
		}
	})

	t.Run("unknown programs with quotes fall back to cmd.exe", func(t *testing.T) {
		cmd := BuildExecCmdWithShell(`no-such-program-xyz 'a b'`, "auto")
		if !strings.EqualFold(baseName(cmd.Path), "cmd.exe") {
			t.Fatalf("unresolvable program should fall back to cmd.exe, got %q", cmd.Args)
		}
	})
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

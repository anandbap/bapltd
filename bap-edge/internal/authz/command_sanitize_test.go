package authz

import (
	"strings"
	"testing"
)

// The exact shape of the command BAP denied as a "cross-folder write" (policy1): a commit message
// containing a lone "/" and ".." tokens, fed to git on stdin.
const realCommitCommand = "git add JIRA_STORIES.md docs/PERMISSION_POLICY.md bap-edge/cmd/zsp.go && git commit -F - <<'EOF'\n" +
	"Harden ZSP grant minting (BAP-925/926/930)\n\n" +
	"- Replace --oob-approve / y-N approval with a one-time-code challenge.\n" +
	"- Add Epic 46 (BAP-922..931) to the backlog; see ../notes and /etc/hosts for context.\n" +
	"- fix a && b | c ; d\n" +
	"EOF"

func TestBAP932_CommitHeredocIsNotAWorkspaceEscape(t *testing.T) {
	ws := t.TempDir()
	if CheckCommandWorkspaceEscape(ws, realCommitCommand) {
		t.Fatal("git commit heredoc body text must not be treated as paths that escape the workspace")
	}
}

func TestBAP932_GitMessageFlagsAreData(t *testing.T) {
	ws := t.TempDir()
	for _, c := range []string{
		`git commit -m "fix / and .. and /etc/passwd in text"`,
		`git commit -am "update ../docs / notes"`,
		`git commit --message "see /etc/hosts"`,
		`git commit --message="see /etc/hosts"`,
		`git tag -a v1 -m "release / candidate .."`,
	} {
		if CheckCommandWorkspaceEscape(ws, c) {
			t.Errorf("message text flagged as workspace escape: %s", c)
		}
	}
}

// Security invariants: nothing that is real code or a real path may be hidden by the sanitizer.
func TestBAP932_RealEscapesAreStillCaught(t *testing.T) {
	ws := t.TempDir()
	for _, c := range []string{
		"bash <<'EOF'\nrm -rf ../victim\nEOF",                        // heredoc to a shell is CODE
		"python <<EOF\n../../x.py\nEOF",                               // ... and to an interpreter
		"cat <<'EOF' > ../out.txt\nhello\nEOF",                        // redirect target on the header line
		"git commit -m ok ../../evil",                                 // other git args are still checked
		"git -C .. commit -m ok",                                      // -C .. escapes
		"git add ../../etc/passwd && git commit -m x",                 // path arg escapes
		"git commit -F ../../msg.txt",                                 // -F is a path, not message text
		"ls /",                                                        // genuine root reference
		"cd .. && git commit -m x",                                    // cd out of the workspace
		"tee ../x <<'EOF'\ndata\nEOF",                                 // tee target
	} {
		if !CheckCommandWorkspaceEscape(ws, c) {
			t.Errorf("expected workspace escape to be detected for: %q", c)
		}
	}
}

func TestBAP932_SanitizerOnlyDropsDataConsumerBodies(t *testing.T) {
	got := SanitizeCommandForAnalysis(realCommitCommand)
	if strings.Contains(got, "one-time-code") || strings.Contains(got, "<<") {
		t.Errorf("data heredoc body/operator should be removed, got %q", got)
	}
	if !strings.Contains(got, "git commit -F -") {
		t.Errorf("command header must be preserved, got %q", got)
	}
	shell := "bash <<'EOF'\necho hi\nEOF"
	if SanitizeCommandForAnalysis(shell) != shell {
		t.Errorf("heredoc to a shell must be left untouched")
	}
	if SanitizeCommandForAnalysis("git status") != "git status" {
		t.Errorf("commands without heredocs must be unchanged")
	}
}

// Found live: `git commit -m "docs / notes: BAP-922..931 and a && b"` was refused with "resource file://C:/ not in
// granted boundaries" because (1) the escape scan split the command on the `&&` inside the quotes, and (2) parsed
// arguments were re-joined without their quotes, turning one message argument back into many tokens.
func TestBAP932_QuotedMessagesWithOperatorsAndSlashesAreOneArgument(t *testing.T) {
	ws := t.TempDir()
	msgs := []string{
		`git commit --dry-run -m "docs / notes: BAP-922..931 and a && b"`,
		`git commit -m "fix | pipe ; semi & amp / slash .. dots"`,
		`git commit -am 'single quoted && / ..'`,
		`git add a.txt && git commit -m "x / y && z"`,
		`git commit --message="a && b / c"`,
	}
	for _, c := range msgs {
		if CheckCommandWorkspaceEscape(ws, c) {
			t.Errorf("escape wrongly detected: %s", c)
		}
		if HasFilesystemRootEscape(ws, c) {
			t.Errorf("root escape wrongly detected: %s", c)
		}
		checks := ResolveZSPCommandChecks(c, "git", "", "Bash", "", ws)
		if len(checks) == 0 {
			t.Errorf("no checks for %s", c)
		}
		for _, ch := range checks {
			if ch.EscapesWorkspace || ch.Action != "git:commit:write" {
				t.Errorf("%s -> %+v (want git:commit:write inside the workspace)", c, ch)
			}
		}
	}
	// A quoted path argument is still a path: quoting must not hide a real escape.
	for _, c := range []string{`git add "../secret file.txt"`, `git commit -m ok "../../x"`, `cd "../.." && git commit -m x`} {
		if !CheckCommandWorkspaceEscape(ws, c) {
			t.Errorf("real escape must still be detected: %s", c)
		}
	}
}

func TestBAP932_FilesystemRootScanIgnoresMessageTextButCatchesRealRoots(t *testing.T) {
	ws := t.TempDir()
	if HasFilesystemRootEscape(ws, realCommitCommand) {
		t.Error("commit message text must not be reported as a filesystem root reference")
	}
	if HasFilesystemRootEscape(ws, `cd sub && git commit -m "a / b" && git status`) {
		t.Error("quoted message after a chained cd must not be reported as a root reference")
	}
	for _, c := range []string{"ls /", "rm -rf /", "cat <<'EOF' > /\nx\nEOF", "git add / && git commit -m x"} {
		if !HasFilesystemRootEscape(ws, c) {
			t.Errorf("real filesystem root reference must still be detected: %q", c)
		}
	}
}

// End to end through Cedar + AST: the compound command is allowed, and decomposes to the two real actions.
func TestBAP932_GitAddAndCommitPassCedarAndDecomposeCleanly(t *testing.T) {
	authz, err := NewAuthorizer("../../policy.cedar")
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	ws := t.TempDir()
	allowed, reason, err := authz.EvaluateWithWorkspace("git", realCommitCommand, "", ws)
	if err != nil {
		t.Fatalf("EvaluateWithWorkspace error: %v", err)
	}
	if !allowed {
		t.Fatalf("git add && git commit must be allowed in the workspace, got denial: %s", reason)
	}

	checks := ResolveZSPCommandChecks(realCommitCommand, "git", "", "Bash", "", ws)
	if len(checks) != 2 {
		t.Fatalf("expected exactly 2 ZSP checks (git add, git commit), got %d: %+v", len(checks), checks)
	}
	for _, c := range checks {
		if c.Action != "git:commit:write" || c.EscapesWorkspace {
			t.Errorf("unexpected check %+v (want git:commit:write inside workspace)", c)
		}
	}
}

// A genuine escape must still be a policy denial after the fix.
func TestBAP932_RealCrossFolderWriteStillDenied(t *testing.T) {
	authz, err := NewAuthorizer("../../policy.cedar")
	if err != nil {
		t.Fatalf("NewAuthorizer: %v", err)
	}
	ws := t.TempDir()
	allowed, _, err := authz.EvaluateWithWorkspace("cp", "cp secrets.txt ../outside.txt", "secrets.txt ../outside.txt", ws)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("a real cross-folder write must still be denied")
	}
}

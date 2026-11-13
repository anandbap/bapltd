package main

import "testing"

// BAP-932: the hook-side workspace-escape check must treat commit-message text as data, exactly
// like bap-edge/internal/authz, while still catching genuine escapes.

const hookRealCommitCommand = "git add JIRA_STORIES.md docs/PERMISSION_POLICY.md && git commit -F - <<'EOF'\n" +
	"Harden ZSP grant minting (BAP-925/926/930)\n\n" +
	"- Replace --oob-approve / y-N approval with a one-time-code challenge.\n" +
	"- Add Epic 46 (BAP-922..931); see ../notes and /etc/hosts.\n" +
	"EOF"

func TestBAP932Hook_CommitMessageIsNotAWorkspaceEscape(t *testing.T) {
	ws := t.TempDir()
	if checkCommandWorkspaceEscape(ws, hookRealCommitCommand) {
		t.Fatal("heredoc commit message must not be flagged as a workspace escape")
	}
	for _, c := range []string{
		`git commit -m "fix / and .. and /etc/passwd in text"`,
		`git commit -am "update ../docs / notes"`,
		`git commit --message="see /etc/hosts"`,
	} {
		if checkCommandWorkspaceEscape(ws, c) {
			t.Errorf("message text flagged as escape: %s", c)
		}
	}
}

func TestBAP932Hook_QuotedOperatorsAndSlashesAreOneArgument(t *testing.T) {
	ws := t.TempDir()
	for _, c := range []string{
		`git commit --dry-run -m "docs / notes: BAP-922..931 and a && b"`,
		`git commit -m "fix | pipe ; semi & amp / slash .. dots"`,
		`git add a.txt && git commit -m "x / y && z"`,
	} {
		if checkCommandWorkspaceEscape(ws, c) {
			t.Errorf("quoted message flagged as escape: %s", c)
		}
	}
	for _, c := range []string{`git add "../secret file.txt"`, `cd "../.." && git commit -m x`} {
		if !checkCommandWorkspaceEscape(ws, c) {
			t.Errorf("real escape must still be detected: %s", c)
		}
	}
}

func TestBAP932Hook_RealEscapesAreStillCaught(t *testing.T) {
	ws := t.TempDir()
	for _, c := range []string{
		"bash <<'EOF'\nrm -rf ../victim\nEOF",
		"cat <<'EOF' > ../out.txt\nhello\nEOF",
		"git commit -m ok ../../evil",
		"git -C .. commit -m ok",
		"git add ../../etc/passwd && git commit -m x",
		"cd .. && git commit -m x",
	} {
		if !checkCommandWorkspaceEscape(ws, c) {
			t.Errorf("expected escape to be detected for: %q", c)
		}
	}
}

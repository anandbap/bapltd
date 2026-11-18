package authz

import (
	"errors"
	"runtime"
	"testing"
)

const firstTurnCommand = "git log -1 --format=%B; ls; head -c 1500 README.md GEMINI.md package.json 2>/dev/null"

func TestFirstTurnInspectionReceivesBoundGrantWithoutRetry(t *testing.T) {
	for _, shell := range []string{"bash", "sh", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			dir, ws := batchFixture(t)
			checks, ok := automaticBatchChecks(firstTurnCommand, ws, shell)
			if !ok || len(checks) != 3 {
				t.Fatalf("first-turn inspection not recognized: %+v, %v", checks, ok)
			}
			_, grant, _, err := AuthorizeSessionCommandBatch(dir, "fresh-session", "claude-code", firstTurnCommand, ws, commandChecks(firstTurnCommand, ws), false, nil, shell)
			if err != nil || grant == nil || grant.Shell != shell || grant.MaxUses != 1 {
				t.Fatalf("first call required an explicit grant: %+v %v", grant, err)
			}
			_, used, _, err := AuthorizeSessionCommandBatch(dir, "fresh-session", "claude-code", firstTurnCommand, ws, commandChecks(firstTurnCommand, ws), true, nil, shell)
			if err != nil || used.GrantID != grant.GrantID || used.RemainingUses != 0 {
				t.Fatalf("precheck/execution did not share one grant: %+v %v", used, err)
			}
		})
	}
}

func TestAutomaticGrantCannotCrossShellBoundary(t *testing.T) {
	dir, ws := batchFixture(t)
	command := "git status"
	checks := commandChecks(command, ws)
	_, grant, _, err := AuthorizeSessionCommandBatch(dir, "shell-bound", "test", command, ws, checks, false, nil, "bash")
	if err != nil {
		t.Fatal(err)
	}
	for _, shell := range []string{"cmd", "powershell", "sh", "auto"} {
		if _, _, _, err := VerifyOrConsumeSessionZSPChecks(dir, "shell-bound", "test", checks, command, ws, true, nil, shell); !errors.Is(err, ErrActionNotGranted) {
			t.Fatalf("grant crossed into %s: %v", shell, err)
		}
	}
	_, _, minter, secret, err := EnsureSessionPrincipal(dir, "shell-bound", "test")
	if err != nil {
		t.Fatal(err)
	}
	engine := NewZSPEngine(minter, secret)
	tampered := *grant
	tampered.Shell = "cmd"
	if engine.LoadGrant(&tampered) == nil {
		t.Fatal("shell binding was not signed")
	}
	if err := engine.LoadGrant(grant); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.ConsumeTaskGrant(grant.GrantID, checks[0].Action, "workspace://current", command, nil, "cmd"); err == nil {
		t.Fatal("direct consumption ignored shell binding")
	}
}

func TestFirstTurnSyntaxDoesNotAuthorizeExtraEffects(t *testing.T) {
	_, ws := batchFixture(t)
	for _, command := range []string{
		firstTurnCommand + "; git push origin main",
		"git log -1 --format=%B > report.txt",
		"git log -1 --format=%B 2> report.txt",
		"git log -1 --format=%B 2>>/dev/null",
		"git log -1 --format=%B </dev/null",
		"git log -1 --format=%B 2>/dev/null/other",
		"git log -1 --format=%B; cat .env",
		"git log -1 --format=%B; head -c 1500 README.md .env",
		"git log -1 --format=%B; cat ../outside.txt",
		"git log -1 --format=%B; unknown-tool",
		"git log -1 --format=$(helper)",
		"git log -1 --format=%B; cat %FILE%",
		"git log -1 --format=%B; cat README.md 2>NUL",
		"git log -1 --format=%B & ls",
		"git log -1 --output=report.txt",
		"git log -1 --ext-diff",
	} {
		if _, ok := automaticBatchChecks(command, ws, "bash"); ok {
			t.Errorf("unsafe candidate accepted: %s", command)
		}
	}
	for _, shell := range []string{"cmd", "auto"} {
		if shell == "auto" && runtime.GOOS != "windows" {
			continue
		}
		if _, ok := automaticBatchChecks("git log -1 --format=%PATH%", ws, shell); ok {
			t.Errorf("CMD expansion accepted in %s", shell)
		}
	}
	if _, ok := automaticBatchChecks("git log -1; dir 2>NUL", ws, "cmd"); ok != (runtime.GOOS == "windows") {
		t.Fatal("NUL treated as a null device on the wrong OS")
	}
}

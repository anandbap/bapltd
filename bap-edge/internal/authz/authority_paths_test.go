package authz

import (
	"errors"
	"path/filepath"
	"testing"
)

// ZSP-REVIEW-01 hardening: BAP's own authority state must never be nameable by an agent tool call.

func TestIsBAPAuthorityPath(t *testing.T) {
	zsp := filepath.Join(t.TempDir(), "custom-zsp")
	state := t.TempDir()
	t.Setenv("BAP_ZSP_DIR", zsp)
	t.Setenv("BAP_STATE_DIR", state)

	positives := []string{
		`C:\Users\dev\bin\.bapstate\zsp\pepper.key`,
		`C:\Users\DEV\BIN\.BAPSTATE\ZSP\grants\g-1.json`,
		`~/bin/.bapstate/zsp/approvals/req-ab12cd34.json`,
		`../../bin/.bapstate/zsp`,
		`.bapstate/zsp/autoapprove.json`,
		`pepper.key`,
		`PEPPER.KEY.`,
		`somewhere/autoapprove.json::$DATA`,
		`"C:\Users\dev\bin\.bapstate\zsp\native-invocations\x.json"`,
		`C:\Users\dev\AppData\Local\Temp\bapstate\zsp\pepper.key`,
		zsp,
		filepath.Join(zsp, "approvals", "req-1.json"),
		filepath.Join(state, "zsp", "grants", "g.json"),
	}
	for _, p := range positives {
		if !IsBAPAuthorityPath(p) {
			t.Errorf("%q must be treated as BAP authority state", p)
		}
		if !LooksLikeCredentialPath(p) {
			t.Errorf("%q must be refused by the credential-path screen", p)
		}
		if !isCredentialStorePath(p) {
			t.Errorf("%q must be refused as a credential store", p)
		}
	}

	negatives := []string{
		``,
		`src/main.go`,
		`docs/zsp.md`,
		`docs/approvals.md`,
		`.bapstate/shims-abc/git.cmd`,
		`C:\Users\dev\bin\.bapstate\sessions\pid-1.json`,
		`test-runtime-tmp/bapstate206180543/policy/policy.cedar`,
		`bapedge`,
		`zsp`,
		`workspace://current`,
	}
	for _, p := range negatives {
		if IsBAPAuthorityPath(p) {
			t.Errorf("%q must NOT be treated as BAP authority state (would make BAP unusable)", p)
		}
	}
}

// A misconfigured state directory (a drive root or the filesystem root) must never turn the whole
// disk into "authority state".
func TestAuthorityDirNeverMatchesFilesystemRoot(t *testing.T) {
	t.Setenv("BAP_ZSP_DIR", string(filepath.Separator))
	t.Setenv("BAP_STATE_DIR", "")
	if IsBAPAuthorityPath(filepath.Join(t.TempDir(), "main.go")) {
		t.Fatal("a root-level state directory must not protect every path")
	}
}

// Usability guard: the commands an agent legitimately runs do not name an authority path, so the
// screen must not touch them.
func TestAgentControlCommandsAreNotRefusedByAuthorityScreen(t *testing.T) {
	for _, c := range []string{
		`bapedge zsp status`,
		`bapedge zsp grants`,
		`bapedge zsp approvals`,
		`bapedge zsp authorize --session-id s-1 --mission TASK_EXECUTION --goal "edit files" --actions fs:file:write --resources workspace://current`,
		`bapedge.exe exec "git status"`,
		`go test ./...`,
	} {
		if CommandReferencesCredential(c) {
			t.Errorf("legitimate agent command must stay allowed: %q", c)
		}
	}
}

func TestShellCommandsNamingAuthorityStateAreRefused(t *testing.T) {
	for _, c := range []string{
		`type C:\Users\dev\bin\.bapstate\zsp\pepper.key`,
		`Get-Content ~/bin/.bapstate/zsp/autoapprove.json`,
		`cat ../bin/.bapstate/zsp/approvals/req-1.json`,
		`dir C:\Users\dev\bin\.bapstate\zsp`,
		`copy pepper.key x.txt`,
	} {
		if !CommandReferencesCredential(c) {
			t.Errorf("command naming BAP authority state must be refused: %q", c)
		}
	}
}

// The native Read/Grep/Glob/Write path must refuse authority state even when it lives INSIDE the
// workspace boundary (the case the old workspace check would have waved through), and for legacy
// clients that send no stable invocation ID.
func TestNativeToolsCannotReachAuthorityState(t *testing.T) {
	workspace := t.TempDir()
	zsp := filepath.Join(workspace, ".state", "zsp")
	t.Setenv("BAP_ZSP_DIR", zsp)
	digest, err := NativeToolInputDigest(map[string]string{"file_path": "x"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range []string{"Read", "Grep", "Glob", "Write", "Edit"} {
		for _, name := range []string{"pepper.key", "autoapprove.json", filepath.Join("approvals", "req-1.json")} {
			target := filepath.Join(zsp, name)
			for _, inv := range []NativeToolInvocation{{}, {ID: "toolu_1", InputDigest: digest}} {
				_, _, _, err := AuthorizeNativeToolInvocation(zsp, "sess-authority", "claude-code", tool, target, workspace, inv)
				if !errors.Is(err, ErrResourceNotGranted) {
					t.Errorf("%s %s (invocation id %q) must be refused as authority state, got %v", tool, name, inv.ID, err)
				}
			}
		}
	}
}

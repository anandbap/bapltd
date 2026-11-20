package main

import (
	"path/filepath"
	"testing"
)

// Golden vectors shared with bap-edge/internal/authz/authority_paths_test.go (keep in sync).
func TestAuthorityPathGoldenVectors(t *testing.T) {
	zsp := filepath.Join(t.TempDir(), "custom-zsp")
	t.Setenv("BAP_ZSP_DIR", zsp)
	t.Setenv("BAP_STATE_DIR", "")

	for _, p := range []string{
		`C:\Users\dev\bin\.bapstate\zsp\pepper.key`,
		`C:\Users\DEV\BIN\.BAPSTATE\ZSP\grants\g-1.json`,
		`~/bin/.bapstate/zsp/approvals/req-ab12cd34.json`,
		`../../bin/.bapstate/zsp`,
		`.bapstate/zsp/autoapprove.json`,
		`pepper.key`,
		`PEPPER.KEY.`,
		`somewhere/autoapprove.json::$DATA`,
		`C:\Users\dev\AppData\Local\Temp\bapstate\zsp\pepper.key`,
		zsp,
		filepath.Join(zsp, "approvals", "req-1.json"),
	} {
		if !isBAPAuthorityPath(p) || !looksLikeCredentialPath(p) {
			t.Errorf("%q must be refused as BAP authority state", p)
		}
	}
	for _, p := range []string{
		``,
		`src/main.go`,
		`docs/zsp.md`,
		`docs/approvals.md`,
		`.bapstate/shims-abc/git.cmd`,
		`C:\Users\dev\bin\.bapstate\sessions\pid-1.json`,
		`test-runtime-tmp/bapstate206180543/policy/policy.cedar`,
		`workspace://current`,
	} {
		if isBAPAuthorityPath(p) {
			t.Errorf("%q must not be treated as BAP authority state", p)
		}
	}
}

func TestAuthorityDirNeverMatchesFilesystemRoot(t *testing.T) {
	t.Setenv("BAP_ZSP_DIR", string(filepath.Separator))
	t.Setenv("BAP_STATE_DIR", "")
	if isBAPAuthorityPath(filepath.Join(t.TempDir(), "main.go")) {
		t.Fatal("a root-level state directory must not protect every path")
	}
}

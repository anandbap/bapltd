//go:build !devoverride

package cmd

import "testing"

// requireDevOverrideBuild skips tests that exercise the developer override itself. Default builds
// (CI, release, anyone but a local developer) compile the override out, so those tests cannot run.
// Run them locally with: go test -tags devoverride ./...
func requireDevOverrideBuild(t *testing.T) {
	t.Helper()
	t.Skip("developer override is compiled out of this build; run with -tags devoverride on a developer machine")
}

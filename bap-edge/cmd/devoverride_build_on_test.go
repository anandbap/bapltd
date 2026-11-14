//go:build devoverride

package cmd

import "testing"

// requireDevOverrideBuild is a no-op in developer-override builds (-tags devoverride).
func requireDevOverrideBuild(t *testing.T) { t.Helper() }

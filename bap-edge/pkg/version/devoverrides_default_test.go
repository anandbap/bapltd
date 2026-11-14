//go:build !devoverride

package version

import "testing"

// Guard: a default (production-shaped) build must never allow developer override, even if the
// runtime flag is forced to "true" (e.g. a missing or wrong -ldflags on a release build).
func TestDevOverridesNeverAllowedInDefaultBuild(t *testing.T) {
	orig := AllowDevOverrides
	defer func() { AllowDevOverrides = orig }()
	for _, v := range []string{"true", "TRUE", " true ", "1", "on", ""} {
		AllowDevOverrides = v
		if DevOverridesAllowed() {
			t.Fatalf("DevOverridesAllowed() = true with flag %q in a build without -tags devoverride", v)
		}
	}
	if Get("bapedge").AllowDevOverrides {
		t.Fatal("version info must report dev overrides as disabled in a default build")
	}
}

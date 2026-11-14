//go:build !devoverride

package version

// devOverridesCompiledIn is false in every default build (production, CI, release, wheel).
// Developer override is a constant-false path here, not a flag that can be flipped.
const devOverridesCompiledIn = false

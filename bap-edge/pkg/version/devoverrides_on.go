//go:build devoverride

package version

// devOverridesCompiledIn is true ONLY in local developer builds made with `-tags devoverride`.
// CI, release and wheel builds never pass this tag, so developer override cannot be enabled there
// no matter what flags, environment variables or marker files are present.
const devOverridesCompiledIn = true

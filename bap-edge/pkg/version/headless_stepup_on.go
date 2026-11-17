//go:build headlessstepup

package version

// headlessStepUpCompiledIn is true only for test-harness builds (`-tags headlessstepup`).
// Official release and developer-distribution builds never set this tag (BAP-1096).
const headlessStepUpCompiledIn = true

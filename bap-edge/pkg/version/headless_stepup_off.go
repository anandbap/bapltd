//go:build !headlessstepup

package version

// headlessStepUpCompiledIn is false in every build that is not a tagged test harness.
const headlessStepUpCompiledIn = false

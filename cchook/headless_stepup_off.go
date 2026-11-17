//go:build !headlessstepup

package main

// headlessStepUpCompiledIn is false in every build that is not a tagged test harness.
const headlessStepUpCompiledIn = false

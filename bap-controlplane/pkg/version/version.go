package version

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"
)

var (
	// Version is the semantic release version (e.g. "v1.0.0").
	// Injected at compile-time via -ldflags "-X 'bap-controlplane/pkg/version.Version=...'"
	Version = "v1.1.2"

	// GitCommit is the git SHA hash.
	GitCommit = "dev"

	// BuildDate is the UTC build timestamp in RFC3339.
	BuildDate = "unknown"
)

type Info struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	GitCommit string `json:"git_commit"`
	BuildDate string `json:"build_date"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

func Get(component string) Info {
	return Info{
		Component: component,
		Version:   Version,
		GitCommit: GitCommit,
		BuildDate: BuildDate,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
}

func (i Info) String() string {
	return fmt.Sprintf("%s %s (commit: %s, built: %s, %s/%s, %s)",
		i.Component, i.Version, i.GitCommit, i.BuildDate, i.OS, i.Arch, i.GoVersion)
}

func (i Info) JSON() string {
	b, _ := json.MarshalIndent(i, "", "  ")
	return string(b)
}

// Compare compares two semantic versions (e.g. "v1.0.0" vs "v1.1.0").
// Returns -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2.
// "dev" is treated as matching (0) for development convenience.
func Compare(v1, v2 string) int {
	clean1 := strings.TrimPrefix(strings.TrimSpace(v1), "v")
	clean2 := strings.TrimPrefix(strings.TrimSpace(v2), "v")

	if clean1 == "dev" || clean2 == "dev" || clean1 == "" || clean2 == "" {
		return 0
	}

	parts1 := parseSemVerParts(clean1)
	parts2 := parseSemVerParts(clean2)

	for i := 0; i < 3; i++ {
		if parts1[i] < parts2[i] {
			return -1
		}
		if parts1[i] > parts2[i] {
			return 1
		}
	}
	return 0
}

func parseSemVerParts(s string) [3]int {
	idx := strings.IndexAny(s, "-+")
	if idx != -1 {
		s = s[:idx]
	}
	parts := strings.Split(s, ".")
	var res [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		res[i], _ = strconv.Atoi(parts[i])
	}
	return res
}

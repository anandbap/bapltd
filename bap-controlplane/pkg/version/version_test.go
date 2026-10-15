package version

import (
	"encoding/json"
	"testing"
)

func TestVersionCompare(t *testing.T) {
	tests := []struct {
		v1   string
		v2   string
		want int
	}{
		{"v1.0.0", "v1.0.0", 0},
		{"1.0.0", "1.0.0", 0},
		{"v1.0.1", "v1.0.0", 1},
		{"v1.0.0", "v1.0.1", -1},
		{"v1.1.0", "v1.0.9", 1},
		{"v2.0.0", "v1.9.9", 1},
		{"v1.0.0-rc1", "v1.0.0", 0},
		{"dev", "v1.0.0", 0},
		{"v1.0.0", "dev", 0},
		{"", "v1.0.0", 0},
	}

	for _, tc := range tests {
		got := Compare(tc.v1, tc.v2)
		if got != tc.want {
			t.Errorf("Compare(%q, %q) = %d; want %d", tc.v1, tc.v2, got, tc.want)
		}
	}
}

func TestVersionInfo(t *testing.T) {
	info := Get("bapcontrolplane")
	if info.Component != "bapcontrolplane" {
		t.Errorf("expected component bapcontrolplane, got %s", info.Component)
	}
	if info.Version == "" {
		t.Errorf("expected non-empty version")
	}

	jsonStr := info.JSON()
	var parsed Info
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("failed to parse version JSON: %v", err)
	}
	if parsed.Component != "bapcontrolplane" {
		t.Errorf("expected parsed component bapcontrolplane, got %s", parsed.Component)
	}
}

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLayerStatusLinesNeverClaimUnseenLayers(t *testing.T) {
	lines := layerStatusLines(map[string]bool{})
	if !strings.Contains(lines[0], "NOT_OBSERVED") || !strings.Contains(lines[1], "NOT_OBSERVED") || !strings.Contains(lines[4], "NOT_OBSERVED") {
		t.Fatalf("unseen layers must not be reported observed: %v", lines)
	}
	if !strings.Contains(lines[3], "AVAILABLE") {
		t.Fatalf("broker without events is only available: %v", lines[3])
	}
}

func TestLayerStatusNamesLikelyHookProblem(t *testing.T) {
	lines := layerStatusLines(map[string]bool{"mcp": true})
	if !strings.Contains(lines[0], "unapproved or disabled") || !strings.Contains(lines[1], "OBSERVED") {
		t.Fatalf("expected degraded hook hint: %v", lines)
	}
}

func TestObservedLayersFromSpoolAndHeartbeat(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("BAP_STATE_DIR", "")
	log := filepath.Join(dir, "audit.jsonl")
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	body := `{"reporting_layer":"broker","timestamp":"` + now.Format(time.RFC3339Nano) + `"}` + "\n" +
		`{"reporting_layer":"gateway","timestamp":"` + old.Format(time.RFC3339Nano) + `"}` + "\n" +
		"not json\n"
	if err := os.WriteFile(log, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "hook-heartbeat"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "hook-heartbeat", "s1"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	got := observedLayers(log)
	if !got["broker"] || !got["hook"] {
		t.Fatalf("broker and hook should be observed: %v", got)
	}
	if got["gateway"] {
		t.Fatalf("stale evidence older than 24h must not count: %v", got)
	}
}

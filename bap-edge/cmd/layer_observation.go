package cmd

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const (
	layerEvidenceWindow = 24 * time.Hour
	hookHeartbeatWindow = 15 * time.Minute
	auditTailBytes      = 1 << 20 // read at most the last 1 MiB of the spool
)

// observedLayers reports which reporting layers have produced real local evidence:
// recent hook heartbeats, and reporting_layer values in the tail of the audit spool.
// "Observed" means events were seen; it never means every action is intercepted.
func observedLayers(auditLogPath string) map[string]bool {
	seen := map[string]bool{}
	now := time.Now()

	dirs := []string{}
	if auditLogPath != "" {
		dirs = append(dirs, filepath.Dir(auditLogPath))
	}
	if d := os.Getenv("BAP_STATE_DIR"); d != "" {
		dirs = append(dirs, d)
	}
	for _, d := range dirs {
		entries, err := os.ReadDir(filepath.Join(d, "hook-heartbeat"))
		if err != nil {
			continue
		}
		for _, e := range entries {
			if info, err := e.Info(); err == nil && !e.IsDir() && now.Sub(info.ModTime()) <= hookHeartbeatWindow {
				seen["hook"] = true
			}
		}
	}

	if auditLogPath == "" {
		return seen
	}
	f, err := os.Open(auditLogPath)
	if err != nil {
		return seen
	}
	defer f.Close()
	size, err := f.Seek(0, 2)
	if err != nil {
		return seen
	}
	start := int64(0)
	if size > auditTailBytes {
		start = size - auditTailBytes
	}
	if _, err := f.Seek(start, 0); err != nil {
		return seen
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	first := true
	for sc.Scan() {
		line := sc.Bytes()
		if first && start > 0 {
			first = false // partial line at the seek boundary
			continue
		}
		first = false
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var rec struct {
			ReportingLayer string `json:"reporting_layer"`
			Timestamp      string `json:"timestamp"`
		}
		if json.Unmarshal(line, &rec) != nil || rec.ReportingLayer == "" {
			continue
		}
		if ts, err := time.Parse(time.RFC3339Nano, rec.Timestamp); err == nil && now.Sub(ts) > layerEvidenceWindow {
			continue
		}
		seen[rec.ReportingLayer] = true
	}
	return seen
}

// layerStatusLines renders the five-layer section. A layer is OBSERVED only after real events.
// When Layer 1 is silent but a lower layer is reporting, the likely cause is named.
func layerStatusLines(seen map[string]bool) []string {
	lower := seen["mcp"] || seen["shim"] || seen["broker"] || seen["gateway"]
	line := func(label, layer, hint string) string {
		if seen[layer] {
			return fmt.Sprintf("    %s: OBSERVED - events received", label)
		}
		return fmt.Sprintf("    %s: NOT_OBSERVED - %s", label, hint)
	}
	l1 := line("Layer 1 (Native Hooks)", "hook", "verify approval and received callbacks")
	if !seen["hook"] && lower {
		l1 = "    Layer 1 (Native Hooks): NOT_OBSERVED - hooks may be unapproved or disabled; lower layers are reporting"
	}
	l4 := "    Layer 4 (Broker): AVAILABLE - OS-wide enforcement is not attested here"
	if seen["broker"] {
		l4 = "    Layer 4 (Broker): OBSERVED - broker events received (OS-wide enforcement is not attested here)"
	}
	return []string{
		l1,
		line("Layer 2 (BAP MCP)", "mcp", "verify calls routed through BAP tools"),
		line("Layer 3 (Terminal Shims)", "shim", "verify actual shim-routed commands"),
		l4,
		line("Layer 5 (Gateway PEP)", "gateway", "verify protected resource events"),
	}
}

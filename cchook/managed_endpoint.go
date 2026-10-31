package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var hookManagedDir = func() string {
	if runtime.GOOS == "windows" {
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "BAP")
		}
		return ""
	}
	return "/etc/bap"
}

func managedHookEndpoint() (string, bool) {
	dir := hookManagedDir()
	if dir == "" {
		return "", false
	}
	for _, name := range []string{"config.json", "bap-config.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			continue
		}
		var cfg map[string]any
		if json.Unmarshal(data, &cfg) != nil {
			continue
		}
		locked, _ := cfg["lock_endpoints"].(bool)
		environment, _ := cfg["environment"].(string)
		if !locked && !strings.EqualFold(strings.TrimSpace(environment), "production") {
			return "", false
		}
		endpoint := ""
		for _, key := range []string{"controlplane_url", "control_plane_url", "server_url", "server", "controlplane", "controlPlaneUrl"} {
			if v, ok := cfg[key].(string); ok && v != "" {
				endpoint = v
				break
			}
		}
		var bg struct {
			URL       string `json:"controlplane_url"`
			Operator  string `json:"operator"`
			Reason    string `json:"reason"`
			ExpiresAt string `json:"expires_at"`
		}
		if data, err := os.ReadFile(filepath.Join(dir, "breakglass.json")); err == nil && json.Unmarshal(data, &bg) == nil {
			exp, err := time.Parse(time.RFC3339, bg.ExpiresAt)
			now := time.Now()
			if err == nil && exp.After(now) && !exp.After(now.Add(24*time.Hour)) && bg.Operator != "" && bg.Reason != "" && strings.TrimSpace(bg.URL) != "" {
				endpoint = bg.URL
			}
		}
		return strings.TrimRight(endpoint, "/"), true
	}
	return "", false
}

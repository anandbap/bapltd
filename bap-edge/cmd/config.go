package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bap-edge/internal/config"
	"bap-edge/internal/state"
)

// RunConfig handles `bapedge config` commands.
func RunConfig(args []string) error {
	if len(args) == 0 || args[0] == "show" {
		cfg := config.ResolveEndpoints()
		fmt.Println("===============================================================================")
		fmt.Println("   BAP (Bounded Authority Plane) - Central Endpoint Configuration")
		fmt.Println("===============================================================================")
		fmt.Printf("Control Plane Host (bapcontrolplane) : %s\n", cfg.ControlPlaneURL)
		fmt.Printf("API Gateway PEP (bapgateway / Envoy) : %s\n", cfg.GatewayURL)
		fmt.Printf("Envoy Container Gateway              : %s\n", cfg.EnvoyURL)
		fmt.Printf("SPIFFE Trust Domain                  : %s\n", cfg.TrustDomain)
		fmt.Printf("Active Environment                   : %s\n", cfg.Environment)
		fmt.Printf("Enforcement Mode                     : %s\n", cfg.EnforcementMode)
		fmt.Printf("Resolved From Source                 : %s\n", cfg.ConfigSource)
		if cfg.Locked {
			fmt.Println("Endpoint Lock                        : LOCKED by managed config (env vars, project and user files are ignored)")
		}
		if cfg.Override != "" {
			fmt.Printf("Override                             : %s\n", cfg.Override)
		}
		fmt.Println("===============================================================================")
		fmt.Println("To update: bapedge config set [--server <url>] [--gateway <url>] [--mode audit|enforce] [--global]")
		return nil
	}

	if args[0] == "set" {
		fs := flag.NewFlagSet("config set", flag.ContinueOnError)
		server := fs.String("server", "", "Central BAP Control Plane URL (e.g. https://bap.corp.internal:8080)")
		gateway := fs.String("gateway", "", "API Gateway PEP URL (e.g. https://gateway.corp.internal:9090)")
		envoy := fs.String("envoy", "", "Envoy Gateway URL (e.g. http://envoy.corp.internal:10000)")
		mode := fs.String("mode", "", "Enforcement mode: 'enforce' (block violations) or 'audit' (log violations as shadow_deny and permit)")
		global := fs.Bool("global", false, "Write to user home directory (~/.bap/config.json) instead of current repository")

		if err := fs.Parse(args[1:]); err != nil {
			return err
		}

		cfg := config.ResolveEndpoints()
		if cfg.Locked {
			return fmt.Errorf("endpoints are locked by managed config (%s); local changes would be ignored. Ask your administrator to update the managed config", cfg.ConfigSource)
		}
		if *mode != "" {
			m := strings.ToLower(strings.TrimSpace(*mode))
			if m != "audit" && m != "enforce" {
				return fmt.Errorf("invalid --mode %q: use 'audit' or 'enforce'", *mode)
			}
			cfg.EnforcementMode = m
		}
		if *server != "" {
			cfg.ControlPlaneURL = *server
		}
		if *gateway != "" {
			cfg.GatewayURL = *gateway
		}
		if *envoy != "" {
			cfg.EnvoyURL = *envoy
		}

		// Support positional key-value pairs like `bapedge config set server <url>` or `bapedge config set mode audit`
		remaining := fs.Args()
		for i := 0; i < len(remaining); i++ {
			key := strings.ToLower(strings.TrimPrefix(remaining[i], "--"))
			key = strings.TrimPrefix(key, "-")
			if i+1 < len(remaining) {
				val := remaining[i+1]
				switch key {
				case "server", "controlplane", "control_plane", "controlplane_url", "cp":
					cfg.ControlPlaneURL = val
					i++
				case "gateway", "pep", "gateway_url":
					cfg.GatewayURL = val
					i++
				case "envoy", "envoy_url":
					cfg.EnvoyURL = val
					i++
				case "mode", "enforcement_mode":
					m := strings.ToLower(strings.TrimSpace(val))
					if m != "audit" && m != "enforce" {
						return fmt.Errorf("invalid mode %q: use 'audit' or 'enforce'", val)
					}
					cfg.EnforcementMode = m
					i++
				}
			}
		}

		home, _ := os.UserHomeDir()
		var syncedLocations []string

		targetFile := "bap-config.json"
		if *global {
			if home == "" {
				return fmt.Errorf("could not determine user home directory")
			}
			targetFile = filepath.Join(home, ".bap", "config.json")
		}

		if err := config.SaveConfig(cfg, targetFile); err != nil {
			return fmt.Errorf("failed to save configuration to %s: %w", targetFile, err)
		}
		syncedLocations = append(syncedLocations, targetFile)

		// Synchronize central installation locations
		// 1. ~/.bapstate/config.json (authoritative state cache)
		statePath := state.ConfigPath()
		if statePath != "" && statePath != targetFile {
			if *global || fileExists(statePath) {
				if err := config.SaveConfig(cfg, statePath); err == nil {
					syncedLocations = append(syncedLocations, statePath)
				}
			}
		}

		// 2. User installed bin directory: ~/bin/bap-config.json
		if home != "" {
			userBinCfg := filepath.Join(home, "bin", "bap-config.json")
			if userBinCfg != targetFile {
				// Save if --global, or if ~/bin exists, or if ~/bin/bap-config.json already exists
				if *global || dirExists(filepath.Join(home, "bin")) || fileExists(userBinCfg) {
					if err := config.SaveConfig(cfg, userBinCfg); err == nil {
						syncedLocations = append(syncedLocations, userBinCfg)
					}
				}
			}
			// 3. ~/.bap/config.json and ~/.bap/bap-config.json
			dotBapCfg := filepath.Join(home, ".bap", "config.json")
			if dotBapCfg != targetFile {
				if *global || dirExists(filepath.Join(home, ".bap")) || fileExists(dotBapCfg) {
					if err := config.SaveConfig(cfg, dotBapCfg); err == nil {
						syncedLocations = append(syncedLocations, dotBapCfg)
					}
				}
			}
			dotBapBapCfg := filepath.Join(home, ".bap", "bap-config.json")
			if dotBapBapCfg != targetFile && (*global || fileExists(dotBapBapCfg)) {
				_ = config.SaveConfig(cfg, dotBapBapCfg)
			}
		}

		// 4. Executable directory if bapedge is running from an installed path (e.g. C:\Users\User\bin)
		if exe, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exe)
			exeCfg := filepath.Join(exeDir, "bap-config.json")
			if exeCfg != targetFile && !containsStr(syncedLocations, exeCfg) && fileExists(exeCfg) {
				if err := config.SaveConfig(cfg, exeCfg); err == nil {
					syncedLocations = append(syncedLocations, exeCfg)
				}
			}
		}

		// 5. If not global, also keep .bap/config.json in cwd in sync if it exists
		if !*global {
			dotBapLocal := filepath.Join(".bap", "config.json")
			if dotBapLocal != targetFile && fileExists(dotBapLocal) {
				if err := config.SaveConfig(cfg, dotBapLocal); err == nil {
					syncedLocations = append(syncedLocations, dotBapLocal)
				}
			}
		}

		fmt.Printf("[+] Central BAP configuration successfully saved to %s\n", targetFile)
		for _, loc := range syncedLocations {
			if loc != targetFile {
				fmt.Printf("    - Synced central cache: %s\n", loc)
			}
		}
		fmt.Printf("    - Control Plane URL : %s\n", cfg.ControlPlaneURL)
		fmt.Printf("    - Gateway PEP URL   : %s\n", cfg.GatewayURL)
		fmt.Printf("    - Enforcement mode  : %s\n", cfg.EnforcementMode)
		return nil
	}

	return fmt.Errorf("unknown config action %q. Usage: bapedge config [show|set] (e.g. bapedge config set --mode audit)", args[0])
}

func fileExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && !info.IsDir()
}

func dirExists(p string) bool {
	info, err := os.Stat(p)
	return err == nil && info.IsDir()
}

func containsStr(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

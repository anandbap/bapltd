package cmd

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bap-edge/internal/config"
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

		targetFile := "bap-config.json"
		if *global {
			home, err := os.UserHomeDir()
			if err != nil {
				return fmt.Errorf("could not determine user home directory: %w", err)
			}
			targetFile = filepath.Join(home, ".bap", "config.json")
		}

		if err := config.SaveConfig(cfg, targetFile); err != nil {
			return fmt.Errorf("failed to save configuration to %s: %w", targetFile, err)
		}

		fmt.Printf("[+] Central BAP configuration successfully saved to %s\n", targetFile)
		fmt.Printf("    - Control Plane URL : %s\n", cfg.ControlPlaneURL)
		fmt.Printf("    - Gateway PEP URL   : %s\n", cfg.GatewayURL)
		fmt.Printf("    - Enforcement mode  : %s\n", cfg.EnforcementMode)
		return nil
	}

	return fmt.Errorf("unknown config action %q. Usage: bapedge config [show|set] (e.g. bapedge config set --mode audit)", args[0])
}

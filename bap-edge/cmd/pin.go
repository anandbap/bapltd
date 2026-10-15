package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"bap-edge/internal/authz"
	"bap-edge/internal/pinning"
)

// RunPin handles the 'pin' subcommand for content pinning and dynamic tool attestation (BAP-531).
func RunPin(args []string) error {
	if len(args) == 0 {
		printPinUsage()
		return nil
	}

	sub := args[0]
	subArgs := args[1:]

	manifestPath := pinning.LocalManifestPath()
	if _, err := os.Stat(manifestPath); os.IsNotExist(err) {
		manifestPath = pinning.DefaultManifestPath()
	}

	switch sub {
	case "list":
		return runPinList(subArgs, manifestPath)
	case "verify", "check":
		return runPinVerify(subArgs, manifestPath)
	case "update":
		return runPinUpdate(subArgs, manifestPath)
	case "add":
		return runPinAdd(subArgs, manifestPath)
	case "scan":
		return runPinScan(subArgs, manifestPath)
	case "unpin":
		return runPinUnpin(subArgs, manifestPath)
	case "clear":
		return runPinClear(subArgs, manifestPath)
	case "reset":
		return runPinReset(subArgs, manifestPath)
	default:
		printPinUsage()
		return fmt.Errorf("unknown pin subcommand: %s", sub)
	}
}

func printPinUsage() {
	fmt.Println("Usage: bapedge pin <subcommand> [options]")
	fmt.Println("\nSubcommands:")
	fmt.Println("  list              List all cryptographically pinned skills, prompts, and MCP tools")
	fmt.Println("  verify            Verify pinned assets against current disk state (AIR attestation)")
	fmt.Println("  update            Re-attest and update hash after approved modification")
	fmt.Println("  add <path>        Pin a specific skill file, prompt template, or script")
	fmt.Println("  unpin <id>        Remove a pinned asset (or --all to unpin everything)")
	fmt.Println("  clear             Clear all pins from the manifest to start fresh")
	fmt.Println("  reset             Clear manifest and re-discover workspace skills with agent scoping")
	fmt.Println("  scan              Auto-discover and pin workspace skills and configuration manifests")
	fmt.Println("\nExamples:")
	fmt.Println("  bapedge pin scan")
	fmt.Println("  bapedge pin verify")
	fmt.Println("  bapedge pin verify --scope antigravity")
	fmt.Println("  bapedge pin add .claude/skills/deploy/SKILL.md --id skill:deploy --scope claude-code")
	fmt.Println("  bapedge pin update skill:deploy")
	fmt.Println("  bapedge pin unpin skill:deploy")
	fmt.Println("  bapedge pin clear")
	fmt.Println("  bapedge pin reset")
}

func runPinList(args []string, manifestPath string) error {
	fs := flag.NewFlagSet("pin list", flag.ContinueOnError)
	jsonFlag := fs.Bool("json", false, "Output list as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}

	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}

	if *jsonFlag {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(manifest)
	}

	fmt.Println("================================================================================")
	fmt.Println("  [BAP AIR MODEL] 📌 Cryptographically Pinned Assets & Tool Manifests")
	fmt.Println("================================================================================")
	fmt.Printf("  Manifest Source: %s\n", manifestPath)
	fmt.Printf("  Total Pinned:    %d asset(s)\n", len(manifest.Assets))
	fmt.Println("--------------------------------------------------------------------------------")

	if len(manifest.Assets) == 0 {
		fmt.Println("  (No pinned assets found. Run 'bapedge pin scan' to discover workspace skills)")
		fmt.Println("================================================================================")
		return nil
	}

	for id, a := range manifest.Assets {
		scope := a.AgentScope
		if scope == "" {
			scope = "all"
		}
		fmt.Printf("  • ID:            %s\n", id)
		fmt.Printf("    Type:          %s\n", a.AssetType)
		fmt.Printf("    Scope:         %s\n", scope)
		fmt.Printf("    Path:          %s\n", a.Path)
		fmt.Printf("    Pinned Digest: %s\n", a.ExpectedHash)
		fmt.Printf("    Attested:      %s by %s\n", a.AttestedAt.Format("2006-01-02 15:04:05 UTC"), a.AttestedBy)
		fmt.Println("    ----------------------------------------------------------------------------")
	}
	fmt.Println("================================================================================")
	return nil
}

func runPinVerify(args []string, manifestPath string) error {
	fs := flag.NewFlagSet("pin verify", flag.ContinueOnError)
	jsonFlag := fs.Bool("json", false, "Output verification results as JSON")
	scopeFlag := fs.String("scope", "", "Filter verification to specific agent scope (e.g. antigravity, claude-code, copilot, all)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}

	allResults := manifest.VerifyAll()
	var results []pinning.VerificationResult
	for _, r := range allResults {
		if *scopeFlag == "" || pinning.IsAssetInAgentScope(r.Asset.AgentScope, *scopeFlag) {
			results = append(results, r)
		}
	}

	driftCount := 0
	cleanCount := 0

	for _, r := range results {
		if !r.Matches {
			driftCount++
		} else {
			cleanCount++
		}
	}

	if *jsonFlag {
		output := map[string]interface{}{
			"verified":    cleanCount,
			"drifted":     driftCount,
			"clean":       driftCount == 0,
			"results":     results,
			"scope":       *scopeFlag,
			"manifest":    manifestPath,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(output)
		if driftCount > 0 {
			return fmt.Errorf("content hash mismatch detected across %d asset(s)", driftCount)
		}
		return nil
	}

	fmt.Println("================================================================================")
	fmt.Println("  [BAP AIR MODEL] 🛡️  Cryptographic Tool & Skill Content Verification")
	fmt.Println("================================================================================")
	if *scopeFlag != "" {
		fmt.Printf("  Agent Filter: %s\n", *scopeFlag)
	}
	fmt.Printf("  Verified:     %d clean, %d drifted (Total in scope: %d)\n", cleanCount, driftCount, len(results))
	fmt.Println("--------------------------------------------------------------------------------")

	for _, r := range results {
		scope := r.Asset.AgentScope
		if scope == "" {
			scope = "all"
		}
		if r.Matches {
			fmt.Printf("  [✓] MATCH:   %s [scope:%s] (%s)\n", r.Asset.ID, scope, r.Asset.ExpectedHash[:19]+"...")
		} else {
			fmt.Printf("  [!] DRIFT:   🚨 %s [scope:%s]\n", r.Asset.ID, scope)
			fmt.Printf("      Path:     %s\n", r.Asset.Path)
			fmt.Printf("      Expected: %s\n", r.Asset.ExpectedHash)
			fmt.Printf("      Actual:   %s\n", r.CurrentHash)
			fmt.Printf("      Reason:   %s\n", r.Error)
		}
	}
	fmt.Println("================================================================================")

	if driftCount > 0 {
		fmt.Printf("  ⛔ SECURITY ALERT: %d asset(s) modified or tampered with on disk.\n", driftCount)
		fmt.Println("     Re-attestation required via 'bapedge pin update <id>' before execution.")
		fmt.Println("================================================================================")
		return fmt.Errorf("content hash mismatch: %d asset(s) drifted", driftCount)
	}

	fmt.Println("  ✅ All pinned skills, prompts, and tool manifests in scope are intact and verified.")
	fmt.Println("================================================================================")
	return nil
}

func runPinUpdate(args []string, manifestPath string) error {
	fs := flag.NewFlagSet("pin update", flag.ContinueOnError)
	allFlag := fs.Bool("all", false, "Re-attest and update all registered assets")
	if err := fs.Parse(args); err != nil {
		return err
	}

	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}

	targetIDs := fs.Args()
	if *allFlag {
		targetIDs = nil
		for id := range manifest.Assets {
			targetIDs = append(targetIDs, id)
		}
	}

	if len(targetIDs) == 0 {
		return fmt.Errorf("specify an asset ID to update or pass --all. See 'bapedge pin list'")
	}

	updated := 0
	for _, id := range targetIDs {
		asset, exists := manifest.Assets[id]
		if !exists {
			fmt.Printf("  [!] Asset %q not found in manifest\n", id)
			continue
		}
		newAsset, err := manifest.PinFileWithScope(id, asset.AssetType, asset.Path, "manual_re_attestation", asset.AgentScope, asset.Metadata)
		if err != nil {
			fmt.Printf("  [!] Failed to re-attest %s: %v\n", id, err)
			continue
		}
		fmt.Printf("  [✓] Updated %s -> %s\n", id, newAsset.ExpectedHash)
		updated++
	}

	if err := pinning.SaveManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("failed to save manifest: %w", err)
	}

	fmt.Printf("\n✅ Successfully re-attested and pinned %d asset(s) in %s\n", updated, manifestPath)
	return nil
}

func runPinAdd(args []string, manifestPath string) error {
	fs := flag.NewFlagSet("pin add", flag.ContinueOnError)
	idFlag := fs.String("id", "", "Custom asset ID (defaults to <type>:<basename>)")
	typeFlag := fs.String("type", "skill", "Asset type: skill, mcp_tool, prompt, or script")
	scopeFlag := fs.String("scope", "", "Agent scope: all, antigravity, claude-code, copilot, cursor")
	var flagArgs, posArgs []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flagArgs = append(flagArgs, arg)
			if !strings.Contains(arg, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flagArgs = append(flagArgs, args[i])
			}
		} else {
			posArgs = append(posArgs, arg)
		}
	}
	reordered := append(flagArgs, posArgs...)
	if err := fs.Parse(reordered); err != nil {
		return err
	}

	if len(fs.Args()) == 0 {
		return fmt.Errorf("missing file path to pin. Usage: bapedge pin add <file_path> [--id <name>] [--scope <agent>]")
	}

	targetPath := fs.Args()[0]
	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}

	scope := strings.TrimSpace(*scopeFlag)
	if scope == "" {
		lowerPath := strings.ToLower(filepath.ToSlash(targetPath))
		if strings.Contains(lowerPath, "claude") {
			scope = "claude-code"
		} else if strings.Contains(lowerPath, "antigravity") || strings.Contains(lowerPath, "gemini") {
			scope = "antigravity"
		} else if strings.Contains(lowerPath, "copilot") || strings.Contains(lowerPath, "agents.md") {
			scope = "copilot"
		} else if strings.Contains(lowerPath, "cursor") {
			scope = "cursor"
		} else {
			scope = "all"
		}
	}

	asset, err := manifest.PinFileWithScope(*idFlag, *typeFlag, targetPath, "manual_pin", scope, nil)
	if err != nil {
		return err
	}

	if err := pinning.SaveManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("failed to save manifest: %w", err)
	}

	fmt.Printf("✅ Pinned %s (%s)\n", asset.ID, asset.Path)
	fmt.Printf("   Scope:  %s\n", asset.AgentScope)
	fmt.Printf("   Digest: %s\n", asset.ExpectedHash)
	return nil
}

func runPinScan(args []string, manifestPath string) error {
	fs := flag.NewFlagSet("pin scan", flag.ContinueOnError)
	dirFlag := fs.String("dir", ".", "Directory root to scan for skills, manifests, and prompt templates")
	if err := fs.Parse(args); err != nil {
		return err
	}

	workspace := *dirFlag
	if workspace == "." {
		workspace = authz.GetWorkspaceRoot()
		if workspace == "" {
			workspace = "."
		}
	}

	fmt.Printf("[*] Scanning workspace %s for skills, prompts, and MCP configurations...\n", workspace)
	discovered, err := pinning.DiscoverAssets(workspace)
	if err != nil {
		return err
	}

	if len(discovered) == 0 {
		fmt.Println("  No unpinned skills or manifests discovered.")
		return nil
	}

	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}

	count := 0
	for _, a := range discovered {
		manifest.Assets[a.ID] = a
		fmt.Printf("  [+] Pinned %s [scope:%s] -> %s (%s)\n", a.ID, a.AgentScope, a.Path, a.ExpectedHash[:19]+"...")
		count++
	}

	if err := pinning.SaveManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("failed to save manifest: %w", err)
	}

	fmt.Printf("\n✅ Successfully discovered and pinned %d asset(s) with agent scoping to %s\n", count, manifestPath)
	return nil
}

func runPinUnpin(args []string, manifestPath string) error {
	fs := flag.NewFlagSet("pin unpin", flag.ContinueOnError)
	allFlag := fs.Bool("all", false, "Unpin all registered assets from manifest")
	if err := fs.Parse(args); err != nil {
		return err
	}

	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}

	if *allFlag {
		count := len(manifest.Assets)
		manifest.ClearAssets()
		if err := pinning.SaveManifest(manifest, manifestPath); err != nil {
			return fmt.Errorf("failed to save manifest: %w", err)
		}
		fmt.Printf("✅ Successfully unpinned all %d asset(s) from %s\n", count, manifestPath)
		return nil
	}

	targetIDs := fs.Args()
	if len(targetIDs) == 0 {
		return fmt.Errorf("specify an asset ID to unpin or pass --all. See 'bapedge pin list'")
	}

	unpinned := 0
	for _, id := range targetIDs {
		if manifest.RemoveAsset(id) {
			fmt.Printf("  [✓] Unpinned %s\n", id)
			unpinned++
		} else {
			fmt.Printf("  [!] Asset %q not found in manifest\n", id)
		}
	}

	if err := pinning.SaveManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("failed to save manifest: %w", err)
	}

	fmt.Printf("\n✅ Successfully unpinned %d asset(s) from %s\n", unpinned, manifestPath)
	return nil
}

func runPinClear(args []string, manifestPath string) error {
	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}
	count := len(manifest.Assets)
	manifest.ClearAssets()
	if err := pinning.SaveManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("failed to clear manifest: %w", err)
	}
	fmt.Printf("✅ Cleared %d pinned asset(s) from manifest: %s\n", count, manifestPath)
	return nil
}

func runPinReset(args []string, manifestPath string) error {
	fs := flag.NewFlagSet("pin reset", flag.ContinueOnError)
	dirFlag := fs.String("dir", ".", "Directory root to scan and reset")
	if err := fs.Parse(args); err != nil {
		return err
	}

	workspace := *dirFlag
	if workspace == "." {
		workspace = authz.GetWorkspaceRoot()
		if workspace == "" {
			workspace = "."
		}
	}

	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}
	manifest.ClearAssets()

	discovered, err := pinning.DiscoverAssets(workspace)
	if err != nil {
		return fmt.Errorf("discovery failed during reset: %w", err)
	}

	for _, a := range discovered {
		manifest.Assets[a.ID] = a
	}

	if err := pinning.SaveManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("failed to save reset manifest: %w", err)
	}

	fmt.Printf("✅ Pinned assets reset! Manifest re-initialized with %d auto-discovered asset(s) with agent scoping in %s\n", len(discovered), manifestPath)
	return nil
}

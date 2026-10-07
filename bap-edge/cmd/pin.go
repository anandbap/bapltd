package cmd

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

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
	fmt.Println("  scan              Auto-discover and pin workspace skills and configuration manifests")
	fmt.Println("\nExamples:")
	fmt.Println("  bapedge pin scan")
	fmt.Println("  bapedge pin verify")
	fmt.Println("  bapedge pin add .claude/skills/deploy/SKILL.md --id skill:deploy")
	fmt.Println("  bapedge pin update skill:deploy")
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
		fmt.Printf("  • ID:            %s\n", id)
		fmt.Printf("    Type:          %s\n", a.AssetType)
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}

	results := manifest.VerifyAll()
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
	fmt.Printf("  Verified: %d clean, %d drifted\n", cleanCount, driftCount)
	fmt.Println("--------------------------------------------------------------------------------")

	for _, r := range results {
		if r.Matches {
			fmt.Printf("  [✓] MATCH:   %s (%s)\n", r.Asset.ID, r.Asset.ExpectedHash[:19]+"...")
		} else {
			fmt.Printf("  [!] DRIFT:   🚨 %s\n", r.Asset.ID)
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

	fmt.Println("  ✅ All pinned skills, prompts, and tool manifests are intact and verified.")
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
		newAsset, err := manifest.PinFile(id, asset.AssetType, asset.Path, "manual_re_attestation", asset.Metadata)
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
	if err := fs.Parse(args); err != nil {
		return err
	}

	if len(fs.Args()) == 0 {
		return fmt.Errorf("missing file path to pin. Usage: bapedge pin add <file_path> [--id <name>]")
	}

	targetPath := fs.Args()[0]
	manifest, err := pinning.LoadManifest(manifestPath)
	if err != nil {
		return err
	}

	asset, err := manifest.PinFile(*idFlag, *typeFlag, targetPath, "manual_pin", nil)
	if err != nil {
		return err
	}

	if err := pinning.SaveManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("failed to save manifest: %w", err)
	}

	fmt.Printf("✅ Pinned %s (%s)\n", asset.ID, asset.Path)
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
		fmt.Printf("  [+] Pinned %s -> %s (%s)\n", a.ID, a.Path, a.ExpectedHash[:19]+"...")
		count++
	}

	if err := pinning.SaveManifest(manifest, manifestPath); err != nil {
		return fmt.Errorf("failed to save manifest: %w", err)
	}

	fmt.Printf("\n✅ Successfully discovered and pinned %d asset(s) to %s\n", count, manifestPath)
	return nil
}

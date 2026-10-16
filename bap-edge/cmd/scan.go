package cmd

import (
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"bap-edge/internal/pinning"
	"bap-edge/internal/scanner"
)

// RunScan implements the 'scan' subcommand for continuous add-on, skill, and configuration scanning (BAP-536).
func RunScan(args []string) error {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	jsonFlag := fs.Bool("json", false, "Output results in JSON format")
	failOn := fs.String("fail-on", "high", "Fail with exit code 1 on findings of specified severity or higher (critical, high, medium, low)")
	manifestFlag := fs.String("manifest", "", "Custom path to cryptographic pin manifest")
	fixFlag := fs.Bool("fix", false, "Automatically pin clean unpinned skills into manifest")
	var flags []string
	var positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if (arg == "--fail-on" || arg == "-fail-on" || arg == "--manifest" || arg == "-manifest") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				flags = append(flags, args[i+1])
				i++
			}
		} else {
			positional = append(positional, arg)
		}
	}

	if err := fs.Parse(flags); err != nil {
		return err
	}

	targetDir := "."
	if len(positional) > 0 {
		targetDir = positional[0]
	}

	absDir, err := filepath.Abs(targetDir)
	if err != nil {
		return fmt.Errorf("invalid directory %q: %w", targetDir, err)
	}

	sc := scanner.NewScanner(absDir, *manifestFlag)
	res, err := sc.Scan()
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Auto-fix if requested
	if *fixFlag && len(res.Vulnerabilities) > 0 {
		manifestPath := sc.ManifestPath
		manifest, _ := pinning.LoadManifest(manifestPath)
		if manifest == nil {
			manifest = pinning.NewManifest()
		}
		fixedCount := 0
		for _, v := range res.Vulnerabilities {
			if v.Category == scanner.CatUnpinnedAsset {
				fullPath := filepath.Join(absDir, v.TargetFile)
				hash, hErr := pinning.ComputeFileHash(fullPath)
				if hErr == nil {
					assetID := fmt.Sprintf("skill:%s", strings.TrimSuffix(filepath.Base(v.TargetFile), filepath.Ext(v.TargetFile)))
					manifest.Assets[assetID] = pinning.PinnedAsset{
						ID:           assetID,
						AssetType:    "skill",
						Path:         fullPath,
						ExpectedHash: hash,
						AttestedAt:   res.Timestamp,
						AttestedBy:   "bapedge scan --fix",
						AgentScope:   "all",
					}
					fixedCount++
				}
			}
		}
		if fixedCount > 0 {
			if err := pinning.SaveManifest(manifest, manifestPath); err == nil {
				if !*jsonFlag {
					fmt.Printf("  [✓] Auto-pinned %d clean unpinned assets into %s\n", fixedCount, manifestPath)
				}
				// Re-run scan to reflect fixes
				res, _ = sc.Scan()
			}
		}
	}

	if *jsonFlag {
		jsonOut, err := res.ToJSON()
		if err != nil {
			return err
		}
		fmt.Println(jsonOut)
	} else {
		fmt.Print(res.FormatTerminal())
	}

	// Determine if exit error should be triggered
	threshold := strings.ToLower(strings.TrimSpace(*failOn))
	shouldFail := false
	for _, v := range res.Vulnerabilities {
		vSev := strings.ToLower(string(v.Severity))
		switch threshold {
		case "critical":
			if vSev == "critical" {
				shouldFail = true
			}
		case "high":
			if vSev == "critical" || vSev == "high" {
				shouldFail = true
			}
		case "medium":
			if vSev == "critical" || vSev == "high" || vSev == "medium" {
				shouldFail = true
			}
		case "low":
			shouldFail = true
		}
		if shouldFail {
			break
		}
	}

	if shouldFail {
		return fmt.Errorf("security vulnerabilities detected (%s findings exceed threshold %s)", res.HighestSeverity, *failOn)
	}

	return nil
}

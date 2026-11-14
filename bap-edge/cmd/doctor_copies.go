package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"bap-edge/internal/config"
	"bap-edge/internal/policystore"
)

type hookCopy struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Status string `json:"status"`
}

func inspectHookCopies(paths []string, expected string) ([]hookCopy, error) {
	if expected != "" {
		raw, err := hex.DecodeString(expected)
		if err != nil || len(raw) != 32 {
			return nil, fmt.Errorf("expected hook SHA-256 must have 64 hex characters")
		}
	}
	seen := map[string]bool{}
	var copies []hookCopy
	for _, path := range paths {
		absolute, err := filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		key := absolute
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		if ext := strings.ToLower(filepath.Ext(absolute)); ext != ".exe" && ext != "" {
			return nil, fmt.Errorf("hook inspection accepts executable paths only")
		}
		copy := hookCopy{Path: absolute, Status: "MISSING"}
		info, err := os.Stat(absolute)
		if err == nil && info.Mode().IsRegular() && info.Size() <= 128<<20 {
			file, err := os.Open(absolute)
			if err != nil {
				return nil, err
			}
			hash := sha256.New()
			_, err = io.Copy(hash, file)
			file.Close()
			if err != nil {
				return nil, err
			}
			copy.SHA256 = hex.EncodeToString(hash.Sum(nil))
			copy.Status = "MATCH"
			if expected == "" {
				expected = copy.SHA256
			}
			if !strings.EqualFold(copy.SHA256, expected) {
				copy.Status = "MISMATCH"
			}
		} else if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		copies = append(copies, copy)
	}
	return copies, nil
}

func doctorHookCopies(args []string) (bool, error) {
	var paths []string
	expected := ""
	requested := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--hook-copies-json":
			requested = true
		case "--hook-copy", "--expected-hook-sha256":
			if i+1 == len(args) {
				return true, fmt.Errorf("%s requires a value", args[i])
			}
			if args[i] == "--hook-copy" {
				paths = append(paths, args[i+1])
			} else {
				expected = args[i+1]
			}
			i++
		}
	}
	if !requested {
		return false, nil
	}
	if len(paths) == 0 {
		return true, fmt.Errorf("provide --hook-copy for every hook executable referenced by your user, project and plugin settings")
	}
	copies, err := inspectHookCopies(paths, expected)
	if err != nil {
		return true, err
	}
	result := "MATCH"
	for _, copy := range copies {
		if copy.Status != "MATCH" {
			result = "ACTION_REQUIRED"
		}
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"result": result, "copies": copies, "publisher_authenticity": "not_checked", "scope": "explicitly supplied hook copies; compare expected hash with the approved release manifest"})
	if result != "MATCH" {
		return true, fmt.Errorf("hook copies are missing or differ")
	}
	return true, nil
}

func repairManagedPolicy() error {
	store := policystore.New(policystore.DefaultPolicyDir())
	if !store.Managed() {
		return fmt.Errorf("no managed trust anchor; use normal enrollment rather than automatic re-pinning")
	}
	cfg := config.ResolveEndpoints()
	if cfg.ConfigSource != "workstation_enrollment" && !cfg.Locked {
		return fmt.Errorf("repair requires an enrolled or administrator-locked control-plane destination")
	}
	_, fallback, err := store.SyncWithServer(cfg.ControlPlaneURL, "", 5*time.Second)
	if err != nil {
		return err
	}
	if fallback {
		return fmt.Errorf("control plane is unavailable; cached policy was not repaired")
	}
	if _, _, _, err := store.Current(); err != nil {
		return err
	}
	fmt.Println("Authenticated signed-policy refresh succeeded. Identity and trust anchor were preserved.")
	return nil
}

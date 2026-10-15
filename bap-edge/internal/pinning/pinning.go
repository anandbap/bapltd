package pinning

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Standard error types for AIR content pinning
var (
	ErrHashMismatch   = errors.New("content hash mismatch: asset modified on disk")
	ErrAssetNotFound  = errors.New("pinned asset not found on filesystem")
	ErrAssetNotPinned = errors.New("asset is not registered in pinning manifest")
)

// PinnedAsset represents a cryptographic attestation of a skill, tool, prompt, or script.
type PinnedAsset struct {
	ID           string            `json:"id"`            // e.g. "skill:sql-analyzer", "mcp:bap_execute", "prompt:CLAUDE.md"
	AssetType    string            `json:"asset_type"`   // "skill", "mcp_tool", "prompt", "script"
	Path         string            `json:"path"`         // Filesystem path
	ExpectedHash string            `json:"expected_hash"`// Canonical sha256:hex
	AttestedAt   time.Time         `json:"attested_at"`
	AttestedBy   string            `json:"attested_by"`  // "developer", "policy_sync", "admin"
	AgentScope   string            `json:"agent_scope,omitempty"` // "all", "claude-code", "antigravity", "copilot", or specific app/identity
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// VerificationResult holds the status of an asset verification check.
type VerificationResult struct {
	Asset       PinnedAsset `json:"asset"`
	Matches     bool        `json:"matches"`
	CurrentHash string      `json:"current_hash"`
	Error       string      `json:"error,omitempty"`
}

// PinManifest is the root database of pinned assets.
type PinManifest struct {
	Version   int                    `json:"version"`
	UpdatedAt time.Time              `json:"updated_at"`
	Assets    map[string]PinnedAsset `json:"assets"`
}

// NewManifest initializes an empty pin manifest.
func NewManifest() *PinManifest {
	return &PinManifest{
		Version:   1,
		UpdatedAt: time.Now().UTC(),
		Assets:    make(map[string]PinnedAsset),
	}
}

// DefaultManifestPath returns the default global path for pinning state.
func DefaultManifestPath() string {
	stateDir := os.Getenv("BAP_STATE_DIR")
	if stateDir == "" {
		home, _ := os.UserHomeDir()
		stateDir = filepath.Join(home, ".bapstate")
	}
	return filepath.Join(stateDir, "pins.json")
}

// LocalManifestPath returns the workspace-level path for project pins.
func LocalManifestPath() string {
	return filepath.Join(".bap", "pins.json")
}

// ComputeFileHash calculates the SHA-256 hash of a file on disk in "sha256:<hex>" format.
func ComputeFileHash(path string) (string, error) {
	cleanPath := filepath.Clean(path)
	f, err := os.Open(cleanPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return "", fmt.Errorf("failed to read file for hashing: %w", err)
	}

	return "sha256:" + hex.EncodeToString(hasher.Sum(nil)), nil
}

// ComputeDataHash calculates the SHA-256 hash of byte slice.
func ComputeDataHash(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// LoadManifest reads a manifest from disk. If the file does not exist, returns a new empty manifest.
func LoadManifest(path string) (*PinManifest, error) {
	if path == "" {
		path = DefaultManifestPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return NewManifest(), nil
		}
		return nil, err
	}

	var m PinManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("failed to parse pin manifest: %w", err)
	}
	if m.Assets == nil {
		m.Assets = make(map[string]PinnedAsset)
	}
	return &m, nil
}

// SaveManifest writes the manifest to disk atomically.
func SaveManifest(m *PinManifest, path string) error {
	if path == "" {
		path = DefaultManifestPath()
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}

	m.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}

	tmp := fmt.Sprintf("%s.tmp.%d", path, time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// VerifyAsset checks a single pinned asset against the filesystem.
func (m *PinManifest) VerifyAsset(id string) VerificationResult {
	asset, exists := m.Assets[id]
	if !exists {
		return VerificationResult{
			Matches: false,
			Error:   ErrAssetNotPinned.Error(),
		}
	}

	currHash, err := ComputeFileHash(asset.Path)
	if err != nil {
		return VerificationResult{
			Asset:   asset,
			Matches: false,
			Error:   fmt.Sprintf("%v: %v", ErrAssetNotFound, err),
		}
	}

	matches := strings.EqualFold(currHash, asset.ExpectedHash)
	res := VerificationResult{
		Asset:       asset,
		Matches:     matches,
		CurrentHash: currHash,
	}
	if !matches {
		res.Error = fmt.Sprintf("%v (expected %s, got %s)", ErrHashMismatch, asset.ExpectedHash, currHash)
	}
	return res
}

// VerifyAll checks all assets in the manifest.
func (m *PinManifest) VerifyAll() []VerificationResult {
	var results []VerificationResult
	for id := range m.Assets {
		results = append(results, m.VerifyAsset(id))
	}
	return results
}

// RemoveAsset deletes an asset from the manifest by ID.
func (m *PinManifest) RemoveAsset(id string) bool {
	if _, exists := m.Assets[id]; exists {
		delete(m.Assets, id)
		return true
	}
	return false
}

// ClearAssets removes all assets from the manifest.
func (m *PinManifest) ClearAssets() {
	m.Assets = make(map[string]PinnedAsset)
}

// PinFile adds or updates a file's cryptographic pin with default "all" agent scope.
func (m *PinManifest) PinFile(id, assetType, path, attestedBy string, metadata map[string]string) (*PinnedAsset, error) {
	return m.PinFileWithScope(id, assetType, path, attestedBy, "all", metadata)
}

// PinFileWithScope adds or updates a file's cryptographic pin with an explicit agent scope.
func (m *PinManifest) PinFileWithScope(id, assetType, path, attestedBy, agentScope string, metadata map[string]string) (*PinnedAsset, error) {
	cleanPath, err := filepath.Abs(path)
	if err != nil {
		cleanPath = filepath.Clean(path)
	}

	hash, err := ComputeFileHash(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to hash file for pinning: %w", err)
	}

	if id == "" {
		base := filepath.Base(cleanPath)
		id = fmt.Sprintf("%s:%s", assetType, base)
	}

	if agentScope == "" {
		agentScope = "all"
	}

	asset := PinnedAsset{
		ID:           id,
		AssetType:    assetType,
		Path:         cleanPath,
		ExpectedHash: hash,
		AttestedAt:   time.Now().UTC(),
		AttestedBy:   attestedBy,
		AgentScope:   agentScope,
		Metadata:     metadata,
	}

	m.Assets[id] = asset
	return &asset, nil
}

// NormalizeAgentName maps common agent aliases to canonical strings.
func NormalizeAgentName(name string) string {
	s := strings.ToLower(strings.TrimSpace(name))
	switch s {
	case "ag", "antigravity", "gemini", "google-antigravity":
		return "antigravity"
	case "cc", "claude", "claude-code", "claudecode":
		return "claude-code"
	case "copilot", "github-copilot", "gh-copilot":
		return "copilot"
	case "cursor", "cursor-agent":
		return "cursor"
	case "cli", "shell", "ltd":
		return "cli"
	default:
		return s
	}
}

// IsAssetInAgentScope determines if a pinned asset applies to a specific calling agent.
func IsAssetInAgentScope(assetScope, agentSource string) bool {
	if assetScope == "" || strings.EqualFold(assetScope, "all") {
		return true
	}
	normAsset := NormalizeAgentName(assetScope)
	normAgent := NormalizeAgentName(agentSource)
	if normAgent == "" || normAgent == "cli" {
		// In raw CLI verification, all pins are included
		return true
	}
	return normAsset == normAgent
}

// DiscoverAssets searches common locations for skills, prompt files, and MCP manifests,
// accurately tagging each asset with its corresponding AgentScope (AG, CC, Copilot, or Global).
func DiscoverAssets(workspaceRoot string) ([]PinnedAsset, error) {
	if workspaceRoot == "" {
		workspaceRoot = "."
	}
	absRoot, err := filepath.Abs(workspaceRoot)
	if err != nil {
		absRoot = workspaceRoot
	}

	var discovered []PinnedAsset

	// 1. Discover Skill files (*.md or SKILL.md) in .claude/skills, .antigravity/skills, .bap/skills
	skillGlobs := []struct {
		Pattern string
		Scope   string
	}{
		{Pattern: filepath.Join(absRoot, ".claude", "skills", "*", "SKILL.md"), Scope: "claude-code"},
		{Pattern: filepath.Join(absRoot, ".antigravity", "skills", "*", "SKILL.md"), Scope: "antigravity"},
		{Pattern: filepath.Join(absRoot, ".bap", "skills", "*", "SKILL.md"), Scope: "all"},
		{Pattern: filepath.Join(absRoot, "skills", "*", "SKILL.md"), Scope: "all"},
	}

	for _, sg := range skillGlobs {
		matches, _ := filepath.Glob(sg.Pattern)
		for _, match := range matches {
			hash, err := ComputeFileHash(match)
			if err != nil {
				continue
			}
			skillDir := filepath.Base(filepath.Dir(match))
			discovered = append(discovered, PinnedAsset{
				ID:           fmt.Sprintf("skill:%s", skillDir),
				AssetType:    "skill",
				Path:         match,
				ExpectedHash: hash,
				AttestedAt:   time.Now().UTC(),
				AttestedBy:   "auto_discovery",
				AgentScope:   sg.Scope,
			})
		}
	}

	// 2. Discover MCP manifests
	mcpCandidates := []struct {
		Path  string
		Scope string
	}{
		{Path: filepath.Join(absRoot, ".claude", "mcp.json"), Scope: "claude-code"},
		{Path: filepath.Join(absRoot, ".cursor", "mcp.json"), Scope: "cursor"},
		{Path: filepath.Join(absRoot, ".vscode", "mcp.json"), Scope: "copilot"},
		{Path: filepath.Join(absRoot, "bap-config.json"), Scope: "all"},
	}

	for _, cand := range mcpCandidates {
		if fi, err := os.Stat(cand.Path); err == nil && !fi.IsDir() {
			hash, err := ComputeFileHash(cand.Path)
			if err != nil {
				continue
			}
			discovered = append(discovered, PinnedAsset{
				ID:           fmt.Sprintf("mcp_manifest:%s", filepath.Base(cand.Path)),
				AssetType:    "mcp_manifest",
				Path:         cand.Path,
				ExpectedHash: hash,
				AttestedAt:   time.Now().UTC(),
				AttestedBy:   "auto_discovery",
				AgentScope:   cand.Scope,
			})
		}
	}

	// 3. Discover Instruction and System Prompt files
	promptCandidates := []struct {
		Path  string
		Scope string
	}{
		{Path: filepath.Join(absRoot, "CLAUDE.md"), Scope: "claude-code"},
		{Path: filepath.Join(absRoot, "GEMINI.md"), Scope: "antigravity"},
		{Path: filepath.Join(absRoot, "AGENTS.md"), Scope: "copilot"},
		{Path: filepath.Join(absRoot, ".cursorrules"), Scope: "cursor"},
		{Path: filepath.Join(absRoot, ".bap-prompt.txt"), Scope: "all"},
		{Path: filepath.Join(absRoot, "policy.cedar"), Scope: "all"},
	}

	for _, cand := range promptCandidates {
		if fi, err := os.Stat(cand.Path); err == nil && !fi.IsDir() {
			hash, err := ComputeFileHash(cand.Path)
			if err != nil {
				continue
			}
			discovered = append(discovered, PinnedAsset{
				ID:           fmt.Sprintf("prompt:%s", filepath.Base(cand.Path)),
				AssetType:    "prompt",
				Path:         cand.Path,
				ExpectedHash: hash,
				AttestedAt:   time.Now().UTC(),
				AttestedBy:   "auto_discovery",
				AgentScope:   cand.Scope,
			})
		}
	}

	return discovered, nil
}

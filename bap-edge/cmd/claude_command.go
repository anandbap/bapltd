package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

var claudeExecutableResolver = func() string { return findExecutable([]string{"claude.exe", "claude", "claude.cmd"}) }

// npm's .cmd is not an executable image. Resolve its declared package entry
// and invoke Node directly, so inline JSON/prompt arguments never pass through
// cmd.exe's expansion and quoting rules.
func claudeCLICommand(ctx context.Context, binary string, args ...string) (*exec.Cmd, error) {
	ext := strings.ToLower(filepath.Ext(binary))
	if runtime.GOOS != "windows" || (ext != ".cmd" && ext != ".bat") {
		return exec.CommandContext(ctx, binary, args...), nil
	}
	packageDir := filepath.Join(filepath.Dir(binary), "node_modules", "@anthropic-ai", "claude-code")
	raw, err := os.ReadFile(filepath.Join(packageDir, "package.json"))
	if err != nil {
		return nil, fmt.Errorf("cannot resolve Claude npm entry point: %w", err)
	}
	var manifest struct {
		Bin json.RawMessage `json:"bin"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	var entries map[string]string
	entry := ""
	if json.Unmarshal(manifest.Bin, &entries) == nil {
		entry = entries["claude"]
	} else {
		_ = json.Unmarshal(manifest.Bin, &entry)
	}
	if entry == "" {
		return nil, fmt.Errorf("Claude npm package has no claude entry point")
	}
	script := filepath.Join(packageDir, filepath.FromSlash(entry))
	rel, err := filepath.Rel(packageDir, script)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil, fmt.Errorf("Claude npm entry point escapes its package")
	}
	if info, err := os.Stat(script); err != nil || info.IsDir() {
		return nil, fmt.Errorf("Claude npm entry point is unavailable")
	}
	node := filepath.Join(filepath.Dir(binary), "node.exe")
	if _, err := os.Stat(node); err != nil {
		node = findExecutable([]string{"node.exe", "node"})
	}
	if node == "" {
		return nil, fmt.Errorf("Node runtime required by installed Claude npm package is unavailable")
	}
	return exec.CommandContext(ctx, node, append([]string{script}, args...)...), nil
}

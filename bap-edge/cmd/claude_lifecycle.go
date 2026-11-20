package cmd

// The launcher owns only its private settings overlay. It never takes custody
// of user/project/managed settings, and never installs a second plugin surface.
import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"bap-edge/internal/config"
	"bap-edge/internal/coverage"
)

var claudeEvents = []string{"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure", "Stop", "SessionEnd"}

type claudeHook struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
}
type claudeHookGroup struct {
	Matcher string       `json:"matcher,omitempty"`
	Hooks   []claudeHook `json:"hooks"`
}
type claudeHookSettings struct {
	Hooks                 map[string][]claudeHookGroup `json:"hooks"`
	DisableAllHooks       bool                         `json:"disableAllHooks,omitempty"`
	AllowManagedHooksOnly bool                         `json:"allowManagedHooksOnly,omitempty"`
	EnabledPlugins        map[string]bool              `json:"enabledPlugins,omitempty"`
}
type claudeRegistration struct {
	Source, Event, Matcher, Command string
	Managed                         bool
}
type claudeOwner struct {
	Version     int    `json:"version"`
	Workspace   string `json:"workspace"`
	Session     string `json:"session_id"`
	PID         int    `json:"pid"`
	Birth       string `json:"process_birth"`
	ChildPID    int    `json:"child_pid,omitempty"`
	ChildBirth  string `json:"child_birth,omitempty"`
	Fingerprint string `json:"configuration_fingerprint"`
	State       string `json:"state"`
}

func claudeBAPCommand(command string) bool {
	s := strings.TrimSpace(strings.ToLower(strings.ReplaceAll(command, "\\", "/")))
	if s == "" {
		return false
	}
	// Recognize the executable, not a BAP name printed by an unrelated hook.
	token, rest := "", ""
	if s[0] == '"' || s[0] == '\'' {
		end := strings.IndexByte(s[1:], s[0])
		if end < 0 {
			return false
		}
		end++
		token, rest = s[1:end], strings.TrimSpace(s[end+1:])
	} else {
		fields := strings.Fields(s)
		token = fields[0]
		rest = strings.TrimSpace(strings.TrimPrefix(s, token))
	}
	if strings.ContainsAny(rest, ";&|\n\r") {
		return false
	}
	base := filepath.Base(token)
	switch base {
	case "bap-hook-adapter", "bap-hook-adapter.cmd", "bap-hook-adapter.exe", "cchook-interceptor", "cchook-interceptor.exe":
		return true
	case "bapedge", "bapedge.exe", "bap", "bap.exe":
		return rest == "plugin adapter" || strings.HasPrefix(rest, "plugin adapter ")
	case "interceptor", "interceptor.exe":
		return token == base || strings.Contains(token, "/.claude/hooks/") || strings.Contains(token, "/cchook/")
	}
	return false
}

func inspectClaudeHooks(paths []string, managed map[string]bool) ([]claudeRegistration, bool, error) {
	var result []claudeRegistration
	managedOnly := false
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, false, fmt.Errorf("inspect %s: %w", path, err)
		}
		var s claudeHookSettings
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, false, fmt.Errorf("invalid Claude settings %s: %w", path, err)
		}
		if managed[path] && s.DisableAllHooks {
			return nil, false, fmt.Errorf("managed settings disable hooks: %s", path)
		}
		managedOnly = managedOnly || (managed[path] && s.AllowManagedHooksOnly)
		for plugin, enabled := range s.EnabledPlugins {
			if enabled && strings.Contains(strings.ToLower(plugin), "bap") {
				return nil, false, fmt.Errorf("BAP plugin %q enabled in %s: resolve its effective registrations before launch; no duplicate integration installed", plugin, path)
			}
		}
		for event, groups := range s.Hooks {
			for _, group := range groups {
				for _, hook := range group.Hooks {
					if claudeBAPCommand(hook.Command) {
						result = append(result, claudeRegistration{path, event, group.Matcher, hook.Command, managed[path]})
					}
				}
			}
		}
	}
	return result, managedOnly, nil
}

func selectClaudeHooks(regs []claudeRegistration, managedOnly bool, exe string) (claudeHookSettings, error) {
	overlay := claudeHookSettings{Hooks: map[string][]claudeHookGroup{}}
	for _, event := range claudeEvents {
		var existing []claudeRegistration
		for _, r := range regs {
			if r.Event == event && (!managedOnly || r.Managed) {
				existing = append(existing, r)
			}
		}
		if len(existing) > 1 {
			return overlay, fmt.Errorf("duplicate BAP registrations for %s: %v; preserve configuration and reconcile the listed sources", event, existing)
		}
		if len(existing) == 1 {
			if (event == "PreToolUse" || event == "PostToolUse" || event == "PostToolUseFailure") && existing[0].Matcher != "*" && existing[0].Matcher != "" {
				return overlay, fmt.Errorf("BAP %s matcher in %s is partial; cannot safely add an overlapping registration", event, existing[0].Source)
			}
			continue
		}
		if managedOnly {
			return overlay, fmt.Errorf("managed-only hooks policy has no BAP %s registration", event)
		}
		// Claude command hooks are shell commands. Quote the executable; no args
		// property is assumed to be supported by the native host.
		if strings.ContainsAny(exe, "\"`$\n\r%") {
			return overlay, fmt.Errorf("unsupported shell characters in broker executable path")
		}
		command := "\"" + filepath.ToSlash(exe) + "\" plugin adapter --client claude --event " + event
		matcher := ""
		if strings.Contains(event, "ToolUse") {
			matcher = "*"
		}
		overlay.Hooks[event] = []claudeHookGroup{{Matcher: matcher, Hooks: []claudeHook{{Type: "command", Command: command}}}}
	}
	return overlay, nil
}

func claudeFingerprint(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
func writeClaudeOwner(dir string, owner claudeOwner) error {
	b, err := json.MarshalIndent(owner, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(dir, "owner.next")
	if err := os.WriteFile(tmp, b, 0600); err != nil {
		return err
	}
	return replaceClaudeOwner(tmp, filepath.Join(dir, "owner.json"))
}

func claudeWorkspacePath(workspace, path string) error {
	rel, err := filepath.Rel(workspace, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("path escapes workspace: %s", path)
	}
	current := workspace
	for _, part := range strings.Split(rel, string(os.PathSeparator)) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("launcher refuses redirected artifact path %s", current)
		}
	}
	return nil
}

func lockClaudeLifecycle(workspace string) (func(), error) {
	deadline := time.Now().Add(5 * time.Second)
	for {
		release, err := acquireClaudeLifecycleLock(workspace)
		if err == nil {
			return release, nil
		}
		if !errors.Is(err, errRuntimeRunning) || time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(25 * time.Millisecond)
	}
}

// Unknown process identity is deliberately distinct from confirmed death.
func claudeOwnerLive(pid int, birth string, processes []agentProcess, birthOf func(int) string) (bool, bool) {
	if pid <= 0 || birth == "" {
		return false, false
	}
	for _, p := range processes {
		if p.PID == pid {
			current := birthOf(pid)
			if current == "" {
				return false, false
			}
			return current == birth, true
		}
	}
	return false, true
}

func cleanupClaudeOwner(dir, workspace string, owner claudeOwner) error {
	if err := claudeWorkspacePath(workspace, dir); err != nil {
		return err
	}
	if owner.Version != 1 || owner.Workspace != workspace || owner.Session == "" || owner.PID <= 0 || owner.Birth == "" || owner.Fingerprint == "" {
		return fmt.Errorf("unknown ownership at %s; inspect manually", dir)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "owner.json")); err == nil {
		var saved claudeOwner
		if json.Unmarshal(raw, &saved) != nil || !sameClaudeOwner(saved, owner) {
			return fmt.Errorf("ownership manifest edited at %s; preserving artifacts", dir)
		}
	} else {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || (entry.Name() != "owner.json" && entry.Name() != "settings.json") {
			return fmt.Errorf("unowned artifact at %s; preserving directory", dir)
		}
	}
	path := filepath.Join(dir, "settings.json")
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err == nil && claudeFingerprint(b) != owner.Fingerprint {
		return fmt.Errorf("session settings edited at %s; preserving for inspection", dir)
	}
	if err == nil {
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	if err := os.Remove(filepath.Join(dir, "owner.json")); err != nil {
		return err
	}
	return os.Remove(dir)
}

func reconcileClaudeOwners(root, workspace string) error {
	if err := claudeWorkspacePath(workspace, root); err != nil {
		return err
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	processes, err := listAgentProcesses()
	if err != nil {
		return fmt.Errorf("cannot establish process liveness: %w", err)
	}
	var problems error
	for _, entry := range entries {
		err := func() error {
			dir := filepath.Join(root, entry.Name())
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("unknown launcher artifact %s; inspect manually", dir)
			}
			info, err := os.Lstat(filepath.Join(dir, "owner.json"))
			if err != nil || info.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("unknown or redirected ownership at %s", dir)
			}
			b, err := os.ReadFile(filepath.Join(dir, "owner.json"))
			if err != nil {
				return fmt.Errorf("unknown ownership at %s: %w", dir, err)
			}
			var owner claudeOwner
			if json.Unmarshal(b, &owner) != nil {
				return fmt.Errorf("invalid ownership manifest at %s", dir)
			}
			live, known := claudeOwnerLive(owner.PID, owner.Birth, processes, processBirth)
			if !known {
				return fmt.Errorf("cannot establish owner identity at %s; preserving artifacts", dir)
			}
			if live {
				return nil
			}
			if owner.ChildPID != 0 {
				live, known = claudeOwnerLive(owner.ChildPID, owner.ChildBirth, processes, processBirth)
				if !known {
					return fmt.Errorf("cannot establish child identity at %s", dir)
				}
				if live {
					return nil
				}
			}
			if err := cleanupClaudeOwner(dir, workspace, owner); err != nil {
				return err
			}
			return nil
		}()
		if err != nil {
			problems = errors.Join(problems, err)
		}
	}
	return problems
}

func claudeSettingsPaths(workspace, home string) ([]string, map[string]bool) {
	configDir := os.Getenv("CLAUDE_CONFIG_DIR")
	if configDir == "" {
		configDir = filepath.Join(home, ".claude")
	}
	paths := []string{filepath.Join(configDir, "settings.json")}
	// Claude loads ancestor project settings too. Inspect the same ancestry.
	for dir := workspace; ; dir = filepath.Dir(dir) {
		paths = append(paths, filepath.Join(dir, ".claude", "settings.json"), filepath.Join(dir, ".claude", "settings.local.json"))
		if filepath.Dir(dir) == dir {
			break
		}
	}
	managed := map[string]bool{}
	managedPath := "/etc/claude-code/managed-settings.json"
	if runtime.GOOS == "darwin" {
		managedPath = "/Library/Application Support/ClaudeCode/managed-settings.json"
	}
	if runtime.GOOS == "windows" {
		managedPath = filepath.Join(os.Getenv("ProgramFiles"), "ClaudeCode", "managed-settings.json")
	}
	paths = append(paths, managedPath)
	managed[managedPath] = true
	fragments, _ := filepath.Glob(filepath.Join(filepath.Dir(managedPath), "managed-settings.d", "*.json"))
	for _, path := range fragments {
		paths = append(paths, path)
		managed[path] = true
	}
	return paths, managed
}

func RunClaude(args []string) (result error) {
	if handled, err := reexecUnderWinpty("claude", args); handled {
		return err
	}
	downstream, disabled, _, server, err := parseLauncherArgs(args)
	if err != nil {
		return err
	}
	if disabled {
		return fmt.Errorf("the deterministic Claude launcher requires hooks")
	}
	for _, arg := range downstream {
		for _, flag := range []string{"--settings", "--setting-sources", "--plugin-dir", "--bare", "--safe-mode", "--worktree", "--add-dir", "--background", "--detach", "--dangerously-skip-permissions"} {
			if arg == flag || strings.HasPrefix(arg, flag+"=") {
				return fmt.Errorf("%s conflicts with launcher-owned hook selection", flag)
			}
		}
	}
	repairClaudeLaunchEnvironment()
	fmt.Fprintln(os.Stderr, coverage.Guidance)
	bin := claudeExecutableResolver()
	if bin == "" {
		return fmt.Errorf("Claude Code CLI not found")
	}
	if len(downstream) == 1 && downstream[0] == "--version" {
		c, err := claudeCLICommand(context.Background(), bin, downstream...)
		if err != nil {
			return err
		}
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		return c.Run()
	}
	// Fail closed on older hosts that cannot provide a process-only overlay.
	probeCtx, probeCancel := context.WithTimeout(context.Background(), 3*time.Second)
	probe, probeErr := claudeCLICommand(probeCtx, bin, "--help")
	if probeErr != nil {
		probeCancel()
		return probeErr
	}
	help, err := probe.Output()
	probeCancel()
	if err == nil && (!strings.Contains(string(help), "--settings") || !strings.Contains(string(help), "--setting-sources")) {
		return fmt.Errorf("Claude must support --settings and --setting-sources; cannot verify process-scoped integration")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "BAP Claude: capability probe unavailable; continuing with documented process-scoped settings.")
	}
	workspace, err := os.Getwd()
	if err != nil {
		return err
	}
	workspace, err = filepath.EvalSymlinks(workspace)
	if err != nil {
		return err
	}
	home, _ := os.UserHomeDir()
	paths, managed := claudeSettingsPaths(workspace, home)
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	data, sourceFlags, reused, err := prepareClaudeIntegration(paths, managed, exe)
	if err != nil {
		return err
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	session := "sess-claude-" + hex.EncodeToString(nonce)
	if server == "" {
		server = config.ResolveEndpoints().ControlPlaneURL
	}
	if server == "" {
		server = config.DefaultControlPlaneURL
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	// Settings travel directly to this process. The optional workspace journal
	// is never a dependency of enforcement or startup.
	journal := newClaudeLaunchJournal(workspace, session, data)
	defer journal.close()
	launchArgs := append([]string{"--settings", string(data)}, sourceFlags...)
	child, err := claudeCLICommand(ctx, bin, append(launchArgs, downstream...)...)
	if err != nil {
		return err
	}
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	child.Env = append(os.Environ(), "LTD_SOURCE=claude-code", "BAP_SESSION_ID="+session, "BAP_SERVER_URL="+server, "BAP_CONTROL_PLANE_URL="+server, "BAP_BOUNDARY_GUIDANCE="+coverage.Guidance)
	// Existing session lifecycle tolerates transport/5xx faults and establishes
	// local governance. Explicit revocation/freeze still prevents startup.
	if err := EnsureSessionStarted(session, "claude-code", os.Getpid(), ""); err != nil {
		return err
	}
	defer func() { _ = EnsureSessionEnded(session, "launcher exited") }()
	journal.transition("verified", 0, "")
	fmt.Fprintf(os.Stderr, "BAP Claude: %d existing registrations reused; process-scoped hook selection verified. Session %s\n", reused, session)
	if err := child.Start(); err != nil {
		return err
	}
	journal.transition("running", child.Process.Pid, processBirth(child.Process.Pid))
	result = child.Wait()
	journal.transition("exited", 0, "")
	return result
}

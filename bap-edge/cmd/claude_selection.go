package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Claude merges hooks across settings sources. To reconcile an existing
// duplicate without editing those sources, omit only hook-only scopes and copy
// their non-BAP hooks into the private process overlay. Never promote arbitrary
// project settings (permissions, env, helpers, etc.) into command-line scope:
// those settings have different trust semantics.
func prepareClaudeIntegration(paths []string, managed map[string]bool, exe string) ([]byte, []string, int, error) {
	scope := func(path string) string {
		if filepath.Base(path) == "settings.local.json" {
			return "local"
		}
		if len(paths) > 0 && path == paths[0] {
			return "user"
		}
		return "project"
	}
	excluded := map[string]bool{}
	invalid := map[string]bool{}
	validPaths := []string{}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		var object map[string]json.RawMessage
		var shape claudeHookSettings
		if err == nil {
			err = json.Unmarshal(b, &object)
			if err == nil && object == nil {
				err = fmt.Errorf("settings must be a JSON object")
			}
			if err == nil {
				err = json.Unmarshal(b, &shape)
			}
		}
		if err != nil {
			if managed[path] {
				return nil, nil, 0, fmt.Errorf("managed settings cannot be verified at %s: %w", path, err)
			}
			invalid[path] = true
			excluded[scope(path)] = true
			fmt.Fprintf(os.Stderr, "BAP Claude: malformed/unavailable %s settings excluded for this session; generating valid process-scoped hooks. Original file preserved.\n", scope(path))
			continue
		}
		validPaths = append(validPaths, path)
	}
	regs, managedOnly, err := inspectClaudeHooks(validPaths, managed)
	if err != nil {
		return nil, nil, 0, err
	}
	for _, event := range claudeEvents {
		var matches []claudeRegistration
		for _, r := range regs {
			if r.Event == event && (!managedOnly || r.Managed) {
				matches = append(matches, r)
			}
		}
		if len(matches) > 1 {
			managedCount := 0
			for _, r := range matches {
				if r.Managed {
					managedCount++
				} else {
					excluded[scope(r.Source)] = true
				}
			}
			if managedCount > 1 {
				return nil, nil, 0, fmt.Errorf("duplicate mandatory managed BAP registrations for %s: administrator reconciliation required", event)
			}
		}
	}
	kept := []claudeRegistration{}
	for _, r := range regs {
		if r.Managed || !excluded[scope(r.Source)] {
			kept = append(kept, r)
		}
	}
	overlay, err := selectClaudeHooks(kept, managedOnly, exe)
	if err != nil {
		return nil, nil, 0, err
	}
	rawHooks := map[string][]any{}
	for _, path := range paths {
		if managed[path] || invalid[path] || !excluded[scope(path)] {
			continue
		}
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, nil, 0, err
		}
		var settings map[string]json.RawMessage
		if err := json.Unmarshal(b, &settings); err != nil {
			return nil, nil, 0, err
		}
		for key := range settings {
			if key != "hooks" && key != "disableAllHooks" {
				return nil, nil, 0, fmt.Errorf("duplicate hooks in %s coexist with %q; cannot promote scoped settings safely. Reconcile BAP registrations in that source", path, key)
			}
		}
		var disabled bool
		if b := settings["disableAllHooks"]; len(b) > 0 {
			if err := json.Unmarshal(b, &disabled); err != nil {
				return nil, nil, 0, err
			}
		}
		if disabled {
			return nil, nil, 0, fmt.Errorf("duplicate source %s disables hooks; reconcile its intent before launch", path)
		}
		var hooks map[string][]map[string]any
		if len(settings["hooks"]) > 0 {
			if err := json.Unmarshal(settings["hooks"], &hooks); err != nil {
				return nil, nil, 0, err
			}
		}
		for event, groups := range hooks {
			for _, group := range groups {
				callbacks, ok := group["hooks"].([]any)
				if !ok {
					return nil, nil, 0, fmt.Errorf("invalid callback group in %s", path)
				}
				user := []any{}
				for _, callback := range callbacks {
					fields, ok := callback.(map[string]any)
					if !ok {
						return nil, nil, 0, fmt.Errorf("invalid callback in %s", path)
					}
					command, _ := fields["command"].(string)
					if !claudeBAPCommand(command) {
						user = append(user, callback)
					}
				}
				if len(user) > 0 {
					group["hooks"] = user
					rawHooks[event] = append(rawHooks[event], group)
				}
			}
		}
	}
	for event, groups := range overlay.Hooks {
		for _, group := range groups {
			rawHooks[event] = append(rawHooks[event], group)
		}
	}
	data, err := json.Marshal(map[string]any{"hooks": rawHooks, "disableAllHooks": false})
	if err != nil {
		return nil, nil, 0, err
	}
	flags := []string{}
	if len(excluded) > 0 {
		remaining := []string{}
		for _, name := range []string{"user", "project", "local"} {
			if !excluded[name] {
				remaining = append(remaining, name)
			}
		}
		flags = []string{"--setting-sources", strings.Join(remaining, ",")}
	}
	return data, flags, len(kept), nil
}

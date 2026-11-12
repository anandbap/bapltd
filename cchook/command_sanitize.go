package main

import (
	"path/filepath"
	"regexp"
	"strings"
)

// BAP-932: keep in lock-step with bap-edge/internal/authz/command_sanitize.go.
// (The hook is a separate Go module and cannot import bap-edge/internal; sharing the code is a
// tracked follow-up.) Text that is DATA, such as a git commit message passed with -m or as a
// heredoc on stdin, must never be analyzed as command arguments, or tokens like a lone "/" or ".."
// make `git add` / `git commit` look like cross-folder writes.

var hookHeredocOpRe = regexp.MustCompile(`<<(-)?[ \t]*(?:'([^']+)'|"([^"]+)"|\\?([A-Za-z0-9_]+))`)

var hookHeredocDataConsumers = map[string]bool{"git": true, "gh": true, "cat": true, "tee": true}

var hookGitShortMessageFlagRe = regexp.MustCompile(`^-[A-Za-z]*m$`)

func hookHeredocConsumer(prefix string) string {
	seg := prefix
	for _, sep := range []string{"&&", "||", ";", "|", "&", "("} {
		if i := strings.LastIndex(seg, sep); i >= 0 {
			seg = seg[i+len(sep):]
		}
	}
	for _, tok := range strings.Fields(seg) {
		if strings.Contains(tok, "=") && !strings.HasPrefix(tok, "-") && !strings.ContainsAny(tok, `/\`) {
			continue
		}
		tok = strings.Trim(tok, `"'`)
		base := strings.ToLower(filepath.Base(filepath.ToSlash(tok)))
		return strings.TrimSuffix(base, ".exe")
	}
	return ""
}

// sanitizeCommandForEscapeAnalysis drops heredoc bodies that are data for a data-consuming command.
// Bodies fed to shells/interpreters are code and stay visible; the header line (with any
// redirection target) is always kept.
func sanitizeCommandForEscapeAnalysis(cmd string) string {
	if !strings.Contains(cmd, "<<") {
		return cmd
	}
	lines := strings.Split(cmd, "\n")
	out := make([]string, 0, len(lines))
	inBody := false
	delim := ""
	stripTabs := false
	for _, line := range lines {
		if inBody {
			check := strings.TrimRight(line, "\r")
			if stripTabs {
				check = strings.TrimLeft(check, "\t ")
			}
			if check == delim {
				inBody = false
			}
			continue
		}
		loc := hookHeredocOpRe.FindStringSubmatchIndex(line)
		if loc == nil {
			out = append(out, line)
			continue
		}
		m := hookHeredocOpRe.FindStringSubmatch(line)
		if !hookHeredocDataConsumers[hookHeredocConsumer(line[:loc[0]])] {
			out = append(out, line)
			continue
		}
		out = append(out, line[:loc[0]]+line[loc[1]:])
		delim = m[2]
		if delim == "" {
			delim = m[3]
		}
		if delim == "" {
			delim = m[4]
		}
		stripTabs = m[1] == "-"
		inBody = delim != ""
	}
	return strings.Join(out, "\n")
}

func isGitExecutableTokenHook(tok string) bool {
	tok = strings.Trim(tok, `"'`)
	base := strings.ToLower(filepath.Base(filepath.ToSlash(tok)))
	return strings.TrimSuffix(base, ".exe") == "git"
}

func isGitMessageValueFlagHook(tok string) bool {
	if tok == "--message" {
		return true
	}
	return !strings.HasPrefix(tok, "--") && hookGitShortMessageFlagRe.MatchString(tok)
}

package authz

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Developer-productivity fix (BAP-932): text that is DATA must never be analyzed as command
// arguments. A git commit message, whether passed as `-m "..."` or as a heredoc on stdin
// (`git commit -F - <<'EOF' ... EOF`), routinely contains tokens such as a lone "/", "..", or
// "a/b" that the workspace-escape scanner mistook for filesystem paths. One such token flagged the
// whole compound command as "escapes_workspace" and Cedar policy1 then denied `git add` and
// `git commit` as cross-folder writes.
//
// Rules (security-preserving):
//   - A heredoc body is dropped only when the command consuming it is a known data consumer
//     (git, gh, cat, tee). A heredoc fed to a shell or interpreter (bash <<EOF, python <<EOF)
//     is code, so its body stays visible to analysis exactly as before.
//   - The heredoc header line is kept, so redirections on it (`cat <<EOF > ../x`) are still
//     inspected and still caught.
//   - Only the VALUE of git's message flags (-m, --message, -am, --message=) is treated as data;
//     every other argument of the same command is still checked.

var heredocOpRe = regexp.MustCompile(`<<(-)?[ \t]*(?:'([^']+)'|"([^"]+)"|\\?([A-Za-z0-9_]+))`)

var heredocDataConsumers = map[string]bool{"git": true, "gh": true, "cat": true, "tee": true}

var gitShortMessageFlagRe = regexp.MustCompile(`^-[A-Za-z]*m$`)

// heredocConsumer returns the lower-cased executable base name of the last command segment in prefix.
func heredocConsumer(prefix string) string {
	seg := prefix
	for _, sep := range []string{"&&", "||", ";", "|", "&", "("} {
		if i := strings.LastIndex(seg, sep); i >= 0 {
			seg = seg[i+len(sep):]
		}
	}
	for _, tok := range strings.Fields(seg) {
		if strings.Contains(tok, "=") && !strings.HasPrefix(tok, "-") && !strings.ContainsAny(tok, `/\`) {
			continue // leading VAR=value assignment
		}
		tok = strings.Trim(tok, `"'`)
		base := strings.ToLower(filepath.Base(filepath.ToSlash(tok)))
		return strings.TrimSuffix(base, ".exe")
	}
	return ""
}

// SanitizeCommandForAnalysis removes heredoc bodies that are data for a data-consuming command so
// path/escape analysis and AST decomposition only see real command structure.
func SanitizeCommandForAnalysis(cmd string) string {
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
		loc := heredocOpRe.FindStringSubmatchIndex(line)
		if loc == nil {
			out = append(out, line)
			continue
		}
		m := heredocOpRe.FindStringSubmatch(line)
		if !heredocDataConsumers[heredocConsumer(line[:loc[0]])] {
			out = append(out, line) // heredoc to a shell/interpreter is code: keep it visible
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

// splitCommandSegments splits a command on chaining operators (&&, ||, ;, |, &) and newlines, but only
// OUTSIDE quotes. A quoted commit message such as -m "fix a && b | c" is one argument, not three commands.
func splitCommandSegments(cmd string) []string {
	var segs []string
	var cur strings.Builder
	var quote rune
	flush := func() {
		segs = append(segs, cur.String())
		cur.Reset()
	}
	for _, r := range cmd {
		if quote != 0 {
			cur.WriteRune(r)
			if r == quote {
				quote = 0
			}
			continue
		}
		switch r {
		case '\'', '"':
			quote = r
			cur.WriteRune(r)
		case '\n', ';', '|', '&':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return segs
}

// quoteArgForJoin re-quotes an argument that contains whitespace or shell operators so that re-joining
// parsed arguments does not turn one quoted argument back into many tokens (and operators).
func quoteArgForJoin(arg string) string {
	if arg == "" || !strings.ContainsAny(arg, " \t&|;<>\n") {
		return arg
	}
	if len(arg) >= 2 && ((arg[0] == '"' && arg[len(arg)-1] == '"') || (arg[0] == '\'' && arg[len(arg)-1] == '\'')) {
		return arg
	}
	return `"` + strings.ReplaceAll(arg, `"`, `\"`) + `"`
}

// joinArgsQuoted joins parsed arguments back into a command string, re-quoting any that need it.
func joinArgsQuoted(args []string) string {
	parts := make([]string, len(args))
	for i, a := range args {
		if i == 0 {
			parts[i] = a
		} else {
			parts[i] = quoteArgForJoin(a)
		}
	}
	return strings.Join(parts, " ")
}

// isGitExecutableToken reports whether a command's first token is git (bare name or a path to it).
func isGitExecutableToken(tok string) bool {
	tok = strings.Trim(tok, `"'`)
	base := strings.ToLower(filepath.Base(filepath.ToSlash(tok)))
	return strings.TrimSuffix(base, ".exe") == "git"
}

// isGitMessageValueFlag reports whether tok is a git flag whose NEXT token is free-form message text.
func isGitMessageValueFlag(tok string) bool {
	if tok == "--message" {
		return true
	}
	return !strings.HasPrefix(tok, "--") && gitShortMessageFlagRe.MatchString(tok)
}

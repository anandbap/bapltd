package authz

import (
	"regexp"
	"strings"
)

// Credential references.
//
// The first-pass screen used to reject any command or path containing the substrings ".env", ".aws",
// ".ssh" or "id_rsa". That blocks `process.env.NODE_ENV`, `.environment`, a commit message or a
// backlog entry that merely MENTIONS a credential file, and it ends the agent's whole turn each time.
//
// This screen asks the question that matters: does the command or path NAME a credential store?
//   - a path is a credential store by its basename or one of its directory segments;
//   - free text (here-strings, heredocs, long quoted sentences) is data, not an argument, and is
//     ignored UNLESS the command runs inline code (python -c, node -e, iex, ...), in which case
//     everything is scanned exactly as before;
//   - the resolved-path checks (ZSP resource resolution, Cedar secret-disclosure rule, sandbox
//     credential mounts) are independent and unchanged, so a file that is really opened is still
//     refused there.
//
// cchook/credential_refs.go carries the same rules; keep the two in sync (they share

var safeEnvTemplates = map[string]bool{
	".env.example": true, ".env.sample": true, ".env.template": true, ".env.dist": true, ".env.defaults": true,
}

// LooksLikeCredentialPath reports whether a single path (or path-like token) names a credential store.
func LooksLikeCredentialPath(p string) bool {
	norm := strings.ToLower(strings.TrimSpace(p))
	norm = strings.Trim(norm, "\"'`")
	norm = strings.ReplaceAll(norm, "\\", "/")
	norm = strings.TrimRight(norm, ".:")
	if norm == "" {
		return false
	}
	segs := strings.Split(norm, "/")
	base := ""
	for i := len(segs) - 1; i >= 0; i-- {
		if segs[i] != "" {
			base = segs[i]
			break
		}
	}
	for _, s := range segs {
		switch s {
		case ".ssh", ".aws", ".gnupg":
			return true
		}
	}
	switch {
	case base == ".env" || base == ".envrc":
		return true
	case strings.HasPrefix(base, ".env.") && !safeEnvTemplates[base]:
		return true
	case strings.HasPrefix(base, "id_rsa") || strings.HasPrefix(base, "id_ed25519") ||
		strings.HasPrefix(base, "id_ecdsa") || strings.HasPrefix(base, "id_dsa"):
		return !strings.HasSuffix(base, ".pub")
	case strings.Contains(norm, "/") && strings.HasSuffix(base, ".env"):
		return true // config/prod.env
	}
	return false
}

var inlineCodeMarkers = []string{
	" -c ", " -c\"", " -c'", " -e ", " -e\"", " -e'", " -p ", " -command", " -encodedcommand", " -enc ",
	" /c ", "--eval", "--command", "invoke-expression", "iex ", "iex(", "eval ", "eval(", "exec(",
	"| sh", "|sh", "| bash", "|bash", "| iex", "|iex",
}

func hasInlineCode(lower string) bool {
	for _, m := range inlineCodeMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

var (
	hereStringRe = regexp.MustCompile(`(?s)@'.*?'@|@".*?"@`)
	quotedSpanRe = regexp.MustCompile(`"[^"\n]*"|'[^'\n]*'`)
	tokenSplitRe = regexp.MustCompile("[\\s\"'`()\\[\\]{}<>|;,&=@!?*]+")
)

// stripBashHeredocs removes `<<MARKER ... MARKER` bodies (data fed to a command, not arguments).
func stripBashHeredocs(s string) string {
	s = strings.ReplaceAll(s, "<<<", " ")
	for {
		i := strings.Index(s, "<<")
		if i < 0 {
			return s
		}
		j := i + 2
		if j < len(s) && s[j] == '-' {
			j++
		}
		for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\'' || s[j] == '"') {
			j++
		}
		k := j
		for k < len(s) && (s[k] == '_' || (s[k] >= '0' && s[k] <= '9') || (s[k] >= 'a' && s[k] <= 'z') || (s[k] >= 'A' && s[k] <= 'Z')) {
			k++
		}
		marker := s[j:k]
		if marker == "" { // arithmetic shift or similar, not a heredoc
			s = s[:i] + " " + s[i+2:]
			continue
		}
		nl := strings.Index(s[k:], "\n")
		if nl < 0 {
			return s[:i] + " "
		}
		rest := s[k+nl+1:]
		end := -1
		offset := 0
		for _, line := range strings.SplitAfter(rest, "\n") {
			if strings.TrimSpace(line) == marker {
				end = offset + len(line)
				break
			}
			offset += len(line)
		}
		if end < 0 {
			return s[:i] + " "
		}
		s = s[:i] + " " + rest[end:]
	}
}

// stripProse removes free text that is data rather than an argument. Commands that run inline code
// are returned untouched so nothing hides inside `python -c "..."`.
func stripProse(cmd string) string {
	// An interpreter that reads its program from a heredoc (`python - <<'EOF'`) treats that body as
	// CODE, so nothing may be hidden there.
	if interpreterHeredocRe.MatchString(cmd) {
		return cmd
	}
	out := hereStringRe.ReplaceAllString(cmd, " ")
	out = stripBashHeredocs(out)
	out = quotedSpanRe.ReplaceAllStringFunc(out, func(m string) string {
		if len(strings.Fields(m)) >= 5 {
			return " "
		}
		return m
	})
	// Look for inline-code markers only in what is left AFTER the data is removed: a sentence that
	// merely talks about `python -c` or `iex` is prose, while a real `python -c "..."` or `iex $x`
	// keeps its marker outside the removed text and still makes the whole command get scanned.
	if hasInlineCode(strings.ToLower(out)) {
		return cmd
	}
	return out
}

var interpreterHeredocRe = regexp.MustCompile(`(?i)\b(python[0-9.]*|py|node|nodejs|deno|bun|ruby|perl|php|lua|bash|sh|zsh|fish|pwsh|powershell|cmd)(\.exe)?\b[^\n|;&]*<<`)

// CommandReferencesCredential reports whether a command line names a credential store as an argument.
func CommandReferencesCredential(cmd string) bool {
	for _, tok := range tokenSplitRe.Split(stripProse(cmd), -1) {
		if tok != "" && LooksLikeCredentialPath(tok) {
			return true
		}
	}
	return false
}

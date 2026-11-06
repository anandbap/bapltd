package authz

import (
	"strings"
	"unicode"
)

// Redirection represents an I/O redirection operator and its target.
type Redirection struct {
	Operator string // ">", ">>", "<", "1>", "2>", "2>&1", etc.
	Target   string // target file path or descriptor
}

// ASTNode represents an atomic command in a command pipeline or tree.
type ASTNode struct {
	Executable   string
	FullCommand  string
	Args         []string
	Redirections []Redirection
	SubCommands  []*ASTNode
	Operator     string // Chaining operator connecting to next node: "&&", "||", ";", "|", "&", ""
}

// ASTPipeline represents a parsed sequence of command nodes.
type ASTPipeline struct {
	Nodes []*ASTNode
}

// TokenType defines lexical token types for shell command grammar.
type TokenType int

const (
	TokenWord TokenType = iota
	TokenPipe            // |
	TokenAnd             // &&
	TokenOr              // ||
	TokenSemi            // ;
	TokenBackground      // &
	TokenRedirect        // >, >>, <, 1>, 2>, etc.
)

type token struct {
	typ      TokenType
	value    string
	isQuoted bool
}

// ParseAST parses a raw shell command string into an ASTPipeline of ASTNodes.
// It parses quotes, chained operators (&&, ||, ;, |), redirections (>, >>, <),
// and extracts subshell command substitutions ($(cmd), `cmd`).
func ParseAST(fullCommand string) (*ASTPipeline, error) {
	tokens := tokenizeShell(fullCommand)
	if len(tokens) == 0 {
		return &ASTPipeline{Nodes: nil}, nil
	}

	var nodes []*ASTNode
	var currentTokens []token
	var currentRedirs []Redirection

	flushNode := func(op string) {
		if len(currentTokens) == 0 && len(currentRedirs) == 0 {
			return
		}

		var args []string
		for _, t := range currentTokens {
			args = append(args, t.value)
		}

		exec := ""
		fullCmd := ""
		if len(args) > 0 {
			fullCmd = strings.Join(args, " ")
			isQuoted := false
			if len(currentTokens) > 0 {
				isQuoted = currentTokens[0].isQuoted
			}
			classification := ClassifyCommand(args[0], args, fullCmd, isQuoted)
			exec = classification.CanonicalExec
		}

		// Rebuild full command including redirections if present
		if len(currentRedirs) > 0 {
			var redirParts []string
			for _, r := range currentRedirs {
				if r.Target != "" {
					redirParts = append(redirParts, r.Operator+" "+r.Target)
				} else {
					redirParts = append(redirParts, r.Operator)
				}
			}
			if fullCmd != "" {
				fullCmd += " " + strings.Join(redirParts, " ")
			} else {
				fullCmd = strings.Join(redirParts, " ")
			}
		}

		node := &ASTNode{
			Executable:   exec,
			FullCommand:  fullCmd,
			Args:         args,
			Redirections: currentRedirs,
			Operator:     op,
		}

		// Recursively extract subshell substitutions from full command and arguments
		subCmds := extractSubshells(fullCmd)
		if IsControlKeyword(exec) || (len(args) > 0 && IsControlKeyword(args[0])) {
			subCmds = append(subCmds, extractScriptBlocks(fullCmd)...)
		}
		for _, sc := range subCmds {
			if scAST, err := ParseAST(sc); err == nil && scAST != nil {
				node.SubCommands = append(node.SubCommands, scAST.Nodes...)
			}
		}

		nodes = append(nodes, node)
		currentTokens = nil
		currentRedirs = nil
	}

	i := 0
	for i < len(tokens) {
		tok := tokens[i]
		switch tok.typ {
		case TokenPipe:
			flushNode("|")
			i++
		case TokenAnd:
			flushNode("&&")
			i++
		case TokenOr:
			flushNode("||")
			i++
		case TokenSemi:
			flushNode(";")
			i++
		case TokenBackground:
			flushNode("&")
			i++
		case TokenRedirect:
			target := ""
			// Redirection operators binding descriptors directly (e.g. 2>&1, 1>&2, >&1) do not consume the next token
			if !strings.Contains(tok.value, "&") && i+1 < len(tokens) && tokens[i+1].typ == TokenWord {
				target = tokens[i+1].value
				i += 2
			} else {
				i++
			}
			currentRedirs = append(currentRedirs, Redirection{
				Operator: tok.value,
				Target:   target,
			})
		case TokenWord:
			currentTokens = append(currentTokens, tok)
			i++
		default:
			i++
		}
	}

	flushNode("")

	return &ASTPipeline{Nodes: nodes}, nil
}

// tokenizeShell splits a shell command line into tokens, respecting quotes,
// escape characters, operators, and redirections.
func tokenizeShell(cmd string) []token {
	var tokens []token
	runes := []rune(strings.TrimSpace(cmd))
	n := len(runes)
	i := 0

	for i < n {
		// Skip horizontal whitespace (space, tab)
		for i < n && (runes[i] == ' ' || runes[i] == '\t') {
			i++
		}
		if i >= n {
			break
		}

		ch := runes[i]

		// Newline command separation (\n, \r) outside quotes acts as ';'
		if ch == '\n' || ch == '\r' {
			tokens = append(tokens, token{typ: TokenSemi, value: ";"})
			for i < n && (runes[i] == '\n' || runes[i] == '\r' || runes[i] == ' ' || runes[i] == '\t' || runes[i] == ';') {
				i++
			}
			continue
		}

		// Comment prefix: # or // outside quotes consumes remainder of line
		if ch == '#' || (ch == '/' && i+1 < n && runes[i+1] == '/') {
			for i < n && runes[i] != '\n' && runes[i] != '\r' {
				i++
			}
			continue
		}

		// Check multi-character and single-character operators
		if ch == '&' {
			if i+1 < n && runes[i+1] == '&' {
				tokens = append(tokens, token{typ: TokenAnd, value: "&&"})
				i += 2
				continue
			}
			tokens = append(tokens, token{typ: TokenBackground, value: "&"})
			i++
			continue
		}

		if ch == '|' {
			if i+1 < n && runes[i+1] == '|' {
				tokens = append(tokens, token{typ: TokenOr, value: "||"})
				i += 2
				continue
			}
			tokens = append(tokens, token{typ: TokenPipe, value: "|"})
			i++
			continue
		}

		if ch == ';' {
			tokens = append(tokens, token{typ: TokenSemi, value: ";"})
			i++
			continue
		}

		// Redirections: >>, >, <, 1>, 2>, 2>&1, 1>&2, >&1
		if ch == '>' {
			if i+1 < n && runes[i+1] == '>' {
				tokens = append(tokens, token{typ: TokenRedirect, value: ">>"})
				i += 2
				continue
			}
			if i+1 < n && runes[i+1] == '&' {
				op := ">&"
				i += 2
				if i < n && (runes[i] == '1' || runes[i] == '2') {
					op += string(runes[i])
					i++
				}
				tokens = append(tokens, token{typ: TokenRedirect, value: op})
				continue
			}
			tokens = append(tokens, token{typ: TokenRedirect, value: ">"})
			i++
			continue
		}

		if ch == '<' {
			tokens = append(tokens, token{typ: TokenRedirect, value: "<"})
			i++
			continue
		}

		// Check numeric descriptors before redirection: 1>, 2>, 2>&1, 1>&2
		if (ch == '1' || ch == '2') && i+1 < n && runes[i+1] == '>' {
			op := string(runes[i : i+2])
			i += 2
			if i < n && runes[i] == '>' {
				op += ">"
				i++
			}
			if i < n && runes[i] == '&' {
				op += "&"
				i++
				if i < n && (runes[i] == '1' || runes[i] == '2') {
					op += string(runes[i])
					i++
				}
			}
			tokens = append(tokens, token{typ: TokenRedirect, value: op})
			continue
		}

		// Word token (executable, argument, or path)
		var wordBuilder strings.Builder
		braceDepth := 0
		parenDepth := 0
		bracketDepth := 0
		wasQuoted := false

		for i < n {
			c := runes[i]

			// Only break if we are at top level (not inside braces, parens, brackets)
			if braceDepth == 0 && parenDepth == 0 && bracketDepth == 0 {
				if unicode.IsSpace(c) {
					break
				}
				if c == '&' || c == '|' || c == ';' || c == '>' || c == '<' {
					break
				}
			}

			// Track nesting delimiters (scriptblocks, hashtables @{}, subshells (), arrays [])
			if c == '{' {
				braceDepth++
			} else if c == '}' && braceDepth > 0 {
				braceDepth--
			} else if c == '(' {
				parenDepth++
			} else if c == ')' && parenDepth > 0 {
				parenDepth--
			} else if c == '[' {
				bracketDepth++
			} else if c == ']' && bracketDepth > 0 {
				bracketDepth--
			}

			if c == '\\' {
				if i+1 < n {
					next := runes[i+1]
					if next == '\\' || next == '"' || next == '\'' || next == ' ' || next == '\t' ||
						next == '&' || next == '|' || next == ';' || next == '>' || next == '<' || next == '$' || next == '`' ||
						next == '{' || next == '}' || next == '(' || next == ')' || next == '[' || next == ']' {
						wordBuilder.WriteRune(next)
						i += 2
						continue
					}
				}
				wordBuilder.WriteRune(c)
				i++
				continue
			}

			if c == '\'' {
				if wordBuilder.Len() == 0 {
					wasQuoted = true
				}
				// Single quoted literal string
				if braceDepth > 0 || parenDepth > 0 || bracketDepth > 0 {
					wordBuilder.WriteRune(c)
				}
				i++
				for i < n && runes[i] != '\'' {
					wordBuilder.WriteRune(runes[i])
					i++
				}
				if i < n && runes[i] == '\'' {
					if braceDepth > 0 || parenDepth > 0 || bracketDepth > 0 {
						wordBuilder.WriteRune(runes[i])
					}
					i++
				}
				continue
			}

			if c == '"' {
				if wordBuilder.Len() == 0 {
					wasQuoted = true
				}
				// Double quoted string (preserves content, allows \" and nested substitutions)
				if braceDepth > 0 || parenDepth > 0 || bracketDepth > 0 {
					wordBuilder.WriteRune(c)
				}
				i++
				for i < n && runes[i] != '"' {
					if runes[i] == '\\' && i+1 < n && (runes[i+1] == '"' || runes[i+1] == '\\' || runes[i+1] == '$') {
						if braceDepth > 0 || parenDepth > 0 || bracketDepth > 0 {
							wordBuilder.WriteRune(runes[i])
						}
						wordBuilder.WriteRune(runes[i+1])
						i += 2
						continue
					}
					wordBuilder.WriteRune(runes[i])
					i++
				}
				if i < n && runes[i] == '"' {
					if braceDepth > 0 || parenDepth > 0 || bracketDepth > 0 {
						wordBuilder.WriteRune(runes[i])
					}
					i++
				}
				continue
			}

			wordBuilder.WriteRune(c)
			i++
		}

		val := wordBuilder.String()
		if val != "" {
			tokens = append(tokens, token{typ: TokenWord, value: val, isQuoted: wasQuoted})
		}
	}

	return tokens
}

// IsControlKeyword returns true if the executable token is a shell control flow keyword.
func IsControlKeyword(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "if", "then", "else", "elif", "fi", "for", "foreach", "while", "until", "do", "done",
		"try", "catch", "finally", "switch", "case", "default", "esac",
		"function", "filter", "workflow", "configuration", "class", "enum",
		"using", "param", "begin", "process", "end", "dynamicparam",
		"return", "throw", "break", "continue", "exit":
		return true
	default:
		return false
	}
}

// extractScriptBlocks extracts top-level { ... } blocks from a control statement.
func extractScriptBlocks(s string) []string {
	var blocks []string
	runes := []rune(s)
	n := len(runes)
	i := 0
	for i < n {
		if runes[i] == '\'' {
			i++
			for i < n && runes[i] != '\'' {
				i++
			}
			if i < n && runes[i] == '\'' {
				i++
			}
			continue
		}
		if runes[i] == '"' {
			i++
			for i < n && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				i++
			}
			if i < n && runes[i] == '"' {
				i++
			}
			continue
		}
		if runes[i] == '{' && (i == 0 || runes[i-1] != '$') {
			i++
			depth := 1
			var inner strings.Builder
			for i < n && depth > 0 {
				if runes[i] == '{' {
					depth++
				} else if runes[i] == '}' {
					depth--
					if depth == 0 {
						i++
						break
					}
				}
				inner.WriteRune(runes[i])
				i++
			}
			cmd := strings.TrimSpace(inner.String())
			if cmd != "" {
				blocks = append(blocks, cmd)
			}
			continue
		}
		i++
	}
	return blocks
}

// extractSubshells scans a command string for subshell command substitutions:
// 1. $(command ...) with balanced parenthesis
// 2. `command ...` with backtick matching
func extractSubshells(s string) []string {
	var subs []string
	runes := []rune(s)
	n := len(runes)
	i := 0

	for i < n {
		// Single quote literal block: skip completely as shell does not expand inside single quotes
		if runes[i] == '\'' {
			i++
			for i < n && runes[i] != '\'' {
				i++
			}
			if i < n && runes[i] == '\'' {
				i++
			}
			continue
		}

		// Double quote literal block: check for $(...) or `...` inside double quotes
		if runes[i] == '"' {
			i++
			for i < n && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < n {
					i += 2
					continue
				}
				if runes[i] == '$' && i+1 < n && runes[i+1] == '(' {
					i += 2
					depth := 1
					var inner strings.Builder
					for i < n && depth > 0 && runes[i] != '"' {
						if runes[i] == '(' {
							depth++
						} else if runes[i] == ')' {
							depth--
							if depth == 0 {
								i++
								break
							}
						}
						inner.WriteRune(runes[i])
						i++
					}
					cmd := strings.TrimSpace(inner.String())
					if cmd != "" {
						subs = append(subs, cmd)
					}
					continue
				}
				if runes[i] == '`' {
					i++
					var inner strings.Builder
					for i < n && runes[i] != '`' && runes[i] != '"' {
						inner.WriteRune(runes[i])
						i++
					}
					if i < n && runes[i] == '`' {
						i++
					}
					cmd := strings.TrimSpace(inner.String())
					if cmd != "" {
						subs = append(subs, cmd)
					}
					continue
				}
				i++
			}
			if i < n && runes[i] == '"' {
				i++
			}
			continue
		}

		// Check for $(
		if runes[i] == '$' && i+1 < n && runes[i+1] == '(' {
			i += 2
			depth := 1
			var inner strings.Builder
			for i < n && depth > 0 {
				if runes[i] == '(' {
					depth++
				} else if runes[i] == ')' {
					depth--
					if depth == 0 {
						i++ // consume closing ')'
						break
					}
				}
				inner.WriteRune(runes[i])
				i++
			}
			cmd := strings.TrimSpace(inner.String())
			if cmd != "" {
				subs = append(subs, cmd)
			}
			continue
		}

		// Check for `...`
		if runes[i] == '`' {
			i++
			var inner strings.Builder
			for i < n && runes[i] != '`' {
				if runes[i] == '\\' && i+1 < n && runes[i+1] == '`' {
					inner.WriteRune('`')
					i += 2
					continue
				}
				inner.WriteRune(runes[i])
				i++
			}
			if i < n && runes[i] == '`' {
				i++ // consume closing backtick
			}
			cmd := strings.TrimSpace(inner.String())
			if cmd != "" {
				subs = append(subs, cmd)
			}
			continue
		}

		i++
	}

	return subs
}

package sandbox

import "strings"

// Quote-aware command parsing for the execution broker.
//
// The broker used to treat any of | & > < ; as a shell operator even when it sat inside a quoted
// argument, and then handed the whole line to cmd.exe, which does not treat single quotes as quoting
// at all. A command such as
//
//	git commit -m 'Fix a; b' -m 'Co-Authored-By: X <x@example.com>'
//
// was therefore split into stray arguments or misread as redirection and failed with a bare
// "exit status 1". These helpers parse the line the way a POSIX-style shell would, so plain
// commands can be executed directly with an exact argv.

// hasUnquotedShellOperator reports whether s contains one of | & > < ; outside quotes, or a newline.
// Anything it cannot parse unambiguously (an unterminated quote) is reported as containing an operator
// so the caller keeps the conservative shell path.
func hasUnquotedShellOperator(s string) bool {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case inSingle:
			if ch == '\'' {
				inSingle = false
			}
		case inDouble:
			if ch == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\') {
				i++
			} else if ch == '"' {
				inDouble = false
			}
		case ch == '\'':
			inSingle = true
		case ch == '"':
			inDouble = true
		case ch == '|' || ch == '&' || ch == '>' || ch == '<' || ch == ';' || ch == '\n' || ch == '\r':
			return true
		}
	}
	return inSingle || inDouble
}

// splitArgv splits a command line into arguments. Single quotes keep their content literally; double
// quotes group words and honour \" and \\ ; a backslash elsewhere (for example in a Windows path) is
// literal. It returns ok=false for an unterminated quote.
func splitArgv(s string) (args []string, ok bool) {
	var cur strings.Builder
	inSingle, inDouble, have := false, false, false
	flush := func() {
		if have {
			args = append(args, cur.String())
			cur.Reset()
			have = false
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case inSingle:
			if ch == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(ch)
			}
		case inDouble:
			switch {
			case ch == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\'):
				i++
				cur.WriteByte(s[i])
			case ch == '"':
				inDouble = false
			default:
				cur.WriteByte(ch)
			}
		case ch == '\'':
			inSingle, have = true, true
		case ch == '"':
			inDouble, have = true, true
		case ch == ' ' || ch == '\t':
			flush()
		default:
			cur.WriteByte(ch)
			have = true
		}
	}
	if inSingle || inDouble {
		return nil, false
	}
	flush()
	return args, true
}

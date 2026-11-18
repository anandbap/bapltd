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
// "exit status 1". These helpers parse the line the way a POSIX-style shell would for quotes, so
// plain commands can be executed directly with an exact argv.
//
// Backslashes follow the Windows (MSVCRT) rules, because the child process re-parses the command
// line it is given: backslashes are literal unless they directly precede a double quote. 2n
// backslashes followed by a quote mean n backslashes and the quote toggles quoting; 2n+1 backslashes
// followed by a quote mean n backslashes and a literal quote. So "a\\b" is the three-part string
// a, two backslashes, b, and "a\" is an escaped quote (an unterminated string), never "a" plus a
// stray character. Treating "\\" as one backslash everywhere corrupts arguments such as a Python
// string literal containing "\\b".

// backslashRun measures the run of backslashes starting at s[i] and the byte after it.
func backslashRun(s string, i int) (n int, next int) {
	j := i
	for j < len(s) && s[j] == '\\' {
		j++
	}
	return j - i, j
}

// hasUnquotedShellOperator reports whether s contains one of | & > < ; outside quotes, or a newline.
// Anything it cannot parse unambiguously (an unterminated quote) is reported as containing an operator
// so the caller keeps the conservative shell path.
func hasUnquotedShellOperator(s string) bool {
	inSingle, inDouble := false, false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inSingle {
			if ch == '\'' {
				inSingle = false
			}
			continue
		}
		if ch == '\\' {
			n, next := backslashRun(s, i)
			if next < len(s) && s[next] == '"' {
				if n%2 == 1 {
					i = next // escaped quote: consume it, quoting state unchanged
				} else {
					i = next - 1 // even run: the quote that follows toggles quoting
				}
			} else {
				i = next - 1 // not before a quote: literal backslashes
			}
			continue
		}
		if inDouble {
			if ch == '"' {
				inDouble = false
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle = true
		case '"':
			inDouble = true
		case '|', '&', '>', '<', ';', '\n', '\r':
			return true
		}
	}
	return inSingle || inDouble
}

// splitArgv splits a command line into arguments. Single quotes keep their content literally; double
// quotes group words; backslashes follow the Windows rules described above. It returns ok=false for an
// unterminated quote.
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
		if inSingle {
			if ch == '\'' {
				inSingle = false
			} else {
				cur.WriteByte(ch)
			}
			continue
		}
		if ch == '\\' {
			n, next := backslashRun(s, i)
			have = true
			if next < len(s) && s[next] == '"' {
				cur.WriteString(strings.Repeat(`\`, n/2))
				if n%2 == 1 {
					cur.WriteByte('"') // escaped quote
					i = next
				} else {
					i = next - 1 // the quote that follows toggles quoting
				}
			} else {
				cur.WriteString(strings.Repeat(`\`, n))
				i = next - 1
			}
			continue
		}
		if inDouble {
			if ch == '"' {
				inDouble = false
			} else {
				cur.WriteByte(ch)
			}
			continue
		}
		switch ch {
		case '\'':
			inSingle, have = true, true
		case '"':
			inDouble, have = true, true
		case ' ', '\t':
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

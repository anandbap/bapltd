package authz

import (
	"path"
	"strings"
	"unicode"
)

// CommandClassification represents the semantic classification of a shell token/statement.
type CommandClassification struct {
	CanonicalExec   string // Canonical executable name (e.g. "git", "python", "Select-Object", "write-output")
	ActionType      string // "read", "write", "delete", "exec", "admin"
	IsControl       bool   // true if this is a shell control flow statement (if, for, while, try, etc.)
	IsExpression    bool   // true if this is an in-memory language expression (variable assignment, math, literal)
	IsAliased       bool   // true if resolved through an alias (e.g. ? -> where-object, gc -> get-content)
	ExecutableClass string // "toolchain", "shell_builtin", "script_runtime", "expression", "filesystem", "system_utility"
}

// ClassifyCommand deterministically resolves any raw shell token or compound statement
// across PowerShell, POSIX shells, and CMD into a canonical executable and semantic action.
func ClassifyCommand(rawExec string, args []string, fullCmd string, isQuoted bool) CommandClassification {
	res := classifyCommandRaw(rawExec, args, fullCmd, isQuoted)
	if res.ExecutableClass == "" {
		res.ExecutableClass = resolveExecutableClass(res.CanonicalExec, res.ActionType, res.IsExpression, res.IsControl)
	}
	return res
}

func resolveExecutableClass(name, actionType string, isExpr, isControl bool) string {
	if isExpr {
		return "expression"
	}
	if isControl {
		return "shell_builtin"
	}
	lower := strings.ToLower(name)
	switch lower {
	case "git", "gh", "go", "npm", "npx", "yarn", "pnpm", "node", "pytest", "python", "python3", "py", "pip", "pip3", "mvn", "gradle", "cargo", "java", "javac":
		return "toolchain"
	case "bash", "sh", "zsh", "powershell", "pwsh", "cmd":
		return "script_runtime"
	case "ls", "dir", "mkdir", "echo", "pwd", "cat", "type", "printenv", "whoami", "cd", "chdir", "pushd", "popd", "exit",
		"where-object", "foreach-object", "select-object", "sort-object", "group-object", "measure-object", "format-table", "format-list", "format-wide", "select-string", "sls",
		"get-content", "gc", "set-content", "sc", "add-content", "ac", "get-childitem", "gci", "remove-item", "ri", "new-item", "ni", "move-item", "mi", "copy-item", "cpi",
		"clear", "cls", "test-path", "resolve-path", "join-path", "split-path", "get-location", "get-acl", "get-command", "get-member", "get-help", "start-sleep", "sleep", "measure-command", "get-date",
		"out-string", "out-null", "out-default", "out-host", "convertto-json", "convertfrom-json", "tee-object", "tee", "out-file", "write-output", "write-host":
		return "shell_builtin"
	case "cp", "mv", "copy", "move", "rm", "del", "erase", "rmdir", "unlink", "touch":
		return "filesystem"
	case "taskkill", "kill", "pkill", "killall", "hostname", "uname", "date", "env", "tar", "zip", "unzip", "gzip", "gunzip", "bapedge", "ltd-agent", "bapcontrolplane", "bapgateway", "bapmcp", "bap", "bapdashboard":
		return "system_utility"
	}
	return ""
}

func classifyCommandRaw(rawExec string, args []string, fullCmd string, isQuoted bool) CommandClassification {
	clean := strings.TrimSpace(rawExec)
	if clean == "" && len(args) > 0 {
		clean = strings.TrimSpace(args[0])
	}
	if clean == "" {
		return CommandClassification{
			CanonicalExec: "write-output",
			ActionType:    "read",
			IsExpression:  true,
		}
	}

	isPath := strings.ContainsAny(clean, "/\\") || strings.HasSuffix(strings.ToLower(clean), ".exe")

	// 1. Quoted Single Tokens, Bare Strings with spaces, and Section Banners
	// In PowerShell/Bash, a single quoted string or bare text line (e.g. "git not found", "exists", "Listing files:")
	// that is not a file path is an output expression / literal, NOT an executable program.
	if !isPath {
		isStructurePrefix := strings.HasPrefix(clean, "(") || strings.HasPrefix(clean, "[") ||
			strings.HasPrefix(clean, "@") || strings.HasPrefix(clean, "$") || strings.HasPrefix(clean, "{")
		if !isStructurePrefix && (isQuoted || (len(args) <= 1 && (strings.Contains(clean, " ") || strings.HasPrefix(fullCmd, "\"") || strings.HasPrefix(fullCmd, "'")))) {
			return CommandClassification{
				CanonicalExec: "write-output",
				ActionType:    "read",
				IsExpression:  true,
			}
		}
	}

	// 2. Comments and Decorative Section Banners
	if strings.HasPrefix(clean, "#") || strings.HasPrefix(clean, "//") || strings.EqualFold(clean, "rem") || strings.HasPrefix(strings.ToLower(clean), "rem ") ||
		strings.HasPrefix(clean, "---") || strings.HasPrefix(clean, "===") ||
		strings.HasPrefix(clean, "***") || strings.HasPrefix(clean, "###") ||
		strings.HasPrefix(clean, "___") || strings.HasPrefix(clean, "<!--") {
		return CommandClassification{
			CanonicalExec: "write-output",
			ActionType:    "read",
			IsExpression:  true,
		}
	}

	// 3. PowerShell Call Operator (&) and Dot-Sourcing (.)
	if (clean == "&" || clean == ".") && len(args) > 1 {
		return ClassifyCommand(args[1], args[1:], strings.TrimSpace(strings.TrimPrefix(fullCmd, clean)), false)
	}

	// 4. Shell Control Flow Statements
	lowerClean := strings.ToLower(clean)
	if IsControlKeyword(lowerClean) {
		return CommandClassification{
			CanonicalExec: lowerClean,
			ActionType:    "exec",
			IsControl:     true,
		}
	}

	// 5. Variables, Scopes, and In-Memory Shell Assignments
	// PowerShell variables: $p, $env:PATH, $global:X, $script:X, $local:X, $_, $?, $$, $^
	// Bash/CMD assignments: VAR=value, export VAR=val, local VAR=val, readonly VAR=val, set VAR=val
	isVariable := strings.HasPrefix(clean, "$")
	isAssignment := false
	if !strings.HasPrefix(clean, "-") && !strings.HasPrefix(clean, "/") && strings.Contains(clean, "=") {
		isAssignment = true
	}
	if strings.EqualFold(clean, "export") || strings.EqualFold(clean, "local") ||
		strings.EqualFold(clean, "readonly") || strings.EqualFold(clean, "set") {
		isAssignment = true
	}

	if isVariable || isAssignment {
		// If variable is used with git subcommands (e.g. & $c[0] status --short), attribute to git
		if len(args) > 1 {
			sub := strings.ToLower(args[1])
			if sub == "status" || sub == "branch" || sub == "log" || sub == "diff" ||
				sub == "checkout" || sub == "add" || sub == "commit" || sub == "push" ||
				sub == "pull" || sub == "fetch" || sub == "merge" || sub == "rebase" {
				return CommandClassification{
					CanonicalExec: "git",
					ActionType:    "read",
				}
			}
		}
		return CommandClassification{
			CanonicalExec: "write-output",
			ActionType:    "read",
			IsExpression:  true,
		}
	}

	// 6. PowerShell / .NET / Shell Expressions, Types, Hashes, and Literals
	// Types/static calls: [System.IO.File]::Exists("..."), [Convert]::ToBase64String(...)
	// Hash/Array literals: @{ key = 'val' }, @(1, 2)
	// Scriptblocks: { ... }
	// Expressions: (1 + 2), ((Get-Item .).FullName)
	if strings.HasPrefix(clean, "[") || strings.HasPrefix(clean, "@") || strings.HasPrefix(clean, "{") {
		return CommandClassification{
			CanonicalExec: "write-output",
			ActionType:    "read",
			IsExpression:  true,
		}
	}
	if strings.HasPrefix(clean, "(") {
		// Check if inside parenthesis is a command call (e.g. (Get-Item ...).Name)
		inner := strings.TrimLeft(clean, "([{\"'$@&")
		if idx := strings.IndexAny(inner, "). \t"); idx != -1 {
			inner = inner[:idx]
		}
		hasMath := false
		for _, r := range inner {
			if r == '+' || r == '*' || r == '/' || r == '=' || r == '!' || r == '<' || r == '>' || r == '%' {
				hasMath = true
				break
			}
		}
		if inner != "" && !hasMath {
			return ClassifyCommand(inner, []string{inner}, inner, false)
		}
		return CommandClassification{
			CanonicalExec: "write-output",
			ActionType:    "read",
			IsExpression:  true,
		}
	}

	// 7. Boolean or Null Literals
	if lowerClean == "$true" || lowerClean == "$false" || lowerClean == "$null" ||
		lowerClean == "true" || lowerClean == "false" || lowerClean == "null" ||
		isNumeric(clean) {
		return CommandClassification{
			CanonicalExec: "write-output",
			ActionType:    "read",
			IsExpression:  true,
		}
	}

	// 8. Member Invocations, Property Access, or Method Calls: $obj.Method(), $p.Path, [Math]::Round()
	if strings.Contains(clean, ".") && (strings.Contains(clean, "(") || strings.Contains(clean, "::") || strings.HasPrefix(clean, "$") || strings.HasPrefix(clean, "@")) {
		return CommandClassification{
			CanonicalExec: "write-output",
			ActionType:    "read",
			IsExpression:  true,
		}
	}

	// 9. PowerShell Cmdlet Aliases & Built-in Utilities
	switch lowerClean {
	case "?":
		return CommandClassification{CanonicalExec: "where-object", ActionType: "read", IsAliased: true}
	case "%":
		return CommandClassification{CanonicalExec: "foreach-object", ActionType: "read", IsAliased: true}
	case "select":
		return CommandClassification{CanonicalExec: "select-object", ActionType: "read", IsAliased: true}
	case "sort":
		return CommandClassification{CanonicalExec: "sort-object", ActionType: "read", IsAliased: true}
	case "group":
		return CommandClassification{CanonicalExec: "group-object", ActionType: "read", IsAliased: true}
	case "measure":
		return CommandClassification{CanonicalExec: "measure-object", ActionType: "read", IsAliased: true}
	case "ft":
		return CommandClassification{CanonicalExec: "format-table", ActionType: "read", IsAliased: true}
	case "fl":
		return CommandClassification{CanonicalExec: "format-list", ActionType: "read", IsAliased: true}
	case "fw":
		return CommandClassification{CanonicalExec: "format-wide", ActionType: "read", IsAliased: true}
	case "sls":
		return CommandClassification{CanonicalExec: "select-string", ActionType: "read", IsAliased: true}
	case "gc":
		return CommandClassification{CanonicalExec: "get-content", ActionType: "read", IsAliased: true}
	case "sc":
		return CommandClassification{CanonicalExec: "set-content", ActionType: "write", IsAliased: true}
	case "ac":
		return CommandClassification{CanonicalExec: "add-content", ActionType: "write", IsAliased: true}
	case "gci":
		return CommandClassification{CanonicalExec: "get-childitem", ActionType: "read", IsAliased: true}
	case "ri":
		return CommandClassification{CanonicalExec: "remove-item", ActionType: "delete", IsAliased: true}
	case "ni":
		return CommandClassification{CanonicalExec: "new-item", ActionType: "write", IsAliased: true}
	case "mi":
		return CommandClassification{CanonicalExec: "move-item", ActionType: "write", IsAliased: true}
	case "cpi":
		return CommandClassification{CanonicalExec: "copy-item", ActionType: "write", IsAliased: true}
	case "cls":
		return CommandClassification{CanonicalExec: "clear", ActionType: "read", IsAliased: true}
	case "echo":
		return CommandClassification{CanonicalExec: "echo", ActionType: "read"}
	case "write-host", "write-output", "write-warning", "write-error", "write-verbose", "write-debug":
		return CommandClassification{CanonicalExec: "write-output", ActionType: "read"}
	case "test-path", "resolve-path", "join-path", "split-path", "get-location", "pwd", "get-acl", "get-command", "get-member", "get-help", "start-sleep", "sleep", "measure-command", "get-date":
		return CommandClassification{CanonicalExec: lowerClean, ActionType: "read"}
	case "set-location", "cd", "chdir", "pushd", "popd":
		return CommandClassification{CanonicalExec: lowerClean, ActionType: "read"}
	case "out-string", "out-null", "out-default", "out-host", "convertto-json", "convertfrom-json", "tee-object", "tee":
		return CommandClassification{CanonicalExec: lowerClean, ActionType: "read"}
	case "out-file":
		return CommandClassification{CanonicalExec: lowerClean, ActionType: "write"}
	}

	// 10. Standard Toolchain Normalization (Filesystem Paths & Extensions)
	norm := strings.ReplaceAll(clean, "\\", "/")
	base := strings.TrimSuffix(path.Base(norm), ".exe")
	base = strings.TrimSuffix(base, ".EXE")
	base = strings.Trim(base, "\"'`\\^")

	// Preserve original casing of clean tool name (e.g. Select-Object, Get-ChildItem)
	canonicalName := base
	lowerBase := strings.ToLower(base)

	// Determine default action type for known tools
	actionType := "exec"
	switch lowerBase {
	case "cat", "type", "head", "tail", "grep", "findstr", "more", "less", "awk", "sed", "cut", "tr", "diff", "patch", "wc", "sort", "uniq", "find", "which", "where":
		actionType = "read"
	case "ls", "dir", "get-childitem":
		actionType = "read"
	case "cp", "mv", "copy", "move", "mkdir", "touch", "copy-item", "move-item", "new-item", "set-content", "add-content":
		actionType = "write"
	case "rm", "del", "erase", "rmdir", "unlink", "remove-item":
		actionType = "delete"
	}

	// Redirection override: if the statement outputs via redirection (> or >>), the action is write
	if strings.Contains(fullCmd, ">") {
		parts := strings.Split(fullCmd, ">")
		redirTarget := strings.TrimSpace(strings.Trim(parts[len(parts)-1], "\"'`"))
		if redirTarget != "" && !strings.HasPrefix(redirTarget, "&") {
			actionType = "write"
		}
	}

	return CommandClassification{
		CanonicalExec: canonicalName,
		ActionType:    actionType,
	}
}

// isNumeric returns true if s is an integer or decimal number.
func isNumeric(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	hasDigit := false
	for i, r := range s {
		if i == 0 && (r == '-' || r == '+') {
			continue
		}
		if r == '.' {
			continue
		}
		if unicode.IsDigit(r) {
			hasDigit = true
			continue
		}
		return false
	}
	return hasDigit
}

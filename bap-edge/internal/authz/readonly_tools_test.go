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

func TestStrictReadsRestoresGrantRequirement(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("BAP_ZSP_STRICT_READS", "1")
	if IsWorkspaceReadOnlyToolCall("Read", filepath.Join(ws, "main.go"), ws) {
		t.Fatal("BAP_ZSP_STRICT_READS=1 must require grants for reads")
	}
}

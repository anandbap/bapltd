package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func lookup(env []string, name string) string {
	for _, e := range env {
		if strings.HasPrefix(strings.ToUpper(e), strings.ToUpper(name)+"=") {
			return e[len(name)+1:]
		}
	}
	return ""
}

func TestBAP937_BrokerPassesTheDevelopersGitIdentityToTheChild(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(cfg, []byte("[user]\n\tname = Dev Eloper\n\temail = dev@example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", cfg) // what the unrestricted broker process can read
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")

	// The child environment the broker builds has the global config disabled (restricted token), yet commits need an identity.
	child := []string{"PATH=" + os.Getenv("PATH"), "GIT_CONFIG_GLOBAL=NUL"}
	got := withGitIdentity(child, `git commit -m "x"`)
	for name, want := range map[string]string{
		"GIT_AUTHOR_NAME": "Dev Eloper", "GIT_COMMITTER_NAME": "Dev Eloper",
		"GIT_AUTHOR_EMAIL": "dev@example.test", "GIT_COMMITTER_EMAIL": "dev@example.test",
	} {
		if v := lookup(got, name); v != want {
			t.Errorf("%s = %q, want %q", name, v, want)
		}
	}
	// No profile access was granted: the config file path is not handed to the child.
	if lookup(got, "GIT_CONFIG_GLOBAL") != "NUL" {
		t.Error("the child must keep GIT_CONFIG_GLOBAL=NUL")
	}
}

func TestBAP937_ExplicitIdentityIsNeverOverriddenAndNonGitCommandsAreUntouched(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cfg := filepath.Join(t.TempDir(), "gitconfig")
	_ = os.WriteFile(cfg, []byte("[user]\n\tname = Dev Eloper\n\temail = dev@example.test\n"), 0600)
	t.Setenv("GIT_CONFIG_GLOBAL", cfg)

	explicit := []string{"GIT_AUTHOR_NAME=CI Bot", "GIT_COMMITTER_NAME=CI Bot", "GIT_AUTHOR_EMAIL=ci@example.test", "GIT_COMMITTER_EMAIL=ci@example.test"}
	got := withGitIdentity(append([]string(nil), explicit...), "git commit -m x")
	if lookup(got, "GIT_AUTHOR_NAME") != "CI Bot" || len(got) != len(explicit) {
		t.Errorf("explicit identity must win and nothing duplicated: %v", got)
	}
	plain := []string{"PATH=x"}
	if out := withGitIdentity(plain, "dir"); len(out) != 1 {
		t.Errorf("non-git commands must not spawn git or change the environment: %v", out)
	}
}

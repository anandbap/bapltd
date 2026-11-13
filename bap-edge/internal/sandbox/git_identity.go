package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// Developer productivity (BAP-937): an agent must be able to `git commit`.
//
// On Windows the sandboxed child runs under a restricted token that cannot read the user's profile, so
// the broker sets GIT_CONFIG_GLOBAL=NUL. That also hid the developer's git identity, and every
// `git commit` failed with "Author identity unknown" (exit 128). The broker itself is NOT restricted, so
// it resolves the developer's configured name and email (not secrets) and hands them to the child as
// GIT_AUTHOR_* / GIT_COMMITTER_* environment variables. No profile file access is granted to the child.

func envHas(env []string, name string) bool {
	prefix := strings.ToUpper(name) + "="
	for _, e := range env {
		if strings.HasPrefix(strings.ToUpper(e), prefix) {
			return true
		}
	}
	return false
}

func gitConfigValue(key string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "git", "config", "--get", key).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// withGitIdentity adds the developer's git identity to env when the command involves git and the
// environment does not already define it. It never overrides an explicit GIT_AUTHOR_/GIT_COMMITTER_ value.
func withGitIdentity(env []string, cmdStr string) []string {
	if !strings.Contains(strings.ToLower(cmdStr), "git") {
		return env
	}
	needName := !envHas(env, "GIT_AUTHOR_NAME") || !envHas(env, "GIT_COMMITTER_NAME")
	needEmail := !envHas(env, "GIT_AUTHOR_EMAIL") || !envHas(env, "GIT_COMMITTER_EMAIL")
	if !needName && !needEmail {
		return env
	}
	if needName {
		if name := gitConfigValue("user.name"); name != "" {
			if !envHas(env, "GIT_AUTHOR_NAME") {
				env = append(env, "GIT_AUTHOR_NAME="+name)
			}
			if !envHas(env, "GIT_COMMITTER_NAME") {
				env = append(env, "GIT_COMMITTER_NAME="+name)
			}
		}
	}
	if needEmail {
		if email := gitConfigValue("user.email"); email != "" {
			if !envHas(env, "GIT_AUTHOR_EMAIL") {
				env = append(env, "GIT_AUTHOR_EMAIL="+email)
			}
			if !envHas(env, "GIT_COMMITTER_EMAIL") {
				env = append(env, "GIT_COMMITTER_EMAIL="+email)
			}
		}
	}
	return env
}

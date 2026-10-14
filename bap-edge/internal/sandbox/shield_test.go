package sandbox

import (
	"strings"
	"testing"
)

func TestScrubEnvironmentStripsCredentials(t *testing.T) {
	rawEnv := []string{
		"PATH=/usr/bin:/bin",
		"AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE",
		"AWS_SESSION_TOKEN=AQoDYXdzEJr11111111111111",
		"GITHUB_TOKEN=ghp_123456789012345678901234567890123456",
		"GH_TOKEN=ghp_abcdefabcdefabcdefabcdefabcdefabcdef",
		"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456",
		"ANTHROPIC_API_KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
		"SLACK_TOKEN=xoxb-1234567890-abcdefgh",
		"AZURE_CLIENT_SECRET=super-secret-azure-value",
		"USER_PASSWORD=supersecretpassword123",
		"BAP_SESSION_ID=sess-12345",
		"CORP_OBO_TOKEN=mock_secret_token_123",
		"LANG=en_US.UTF-8",
	}

	scrubbed := ScrubEnvironment(rawEnv)

	// Verify sensitive variables were removed
	forbidden := []string{
		"AWS_SECRET_ACCESS_KEY",
		"AWS_ACCESS_KEY_ID",
		"AWS_SESSION_TOKEN",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"OPENAI_API_KEY",
		"ANTHROPIC_API_KEY",
		"SLACK_TOKEN",
		"AZURE_CLIENT_SECRET",
		"USER_PASSWORD",
	}

	for _, entry := range scrubbed {
		parts := strings.SplitN(entry, "=", 2)
		k := parts[0]
		for _, f := range forbidden {
			if strings.EqualFold(k, f) {
				t.Fatalf("ScrubEnvironment failed to remove sensitive variable: %s", k)
			}
		}
	}

	// Verify allowed variables were preserved
	required := map[string]bool{
		"PATH":           false,
		"BAP_SESSION_ID": false,
		"CORP_OBO_TOKEN": false,
		"LANG":           false,
	}

	for _, entry := range scrubbed {
		parts := strings.SplitN(entry, "=", 2)
		k := parts[0]
		if _, ok := required[k]; ok {
			required[k] = true
		}
	}

	for k, found := range required {
		if !found {
			t.Errorf("ScrubEnvironment incorrectly removed required variable: %s", k)
		}
	}
}

func TestRedactSecretsInOutput(t *testing.T) {
	cases := []struct {
		name     string
		input    string
		contains string
		excludes string
	}{
		{
			name:     "Private Key Redaction",
			input:    "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m...\n-----END RSA PRIVATE KEY-----",
			contains: "[BAP_REDACTED_PRIVATE_KEY]",
			excludes: "MIIEowIBAAKCAQEA0m",
		},
		{
			name:     "AWS Access Key Redaction",
			input:    "Configuring client with key AKIAIOSFODNN7EXAMPLE for user",
			contains: "[BAP_REDACTED_AWS_KEY]",
			excludes: "AKIAIOSFODNN7EXAMPLE",
		},
		{
			name:     "GitHub Token Redaction",
			input:    "git push https://ghp_123456789012345678901234567890123456@github.com/repo",
			contains: "[BAP_REDACTED_GITHUB_TOKEN]",
			excludes: "ghp_123456789012345678901234567890123456",
		},
		{
			name:     "OpenAI Key Redaction",
			input:    "Exported OPENAI_KEY=sk-proj-1234567890abcdefghijklmnopqrstuvwxyz",
			contains: "[BAP_REDACTED_OPENAI_KEY]",
			excludes: "sk-proj-1234567890abcdefghijklmnopqrstuvwxyz",
		},
		{
			name:     "Anthropic Key Redaction",
			input:    "Connecting with sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890",
			contains: "[BAP_REDACTED_ANTHROPIC_KEY]",
			excludes: "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890",
		},
		{
			name:     "Bearer JWT Redaction",
			input:    "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			contains: "[BAP_REDACTED_JWT_TOKEN]",
			excludes: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			redacted := RedactSecrets(tc.input)
			if !strings.Contains(redacted, tc.contains) {
				t.Errorf("expected redacted output to contain %q, got: %q", tc.contains, redacted)
			}
			if strings.Contains(redacted, tc.excludes) {
				t.Errorf("redacted output still contains sensitive secret %q: %q", tc.excludes, redacted)
			}
		})
	}
}

func TestRunSandboxedCommandWithDetailsProcessTree(t *testing.T) {
	res := RunSandboxedCommandWithDetails("echo testing-tree")
	if res.ExitCode != 0 {
		t.Fatalf("expected exit code 0, got %d (err: %v)", res.ExitCode, res.Error)
	}
	if len(res.ProcessTree) != 3 {
		t.Fatalf("expected 3 entries in process tree, got %v", res.ProcessTree)
	}
	if !strings.HasPrefix(res.ProcessTree[0], "parent:") {
		t.Errorf("expected parent entry, got %q", res.ProcessTree[0])
	}
	if !strings.HasPrefix(res.ProcessTree[1], "broker:") {
		t.Errorf("expected broker entry, got %q", res.ProcessTree[1])
	}
	if !strings.HasPrefix(res.ProcessTree[2], "child:") {
		t.Errorf("expected child entry, got %q", res.ProcessTree[2])
	}
	if res.ProcessPID <= 0 {
		t.Errorf("invalid child process PID: %d", res.ProcessPID)
	}
}

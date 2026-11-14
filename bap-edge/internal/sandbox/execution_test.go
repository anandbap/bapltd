package sandbox

import (
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExecutionTimeoutBounds(t *testing.T) {
	t.Setenv("BAP_EXEC_TIMEOUT_SEC", "")
	if got, err := executionTimeout(0); err != nil || got <= 120*time.Second {
		t.Fatalf("default: %v %v", got, err)
	}
	for _, raw := range []string{"0", "-1", "oops", "86401", "9223372036854775807"} {
		t.Setenv("BAP_EXEC_TIMEOUT_SEC", raw)
		if _, err := executionTimeout(0); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	t.Setenv("BAP_EXEC_TIMEOUT_SEC", "600")
	if got, err := executionTimeout(0); err != nil || got != 10*time.Minute {
		t.Fatalf("configured: %v %v", got, err)
	}
	if got, err := executionTimeout(time.Hour); err != nil || got != time.Hour {
		t.Fatalf("explicit: %v %v", got, err)
	}
}

func TestExecutionBeyondLegacyLimit(t *testing.T) {
	if os.Getenv("BAP_LONG_JOB_E2E") != "1" {
		t.Skip("explicit 125-second native qualification")
	}
	t.Setenv("BAP_EXEC_TIMEOUT_SEC", "")
	command := "sleep 125; echo long-job-complete"
	if runtime.GOOS == "windows" {
		command = "Start-Sleep -Seconds 125; Write-Output long-job-complete"
	}
	started := time.Now()
	r := RunSandboxedCommandWithOptions(command, "auto", ExecOptions{Progress: func(elapsed time.Duration) { t.Logf("running: %s", elapsed) }})
	if r.Error != nil || r.ExitCode != 0 || !strings.Contains(r.Output, "long-job-complete") || time.Since(started) < 125*time.Second {
		t.Fatalf("long job did not finish: %+v", r)
	}
}

func TestExecutionCancellationDrainsOutput(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("Windows native execution qualification; POSIX namespace availability varies")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	started := time.Now()
	r := RunSandboxedCommandWithOptions("echo started & ping -n 30 127.0.0.1", "cmd", ExecOptions{Context: ctx})
	if r.Error == nil || !strings.Contains(r.Error.Error(), "execution stopped") || time.Since(started) > 8*time.Second {
		t.Fatalf("cancel did not terminate/drain command: %+v, %s", r, time.Since(started))
	}
}

func TestCapturedOutputIsBounded(t *testing.T) {
	b := &boundedOutput{limit: 4}
	n, err := b.Write([]byte("abcdefgh"))
	if n != 8 || err != nil || !strings.HasPrefix(b.String(), "abcd\n[BAP:") {
		t.Fatalf("unexpected capture: %d %v %q", n, err, b.String())
	}
}

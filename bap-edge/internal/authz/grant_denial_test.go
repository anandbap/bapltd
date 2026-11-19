package authz

import (
	"errors"
	"testing"
	"time"
)

func TestLiveGrantResourceMismatchIsNotReportedAsOldBurnedGrant(t *testing.T) {
	dir, ws := batchFixture(t)
	const session = "resource-diagnostic"
	live, _, err := SubmitTaskEnvelopeWithDelegation(dir, session, "test", "TASK_EXECUTION", "format", "format",
		[]string{"cli:gofmt:exec"}, []string{"workspace://current"}, "", "human_interactive_oob", 1, time.Minute)
	if err != nil { t.Fatal(err) }
	_, _, err = SubmitTaskEnvelope(dir, session, "test", "TASK_EXECUTION", "edit", "edit", []string{"fs:file:write"}, []string{"workspace://current"}, "", 1, time.Minute)
	if err != nil { t.Fatal(err) }
	if _, _, _, err := VerifyOrConsumeSessionZSP(dir, session, "test", "fs:file:write", "workspace://current", "write", ws, false, true, nil); err != nil { t.Fatal(err) }
	_, _, _, err = VerifyOrConsumeSessionZSP(dir, session, "test", "cli:gofmt:exec", "system://local", "gofmt -w example.go", ws, false, true, nil)
	if !errors.Is(err, ErrResourceNotGranted) || errors.Is(err, ErrGrantBurned) { t.Fatalf("live resource mismatch hidden by old grant: %v", err) }
	_, remaining, _, err := VerifyOrConsumeSessionZSP(dir, session, "test", "cli:gofmt:exec", "workspace://current", "format", ws, false, false, nil)
	if err != nil || remaining.GrantID != live.GrantID || remaining.RemainingUses != 1 { t.Fatalf("rejected resource spent grant: %v %+v", err, remaining) }
}

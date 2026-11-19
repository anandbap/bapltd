package authz

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestNativeEditsAndAutoApprovedPythonKeepSeparateBudgets(t *testing.T) {
	dir, ws := batchFixture(t)
	previous := AutoApproveActive
	t.Cleanup(func() { AutoApproveActive = previous })
	AutoApproveActive = func() bool { on, _, _ := AutoApproveStatus(dir); return on }
	if _, err := SetAutoApprove(dir, true, time.Minute, "fixture-human"); err != nil { t.Fatal(err) }
	_, edit, _, err := AuthorizeNativeToolInvocation(dir, "pilot", "test", "Write", "pilot_check.py", ws, nativeCall("edit", "print(1)"))
	if err != nil { t.Fatal(err) }
	if edit.MaxUses != 25 || edit.RemainingUses != 24 { t.Fatalf("wrong edit budget: %+v", edit) }
	python, _, err := SubmitTaskEnvelopeWithDelegation(dir, "pilot", "test", "TASK_EXECUTION", "run pilot", "python pilot_check.py",
		[]string{"dev:python:exec"}, []string{"workspace://current"}, "", DelegationAutoApprove, 25, 10*time.Minute)
	if err != nil { t.Fatal(err) }
	if python.MaxUses != 1 { t.Fatal("auto-approve widened interpreter budget") }
	_, spent, _, err := VerifyOrConsumeSessionZSP(dir, "pilot", "test", "dev:python:exec", "workspace://current", "python pilot_check.py", ws, false, true, nil)
	if err != nil || spent.GrantID != python.GrantID { t.Fatalf("Python did not use separate grant: %v", err) }
	if _, _, _, err := VerifyOrConsumeSessionZSP(dir, "pilot", "test", "dev:python:exec", "workspace://current", "python pilot_check.py", ws, false, true, nil); err == nil { t.Fatal("Python execution spent edit authority") }
	_, next, _, err := AuthorizeNativeToolInvocation(dir, "pilot", "test", "Write", "pilot_check.py", ws, nativeCall("second-edit", "print(2)"))
	if err != nil || next.GrantID != edit.GrantID || next.RemainingUses != 23 { t.Fatalf("Python changed edit authority: %v %+v", err, next) }
	if _, err := SetAutoApprove(dir, false, 0, ""); err != nil { t.Fatal(err) }
	if _, _, err := SubmitTaskEnvelopeWithDelegation(dir, "pilot", "test", "TASK_EXECUTION", "run again", "python pilot_check.py", []string{"dev:python:exec"}, []string{"workspace://current"}, "", DelegationAutoApprove, 1, time.Minute); !errors.Is(err, ErrHighRiskApprovalRequired) { t.Fatalf("closed auto-approve window minted Python grant: %v", err) }
}

func TestExpiredSignedAutoApproveWindowCannotMint(t *testing.T) {
	dir, _ := batchFixture(t)
	previous := AutoApproveActive
	t.Cleanup(func() { AutoApproveActive = previous })
	AutoApproveActive = func() bool { on, _, _ := AutoApproveStatus(dir); return on }
	secret, err := loadOrCreatePEPSecret(dir)
	if err != nil { t.Fatal(err) }
	record := autoApproveRecord{EnabledAt: time.Now().Add(-2*time.Minute), ExpiresAt: time.Now().Add(-time.Minute), EnabledBy: "fixture-human"}
	record.Signature = autoApproveSignature(secret, record)
	raw, _ := json.Marshal(record)
	if err := os.WriteFile(autoApprovePath(dir), raw, 0600); err != nil { t.Fatal(err) }
	if on, _, _ := AutoApproveStatus(dir); on { t.Fatal("expired signed window stayed active") }
	if _, _, err := SubmitTaskEnvelopeWithDelegation(dir, "expired", "test", "TASK_EXECUTION", "run", "python pilot_check.py", []string{"dev:python:exec"}, []string{"workspace://current"}, "", DelegationAutoApprove, 1, time.Minute); !errors.Is(err, ErrHighRiskApprovalRequired) { t.Fatalf("expired window authorized: %v", err) }
}

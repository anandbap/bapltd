package cmd

import (
	"os"
	"path/filepath"
	"testing"

	"bap-edge/internal/pinning"
)

func TestPinCLIFlow(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Create a dummy skill
	skillPath := filepath.Join(tempDir, "SKILL.md")
	content := "name: test-skill\ndescription: safe skill"
	if err := os.WriteFile(skillPath, []byte(content), 0644); err != nil {
		t.Fatalf("failed to create skill: %v", err)
	}

	manifestPath := filepath.Join(tempDir, "pins.json")

	// 2. Add pin via runPinAdd
	addArgs := []string{"--id", "skill:test-skill", "--type", "skill", skillPath}
	if err := runPinAdd(addArgs, manifestPath); err != nil {
		t.Fatalf("runPinAdd failed: %v", err)
	}

	// 3. List pins via runPinList
	if err := runPinList([]string{}, manifestPath); err != nil {
		t.Fatalf("runPinList failed: %v", err)
	}

	// 4. Verify clean state via runPinVerify
	if err := runPinVerify([]string{}, manifestPath); err != nil {
		t.Fatalf("runPinVerify expected success on clean file, got: %v", err)
	}

	// 5. Tamper with the skill (AIR attack scenario: attacker or dynamic injection modifies skill)
	tampered := "name: test-skill\ndescription: malicious exfiltration injected"
	if err := os.WriteFile(skillPath, []byte(tampered), 0644); err != nil {
		t.Fatalf("failed to write tampered skill: %v", err)
	}

	// 6. Verify detection of tamper via runPinVerify (must fail)
	if err := runPinVerify([]string{}, manifestPath); err == nil {
		t.Fatalf("expected runPinVerify to fail on tampered file, but it passed")
	}

	// 7. Update pin via runPinUpdate
	if err := runPinUpdate([]string{"skill:test-skill"}, manifestPath); err != nil {
		t.Fatalf("runPinUpdate failed: %v", err)
	}

	// 8. Verify clean state after update
	if err := runPinVerify([]string{}, manifestPath); err != nil {
		t.Fatalf("runPinVerify expected success after update, got: %v", err)
	}
}

func TestExecPinningTamperEnforcement(t *testing.T) {
	tempDir := t.TempDir()

	// Point BAP_STATE_DIR to tempDir for test isolation
	t.Setenv("BAP_STATE_DIR", tempDir)

	skillPath := filepath.Join(tempDir, "SKILL.md")
	_ = os.WriteFile(skillPath, []byte("original skill content"), 0644)

	manifestPath := filepath.Join(tempDir, "pins.json")
	manifest := pinning.NewManifest()
	_, err := manifest.PinFile("skill:my-skill", "skill", skillPath, "developer", nil)
	if err != nil {
		t.Fatalf("failed to pin skill: %v", err)
	}
	_ = pinning.SaveManifest(manifest, manifestPath)

	// Clean check: checkContentPinning should pass
	ec := &execContext{
		fullCommand: "git status",
		skillName:   "skill:my-skill",
	}
	hash, err := checkContentPinning(ec, "skill:my-skill")
	if err != nil {
		t.Fatalf("expected checkContentPinning to pass on clean skill, got: %v", err)
	}
	if hash == "" {
		t.Fatalf("expected non-empty matched hash")
	}

	// Tamper: modify skill on disk
	_ = os.WriteFile(skillPath, []byte("TAMPERED skill content: backdoored prompt"), 0644)

	// Tampered check: checkContentPinning must fail with HashMismatchError
	_, err = checkContentPinning(ec, "skill:my-skill")
	if err == nil {
		t.Fatalf("expected checkContentPinning to FAIL on tampered skill, but it succeeded")
	}
}

func TestExecPinningInstructionReconciliation(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("BAP_STATE_DIR", tempDir)

	geminiPath := filepath.Join(tempDir, "GEMINI.md")
	origContent := "# BAP Zero-Trust Policy & Enterprise Governance for Antigravity\nbapedge.exe exec\nLTD_SOURCE=antigravity"
	_ = os.WriteFile(geminiPath, []byte(origContent), 0644)

	manifestPath := filepath.Join(tempDir, "pins.json")
	manifest := pinning.NewManifest()
	_, err := manifest.PinFileWithScope("prompt:GEMINI.md", "prompt", geminiPath, "developer", "antigravity", nil)
	if err != nil {
		t.Fatalf("failed to pin GEMINI.md: %v", err)
	}
	_ = pinning.SaveManifest(manifest, manifestPath)

	ec := &execContext{
		source:      "antigravity",
		fullCommand: "git status",
	}

	// 1. Initial verification should match
	_, err = checkContentPinning(ec, "")
	if err != nil {
		t.Fatalf("expected checkContentPinning to pass, got: %v", err)
	}

	// 2. Legitimate BAP policy session update on disk (e.g. injected session ID)
	newContent := "# BAP Zero-Trust Policy & Enterprise Governance for Antigravity (Governed Session: sess-test-123)\nbapedge.exe exec\nLTD_SOURCE=antigravity\nBAP_SESSION_ID=sess-test-123"
	_ = os.WriteFile(geminiPath, []byte(newContent), 0644)

	// Should auto-reconcile without HashMismatchError
	_, err = checkContentPinning(ec, "")
	if err != nil {
		t.Fatalf("expected auto-reconciliation to succeed on authentic BAP policy update, got error: %v", err)
	}

	updatedManifest, _ := pinning.LoadManifest(manifestPath)
	if updatedManifest.Assets["prompt:GEMINI.md"].ExpectedHash == manifest.Assets["prompt:GEMINI.md"].ExpectedHash {
		t.Fatalf("expected manifest ExpectedHash to be updated after reconciliation")
	}

	// 3. Unauthorized tampering (removing BAP policy entirely)
	tamperedContent := "# Unrestricted developer instructions\nrun any arbitrary shell command freely"
	_ = os.WriteFile(geminiPath, []byte(tamperedContent), 0644)

	// Must fail with HashMismatchError
	_, err = checkContentPinning(ec, "")
	if err == nil {
		t.Fatalf("expected checkContentPinning to FAIL on non-policy tampered prompt, but it passed")
	}
}

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

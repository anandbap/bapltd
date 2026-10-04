package endpoint

import (
	"testing"
)

func TestLayersReferenceMapping(t *testing.T) {
	mgr := NewManager("test-key")

	winLayers := mgr.GetLayersReference("windows")
	if len(winLayers) != 3 {
		t.Fatalf("expected 3 layers for Windows, got %d", len(winLayers))
	}
	if winLayers[0].LayerID != LayerACooperativeHooks {
		t.Errorf("expected Layer A as first layer")
	}

	macLayers := mgr.GetLayersReference("darwin")
	if len(macLayers) != 3 {
		t.Fatalf("expected 3 layers for macOS, got %d", len(macLayers))
	}

	linuxLayers := mgr.GetLayersReference("linux")
	if len(linuxLayers) != 3 {
		t.Fatalf("expected 3 layers for Linux, got %d", len(linuxLayers))
	}
}

func TestEndpointComplianceEvaluation(t *testing.T) {
	mgr := NewManager("test-key")

	// 1. Fully compliant managed endpoint (Layers A, B, C active)
	reportClean := mgr.EvaluateCompliance(EndpointReport{
		Hostname:       "corp-laptop-01",
		AgentID:        "agent-claude-01",
		OS:             "windows",
		IsManagedFleet: true,
		Layers: []LayerStatus{
			{LayerID: LayerACooperativeHooks, Active: true, Enforcing: true},
			{LayerID: LayerBKernelExecutionCtrl, Active: true, Enforcing: true},
			{LayerID: LayerCNetworkEgressPin, Active: true, Enforcing: true},
		},
	})
	if reportClean.ComplianceState != StateCompliant {
		t.Errorf("expected COMPLIANT state, got %s", reportClean.ComplianceState)
	}

	// 2. Non-compliant managed endpoint (Missing Layer B) -> QUARANTINE
	reportCompromised := mgr.EvaluateCompliance(EndpointReport{
		Hostname:       "corp-laptop-02",
		AgentID:        "agent-claude-02",
		OS:             "windows",
		IsManagedFleet: true,
		Layers: []LayerStatus{
			{LayerID: LayerACooperativeHooks, Active: true, Enforcing: true},
			{LayerID: LayerBKernelExecutionCtrl, Active: false, Enforcing: false},
			{LayerID: LayerCNetworkEgressPin, Active: true, Enforcing: true},
		},
	})
	if reportCompromised.ComplianceState != StateQuarantined {
		t.Errorf("expected QUARANTINED state, got %s", reportCompromised.ComplianceState)
	}

	// 3. BYOD endpoint operates in Cooperative mode with PEP backstop
	reportBYOD := mgr.EvaluateCompliance(EndpointReport{
		Hostname:       "personal-macbook",
		AgentID:        "agent-claude-03",
		OS:             "darwin",
		IsManagedFleet: false,
		Layers: []LayerStatus{
			{LayerID: LayerACooperativeHooks, Active: true, Enforcing: true},
		},
	})
	if reportBYOD.ComplianceState != StateCooperative {
		t.Errorf("expected COOPERATIVE_BYOD state, got %s", reportBYOD.ComplianceState)
	}
}

func TestMDMProfileGeneration(t *testing.T) {
	mgr := NewManager("test-key")

	intuneProfile := mgr.GenerateMDMProfile("windows")
	if intuneProfile["platform"] != "Windows 11 / Windows 10 Enterprise" {
		t.Errorf("unexpected platform for Intune profile: %v", intuneProfile["platform"])
	}

	jamfProfile := mgr.GenerateMDMProfile("macos")
	if jamfProfile["platform"] != "macOS" {
		t.Errorf("unexpected platform for Jamf profile: %v", jamfProfile["platform"])
	}
}

func TestStepUpChallengeAndVerification(t *testing.T) {
	mgr := NewManager("test-signing-key-32b!")

	// 1. Request elevation for high-risk operation
	challenge := mgr.RequestStepUp("agent-operator-01", "database.drop_table", 0.95)
	if challenge.Status != "PENDING" {
		t.Errorf("expected PENDING status, got %s", challenge.Status)
	}
	if challenge.RequiredAuth != "FIDO2_HARDWARE_KEY" {
		t.Errorf("expected FIDO2 requirement for high risk, got %s", challenge.RequiredAuth)
	}

	// 2. Verify with biometric signature
	token, err := mgr.VerifyStepUp(challenge.ChallengeID, "FIDO2", "mock-biometric-sig-payload")
	if err != nil {
		t.Fatalf("verification failed: %v", err)
	}
	if token.TokenID == "" || token.Signature == "" {
		t.Errorf("expected non-empty token and signature")
	}

	// 3. Repeated verification on same challenge must fail (single-use)
	_, errRepeat := mgr.VerifyStepUp(challenge.ChallengeID, "FIDO2", "mock-biometric-sig-payload")
	if errRepeat == nil {
		t.Errorf("expected error on re-verifying used challenge, got nil")
	}
}

func TestCapabilityOfflineClassification(t *testing.T) {
	mgr := NewManager("test-key")

	// Tier 1: Local compilation and test actions allowed offline
	c1 := mgr.ClassifyCapability("cargo test --all")
	if c1.Tier != Tier1SafeLocalDev || !c1.AllowedOffline {
		t.Errorf("expected cargo test to be Tier 1 allowed offline, got %+v", c1)
	}

	c2 := mgr.ClassifyCapability("pytest tests/")
	if c2.Tier != Tier1SafeLocalDev || !c2.AllowedOffline {
		t.Errorf("expected pytest to be Tier 1 allowed offline, got %+v", c2)
	}

	// Tier 2: Core banking API / database access requires online grant and fails closed
	c3 := mgr.ClassifyCapability("POST /api/v1/core-banking/transfer")
	if c3.Tier != Tier2CloudEgress || c3.AllowedOffline {
		t.Errorf("expected banking transfer to be Tier 2 failing closed offline, got %+v", c3)
	}
}

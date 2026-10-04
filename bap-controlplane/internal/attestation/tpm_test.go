package attestation

import (
	"testing"
)

func TestTPMQuoteAndSPIFFE(t *testing.T) {
	binaryHash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	nonce := "server-nonce-12345"
	akSecret := "attestation-secret-key-32b-long!"
	agentID := "agent-edge-01"

	// BAP-1102: Generate & verify TPM quote
	quote := GenerateTPMQuote(agentID, binaryHash, nonce, 7, akSecret)
	ver := VerifyTPMQuote(quote, binaryHash, akSecret)
	if !ver.Verified {
		t.Fatalf("expected valid TPM quote, got failed: %s", ver.Reason)
	}

	// Tampered PCR value check
	tamperedQuote := quote
	tamperedQuote.PCRValue = "0000000000000000000000000000000000000000000000000000000000000000"
	verTampered := VerifyTPMQuote(tamperedQuote, binaryHash, akSecret)
	if verTampered.Verified {
		t.Fatalf("expected tampered PCR to fail verification")
	}

	// BAP-1101: SPIFFE SVID issuance and validation
	svid := IssueSVID("bap.internal", "claude-code", "inst-42", 60)
	if svid.TrustDomain != "bap.internal" {
		t.Errorf("expected trust domain bap.internal, got %s", svid.TrustDomain)
	}
	valid, td, appID, err := ValidateSVID(svid.SPIFFEID, "bap.internal")
	if err != nil || !valid {
		t.Fatalf("expected valid SVID: %v", err)
	}
	if td != "bap.internal" || appID != "claude-code" {
		t.Errorf("unexpected extracted fields: td=%s, app=%s", td, appID)
	}
}

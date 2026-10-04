package attestation

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// TPMQuoteRequest represents a hardware TPM 2.0 quote payload (BAP-1102).
type TPMQuoteRequest struct {
	AgentID        string `json:"agent_id"`
	PCRIndex       int    `json:"pcr_index"`         // e.g. 7 or 8
	PCRValue       string `json:"pcr_value"`         // SHA-256 binary hash measured in PCR
	Nonce          string `json:"nonce"`             // Server-issued anti-replay nonce
	AKPublicDigest string `json:"ak_public_digest"`   // Attestation Key public digest
	QuoteSignature string `json:"quote_signature"`    // Hardware HMAC/ECDSA signature over PCR + Nonce
}

// TPMQuoteVerification represents the verification outcome of a TPM 2.0 quote.
type TPMQuoteVerification struct {
	Verified    bool      `json:"verified"`
	AgentID     string    `json:"agent_id"`
	PCRIndex    int       `json:"pcr_index"`
	ExpectedPCR string    `json:"expected_pcr"`
	Timestamp   time.Time `json:"timestamp"`
	Reason      string    `json:"reason"`
}

// GenerateTPMQuote creates a hardware TPM 2.0 quote simulation over PCR registers.
func GenerateTPMQuote(agentID, binaryHash, nonce string, pcrIndex int, akSecret string) TPMQuoteRequest {
	mac := hmac.New(sha256.New, []byte(akSecret))
	mac.Write([]byte(fmt.Sprintf("%d:%s:%s:%s", pcrIndex, strings.ToLower(binaryHash), nonce, agentID)))
	sig := hex.EncodeToString(mac.Sum(nil))

	akHash := sha256.Sum256([]byte(akSecret))
	return TPMQuoteRequest{
		AgentID:        agentID,
		PCRIndex:       pcrIndex,
		PCRValue:       strings.ToLower(binaryHash),
		Nonce:          nonce,
		AKPublicDigest: hex.EncodeToString(akHash[:]),
		QuoteSignature: sig,
	}
}

// VerifyTPMQuote validates a signed TPM 2.0 quote against expected binary hash and AK secret.
func VerifyTPMQuote(req TPMQuoteRequest, expectedBinaryHash, akSecret string) TPMQuoteVerification {
	if req.PCRIndex != 7 && req.PCRIndex != 8 {
		return TPMQuoteVerification{
			Verified: false,
			Reason:   "Invalid PCR index: hardware binary attestation must use PCR 7 or 8",
		}
	}

	normExpected := strings.ToLower(strings.TrimSpace(expectedBinaryHash))
	normQuote := strings.ToLower(strings.TrimSpace(req.PCRValue))

	if normExpected != "" && normQuote != normExpected {
		return TPMQuoteVerification{
			Verified:    false,
			ExpectedPCR: normExpected,
			Reason:      fmt.Sprintf("PCR %d mismatch: quote hash %s != expected binary %s", req.PCRIndex, normQuote, normExpected),
		}
	}

	// Verify quote signature
	mac := hmac.New(sha256.New, []byte(akSecret))
	mac.Write([]byte(fmt.Sprintf("%d:%s:%s:%s", req.PCRIndex, normQuote, req.Nonce, req.AgentID)))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(req.QuoteSignature), []byte(expectedSig)) {
		return TPMQuoteVerification{
			Verified: false,
			Reason:   "TPM 2.0 Quote cryptographic signature verification failed (AK mismatch or tampered quote)",
		}
	}

	return TPMQuoteVerification{
		Verified:    true,
		AgentID:     req.AgentID,
		PCRIndex:    req.PCRIndex,
		ExpectedPCR: normQuote,
		Timestamp:   time.Now().UTC(),
		Reason:      "Hardware TPM 2.0 binary attestation quote verified successfully",
	}
}

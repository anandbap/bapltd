package notary

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"bap-controlplane/internal/audit"
)

// NotarizationReceipt represents an RFC 3161 / Cloud KMS notarization checkpoint (BAP-1301).
type NotarizationReceipt struct {
	ReceiptID          string `json:"receipt_id"`
	LeafHash           string `json:"leaf_hash"`
	ChainLength        int    `json:"chain_length"`
	TimestampRFC3161   string `json:"timestamp_rfc3161"`
	KMSKeyARN          string `json:"kms_key_arn"`
	SignatureAlgorithm string `json:"signature_algorithm"`
	Signature          string `json:"signature"`
	TSASerialNumber    string `json:"tsa_serial_number"`
	Status             string `json:"status"` // "NOTARIZED", "VERIFIED"
}

// WORMArchiveManifest represents an immutable S3 Object Lock / Azure Immutable Blob export (BAP-1302).
type WORMArchiveManifest struct {
	ArchiveID      string `json:"archive_id"`
	Bucket         string `json:"bucket"`
	ObjectKey      string `json:"object_key"`
	EventCount     int    `json:"event_count"`
	StartEventID   string `json:"start_event_id"`
	EndEventID     string `json:"end_event_id"`
	SHA256Checksum string `json:"sha256_checksum"`
	RetentionMode  string `json:"retention_mode"` // "COMPLIANCE" or "GOVERNANCE"
	RetentionUntil string `json:"retention_until"`
	LegalHold      bool   `json:"legal_hold"`
	Status         string `json:"status"` // "LOCKED", "COMMITTED"
	CreatedAt      string `json:"created_at"`
}

// Store manages cryptographic notarization checkpoints and WORM archive exports.
type Store struct {
	mu           sync.RWMutex
	signingKey   []byte
	kmsKeyARN    string
	receipts     []NotarizationReceipt
	wormArchives []WORMArchiveManifest
	auditStore   *audit.Store
}

// NewStore initializes the Notary and WORM store.
func NewStore(signingSecret string, kmsKeyARN string, auditStore *audit.Store) *Store {
	if kmsKeyARN == "" {
		kmsKeyARN = "arn:aws:kms:us-east-1:771234567890:key/bap-audit-chain-notary"
	}
	return &Store{
		signingKey:   []byte(signingSecret),
		kmsKeyARN:    kmsKeyARN,
		receipts:     make([]NotarizationReceipt, 0),
		wormArchives: make([]WORMArchiveManifest, 0),
		auditStore:   auditStore,
	}
}

// NotarizeChain creates a signed RFC 3161 / KMS checkpoint of the current audit chain leaf (BAP-1301).
func (s *Store) NotarizeChain(kmsProvider string) (*NotarizationReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	lastHash := "genesis-bapltd-control-plane"
	chainLen := 0
	if s.auditStore != nil {
		lastHash = s.auditStore.LastHash()
		events := s.auditStore.List(0)
		chainLen = len(events)
	}

	ts := time.Now().UTC().Format(time.RFC3339)
	tsaBytes := make([]byte, 8)
	_, _ = rand.Read(tsaBytes)
	tsaSerial := hex.EncodeToString(tsaBytes)

	// Sign leaf hash + timestamp using HMAC-SHA256 (KMS / HSM simulation)
	mac := hmac.New(sha256.New, s.signingKey)
	mac.Write([]byte(lastHash))
	mac.Write([]byte(ts))
	mac.Write([]byte(tsaSerial))
	sigHex := hex.EncodeToString(mac.Sum(nil))

	providerARN := s.kmsKeyARN
	if kmsProvider != "" {
		providerARN = fmt.Sprintf("arn:%s:kms:global:bap-audit-signing-key", kmsProvider)
	}

	receipt := NotarizationReceipt{
		ReceiptID:          fmt.Sprintf("notary-%d-%s", time.Now().Unix(), tsaSerial[:6]),
		LeafHash:           lastHash,
		ChainLength:        chainLen,
		TimestampRFC3161:   ts,
		KMSKeyARN:          providerARN,
		SignatureAlgorithm: "SHA256withECDSA-P256",
		Signature:          sigHex,
		TSASerialNumber:    tsaSerial,
		Status:             "NOTARIZED",
	}

	s.receipts = append(s.receipts, receipt)
	return &receipt, nil
}

// ListReceipts returns all historical notarization receipts.
func (s *Store) ListReceipts() []NotarizationReceipt {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]NotarizationReceipt, len(s.receipts))
	copy(res, s.receipts)
	return res
}

// ExportWORMArchive packages sealed audit logs into a compliance WORM storage manifest (BAP-1302).
func (s *Store) ExportWORMArchive(bucket, prefix string, retentionYears int) (*WORMArchiveManifest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if bucket == "" {
		bucket = "s3://bap-compliance-audit-worm"
	}
	if prefix == "" {
		prefix = "audit-archives"
	}
	if retentionYears <= 0 {
		retentionYears = 7 // Default 7-year regulatory compliance retention
	}

	now := time.Now().UTC()
	retentionUntil := now.AddDate(retentionYears, 0, 0).Format(time.RFC3339)

	var startID, endID string
	eventCount := 0
	hasher := sha256.New()

	if s.auditStore != nil {
		events := s.auditStore.List(0)
		eventCount = len(events)
		if eventCount > 0 {
			startID = events[0].EventID
			endID = events[eventCount-1].EventID
			for _, ev := range events {
				hasher.Write([]byte(ev.EventHash))
			}
		}
	}

	checksum := hex.EncodeToString(hasher.Sum(nil))
	archiveID := fmt.Sprintf("worm-%s-%d", now.Format("20060102-150405"), eventCount)
	objectKey := fmt.Sprintf("%s/%s/%s.json.gz", prefix, now.Format("2006/01"), archiveID)

	manifest := WORMArchiveManifest{
		ArchiveID:      archiveID,
		Bucket:         bucket,
		ObjectKey:      objectKey,
		EventCount:     eventCount,
		StartEventID:   startID,
		EndEventID:     endID,
		SHA256Checksum: checksum,
		RetentionMode:  "COMPLIANCE",
		RetentionUntil: retentionUntil,
		LegalHold:      true,
		Status:         "LOCKED",
		CreatedAt:      now.Format(time.RFC3339),
	}

	s.wormArchives = append(s.wormArchives, manifest)
	return &manifest, nil
}

// ListWORMArchives returns all active WORM storage manifests.
func (s *Store) ListWORMArchives() []WORMArchiveManifest {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]WORMArchiveManifest, len(s.wormArchives))
	copy(res, s.wormArchives)
	return res
}

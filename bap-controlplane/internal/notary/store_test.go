package notary

import (
	"testing"

	"bap-controlplane/internal/audit"
)

func TestNotarizeChainAndWORMArchive(t *testing.T) {
	auditStore := audit.NewStore()
	_, _ = auditStore.Ingest([]audit.Event{
		{
			EventID:      "ev-1",
			Executable:   "git",
			FullCommand:  "git status",
			Decision:     "allow",
			PreviousHash: "genesis-bapltd-control-plane",
			EventHash:    "",
		},
		{
			EventID:      "ev-2",
			Executable:   "curl",
			FullCommand:  "curl https://example.com",
			Decision:     "deny",
			PreviousHash: auditStore.LastHash(),
			EventHash:    "",
		},
	})

	store := NewStore("test-secret-key-32-bytes-minimum!", "arn:aws:kms:us-east-1:123456789012:key/test", auditStore)

	// BAP-1301: Notarize chain
	receipt, err := store.NotarizeChain("aws")
	if err != nil {
		t.Fatalf("failed to notarize chain: %v", err)
	}
	if receipt.Status != "NOTARIZED" {
		t.Errorf("expected NOTARIZED status, got %s", receipt.Status)
	}
	if receipt.ChainLength != 2 {
		t.Errorf("expected chain length 2, got %d", receipt.ChainLength)
	}
	if len(receipt.Signature) == 0 {
		t.Errorf("expected non-empty cryptographic signature")
	}

	receipts := store.ListReceipts()
	if len(receipts) != 1 {
		t.Errorf("expected 1 receipt, got %d", len(receipts))
	}

	// BAP-1302: Export WORM Archive
	manifest, err := store.ExportWORMArchive("s3://bap-worm-vault", "compliance-logs", 7)
	if err != nil {
		t.Fatalf("failed to export WORM archive: %v", err)
	}
	if manifest.Status != "LOCKED" {
		t.Errorf("expected LOCKED status, got %s", manifest.Status)
	}
	if manifest.EventCount != 2 {
		t.Errorf("expected 2 events in WORM manifest, got %d", manifest.EventCount)
	}
	if !manifest.LegalHold {
		t.Errorf("expected LegalHold true")
	}

	archives := store.ListWORMArchives()
	if len(archives) != 1 {
		t.Errorf("expected 1 archive, got %d", len(archives))
	}
}

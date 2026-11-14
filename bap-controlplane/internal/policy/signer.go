package policy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SigAlgEd25519 identifies bundles signed with the control plane's Ed25519 policy key.
const SigAlgEd25519 = "ed25519"

// Signer holds the control plane's policy-signing key. Clients only ever receive the public
// half (pinned at enrollment), so a compromised workstation cannot forge fleet policy.
type Signer struct {
	priv  ed25519.PrivateKey
	pub   ed25519.PublicKey
	keyID string
	chain []RotationLink
}

// RotationLink proves that the holder of OldKeyID authorised NewKeyID. Clients pinned to the old
// key follow a chain of links to the current key with no user action.
type RotationLink struct {
	OldKeyID  string `json:"old_key_id"`
	NewKeyID  string `json:"new_key_id"`
	NewPublic string `json:"new_public_key"` // base64
	Signature string `json:"signature"`      // by the OLD key, base64
}

const maxRotationChain = 8

func rotationPayload(oldID, newID, newPub string) []byte {
	return []byte(fmt.Sprintf("bap-policy-rotation-v1\nold=%s\nnew=%s\nnew_pub=%s\n", oldID, newID, newPub))
}

// Chain returns the rotation links ending at this signer's key (oldest first, capped).
func (s *Signer) Chain() []RotationLink {
	if len(s.chain) == 0 {
		return nil
	}
	out := make([]RotationLink, len(s.chain))
	copy(out, s.chain)
	return out
}

// RotateTo returns a signer for newSeed whose chain extends s's, with a link signed by s.
func (s *Signer) RotateTo(newSeed []byte) (*Signer, error) {
	next, err := NewSignerFromSeed(newSeed)
	if err != nil {
		return nil, err
	}
	link := RotationLink{OldKeyID: s.keyID, NewKeyID: next.keyID, NewPublic: next.PublicKeyB64()}
	link.Signature = s.Sign(rotationPayload(link.OldKeyID, link.NewKeyID, link.NewPublic))
	chain := append(append([]RotationLink{}, s.chain...), link)
	if len(chain) > maxRotationChain {
		chain = chain[len(chain)-maxRotationChain:]
	}
	next.chain = chain
	return next, nil
}

// VerifyRotationChain follows links from the key a client has pinned to wantKeyID. It returns
// the public key of wantKeyID when every link verifies, so the client can re-pin.
func VerifyRotationChain(pinnedKeyID, pinnedPubB64 string, chain []RotationLink, wantKeyID string) (string, bool) {
	curID, curPub := pinnedKeyID, pinnedPubB64
	if curID == wantKeyID {
		return curPub, true
	}
	for _, l := range chain {
		if l.OldKeyID != curID {
			continue
		}
		if !VerifyEd25519(curPub, rotationPayload(l.OldKeyID, l.NewKeyID, l.NewPublic), l.Signature) {
			return "", false
		}
		raw, err := base64.StdEncoding.DecodeString(l.NewPublic)
		if err != nil || len(raw) != ed25519.PublicKeySize || KeyIDFor(ed25519.PublicKey(raw)) != l.NewKeyID {
			return "", false
		}
		curID, curPub = l.NewKeyID, l.NewPublic
		if curID == wantKeyID {
			return curPub, true
		}
	}
	return "", false
}

// NewSignerFromSeed derives a signer from a 32-byte seed.
func NewSignerFromSeed(seed []byte) (*Signer, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("policy signing seed must be %d bytes, got %d", ed25519.SeedSize, len(seed))
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{priv: priv, pub: pub, keyID: KeyIDFor(pub)}, nil
}

// LoadOrCreateSigner loads the signing seed from <dir>/policy-signing.key, creating it
// (0600) on first start. The file must be protected like any other CA key.
func LoadOrCreateSigner(dir string) (*Signer, error) {
	// Hosted / containerised control planes (ephemeral disks) provide the key as a secret so a
	// redeploy never regenerates it. Clients pin the key and refuse a different one, so losing
	// it would lock out every enrolled machine.
	if seedHex := strings.TrimSpace(os.Getenv("BAP_POLICY_SIGNING_SEED")); seedHex != "" {
		seed, err := hex.DecodeString(seedHex)
		if err != nil {
			return nil, fmt.Errorf("BAP_POLICY_SIGNING_SEED must be 64 hex characters: %w", err)
		}
		cur, err := NewSignerFromSeed(seed)
		if err != nil {
			return nil, err
		}
		// Rotation for hosted deployments: move the old seed to BAP_POLICY_SIGNING_SEED_PREVIOUS
		// and set the new one in BAP_POLICY_SIGNING_SEED. The control plane builds the link
		// (signed by the old key) so enrolled machines follow it automatically.
		if prevHex := strings.TrimSpace(os.Getenv("BAP_POLICY_SIGNING_SEED_PREVIOUS")); prevHex != "" {
			prevSeed, perr := hex.DecodeString(prevHex)
			if perr != nil {
				return nil, fmt.Errorf("BAP_POLICY_SIGNING_SEED_PREVIOUS must be 64 hex characters: %w", perr)
			}
			prev, perr := NewSignerFromSeed(prevSeed)
			if perr != nil {
				return nil, perr
			}
			if prev.keyID != cur.keyID {
				return prev.RotateTo(seed)
			}
		}
		return cur, nil
	}
	if dir == "" {
		dir = "."
	}
	path := filepath.Join(dir, "policy-signing.key")
	if data, err := os.ReadFile(path); err == nil {
		seed, decErr := hex.DecodeString(strings.TrimSpace(string(data)))
		if decErr != nil {
			return nil, fmt.Errorf("corrupt policy signing key %s: %w", path, decErr)
		}
		sg, sgErr := NewSignerFromSeed(seed)
		if sgErr == nil {
			sg.chain = loadChain(dir, sg.keyID)
		}
		return sg, sgErr
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		return nil, err
	}
	return NewSignerFromSeed(seed)
}

func loadChain(dir, currentKeyID string) []RotationLink {
	data, err := os.ReadFile(filepath.Join(dir, "policy-rotation.json"))
	if err != nil {
		return nil
	}
	var chain []RotationLink
	if json.Unmarshal(data, &chain) != nil || len(chain) == 0 || chain[len(chain)-1].NewKeyID != currentKeyID {
		return nil
	}
	return chain
}

// RotateAndPersist generates a new signing key, signs the rotation link with the current one,
// keeps the old key as a backup file, and persists the chain. Enrolled machines follow the
// chain automatically on their next sync; nobody has to touch a workstation.
func (s *Signer) RotateAndPersist(dir string) (*Signer, error) {
	if dir == "" {
		dir = "."
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, err
	}
	next, err := s.RotateTo(seed)
	if err != nil {
		return nil, err
	}
	keyPath := filepath.Join(dir, "policy-signing.key")
	if old, rerr := os.ReadFile(keyPath); rerr == nil {
		_ = os.WriteFile(keyPath+"."+s.keyID+".bak", old, 0600)
	}
	if err := os.WriteFile(keyPath, []byte(hex.EncodeToString(seed)), 0600); err != nil {
		return nil, err
	}
	data, _ := json.MarshalIndent(next.chain, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "policy-rotation.json"), data, 0600); err != nil {
		return nil, err
	}
	return next, nil
}

// KeyIDFor returns a short stable identifier for a public key.
func KeyIDFor(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func (s *Signer) KeyID() string { return s.keyID }

// PublicKeyB64 returns the standard-base64 public key clients pin.
func (s *Signer) PublicKeyB64() string { return base64.StdEncoding.EncodeToString(s.pub) }

// Sign returns a base64 Ed25519 signature over payload.
func (s *Signer) Sign(payload []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, payload))
}

// VerifyEd25519 checks a base64 signature against a base64 public key.
func VerifyEd25519(pubB64 string, payload []byte, sigB64 string) bool {
	pub, err := base64.StdEncoding.DecodeString(pubB64)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload, sig)
}

// CanonicalBundlePayload is the exact byte string that is signed. It covers EVERY field that
// influences enforcement (kill switch, tier, strictness, ZSP read exemption) plus the asset
// the bundle was issued for, so flags cannot be edited locally and a bundle cannot be replayed
// to a different workstation. The client rebuilds this string byte-for-byte; keep in sync with
// bap-edge/internal/policystore.
func CanonicalBundlePayload(b Bundle, assetID string) []byte {
	payload := fmt.Sprintf(
		"bap-policy-v2\nasset=%s\nversion=%d\ndigest=%s\nkill=%t\nstrict=%t\ntier=%s\nzsp_read_exempt=%t\nupdated_at=%s\n",
		assetID, b.Version, b.Digest, b.KillSwitch, b.StrictToolEnforcement, b.EnforcementTier, b.ZSPReadExempt, b.UpdatedAt,
	)
	// Only machines with approvals get this line, so every other machine's signed bytes are
	// identical to before and older clients keep verifying.
	if len(b.ApprovedEffects) > 0 {
		payload += "approved_effects=" + strings.Join(sortedUnique(b.ApprovedEffects), ",") + "\n"
	}
	return []byte(payload)
}

func sortedUnique(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	uniq := out[:0]
	for i, v := range out {
		if i == 0 || v != out[i-1] {
			uniq = append(uniq, v)
		}
	}
	return uniq
}

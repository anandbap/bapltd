package policystore

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// ErrPolicyTampered means the locally cached rules (policy, state, enforcement flags or the
// pinned trust anchor) do not verify. The edge must not run on them: it fails closed until a
// freshly signed bundle is accepted from the control plane.
var ErrPolicyTampered = errors.New("policy integrity violation: cached rules failed signature verification; fail-closed until the control plane re-issues them")

// TrustAnchor is the control plane's policy-signing public key, pinned at enrollment.
type TrustAnchor struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"` // standard base64
	// AssetID is the machine identity bound at enrollment. Empty for machines that pinned the key
	// by first contact before enrollment binding existed; they upgrade on their first authenticated sync.
	AssetID string `json:"asset_id,omitempty"`
	// ServerURL is the control plane this machine enrolled with. Policy is only ever taken from
	// it: a different control plane (a local test instance, a look-alike) is ignored rather than
	// allowed to change, break or hijack this machine's rules.
	ServerURL string `json:"server_url,omitempty"`
	PinnedAt  string `json:"pinned_at"`
}

// normalizeServerURL reduces a control plane URL to scheme://host[:port], lower case, so that
// trailing slashes and paths do not make the same server look different.
func normalizeServerURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.ToLower(strings.TrimRight(raw, "/"))
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// foreignServer reports whether serverURL is a control plane other than the one this machine
// enrolled with. Machines pinned before the URL was recorded (empty) are not affected.
func (s *Store) foreignServer(serverURL string) bool {
	pin, ok := s.LoadPin()
	if !ok || pin.ServerURL == "" {
		return false
	}
	return normalizeServerURL(serverURL) != pin.ServerURL
}

// adoptServerURL records the control plane for a machine that was pinned before URLs were
// recorded. It is only called after a bundle verified under the already-pinned key.
func (s *Store) adoptServerURL(serverURL string) {
	pin, ok := s.LoadPin()
	if !ok || pin.ServerURL != "" || pin.PublicKey == "" {
		return
	}
	pin.ServerURL = normalizeServerURL(serverURL)
	_ = s.writePin(pin)
}

// CredentialProvider returns the enrolled workstation credential (OTC or OIDC session token)
// used to authenticate policy sync. Registered by the cmd package; nil/empty means anonymous.
var CredentialProvider func() string

func currentCredential() string {
	if CredentialProvider == nil {
		return ""
	}
	return CredentialProvider()
}

func (s *Store) pinPath() string { return filepath.Join(s.directory, "policy-trust.json") }

// LoadPin returns the pinned trust anchor, if any. A store with a pin is "managed": it only
// accepts and trusts Ed25519-signed bundles issued for this asset.
func (s *Store) LoadPin() (TrustAnchor, bool) {
	data, err := os.ReadFile(s.pinPath())
	if err != nil {
		return TrustAnchor{}, false
	}
	var ta TrustAnchor
	if json.Unmarshal(data, &ta) != nil || ta.PublicKey == "" {
		// A pin file that exists but is unreadable is treated as a pin we cannot honor:
		// callers see Managed()==true and fail closed.
		return TrustAnchor{KeyID: "corrupt"}, true
	}
	return ta, true
}

// Managed reports whether a trust anchor has ever been pinned on this machine.
func (s *Store) Managed() bool {
	_, ok := s.LoadPin()
	return ok
}

// PinKey pins the control plane's key on first contact. Re-pinning the SAME key is a no-op;
// pinning a different key is refused (rotation must be authorised by the current key).
func (s *Store) PinKey(keyID, publicKeyB64, assetID, serverURL string) error {
	raw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid policy public key")
	}
	if existing, ok := s.LoadPin(); ok {
		if existing.PublicKey == publicKeyB64 {
			return nil
		}
		return fmt.Errorf("%w: control plane offered a different signing key (%s) than the pinned one (%s); re-run `bap login` to re-enroll if the control plane key was replaced", ErrPolicyTampered, keyID, existing.KeyID)
	}
	return s.writePin(TrustAnchor{KeyID: keyID, PublicKey: publicKeyB64, AssetID: assetID, ServerURL: normalizeServerURL(serverURL), PinnedAt: time.Now().UTC().Format(time.RFC3339)})
}

// PinEnrollment pins the trust anchor handed out by an AUTHENTICATED enrollment (OTC register or
// OIDC login). Unlike first-contact pinning it may replace an existing pin: the enrollment
// itself proved who the control plane is, so this is also the recovery path after a key loss.
func (s *Store) PinEnrollment(keyID, publicKeyB64, assetID, serverURL string) error {
	raw, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid policy public key")
	}
	// A machine already enrolled with one control plane must not be silently re-pointed at a
	// different one (a test instance, a look-alike, a mistyped URL): that would swap the rules
	// it trusts. Re-enrolling with the SAME control plane (key rotation, key loss) is always fine;
	// moving to another control plane is a deliberate act.
	if existing, ok := s.LoadPin(); ok && existing.ServerURL != "" && serverURL != "" &&
		normalizeServerURL(serverURL) != existing.ServerURL && os.Getenv("BAP_ALLOW_REPIN") != "1" {
		return fmt.Errorf("%w: this machine is enrolled with %s; refusing to re-pin to %s (set BAP_ALLOW_REPIN=1 for a deliberate move to a different control plane)",
			ErrPolicyTampered, existing.ServerURL, normalizeServerURL(serverURL))
	}
	return s.writePin(TrustAnchor{KeyID: keyID, PublicKey: publicKeyB64, AssetID: assetID, ServerURL: normalizeServerURL(serverURL), PinnedAt: time.Now().UTC().Format(time.RFC3339)})
}

// RestorePin puts a previously loaded trust anchor back (used to undo a failed enrollment).
func (s *Store) RestorePin(ta TrustAnchor) error { return s.writePin(ta) }

// RemovePin deletes the trust anchor, returning the machine to the unmanaged state it was in before.
func (s *Store) RemovePin() { _ = os.Remove(s.pinPath()) }

func (s *Store) writePin(ta TrustAnchor) error {
	data, _ := json.MarshalIndent(ta, "", "  ")
	tmp := s.pinPath() + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, s.pinPath())
}

type rotationLink struct {
	OldKeyID  string `json:"old_key_id"`
	NewKeyID  string `json:"new_key_id"`
	NewPublic string `json:"new_public_key"`
	Signature string `json:"signature"`
}

// followRotation re-pins to the control plane's new key when the bundle carries a chain of
// rotation links, each signed by the key before it, starting at the key we already trust.
func (s *Store) followRotation(pin TrustAnchor, b Bundle) (TrustAnchor, bool) {
	if b.KeyID == pin.KeyID || len(b.KeyChain) == 0 {
		return pin, false
	}
	curID, curPub := pin.KeyID, pin.PublicKey
	for _, l := range b.KeyChain {
		if l.OldKeyID != curID {
			continue
		}
		payload := []byte(fmt.Sprintf("bap-policy-rotation-v1\nold=%s\nnew=%s\nnew_pub=%s\n", l.OldKeyID, l.NewKeyID, l.NewPublic))
		if !verifyEd25519(TrustAnchor{PublicKey: curPub}, payload, l.Signature) {
			return pin, false
		}
		raw, err := base64.StdEncoding.DecodeString(l.NewPublic)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return pin, false
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:8]) != l.NewKeyID {
			return pin, false
		}
		curID, curPub = l.NewKeyID, l.NewPublic
		if curID == b.KeyID {
			next := TrustAnchor{KeyID: curID, PublicKey: curPub, AssetID: pin.AssetID, ServerURL: pin.ServerURL, PinnedAt: time.Now().UTC().Format(time.RFC3339)}
			if s.writePin(next) != nil {
				return pin, false
			}
			return next, true
		}
	}
	return pin, false
}

// pinFromServer fetches /api/v1/policy/pubkey and pins it, after checking that it is the key
// the bundle claims to be signed with.
func (s *Store) pinFromServer(client *http.Client, serverURL, expectKeyID, assetID string) error {
	resp, err := client.Get(strings.TrimRight(serverURL, "/") + "/api/v1/policy/pubkey")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("pubkey endpoint returned %d", resp.StatusCode)
	}
	var pk struct {
		Alg       string `json:"alg"`
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4096)).Decode(&pk); err != nil {
		return err
	}
	if pk.Alg != "ed25519" || pk.KeyID == "" || pk.KeyID != expectKeyID {
		return fmt.Errorf("control plane key id %q does not match signed bundle key id %q", pk.KeyID, expectKeyID)
	}
	return s.PinKey(pk.KeyID, pk.PublicKey, assetID, serverURL)
}

// canonicalPayload must match bap-controlplane/internal/policy.CanonicalBundlePayload byte for byte.
func canonicalPayload(assetID string, version uint64, digest string, kill, strict bool, tier string, readExempt bool, updatedAt string) []byte {
	return []byte(fmt.Sprintf(
		"bap-policy-v2\nasset=%s\nversion=%d\ndigest=%s\nkill=%t\nstrict=%t\ntier=%s\nzsp_read_exempt=%t\nupdated_at=%s\n",
		assetID, version, digest, kill, strict, tier, readExempt, updatedAt,
	))
}

func verifyEd25519(pin TrustAnchor, payload []byte, sigB64 string) bool {
	pub, err := base64.StdEncoding.DecodeString(pin.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), payload, sig)
}

// verifyBundleAgainstPin checks algorithm, key id, asset binding and the signature over every
// enforcement-relevant field.
func verifyBundleAgainstPin(pin TrustAnchor, assetID string, b Bundle, digest string) error {
	if b.SigAlg != "ed25519" || b.SignatureEd25519 == "" {
		return fmt.Errorf("%w: bundle is not Ed25519-signed", ErrPolicyTampered)
	}
	if b.KeyID != pin.KeyID {
		return fmt.Errorf("%w: bundle signed by unpinned key %s", ErrPolicyTampered, b.KeyID)
	}
	if b.AssetID != assetID {
		return fmt.Errorf("%w: bundle was issued for asset %q, not this machine (%q); if the control plane was reinstalled or this machine's enrollment changed, run `bap login` to re-enroll", ErrPolicyTampered, b.AssetID, assetID)
	}
	if !verifyEd25519(pin, canonicalPayload(assetID, b.Version, digest, b.KillSwitch, b.StrictToolEnforcement, b.EnforcementTier, b.ZSPReadExempt, b.UpdatedAt), b.SignatureEd25519) {
		return fmt.Errorf("%w: signature does not match bundle contents", ErrPolicyTampered)
	}
	return nil
}

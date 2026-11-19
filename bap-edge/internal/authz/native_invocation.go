package authz

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"bap-edge/pkg/types"
)

// NativeToolInvocation identifies one client-dispatched tool call, not a turn,
// filename or command-text cache entry. The adapters hash the complete input.
type NativeToolInvocation struct {
	ID string
	InputDigest string
}

var ErrNativeInvocation = errors.New("native tool invocation cannot be reused")
const nativeDecisionWindow = 30 * time.Second

type nativeDecision struct {
	Fingerprint string `json:"fingerprint"`
	PolicyHash string `json:"policy_hash"`
	State string `json:"state"`
	Until time.Time `json:"until"`
	GrantID string `json:"grant_id,omitempty"`
	GrantSignature string `json:"grant_signature,omitempty"`
	Proof *types.AuditLineageProof `json:"proof,omitempty"`
	Signature string `json:"signature"`
}

// NativeToolInputDigest uses the same canonical JSON in every adapter. Content
// and edit replacements must be included; only the digest is passed to the PEP.
func NativeToolInputDigest(input any) (string, error) {
	raw, err := json.Marshal(input)
	if err != nil { return "", err }
	var canonical any
	if err := json.Unmarshal(raw, &canonical); err != nil { return "", err }
	raw, err = json.Marshal(canonical)
	if err != nil { return "", err }
	return batchCommandHash(string(raw)), nil
}

func nativeInvocationPath(dir, session, id string) string {
	return filepath.Join(dir, "native-invocations", batchCommandHash(session+"\x00"+id)+".json")
}

func signNativeDecision(d nativeDecision, secret string) string {
	d.Signature = ""
	raw, _ := json.Marshal(d)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(raw)
	return hex.EncodeToString(mac.Sum(nil))
}

func saveNativeDecision(path string, d *nativeDecision, secret string) error {
	d.Signature = signNativeDecision(*d, secret)
	raw, err := json.Marshal(d)
	if err != nil { return err }
	return writeFileAtomic(path, raw, 0600)
}

func loadNativeDecision(path, secret string) (*nativeDecision, error) {
	raw, err := os.ReadFile(path)
	if err != nil { return nil, err }
	var d nativeDecision
	if json.Unmarshal(raw, &d) != nil || !hmac.Equal([]byte(d.Signature), []byte(signNativeDecision(d, secret))) {
		return nil, fmt.Errorf("%w: invalid decision signature", ErrNativeInvocation)
	}
	return &d, nil
}

func nativeGrantRevocationPath(dir, grant string) string {
	return filepath.Join(dir, "native-grant-revocations", batchCommandHash(grant)+".revoked")
}

func nativeGrantRevoked(dir, grant string) bool {
	_, err := os.Stat(nativeGrantRevocationPath(dir, grant))
	return err == nil || !os.IsNotExist(err)
}

func nativeProtectedTarget(target string) bool {
	norm := "/"+strings.ToLower(strings.Trim(filepath.ToSlash(target), "/"))+"/"
	for _, part := range []string{"/.bap/", "/.bapstate/", "/.claude/"} {
		if strings.Contains(norm, part) { return true }
	}
	switch strings.ToLower(filepath.Base(target)) {
	case "agents.md", "gemini.md", "claude.md", "codex.md", ".cursorrules", "copilot-instructions.md", "policy.cedar", "schema.json", "bapedge.exe", "interceptor.exe":
		return true
	}
	return false
}

// AuthorizeNativeToolInvocation spends one use for one logical invocation.
// Identical duplicate prechecks share that decision for at most 30s, until a
// post-tool callback closes it. It does not execute or certify a native write.
// Callers must still run their current session/revocation and invariant checks.
func AuthorizeNativeToolInvocation(dir, session, client, tool, target, workspace string, invocation NativeToolInvocation) (*types.CryptographicAgentSVID, *types.TaskGrant, *types.AuditLineageProof, error) {
	if dir == "" { dir = ResolveZSPDir() }
	tool = strings.ToLower(strings.TrimSpace(tool))
	if err := CheckSessionRevocation(filepath.Join(workspace, "policy.cedar"), session); err != nil { return nil, nil, nil, err }
	canonical := ResolveCanonicalPath(target, workspace)
	action, resource, escapes := ResolveZSPActionAndResource("", "", "", tool, target, workspace)
	command := "tool:"+tool+" "+canonical
	if invocation.ID == "" {
		// Legacy clients do not get guessed IDs or content/time-based reuse.
		return VerifyOrConsumeSessionZSP(dir, session, client, action, resource, command, workspace, escapes, true, nil)
	}
	digest, err := hex.DecodeString(invocation.InputDigest)
	if len(invocation.ID) > 512 || session == "" || err != nil || len(digest) != sha256.Size {
		return nil, nil, nil, fmt.Errorf("%w: stable tool-use ID and complete input SHA-256 required", ErrNativeInvocation)
	}
	if target == "" || escapes || LooksLikeCredentialPath(target) || isCredentialStorePath(canonical) || IsFilesystemRootTarget(canonical) ||
		(action == "fs:file:write" && nativeProtectedTarget(canonical)) {
		return nil, nil, nil, fmt.Errorf("%w: native target is protected or outside workspace", ErrResourceNotGranted)
	}
	svid, _, minter, secret, err := EnsureSessionPrincipal(dir, session, client)
	if err != nil { return nil, nil, nil, err }
	policy, err := LoadPermissionPolicy(dir, secret)
	if err != nil { return svid, nil, nil, err }
	decision := policy.Evaluate([]string{action}, []string{"workspace://current"})
	if len(decision.Denied) > 0 { return svid, nil, nil, ErrActionDenied }
	// Evaluate explicit target rules too. The generic file:// default is not
	// in-boundary, but a matching target restriction must never be discarded.
	for _, rule := range policy.Rules {
		if len(rule.ResourceMatch) > 0 && globAny(rule.Match, action) && globAny(rule.ResourceMatch, strings.ToLower(resource)) {
			if rule.Tier == TierDeny { return svid, nil, nil, ErrActionDenied }
			if rule.Tier == TierApprove { return svid, nil, nil, fmt.Errorf("native target requires a target-scoped human authorization") }
		}
	}
	fingerprint, _ := NativeToolInputDigest([]string{session, svid.Subject, canonicalBatchWorkspace(workspace), tool, canonical, invocation.InputDigest})
	path := nativeInvocationPath(dir, session, invocation.ID)
	var grant *types.TaskGrant
	var proof *types.AuditLineageProof
	err = withZSPStoreLock(dir, "native-"+batchCommandHash(session+"\x00"+invocation.ID), func() error {
		if d, err := loadNativeDecision(path, secret); err == nil {
			if d.State != "accepted" || d.Fingerprint != fingerprint || d.PolicyHash != batchPolicyHash(policy) || !time.Now().Before(d.Until) || nativeGrantRevoked(dir, d.GrantID) {
				return fmt.Errorf("%w: input, policy, lifetime, completion or revocation changed", ErrNativeInvocation)
			}
			engine := NewZSPEngine(minter, secret)
			grants, err := loadSessionGrants(dir, session, engine)
			if err != nil { return err }
			for _, g := range grants {
				if g.GrantID == d.GrantID && g.AuthoritySignature == d.GrantSignature && time.Now().Before(g.ExpiresAt) &&
					(!g.IsBurned || g.BurnReason == "MaxUses Reached") && d.Proof != nil {
					grant, proof = freshestGrantState(dir, session, g), d.Proof
					if grant.IsBurned && grant.BurnReason != "MaxUses Reached" { return ErrNativeInvocation }
					return nil
				}
			}
			return ErrNativeInvocation
		} else if !os.IsNotExist(err) { return err }
		// Publish a pending tombstone BEFORE spending. A crash/write failure can
		// deny this invocation, but cannot cause a retry to spend/mint twice.
		d := &nativeDecision{Fingerprint: fingerprint, PolicyHash: batchPolicyHash(policy), State: "pending"}
		if err := saveNativeDecision(path, d, secret); err != nil { return err }
		var verifyErr error
		_, grant, proof, verifyErr = VerifyOrConsumeSessionZSP(dir, session, client, action, resource, command, workspace, false, true, nil)
		if verifyErr != nil {
			// Renew only ordinary in-workspace native edits whose policy tier is
			// allow. Interpreter, deletion, publish and approval tiers never enter.
			if action != "fs:file:write" || os.Getenv("BAP_ZSP_AUTO_GRANTS") == "0" || len(decision.NeedsApproval) > 0 ||
				!(errors.Is(verifyErr, ErrGrantExpired) || errors.Is(verifyErr, ErrGrantBurned) ||
					(errors.Is(verifyErr, ErrZeroStandingPrivilegeViolation) && strings.Contains(verifyErr.Error(), "has ZERO standing privileges")) ||
					errors.Is(verifyErr, ErrActionNotGranted) || errors.Is(verifyErr, ErrResourceNotGranted)) {
				return verifyErr
			}
			_, _, verifyErr = submitTaskEnvelopeBound(dir, session, client, "TASK_EXECUTION", "Policy-authorized native workspace edit", command,
				[]string{action}, []string{"workspace://current"}, "", "policy_automatic_native", 25, 10*time.Minute, nil)
			if verifyErr != nil { return verifyErr }
			_, grant, proof, verifyErr = VerifyOrConsumeSessionZSP(dir, session, client, action, resource, command, workspace, false, true, nil)
			if verifyErr != nil { return verifyErr }
		}
		d.GrantID, d.GrantSignature, d.Proof = grant.GrantID, grant.AuthoritySignature, proof
		d.Until = time.Now().Add(nativeDecisionWindow)
		if grant.ExpiresAt.Before(d.Until) { d.Until = grant.ExpiresAt }
		d.State = "accepted"
		return saveNativeDecision(path, d, secret)
	})
	return svid, grant, proof, err
}

// CompleteNativeToolInvocation closes successful AND failed calls. Duplicate
// post hooks are harmless; missing IDs never create a reusable authorization.
func CompleteNativeToolInvocation(dir, session, client, id string) error {
	if id == "" { return nil }
	if dir == "" { dir = ResolveZSPDir() }
	_, _, _, secret, err := EnsureSessionPrincipal(dir, session, client)
	if err != nil { return err }
	return withZSPStoreLock(dir, "native-"+batchCommandHash(session+"\x00"+id), func() error {
		path := nativeInvocationPath(dir, session, id)
		d, err := loadNativeDecision(path, secret)
		if os.IsNotExist(err) { return nil }
		if err != nil { return err }
		d.State = "completed"
		return saveNativeDecision(path, d, secret)
	})
}

# Product review: 2026-11-14

Repository review, not hosted-service or installed-client acceptance. No external Jira issues were created. The checkout was clean before this review.

## Current position

BAP has a substantial Windows pilot implementation: bounded grants, signed per-asset policy, enrollment-bound public-key pins, rotation chains, cached-policy verification, recommendations, a control-plane approval inbox, and single-node authority checkpointing. Recent source changes add configurable prompt capture, metadata-first telemetry, signed offline leases, release gates and recovery tooling. These are implementation claims; this review does not requalify the full product.

The product remains a pilot candidate. Browser-to-edge temporary approval/resume (BAP-1022), full native capability/credential enforcement, individual administrator identity, device proof of possession, non-Windows native acceptance, and real latency/fleet evidence remain open. BAP-1082 is explicitly postponed in the existing backlog. Existing story status tables contain historical claims and should be read alongside the newer pilot-hardening update at the top of JIRA_STORIES.md.

## Reported policy-sync failure

`policy rollback rejected` means the edge compared the incoming version with a cached version that passed its rollback-validity check and refused the lower version. This is separate from an invalid signature or an unpinned signing key. Signing alone does not guarantee version continuity.

Relevant source evidence:

- `bap-edge/internal/policystore/store.go`: `Accept` verifies a managed bundle before comparing versions; lower versions are refused.
- `bap-controlplane/internal/policy/settings.go`: legacy `EnsureVersionAtLeast` and its test describe raising versions after ephemeral redeploys.
- `bap-controlplane/cmd/server/main.go`: startup now explicitly avoids wall-clock versions and relies on persisted authority. It no longer calls `EnsureVersionAtLeast`.
- `bap-controlplane/internal/policy/checkpoint.go`: checkpoint restore replaces the policy bundle and its version.

Likely causes are a lost/stale server checkpoint or migration from a previously clock-seeded counter. The provided error does not identify the two versions, and hosted state was not inspected, so neither cause is confirmed. The diagnostic change accompanying this review prints both versions while preserving the sentinel error and rejection behavior.

Updated authority model after review: the live control plane may publish a higher or lower version. Each sync request now carries a cryptographically random 256-bit nonce. The server signs a separate response proof binding that nonce, the directive and the exact bundle signature. The edge verifies the proof under its pinned key (including authorized rotation), then verifies the bundle's signature and asset binding before accepting a lower version. Local `Accept` and responses from older servers without a fresh proof retain rollback protection. Replaying an old signed bundle or an old response proof cannot authorize a downgrade. Both edge and server must be upgraded; cache/pin deletion is unnecessary. Offline operation still requires a valid cached policy, and invalid credentials, signatures or expired authority remain errors.

Recovery sequence for the control-plane operator:

1. Capture the incoming/cached versions using a client containing the diagnostic change. Confirm the deployed server build and enrolled endpoint. Do not copy credentials or signing keys into diagnostics.
2. Check the deployment's persistent database volume, authority checkpoint, replica count and initialization configuration. Production startup requires stable signing configuration, absolute persistent storage and a signed offline budget. The explicitly acknowledged ephemeral mode is unsuitable for persistent fleet authority.
3. Restore the latest valid authority checkpoint when available. Deploy the nonce-bound sync protocol to the control plane and clients: a fresh signed server response now replaces a higher cached version automatically. For clients that cannot yet be upgraded, an audited administrator migration above the legacy fleet maximum remains a compatibility option. Never trust a client-supplied version as automatic authority to advance the server counter, and do not resurrect wall-clock seeding.
4. Verify a fresh signed sync, unchanged asset/key binding, policy edits, restart continuity and a rejected older-bundle replay on an installed client. Cache repair or login alone does not fix a lower server counter under the same trusted key.

Do not delete the cache/pin, disable verification, or accept a lower signed version as the recovery procedure. No hosted state or installed binaries were changed by this review.

## Proposed next Jira work

Identifiers below are local proposals; confirm availability before creating tickets.

| Priority | Story | Scope and acceptance | Sequence |
|---|---|---|---|
| P0 | BAP-1089: live control-plane authority and rollback diagnostics | Source implementation now uses a nonce-bound signed sync response to accept server-directed versions in either direction. Local downgrade, response replay, persisted lower versions, kill-switch and recovery regressions added. Hosted deployment and installed-client qualification remain open; no client-directed counter bump. | First, before broader pilot rollout |
| P0 | BAP-1070/1071/1079: qualify deployed persistence | Reuse existing stories: demonstrate actual hosted restart/redeploy continuity for policy versions, enrollment bindings, recommendations and audit; missing/corrupt volumes fail safely; document backup restore and single-replica operation. | Alongside version recovery |
| P1 | BAP-1080/1085: installed-client recovery and skew acceptance | Exercise current repair tooling and discover every active hook copy. Upgrade and rollback mixed clients while preserving identity, trust and the version floor; require matching hashes or an actionable diagnosis. | After persistence is stable |
| P1 | BAP-1022: browser approval to edge resume | Signed, asset/session-bound temporary decisions; durable pending requests; expiry and replay rejection; prove browser approval resumes only the intended blocked operation. Existing inbox UI alone does not close this story. | Next functional increment |
| P1 | BAP-1081: real session friction and latency | Measure clean installed sessions with developer override off; publish p50/p95, grants/denials per developer-hour and telemetry backlog. Keep the existing under-100-ms target measurable. | Before pilot expansion |
| P1 | BAP-1087: offline lease acceptance | Real disconnected workstation, lease expiry, reconnect and kill-switch/revocation behavior; dashboard stale-machine indication. | Before claiming offline revocation bounds |
| P2 | BAP-1083: device proof of possession | Hardware/OS-keystore-held signing key, server challenge binding and replay tests; copied bearer credential alone cannot impersonate a workstation. | After core pilot stability |

Use a Windows-first pilot until BAP-1088 has native platform evidence. Calendar estimates need an owner and the hosted deployment baseline; the ordering above reflects dependencies, not delivery commitments.

## Validation of the live authority change

Passed: edge `go test ./internal/policystore -count=1`; control plane `go test ./internal/policy ./internal/api -count=1`; `git diff --check`. Dependencies were not downloaded. Tests cover a clock-sized cached version replaced by a lower live server version, refusal of the same bundle through local acceptance or a server without a freshness proof, request-bound replay rejection, restart reads, and lower-version kill-switch activation/recovery. Shared golden payload tests protect the edge/server wire format. Hosted service and installed-client deployment remain unverified.

# Bounded Authority Plane — vision, authority model and acceptance goals

Updated 2026-11-18. This is the product direction and its acceptance contract.
[ARCHITECTURE.md](ARCHITECTURE.md) describes current implementation and limitations.
A source path, passing fixture or checked roadmap box does not qualify an installed
release. Every goal below has acceptance cases in the
[vision test plan](docs/VISION_ACCEPTANCE.md); unrun cases remain NOT_TESTED.

## 1. The product promise

Native tool authorization must spend once per logical call even when two BAP
hooks observe it. Generic grants remain single-use; ordinary workspace edits use
a separate bounded class. Fresh allow-tier edit authority should be obtained by
the integration, while required human approval must be surfaced with an actionable
request ID. See the [native authorization contract](docs/NATIVE_TOOL_AUTHORIZATION.md).
Cross-platform installed-host verification remains required; callback correlation
does not attest exactly-once execution by an arbitrary native tool host.

**Let people use their normal AI coding agent while the enterprise controls the
authority of governed operations and can explain what actually happened.**

The developer experience starts with:

~~~powershell
pip install --upgrade bap-ltd
bap install
# Optional diagnostic helpers: bap install --debug
bap login
bap status
bap claude
~~~

Use the organization's approved package mirror and configured pilot origin.
The user asks for ordinary work. The installed integration supplies the governance
instructions, routes supported operations and handles authorization requests.
Users should not have to append “stay in the workspace,” “obtain a grant” or
“follow policy” to every prompt. Repeated manual authorization instructions for
routine supported work are a product friction issue to measure and fix.

The enterprise must distinguish the person, enrolled workstation, agent principal,
session, requested work, authority, observed operation and actual result.
A prompt, claimed identity, approval or heartbeat is not proof of execution.

## 2. Goals that must be demonstrated

| Goal | Product outcome | Acceptance coverage |
|---|---|---|
| G01 Onboarding and identity | Approved install, corporate sign-in, reliable workstation/session ownership | T01–T05 |
| G02 Useful work | Read, search, edit, build and test through the ordinary client without policy coaching | T06–T08 |
| G03 Bounded authority | No implicit execution rights from identity; exact scope, lifetime and use budgets | T09–T16 |
| G04 Context never grants authority | Prompt injection, misleading intent and wrappers do not widen governed permissions | T17–T19 |
| G05 Human control and step-up | Eligible capabilities can be approved; hard denies remain denied; autoapprove is bounded | T20–T26 |
| G06 Central policy ownership | Signed distribution, freshness, controlled recommendations and explicit restrictions | T27–T31 |
| G07 Real enforcement boundaries | Each received hook/MCP/shim/broker operation is checked; native OS and egress boundaries are independently proven | T32–T37 |
| G08 Independent resource enforcement | Protected APIs derive actual effects and reject tampering, scope mismatch, replay and bypass | T38–T43 |
| G09 Governed remediation | Immutable proposals, parent lineage, fresh evaluation and separate execution outcomes | T44–T46 |
| G10 Trustworthy evidence | Causal IDs, delivery, deduplication, privacy, integrity and independently verified external anchors | T47–T53 |
| G11 Fleet operations | Discovery, honest coverage, session/workstation/user/fleet control and sourced token accounting | T54–T59 |
| G12 Resilience and durability | Offline bounds, recovery, persistent authority, backup restore and compatible rollback | T60–T65 |
| G13 Managed release delivery | Matching artifacts, trusted publication, native OS/client acceptance and managed installation | T66–T68 |
| G14 Leadership visibility | Named roster, work/deliverable evidence, reproducible reports and measured capacity | T69–T73 |
| G15 Stronger roots of trust | Device-held identity, hardware attestation, authenticated human-held approval and credential brokering | T74–T76 |
| G16 Future endpoint/federation scope | Native network enforcement and cross-organization delegation with explicit trust boundaries | T77–T78 |
| G17 Assurance | Evidence usable by assessors without claiming that a hash chain or demo establishes certification | T79 |

The five live demo scenarios exercise a subset. Full acceptance covers every goal,
including unsupported goals that must be recorded as implementation gaps.
Do not remove a goal from the test plan merely because the release cannot pass it.

## 3. Authority: ZSP does not mean a prompt before every command

**Zero Standing Privilege (ZSP)** means agent identity or user intent alone is not
execution authority. A governed operation must satisfy policy and the applicable
grant gate. Current signed read exemptions and administrator-approved machine
effects can exempt supported operations from that gate; these are explicit policy
permissions and must be visible. Do not describe an exempt operation as having
consumed a grant.

For grant-bearing operations, the request describes who, the delegating context,
intent and requested permissions. The PEP evaluates actual effects and signs a
bounded TaskGrant. The agent's signature authenticates a request; it does not
approve it. The envelope's claimed human identity is not proof of a fresh human
decision.

### Policy outcomes

| Outcome | Behavior |
|---|---|
| allow | Policy permits a bounded grant without a per-request human decision |
| approve | Grant requires verified human approval, or an eligible active autoapprove window |
| deny | No grant, including after a human request or during autoapprove |

Most restrictive applicable rule wins. Unknown effects do not become default-allow.
Resource boundaries apply independently of action names. Use the canonical action
reported by the broker rather than guessing an alias.

Source of truth: [default permission policy](bap-edge/internal/authz/default_permission_policy.json),
[permission model](docs/PERMISSION_POLICY.md), and
[command-batch contract](docs/COMMAND_BATCH_AUTHORIZATION.md).

### Automatic grants and explicit grants are different paths

For supported recognized inspection batches, BAP can obtain a grant internally,
without a user/agent request-denial-retry loop. Every constituent effect must pass;
adding a publish effect cannot inherit a read permission. The automatic batch
grant is bound to command hash, workspace, session/principal and policy hash,
with one execution use and at most 30 seconds. Prechecks do not consume it.

An explicit task grant uses the effective policy's grant class. Embedded defaults:

| Class | Scope | Maximum uses | Maximum lifetime |
|---|---|---:|---:|
| single_use | Default for remaining actions, including execution/publish/network | 1 | 300 seconds |
| inspection | Recognized inspection actions | 10 | 300 seconds |
| workspace_edit | Recognized file write/edit actions in the current workspace | 25 | 600 seconds |

These are ceilings, not guarantees. Policy can narrow them. Mixed-class requests
take the strictest ceilings; mint caps also apply. A bounded multi-use grant does
not become standing authority, and a workspace edit grant is not an exact
file-path capability unless that restriction is actually enforced.

The embedded wildcard mappings include repo:* to repo:read and fs:* to fs:read.
Other wildcard asks are not implied permission. Never claim wildcard narrowing
adds publish rights. ALLOWED-LIMITED means the resulting authority was attenuated,
not that every request can be made safe.

Grant verification, session/principal/resource binding and use consumption remain
necessary at execution. An authorization-only check is not workload execution.
A consumed use is not proof of successful completion. Revoking one grant prevents
its reuse; stopping future automatic grants requires an applicable restriction
or policy change.

## 4. Step-up, human approval, autoapprove and recommendations

These are distinct mechanisms:

| Mechanism | Purpose | What it does not establish |
|---|---|---|
| Local ZSP request and approval | Human reviews a missing capability; approval mints a bounded grant for the requesting session | Browser approval delivery or automatic continuation of the original command |
| Central task escalation (bapedge stepup) | Submit/query a control-plane task escalation record | A local ZSP grant, native permission or resumed edge operation by itself |
| Autoapprove window | Human enables temporary pre-consent for eligible approve-tier requests | Policy bypass, unlimited uses or authorization of hard denies |
| Policy recommendation | Human proposes an eligible development effect; admin review adds a signed per-machine grant exemption | Temporary task approval or universal command whitelisting |
| Developer override | Separate development-only degradation path; official release behavior differs | A valid production acceptance result or an agent-controlled recovery mechanism |

### Local ZSP approval

When policy needs a human, the agent reports the pending request and waits.
The human reviews its session/actions/resources in an independent terminal:

~~~powershell
bapedge zsp approvals
bapedge zsp approve <request-id>
# Or: bapedge zsp deny <request-id>
~~~

The current challenge requires an interactive terminal and retyped one-time code.
The agent cannot satisfy it with a flag or piped response. Approval mints a
short-lived grant; retry the original operation before expiry. Re-authorizing
the same fully covered scope can reuse a suitable live human-approved grant.
A broader scope or expired grant needs another decision.

This is not a delivered biometric/hardware-held approval guarantee or proof of
individual administrator SSO. The same-user/pseudo-terminal threat remains a
known limit of the terminal challenge. Browser-to-edge temporary approval and
automatic resume require separate implementation and end-to-end acceptance.

### Autoapprove is pre-consent, not automatic policy allow

The human can open a bounded window with the terminal challenge; the agent may
not turn it on. Current maximum duration is eight hours. Eligible requests still
undergo policy, scope, signing, mint/use/TTL and revocation checks.

The embedded destructive/publishing/admin and network rules have no_auto_approve:
they still require a human per request. Code-level policy/grant/admin escalation
guards and hard credential denies also remain. Mixed requests cannot silently
drop the protected part and execute the rest. Autoapprove does not increase
grant ceilings or relax Cedar/native boundaries.

Record the window state when testing. With it on, eligible Python execution can
demonstrate pre-consented grant issuance; it cannot prove a fresh human decision.
Test expiry and the operator's off action using a fresh request without a
remaining applicable grant. Closing a window is not evidence that already issued
grants were revoked; test grant revocation separately.

### Recommendations

An approved recommendation can remove repetitive grant friction for an eligible
local effect on one machine, through signed policy sync. Secrets, publishing,
network and other excluded effects are not recommendations. Approve/reject/revoke,
machine isolation and policy-sync evidence are all required. Shared admin
authentication does not individually identify the reviewer.

## 5. Security invariants and governed operations

- **I1:** Intent/classification is context, never permission. Unknown intent does
  not authorize an unknown effect. Prompt injection cannot widen governed scope.
- **I2:** The local broker is not the sole PEP and cannot be presumed to observe
  every process or request.
- **I3:** A protected resource independently derives the actual action/resource,
  verifies a compatible grant and performs configured authoritative consumption.
- **I4:** The control plane owns signed policy and lifecycle. Valid cached policy
  supports eligible local decisions; online mutable consumption/enrollment can
  still require a round trip. Latency is measured, not assumed.
- **I5:** Evidence links received intent, authority, PEP decision and observed
  execution/result. A sequential hash chain detects tested retained-history
  changes; it does not prove complete collection, external notarization or success.
  Offline spooling is distinct from local audit-persistence failure.
- **I6:** Agent identity grants no implicit execution authority; explicit policy
  exemptions and bounded grants have different evidence.
- **I7:** Agents do not approve themselves, change trust, sign policy or activate
  developer override. Administration itself is governed.

Four intervention rules remain product goals: R1 proposals are immutable;
R2 corrected input creates a newly evaluated proposal, not a forced DENY-to-ALLOW;
R3 authorization and execution are separate outcomes, including UNKNOWN when
downstream completion is unconfirmed; R4 administrative access is not a bypass.

Inspection, workspace mutation, credential access, network egress and system
reconnaissance remain useful effect categories. They do not replace the actual
canonical action catalog, full shell parsing or OS permission enforcement.

## 6. Four planes, five observed integration layers

The control plane owns enrollment, policy, grants, restrictions and administration.
The edge checks operations it receives and executes supported brokered workloads.
The resource gateway independently checks protected requests reaching it.
The observability plane retains received evidence and shows gaps and provenance.

Hook, MCP, shim, broker/native-provider and gateway observations have distinct
coverage. Hook approval/file presence is not an observed callback. MCP self-reports
are cooperative; process discovery is presence. Neither becomes execution authority.
Disabling hooks must reveal degraded coverage, not silently assert full protection.

The legacy exec classifier and native run provider are different boundaries.
The effect-level grant Set and runner Profile are not yet one active grant-to-OS
authority path. Test real native read/write/network restrictions, credential
masking and whole-agent compatibility before claiming stronger containment.

Current platform limits: Windows AppContainer has bounded native fixtures;
Linux bubblewrap and macOS Seatbelt (native execution unverified) need native
acceptance. Landlock (not implemented), eBPF (simulation only), WFP (not implemented),
Endpoint Security (not implemented), and NetworkExtension (not implemented) are
not delivered host-wide interception. Runtime/MDM configuration does not prove
non-bypassable kernel enforcement.

A gateway only protects routes/backends actually placed behind it. Destination
allowlisting is not independent resource authorization or comprehensive exfiltration
prevention. Backend network isolation must be tested separately from gateway 401s.

## 7. Evidence, fleet control and resilience

Evidence must distinguish requested work, policy check, grant, execution attempt,
actual exit/result, resource-side result, prompt report and process presence.
Correlate stable operation/session/workstation/person IDs. Repeated observations
of one operation are not extra work; identical commands in separate turns are
separate attempts. Missing sources stay partial/unknown.

Measure policy-decision time separately from startup, approval, child work and
reporting. Measure freeze propagation from administrator acknowledgement to each
connected client's actual refusal. Three-second polling is not sub-100ms fleet
revocation; disconnected machines cannot receive a new restriction immediately.
An offline policy lease bounds cached authority, not receipt of a new freeze.

The pilot authority is single-server SQLite on qualified persistent storage,
with stable signing configuration, explicit initialization and a declared offline
budget. Test commit/acknowledgement failure, restart, redeploy, backup restore,
signer continuity and compatible rollback. Multi-replica authority remains unqualified.

Metadata minimization and signed prompt-capture policy are separate settings.
Test actual outbound records, queued data and exports with synthetic markers;
do not promise universal zero-code transmission. Review capture, retention and
authorized readership before collecting another person's work.

Token/credit accounting must identify its producer, unit, time window, retry
semantics and missing data. Token counts are not cost without a validated price
mapping and are not enforced spend caps without an independent limit test.
Leadership reports need an expected roster, reproducible totals, deliverable/
validation/review references and visible coverage gaps. Agent “done,” session exit
and command volume do not establish verified completion or productivity.

## 8. Stronger ambitions retained as explicit acceptance gaps

Device-held SPIFFE-compatible identities, hardware attestation, comprehensive
credential brokering, biometric/human-held approval, independent RFC 3161/KMS
anchors, mandatory endpoint network enforcement and cross-organization delegation
remain goals to prove, not checked release milestones.

A local SPIFFE-shaped identifier is not a deployed CA/mTLS/rotation system.
A retained chain is not a Merkle tree, legal non-repudiation or external notarization.
A fixture/simulation cannot pass native hardware, real IdP, real timestamp
authority or real fleet acceptance. Managed packaging needs actual installed
signature/provenance and MDM enforcement tests on each claimed OS/client.

Compliance and risk reduction need independently scoped assessment and evidence.
BAP does not acquire SOC 2, FedRAMP or ISO status from a demo. Do not claim zero
blast radius, zero friction, thousands of qualified agents, zero audit loss or
instant fleet control without tests establishing the stated boundary and load.

## 9. Release and pilot decision

Use the [five natural demo scenarios](DEMO_CLAUDE_CODEX_ZERO_TRUST.md) for the
first live demonstration and the [full test matrix](docs/VISION_ACCEPTANCE.md)
for complete goal coverage. Record each case as PASS, FAIL or NOT_TESTED with
artifact/build, OS/client, policy, observed IDs and timestamps. Unsupported
implementation is recorded as a gap, not a waived pass.

Start with two qualified Windows workstations, expand to five after ordinary
work/recovery acceptance, then qualify the intended twenty-person roster.
A narrow pilot may proceed only with explicitly accepted exclusions; it must not
be described as the full vision passing. Missing enforcement, privacy, identity
or durability requirements for its actual promise block that pilot.



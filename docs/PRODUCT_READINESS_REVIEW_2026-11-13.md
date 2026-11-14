# Product readiness review — 13 November 2026

Review baseline: `e163a33` (1.13.6). Recommendation: proceed with internal qualification for a narrow Windows/Claude pilot. Do not yet promise an unattended enterprise rollout, durable leadership reporting, or universal workstation containment.

This is a repository assessment, not a deployed-environment certification. No external Jira tickets were created. Ticket drafts below require assignment in the team's tracker; existing BAP IDs refer to the checked-in backlog.

## Where the product stands

BAP has a substantial governance foundation: bounded grants, signed per-asset policy, enrollment-bound policy sync, key-rotation support, workstation/session ownership checks, local evidence spooling, V3 administration, discovery and roster coverage. Recent releases address real operational defects rather than just adding presentation.

| Recent work | Practical value | Remaining qualification |
|---|---|---|
| Enrollment fixes and signed-policy recovery, 1.13.2 | Avoid leaving a workstation pinned without usable signed rules; preserve cached rules on anonymous sync | Clean install, interrupted enrollment, restart and mixed-client acceptance |
| Signed approvals and policy recommendations, 1.13.5 / BAP-1072 | Administrator can exempt a narrow local development effect from grants for one machine | Dashboard review is absent; recommendation flow's recorded 14-check E2E proof is not in CI; hosted persistence remains open |
| Watcher lifecycle fixes, BAP-1073 | Session end and duplicate watcher handling have actual process regression coverage | Full pilot run and remaining integration fixture cleanup |
| Credential-reference screening, 1.13.6 / BAP-1076 | Ordinary prose and code identifiers stop being treated as credential access | Confirm every installed hook/plugin copy matches; this remains command classification, not proof of OS isolation |
| V3 policy studio and escalation inbox, BAP-1007 | Review, simulation and policy deployment have authenticated API/UI contracts | Control-plane escalation approval does not yet deliver an edge-local ZSP grant and resume a real agent |
| Roster, startup and native-probe work | Provides explicit expected check-ins and integration diagnostics | Actual roster deployment, two clean machines, logon/reboot, production IdP and native callbacks |

The architecture transition is unfinished. `docs/CAPABILITY_MODEL.md` explicitly says the capability converter is not the active grant-to-runner authority path. Legacy broker enforcement still uses command classification. Windows AppContainer has boundary-test evidence; Linux/macOS native acceptance remains open. Do not infer protection for an unmediated action from discovery, a heartbeat or a successful broker command.

Three readiness decisions should stay distinct:

- **Internal qualification:** reasonable now, using disposable workstations and isolated services.
- **Limited customer/design-partner pilot:** conditional on the release, recovery, privacy, durability and usability gates below. Qualify each actual client/OS combination.
- **Leadership progress reporting and broad enforcement rollout:** not ready. Durable canonical operations, work/evidence association, reporting access and native enforcement acceptance remain separate requirements.

## Evidence checked in this review

Passed on this checkout: `test_v3_controls.cjs`, `test_v3_discovery.cjs`, `test_activity_metrics.cjs`, `test_v3_admin.cjs`, and `scripts/check_capability_claims.py` (six documents).

Source checks confirmed:

- `bap-edge/internal/sandbox/sandbox.go` initializes `timeoutSec := 120`; BAP-1077 remains relevant. Inspect existing configuration before choosing the implementation.
- Server startup constructs registry and audit stores with `registry.NewStore` and `audit.NewStore`. Session SQLite initialization can fall back to `session.NewStore` on failure. A database filename does not establish durable authoritative state.
- Hosted startup without `BAP_POLICY_SIGNING_SEED` logs a warning. It does not establish a release readiness refusal.
- `bap-edge/cmd/recommend.go` supports `--yes`, including non-interactive submission; BAP-1078 remains relevant.
- `release.yml` packages and publishes without depending on the separate CI test jobs; both CI and release workflows have PyPI publication paths.

The backlog records previous Go, Python, native boundary and isolated E2E results. Those are historical evidence, not reruns in this review. No fresh full Go/Python suite, clean install, hosted restart, real browser approval/resume or native escape suite was run. The broker reported an already-active human development override; successful assessment commands are not production enforcement acceptance.

## Implement existing Jira work first

Avoid a second competing roadmap. The current backlog already names most pilot blockers.

| Order | Existing Jira | Concrete deliverable and acceptance | Suggested owner |
|---|---|---|---|
| 1 | BAP-1086 + BAP-1001 | One publication path, dependent on required tests for the exact release commit. Reject an artifact with a failed/missing test result; match toolchains to modules and prevent unapproved dependency downloads. Record branch-protection configuration separately. | Release engineering |
| 2 | BAP-1079 + BAP-1070 + BAP-1071 | One authoritative persistence plan covering enrollment, restrictions, settings/versions, recommendation decisions, deduplication and audit history. Restart/redeploy without re-enrollment, lost acknowledged events, lost restrictions or policy rollback. Production readiness fails on unavailable storage or signing continuity. | Control plane |
| 3 | BAP-1077 | Configurable execution lifetime with a usable long-job path, cancellation, bounded resources and visible progress. An approved fixture runs beyond 120 seconds, can be cancelled, and leaves no children. | Edge runtime |
| 4 | BAP-1080 + BAP-1085 | Diagnose all installed broker/hook/plugin copies; reject incompatible rollout; document authenticated recovery. A stale copy and damaged local cache can be repaired without deleting identity or weakening integrity checks. | Client/release engineering |
| 5 | BAP-1084 | Inventory actual outbound fields; apply capture policy and redaction before transmission. Synthetic sensitive markers never appear in uploaded payloads, retry spools or exports where prohibited. Publish accurate privacy/retention guidance. | Security + telemetry |
| 6 | BAP-1078 | Human-controlled recommendation submission with server-side approvable-effect restrictions retained. Agent/non-interactive submission fails; an authenticated operator can submit and an administrator can review. Do not treat terminal presence alone as strong human identity. | Edge + security |
| 7 | BAP-1081 + BAP-1002 + BAP-1004 | Measure real daily-work friction and distinct policy/command/upload/UI timings; show stale uploads/backlog. Normal read/edit/build/test/commit workflow succeeds under the intended production policy without repetitive prompts. Reconcile 20 known operations end to end. | Developer experience + telemetry |
| 8 | BAP-1087 | Signed-policy freshness budget and explicit offline behavior. A disconnected restricted machine cannot regain authority; stale-policy degradation is tested and visible. | Policy/security |
| 9 | BAP-1022 | If browser approval is promised: authenticated edge request transport, signed bound decision, single-use grant/resume, expiry and restart persistence. Wrong-session, replay and expired decisions fail. | Edge + control plane |
| 10 | BAP-1088 + BAP-1030 + BAP-1011/1012/1014 | Qualify the actual native runner, resource and egress boundaries for each advertised platform. Hook-disabled tests exercise prohibited effects; missing providers fail closed. | Runtime/security |

BAP-1082 individual administrator identity is explicitly postponed in the current backlog; keep that decision. A limited pilot may use the accepted shared-token model with the attribution limitation stated. Do not claim individual SSO approval attribution. BAP-1083 proof of possession remains important security debt; reassess its priority against the selected customer's device and credential threat model.

Use the PostgreSQL direction already proposed in `LEADERSHIP_PILOT_PLAN.md` as the production persistence decision to resolve against older SQLite-oriented BAP-1070 wording. Do not build separate databases for enrollment and reporting without a transaction/ownership plan. Provisioning is not established by this review.

## New Jira drafts worth creating

These are narrow child stories, not new umbrella epics. Suggested keys are labels only; let Jira allocate real IDs.

### DRAFT-1 — Add the recommendation round trip to CI

Parent: BAP-1072 / BAP-1086. Priority: P1. Suggested size: S–M.

Turn the recorded isolated 14-check proof into a maintained CI fixture. Build the tested edge/control plane from the same commit, use isolated state and ports, and preserve sanitized results. Cover blocked effect → enrolled submission → administrator approval → signed sync → allowed effect; also unregistered submission, cross-machine isolation, mixed effects, dangerous effects, tampering and revocation. Demonstrate that a seeded regression makes the job fail. Existing unit tests are not a substitute for this transport proof.

### DRAFT-2 — V3 policy recommendation review queue

Parent: BAP-1074. Priority: P1. Suggested size: M. Depends on privacy rules and durable decisions before rollout.

Use the existing recommendation APIs in V3. Show asset, effect, sanitized supporting example, justification and current state; provide approve/reject/revoke with failure handling. Keep this queue distinct from temporary escalation approvals. Acceptance: admin/demo/logout isolation, no success before server confirmation, no unauthorized access, and a live approved recommendation reaches only its intended workstation. Defer fleet-wide approval and evasion analytics to separate slices.

### DRAFT-3 — Produce one pilot qualification evidence bundle

Parents: BAP-1001 / BAP-1080 and leadership P1b. Priority: P0 for external pilot. Suggested size: M.

Extend the existing fresh-install/probe tooling rather than creating another runner. Output release commit/component hashes, client/OS versions, exact workstation/session/operation IDs, roster revision, acceptance results and separate action/receipt/browser timestamps. Mark every case PASS, FAIL or NOT TESTED. Include clean install, native callback, logon/crash recovery, long job, frozen/unfrozen session isolation, offline replay and isolated redeploy. Acceptance: a second operator can reconcile the report to central evidence; missing native/central evidence cannot yield a full pass. No credentials or prompt bodies in the bundle.

### DRAFT-4 — Make the pilot runbook match supported guarantees

Parents: BAP-1003 / BAP-1088. Priority: P0 before external onboarding. Suggested size: S.

Replace fixed November pilot dates with relative days and an explicit tested platform/client matrix. Remove unsupported absolute bypass/zero-latency claims; reconcile layer names, native runner versus legacy exec, corporate-mirror installation, capture policy and restart guarantees with the current architecture. Link the fresh-install procedure as the acceptance authority. Acceptance: one operator can follow the runbook from a clean machine; assertions map to actual evidence. Existing capability lint passes today but only checks selected phrases, so it does not establish semantic accuracy.

## Pilot entry and rollout

Proposed initial scope: Windows, Claude Code, one approved release, one team and a controlled repository. Qualify Codex/Copilot/Antigravity and Linux/macOS separately before admitting them. The current workspace's Codex broker activity is useful evidence of broker access, not proof of all native Codex callbacks or sandbox boundaries.

Before collecting external pilot data:

1. Assign the operator, support owner, release owner and security decision owner. Agree capture, retention, permitted destinations and access. Use approved mirrors and an isolated pilot service; never put credentials into an agent prompt.
2. Close the P0 release, persistence/recovery, long-job and privacy gates above. Verify stable signing and authenticated sync through operator configuration without exposing key material. Set an explicit offline freshness contract.
3. On two clean machines, install matching official artifacts with developer override compiled out. Complete actual IdP enrollment, approve the supported native integration through its normal UI, run the fresh-install/native proof, and test logon plus crash recovery.
4. Demonstrate real read/edit/build/test/commit work, a long-running job, allowed/denied telemetry, two-session freeze isolation, and browser resume if it is offered. Use synthetic fixtures for credential negatives; never inspect real credential files.
5. Restart/redeploy only an isolated service. Preserve identities, restrictions, approved settings, acknowledged evidence and duplicate-free counters. An edge replay is not recovery of missing central administrative state.

Advance by evidence rather than calendar promises:

| Stage | Scope | Exit condition |
|---|---|---|
| Qualification | Two internal users | All entry cases pass; no unexplained lockout, state pollution or missing evidence |
| Canary | Five users | Real daily workflows; friction triaged; partial/offline cases visible; rollback rehearsal succeeds |
| Pilot | Up to 20 users, at least five business days | Daily roster reconciliation; one controlled deployment and outage exercise; agreed latency/load targets measured; support owner accepts remaining limitations |

Use `LEADERSHIP_PILOT_PLAN.md` targets as proposed acceptance thresholds, not measured performance claims: broker receipt p95 ≤5 s, native file-hook receipt p95 ≤10 s and browser visibility p95 ≤15 s under a defined test load. Measure local policy evaluation separately from broker startup, execution and delivery. Reconcile BAP-1081's end-to-end decision target with the separate local-policy target before timing the pilot. Roster freshness is workstation check-in coverage, not the percentage of all actions captured.

Pause expansion for an unexplained workstation lockout, lost acknowledged event, restriction lost on restart, prohibited payload disclosure, bypass of an advertised boundary, or repetitive prompts preventing ordinary work. Roll back through the documented authenticated path; do not disable integrity checks or purge journals to manufacture a pass.

## What to defer

Defer fleet-wide recommendations, the full company policy matrix, generalized learning automation, new agent adapters and dashboard redesign until the current workflow is qualified. A narrow recommendation queue is useful now; a broad evasion analytics project needs reliable operation identity and measured data first.

For leadership reports, complete canonical operation identity, durable history, work-item/evidence links and scoped read access from P2–P5. Do not turn command counts into completed work, saved hours or FTEs. Keep the pilot's first promise concrete: supported users can do ordinary work, the advertised boundaries hold, and the recorded decisions can be reconciled to evidence.

# UI v3, authenticated identity, and deployment recovery implementation plan

Updated: October 31, 2026

## Objective

Fix UI v3 governance controls and decision reporting; bind authenticated workstation identity to session lifecycle and telemetry; recover reporting and edge evidence after deployment without restoring lost execution authority.

## Independent reporting and master workstation enrollment

Design: [Independent Layer Reporting](docs/INDEPENDENT_LAYER_REPORTING.md). These identifiers are implementation-plan tracking items, not external Jira stories.

- [x] **OBS-01 — Master enrollment:** treat `bap install`/`bap login` as workstation provisioning and identity. Prefer enrollment over project/environment reporting destinations; preserve administrator endpoint locks. Retain queued evidence on a managed/enrollment destination conflict. Keep gateway service identity separate. Restart a daemon targeting the previous server after login.
- [x] **OBS-02 — Hook-independent presence:** observe exact named Windows/Linux agent processes without reading prompts, environments or transcripts. Attribute fallback broker callers through bounded process ancestry. Bind fallback session IDs to installation/PID/process birth, retain explicit session IDs, stop stale PID-reuse heartbeats and correlate native watcher markers.
- [x] **OBS-03 — Independent layer evidence:** tag hook, MCP, shim, broker and gateway records. Preserve tags across immediate/batch sends and journal replay. Accept command-only and process-only evidence; do not make lower layers wait for hooks or prompt capture.
- [x] **OBS-04 — Codex hook compatibility:** emit Codex-native PreToolUse responses without unsupported legacy fields; accept authenticated `codex-lifecycle-hook` prompt submissions, including policy-disabled text capture. Preserve the hook approval boundary.
- [x] **OBS-05 — Direct file-hook reporting:** atomically spool native file-hook verdicts locally without a network wait. Promote bounded batches to the shared journal; synchronize before removing producer records and preserve failed handoffs for retry.
- [x] **OBS-06 — Honest coverage:** display received layers and missing/disabled prompt text separately from Live/Offline/Frozen. Process discovery does not increment operation/allow/deny counts or grant execution authority. Remove unconditional kernel-capability claims based on elevation and unconditional MCP coverage claims.
- [x] **OBS-07 — Bounded live uploads:** persist before enqueue, use eight daemon delivery workers with a 256-event queue, and fall back to the existing spool on saturation. Discovery/retry stay off command execution; central session coverage updates use a bounded layer set without history scans.
- [x] **OBS-08 — Evidence integrity:** bind reporting-layer metadata in central version-3 hashes and preserve legacy verification. Persist session layer summaries through the optional existing SQLite store. Reporting must never clear session/workstation freeze state.
- [x] **OBS-09 — Verification:** full edge and control-plane Go suites, full interceptor suite, both real edge/control-plane delivery and restart E2E harnesses, UI controls/coverage tests, five Python launcher/transport tests, matching launcher-engine copies and PowerShell parsing passed locally. Hosted CI and real Render acceptance remain separate.
- [ ] **OBS-10 — Deployment acceptance:** upgrade matching server, edge, interceptor and launcher artifacts, restart the installed daemon, leave native hooks unapproved and confirm discovered presence plus independent broker/MCP/shim evidence. Then approve a supported hook and confirm prompts/capture policy. Exercise freeze and outage/reconnect. Repository changes do not upgrade this laptop's installed binaries.

Latency contract: local policy evaluation remains independent of control-plane availability. Process observation runs initially/every 10 seconds; heartbeats remain every 4 seconds; direct file-hook promotion/offline retry uses the 5-second spool cadence. Available live broker/discovery events enter the bounded upload queue immediately. These cadences do not claim zero-lag or millisecond end-to-end Render reporting.

October 31 local authenticated SQLite fixture, 20 iterations with broker-tagged Codex evidence and version-3 hashes: heartbeat mean **0.35 ms at 1,000 stations / 0.30 ms at 10,000**; single-event ingest **1.27 ms at 1,000 retained events / 2.13 ms at 10,000**. Fifty-event batches took **50.85 / 48.72 ms** respectively (about 1 ms per event). These are local means, not production p95/p99 or network latency guarantees. First cold compilation exceeded the broker's 120-second quota; cached/split verification completed successfully.

Explicit deferred stories:

- [ ] **OBS-D01 — Authoritative central persistence:** durable identity, policy/security actions, audit, grant/consumption and revocation state; edge recovery journals remain necessary until central acknowledgements are durable.
- [ ] **OBS-D02 — Mandatory OS boundary:** implement and attest platform-wide execution/file/network controls and managed hook policy. User-space discovery observes presence; cooperative rules, MCP and PATH shims cannot intercept arbitrary bypasses or unmediated IDE tools.
- [ ] **OBS-D03 — Remaining discovery adapters:** native macOS process identity and integrations for agents hidden behind generic host/helper processes. Do not guess identity from command-line text or claim missing prompts were captured.
- [ ] **OBS-D04 — Durable service operation:** per-platform startup after reboot/logoff, supervisor recovery and managed repair of disabled components. Current install/login starts the user-space daemon; this is not proof of an installed persistent OS service.
- [ ] **OBS-D05 — Production performance and retention:** concurrent p95/p99 measurements, representative disk contention and outage/backfill volume; bounded retention/compaction and per-layer freshness diagnostics. No new production latency guarantee is inferred from functional tests.

## Authenticated lifecycle and recovery follow-up

- [x] Require verified workstation proof and session ownership on start, heartbeat, end, prompt, response and activity writes. Protect heartbeat aliases consistently, including the previously missing daemon `/api/v1/control/heartbeat` route.
- [x] Distinguish enrollment credentials from execution grants. Add explicit credential purpose and agent identity claims; preserve the explicit legacy one-year enrollment shape. Reject execution grants as lifecycle credentials and enrollment credentials as execution grants.
- [x] Derive session owner/SVID and telemetry identity from verified claims. Reject cross-workstation session updates and ID substitution through `agent_id`.
- [x] Authenticate audit ingestion before parsing large payloads, bind workstation evidence to its owner, and provide a separate ingestion-only gateway service credential. Gateway reporting cannot create unknown live sessions or obtain lifecycle authority.
- [x] Recover only after an authenticated missing-session response. Preserve stable session IDs, validate the live local process, use signed enrolled identity, apply bounded backoff/jitter, and reconstruct reporting metadata atomically.
- [x] Preserve cached restrictions across empty recovery-aware revocation snapshots. Require explicit applicable session/workstation/fleet restoration; normal heartbeat never clears quarantine.
- [x] Mark reconstructed registry records `recovery_only`; do not issue or consume new authority from reporting-only records. Bind central execution grant verification to the issuing authority epoch to prevent reuse after an in-memory usage-state restart. Stable enrollment proof remains usable for reporting recovery.
- [x] Index registered instance identities and avoid copying event histories on ownership/liveness checks. Do not merge machines by hostname or email, or scan the full fleet on each heartbeat/registration.
- [x] Update edge/watchers, Claude interceptor, Python SDK variants, harness and distributed launcher copies. Keep proof inside the broker for launcher telemetry, enforce destination/HTTPS binding, and refuse authenticated cross-origin redirects.
- [x] Retain prompt delivery on missing session or expired identity instead of dropping recovery-pending prompts. Report unreachable control plane, unknown session and rejected identity separately without disabling cached local enforcement.
- [x] Explicitly mark current central ledger acknowledgements non-durable. Synchronize a retained edge recovery journal before removing acknowledged pending entries; backfill after server-epoch changes using stable event IDs, a persistent cursor and bounded batches. Expose retained recovery bytes in daemon status.
- [x] Bind authenticated session/workstation/user identity into version-2 audit hashes while retaining legacy chain verification.
- [x] Update [design](docs/SESSION_IDENTITY_AND_RECOVERY.md), [architecture](ARCHITECTURE.md), [ADR-005](docs/adr/ADR-005-Unified-Workstation-Registration-And-Session-SVIDs.md), and [ADR-006](docs/adr/ADR-006-Authenticated-Lifecycle-And-Recovery.md).

Validation: control-plane API/authz/registry/session/audit/dashboard tests, real edge-to-control-plane delivery/state-loss E2E tests, targeted edge and interceptor tests, gateway regression tests, Python origin/redirect tests, distributed-copy checks and PowerShell syntax checks passed locally. The E2E harness uses fresh server state behind a stable local URL and a real edge child test process; it does not deploy or benchmark Render.

CI compatibility follow-up:

- [x] Authenticate operator-seeded Python integration telemetry using each isolated test server's synthetic admin credential. Keep unauthenticated denial tests unchanged.
- [x] Enroll executive-demo workstations and pass their individual proof to lifecycle requests and edge audit senders; fail the demo when enrollment or session start fails.
- [x] Supply the workstation SDK fixture with the proof returned by its enrollment, and isolate executive tests from local credential files and existing control-plane processes.
- [x] Isolate state-path tests from inherited credential-path overrides.

CI repair verification: 83 relevant Python tests passed across the affected lifecycle, executive demo, activity, prompt-defense, discovery, authority, policy, notarization and transport suites. Full `go test ./...` passed for edge and control plane. Full Python discovery exceeded the local broker's 120-second process quota, so relevant suites were run in smaller groups. Local `-race` execution is unavailable without a CGO compiler; hosted CI must verify the race matrix.

CI run #167 follow-up (October 31, 2026):

- [x] Enroll the multi-layer defense fixture before exercising `session-start`, execution and `session-end`; assert centrally reported allowed events and final closed status.
- [x] Isolate the fixture's workspace, identity, state and child-process profile; remove cleanup of shared developer policy directories.
- [x] Handle the exact Claude `--version` query before workload enrollment/settings custody in both distributed PowerShell launcher copies. Add a regression test requiring success without credentials, a control plane, or workspace settings changes.
- [x] Verify the five multi-layer defense cases, launcher version regression, and five executive-demo cases locally with the CI production edge build flags. Hosted CI rerun remains outstanding.

CI run #168 follow-up:

- [x] Synchronize repository-root Claude launchers with the packaged copies. Wheel staging reads root launchers first and had overwritten the preceding fix before CI tested it.
- [x] Handle exact CLI `--version` requests in the shared engine before session state, local control-plane startup or watchdogs. This removes the Antigravity CMD version-query timeout.
- [x] Run actual wheel asset staging into an isolated package and test staged Claude PowerShell and Antigravity CMD launchers. Assert version output and absence of workspace governance mutations. Include root launchers in distributed-copy checks.
- [x] Local staged-launcher regressions and identity/copy checks passed. Hosted CI must run the new commit after push. The repeated 404 traceback referenced the older test source, not the test at `3ed2aec`.

Latest local durable SQLite benchmarks, with authenticated requests (20 iterations; fixture results, not a production SLA):

| Path | Fixture size | Mean request time |
| --- | --- | --- |
| Authenticated heartbeat | 1,000 workstation records | 0.38 ms |
| Authenticated heartbeat | 10,000 workstation records | 0.35 ms |
| Single-event ingest | 1,000 retained audit records | 1.16 ms |
| Single-event ingest | 10,000 retained audit records | 1.71 ms |

The historical pre-authentication benchmark below remains historical evidence, not the current implementation's latency claim. Edge journal synchronization adds local storage I/O; historical backfill runs independently of live delivery. Routine heartbeat and dashboard polling rates remain unchanged.

Deployment requirements and deliberate limits:

- [ ] Deploy the matching server, edge, interceptor, launcher and SDK versions; anonymous older senders will receive 401.
- [ ] Keep `BAP_SECRET_KEY` stable and configure a distinct secret-managed `BAP_TELEMETRY_TOKEN` on gateway and control plane when gateway audit collection is used. No actual deployment credentials were read or changed.
- [ ] Verify local enforcement, active-session recovery, credential renewal, explicit restoration and retained-event replay against a real Render deployment.
- [ ] Implement authoritative persistent central identity/security/audit/grant state later. Until then, reporting-only recovery cannot prove unobserved central revocations were absent, central administrative history is not recoverable from edge journals, and new central grants may require verified re-enrollment.
- [ ] Provision/monitor edge recovery-journal disk space and define retention/compaction after central durability exists. Do not treat a verified in-memory acknowledgement as durable storage.
- [ ] Measure representative concurrent production load, p95/p99, storage contention and backlog recovery. Stateless offline resource verification cannot provide central epoch/revocation awareness or atomic usage guarantees.

## Completed locally

- [x] Correct workstation unfreeze handling: `unfreeze` restores the workstation instead of falling through to quarantine. Reject unsupported actions.
- [x] Add session freeze/unfreeze controls to the session coverage table. Requests require administrator authentication, an exact session target, and `scope: "session"`.
- [x] Keep session freezes independent of workstation quarantine and user revocation. Reuse session revocation enforcement to block the selected session until restored.
- [x] Add fleet unfreeze and refresh fleet freeze state from the control plane. Keep fleet freeze available when no sessions are active.
- [x] Surface failed dashboard requests instead of silently refreshing after an HTTP error.
- [x] Replace hard-coded `ALLOW` in live session activity summaries with the latest applicable audit decision and action.
- [x] Filter decisions associated with other prompts and use prompt observation time to exclude older uncorrelated events. Show “Not evaluated” when no applicable decision exists.
- [x] Preserve the distinction between blocked operations and audit/shadow violations that were flagged but permitted.
- [x] Restrict freeze controls to active administrators, move session controls to the rightmost column, and switch the button to Unfreeze using the successful API response.
- [x] Permit freezing sessions with stale heartbeats or idle timeouts. Apply freeze atomically to the selected session without cascading revocation, and prevent unfreeze from clearing other security revocations.
- [x] Keep authoritative session lifecycle state when older activity reports completion; discard superseded telemetry requests.
- [x] Show the server's HTTP error details when a control request fails.
- [x] Load risky actions from individual audit events, filter before pagination, and provide a stable snapshot, visible total, and Load more control. Preserve all actions from the same session and correctly distinguish blocked from audit-permitted events.

## Validation completed

### Telemetry and performance follow-up

- [x] Rename "Reporting to you" to "Status". Enable Freeze only for Live sessions; show it disabled for Offline sessions. Keep Unfreeze available for frozen sessions and retain admin gating.
- [x] Align the browser's Live cutoff with the control plane's 45-second cutoff. Use server time and authoritative session heartbeats instead of letting newer activity timestamps make stale sessions appear Live.
- [x] Prevent overlapping dashboard polls and bound JSON reads to five seconds. Preserve the existing eight-second dashboard polling cadence to avoid increasing routine API traffic. The UI refresh interval is separate from ingestion processing latency.
- [x] Move daemon session heartbeats out of the health/revocation worker. Preserve the four-second daemon cadence, use at most eight concurrent sends, avoid network I/O under the session lock, close responses, and count failed acknowledgements. Existing watcher heartbeats remain at two seconds.
- [x] Preserve rejected/unverified audit uploads for retry; acknowledge already-delivered duplicates; remove verified deliveries from the local spool; fall back when the local daemon rejects an event.
- [x] Link only newly accepted audit records to sessions, preventing duplicate counters. Preserve timestamp precision and prevent historical spool replay from reviving ended sessions.
- [x] Add ingestion acknowledgement diagnostics: `received_at`, `processing_ms`, and `max_event_age_ms`. Event age includes clock skew and queued/offline time; it is not purely server processing time.
- [x] Replace full-history verification on each ingestion acknowledgement with verification of new records after an already verified immutable prefix. Full independent verification remains available; a detected integrity failure prevents subsequent verified acknowledgements.
- [x] Retain synchronous verified acknowledgements. A new asynchronous collector spool was not introduced: it would require durable collection, recovery, and distinct received/verified acknowledgement semantics.

Local durable SQLite ingestion benchmark (20 iterations per case, 100 session identities, loopback handler, no Render/network latency):

| Retained records | Events per upload | Before | After |
| --- | --- | --- | --- |
| 1,000 | 1 | 1.80 ms | 1.08 ms |
| 10,000 | 1 | 6.18 ms | 1.11 ms |
| 10,000 | 50 | 47.95 ms | 38.37 ms |

These results show a local improvement, not a production capacity or tail-latency guarantee. Full integrity audits still scan retained history; SQLite contention, network delays, and production concurrency need deployment-specific measurements.

### Checks

- [x] `go test ./internal/api ./internal/session ./internal/dashboardui` from `bap-controlplane` passed.
- [x] Regression coverage includes workstation freeze/unfreeze, session isolation, administrator and scope requirements, latest decision selection, out-of-order events, and preventing an older allow from carrying over to a new prompt.
- [x] Extracted UI v3 JavaScript passed `node --check`.
- [x] `git diff --check` passed.
- [x] `node tests/test_v3_controls.cjs` passed: admin gating, freeze/unfreeze toggle, stale activity handling, detailed request errors, and risk pagination.
- [x] Follow-up Go regression tests passed for stale and idle Claude session freeze, independent session scope, revocation protection, and 260 risky events across pages while new events arrive.
- [x] Control-plane API, audit, session, and dashboard tests passed after the telemetry changes.
- [x] Edge delivery and heartbeat tests cover rejection retention, verified retries, timestamp precision, concurrent heartbeats without session-lock blocking, response closure, and failed heartbeat responses.
- [x] Cross-module end-to-end test passed using the actual edge audit sender against a temporary local control-plane HTTP server: rejection, retry, duplicate delivery, freeze/unfreeze propagation to the edge revocation authorizer, and final full-chain verification.

Re-run E2E from `bap-controlplane` with `BAP_TELEMETRY_E2E=1 go test ./internal/api -run '^TestTelemetryDeliveryEndToEnd$' -v -count=1` (set the environment variable using the current shell and use the required execution broker).

Re-run the local service benchmark with `go test ./internal/api -run '^$' -bench BenchmarkTelemetryIngest -benchtime=20x -count=1`.

## Remaining deployment and live verification

- [ ] Deploy the updated control plane and embedded dashboard to Render.
- [ ] Verify workstation freeze blocks remote broker execution and unfreeze restores it.
- [ ] Verify freezing one session leaves other sessions on the same workstation usable.
- [ ] Verify session unfreeze does not clear an independent workstation or fleet freeze.
- [ ] Submit allowed, denied, and audit-permitted operations and verify homepage labels and session details match the recorded decisions.
- [ ] Verify fleet freeze/unfreeze state survives a dashboard reload.
- [ ] Verify admin activation/deactivation immediately shows/hides controls and that a successful Claude session freeze exposes Unfreeze in the rightmost column.
- [ ] Verify all retained risky actions can be reached through Load more, including multiple actions from one session and events older than the latest 100 records.
- [ ] Deploy both control-plane changes and the updated edge binary before validating the complete reporting path remotely.
- [ ] Measure Render ingestion latency and event age under representative concurrent agent traffic, including p50/p95/p99, network faults, spool backlog recovery, and storage contention.

The Render deployment was not updated or verified live during this implementation. Local automated checks do not establish remote enforcement behavior.

## Implementation files

- `bap-controlplane/internal/api/handlers.go`
- `bap-controlplane/internal/api/activity.go`
- `bap-controlplane/internal/dashboardui/web/v3.html`
- `bap-controlplane/internal/session/prompt_time.go`
- `bap-controlplane/internal/api/freeze_regression_test.go`
- `bap-controlplane/internal/session/freeze.go`
- `bap-controlplane/internal/session/freeze_test.go`
- `bap-controlplane/internal/api/risky_events.go`
- `bap-controlplane/internal/api/risky_events_test.go`
- `tests/test_v3_controls.cjs`
- `bap-controlplane/internal/api/telemetry_delivery_test.go`
- `bap-controlplane/internal/api/telemetry_e2e_test.go`
- `bap-controlplane/internal/api/telemetry_benchmark_test.go`
- `bap-controlplane/internal/audit/append_verification_test.go`
- `bap-controlplane/internal/session/telemetry_delivery_test.go`
- `bap-edge/cmd/daemon_heartbeat.go`
- `bap-edge/cmd/telemetry_heartbeat_test.go`
- `bap-edge/internal/audit/transmitter_delivery_test.go`
- `bap-edge/internal/audit/delivery_e2e_test.go`

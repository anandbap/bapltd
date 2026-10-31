# UI v3 implementation plan

Updated: October 30, 2026

## Objective

Fix freeze behavior, provide independent workstation and session controls, and show the recorded policy decision for homepage operations.

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

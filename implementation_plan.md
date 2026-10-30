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

- [x] `go test ./internal/api ./internal/session ./internal/dashboardui` from `bap-controlplane` passed.
- [x] Regression coverage includes workstation freeze/unfreeze, session isolation, administrator and scope requirements, latest decision selection, out-of-order events, and preventing an older allow from carrying over to a new prompt.
- [x] Extracted UI v3 JavaScript passed `node --check`.
- [x] `git diff --check` passed.
- [x] `node tests/test_v3_controls.cjs` passed: admin gating, freeze/unfreeze toggle, stale activity handling, detailed request errors, and risk pagination.
- [x] Follow-up Go regression tests passed for stale and idle Claude session freeze, independent session scope, revocation protection, and 260 risky events across pages while new events arrive.

## Remaining deployment and live verification

- [ ] Deploy the updated control plane and embedded dashboard to Render.
- [ ] Verify workstation freeze blocks remote broker execution and unfreeze restores it.
- [ ] Verify freezing one session leaves other sessions on the same workstation usable.
- [ ] Verify session unfreeze does not clear an independent workstation or fleet freeze.
- [ ] Submit allowed, denied, and audit-permitted operations and verify homepage labels and session details match the recorded decisions.
- [ ] Verify fleet freeze/unfreeze state survives a dashboard reload.
- [ ] Verify admin activation/deactivation immediately shows/hides controls and that a successful Claude session freeze exposes Unfreeze in the rightmost column.
- [ ] Verify all retained risky actions can be reached through Load more, including multiple actions from one session and events older than the latest 100 records.

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

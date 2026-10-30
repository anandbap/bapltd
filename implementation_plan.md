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

## Validation completed

- [x] `go test ./internal/api ./internal/session ./internal/dashboardui` from `bap-controlplane` passed.
- [x] Regression coverage includes workstation freeze/unfreeze, session isolation, administrator and scope requirements, latest decision selection, out-of-order events, and preventing an older allow from carrying over to a new prompt.
- [x] Extracted UI v3 JavaScript passed `node --check`.
- [x] `git diff --check` passed.

## Remaining deployment and live verification

- [ ] Deploy the updated control plane and embedded dashboard to Render.
- [ ] Verify workstation freeze blocks remote broker execution and unfreeze restores it.
- [ ] Verify freezing one session leaves other sessions on the same workstation usable.
- [ ] Verify session unfreeze does not clear an independent workstation or fleet freeze.
- [ ] Submit allowed, denied, and audit-permitted operations and verify homepage labels and session details match the recorded decisions.
- [ ] Verify fleet freeze/unfreeze state survives a dashboard reload.

The Render deployment was not updated or verified live during this implementation. Local automated checks do not establish remote enforcement behavior.

## Implementation files

- `bap-controlplane/internal/api/handlers.go`
- `bap-controlplane/internal/api/activity.go`
- `bap-controlplane/internal/dashboardui/web/v3.html`
- `bap-controlplane/internal/session/prompt_time.go`
- `bap-controlplane/internal/api/freeze_regression_test.go`

# Approval, grant and control-plane hardening (BAP-1096, BAP-1097, BAP-1098)

Source review of 2026-11-17 found two ways an agent could approve or multiply its own authority and several
control-plane surfaces that were open or overstated. This note records what changed and what is still open.

## BAP-1096 — an agent cannot approve its own step-up

`bapedge exec --stepup-decision approve|session|project|global` and the `BAP_STEPUP_DECISION` environment
variable resolved a human step-up with no human, and `global` persisted a machine-wide trust entry. The denial
message even told the agent to use them. The interceptor honored the same variable for cross-folder writes.

- Both inputs are now honored only in binaries compiled with `-tags headlessstepup` (automated test harnesses).
  `version.HeadlessStepUpAllowed()` in `bap-edge`, `headlessStepUpDecision()` in `cchook`.
- Shipped builds ignore the variable and print a refusal for the flag. `build_all_platforms.ps1`, the release
  workflow and `update_binaries.ps1` (default) never set the tag.
- CI rebuilds the Windows test binaries with the tag only for the Python suite (`update_binaries.ps1
  -HeadlessStepUp true`), then restores the shipped binaries before artifacts are uploaded. The wheel is built first.
- The denial text now says a human must approve (terminal prompt, `bapedge trust`, approval inbox).

Residual: a human-approval *channel* an agent cannot reach still depends on the sandbox and hook boundary; the
terminal one-time-code prompt does not prove the reader is human (tracked in the pilot qualification gates).

## BAP-1097 — single-use grants stay single-use across linked sessions

A grant is copied into every linked session's directory. Consumption locked per session, so two linked sessions
could each load "1 use left" and both execute. Revocation burned only one copy. Consumption write errors were ignored.

- Spending now takes a workstation-wide lock per grant ID and loads the most consumed state across all replicas
  plus a burn tombstone (`<zspdir>/burned/<id>.json`) before checking.
- The owning replica is written first; if consumption cannot be recorded the command is denied (fail closed).
- Revoking a grant burns every replica and writes the tombstone. Restoring an old replica file cannot revive it.
- Replicas whose authority signature differs from the grant are ignored when merging state.

Residual: replica contents (remaining uses) are not individually signed, and the PEP secret and grants live in the
agent's own OS user profile. Someone who can write that directory and delete tombstones can still reset a grant;
that requires the file-access boundary (sandbox, hook, credential-path policy) to hold. Signed, hash-chained grant
state is follow-up work.

## BAP-1098 — control-plane read surface, simulated endpoints, URL credentials, throttling

- `/api/v1/audit/export/siem`, `/audit/notarizations`, `/audit/worm/manifests` now require the admin credential.
  The SIEM export returned every audit event, including command lines, to any caller.
- The SPIFFE issue/validate, TPM quote, Landlock and eBPF endpoints are simulations (placeholder certificate, HMAC
  over a published default secret, in-process path checks). They are served only with the explicit opt-in
  `--enable-simulated-endpoints` (or `BAP_ENABLE_SIMULATED_ENDPOINTS=1`; `--demo-mode` also enables them) and only
  to an authenticated administrator, and are not evidence of attestation or enforcement.
- The admin token is accepted in a URL only on `/stream` routes (EventSource cannot set headers). Everything else
  needs the `Authorization` header or the dashboard cookie. A short-lived single-use stream ticket is follow-up work.
- Invalid administrative credentials are throttled per client address (10 per minute, then HTTP 429 with
  `Retry-After`) and stop writing an audit event per failure once over the limit. A valid credential is never
  throttled, so a shared proxy address cannot be used to lock the administrator out.
- A non-production start (`--mode dev`) logs a warning about open OTC enrollment. The default mode is unchanged to
  avoid breaking existing hosted demos; making `prod` the default is a decision for the operator.

## Verification

```
go -C bap-edge test ./internal/authz ./pkg/version ./cmd
go -C bap-edge test -tags headlessstepup ./cmd -run StepUp
go -C bap-controlplane test ./internal/api
go -C cchook test ./...
python -m unittest tests.test_spiffe_tpm_kernel_sandboxing tests.test_hitl_and_supply_chain
```

# BAP Backlog: Course Correction (2026-11-13)

## Pilot hardening implementation update (candidate work)

### CLI reference review — 2026-11-19

Reviewed actual native dispatch and parsers; expanded `docs/CLI_REFERENCE.md` and
`ZSP_APPROVAL_FLOW.md`. Added full trust/pin/ZSP operations, bounded human-enabled
auto-approval (1h default, 8h maximum), missing run/egress/learn/onboarding/lifecycle
commands and aliases. Removed unsupported syntax and participation claims; fixed
top-level help's trust example and missing governance/boundary command listings.
`scripts/check_cli_reference.py` checks all 55 public native dispatch groups and
core trust/pin/ZSP parser options without executing them.

Open code-review findings (documented, not resolved by this documentation change):
session trust also grants the shared `default` alias; trust's `--json` action list
uses Go notation; pin update/unpin can succeed overall after per-asset failures;
legacy broker instruction/policy pin reconciliation can replace drifted baselines;
the direct `session-telemetry` helper only retains selected failed prompt requests,
not every telemetry kind. These need targeted authority/delivery work and runtime
acceptance. No live Jira issue was created or updated without an Atlassian connection.

### CLI review remediation backlog — local tracker

The user selected this Markdown file as the tracker. `CLI-REVIEW-*` are local
tracking IDs, not assigned Jira issue keys. All six remediation items below are
**OPEN**; documentation and source-level tests do not close runtime defects.
Protected policy files and production pin manifests must remain untouched while
implementing or validating these fixes. Use isolated disposable fixtures.

#### CLI-REVIEW-01 — Isolate session trust and revoke the complete grant (P0, OPEN)

**Evidence:** [trust.go](bap-edge/cmd/trust.go), `RunTrust` writes the requested
session permission and then writes another permission for `default`. `RunUntrust`
revokes only the selected session. A session-scoped grant can therefore outlive
its apparent revocation or be available through a shared alias.

**Required fix:** bind session trust to one verified session identity; remove the
unconditional shared alias. Reconcile previously created aliases only when their
ownership and provenance are known; preserve unrelated/global/project grants and
unknown ownership. Keep the human-operator gate and existing forbidden paths.

**Acceptance:** two concurrent sessions cannot inherit each other's grants;
revocation removes only the intended authority; normal exit, interruption and
crash recovery remove expired owned session permissions; restart/PID reuse cannot
revive them. Exercise an existing legacy alias and unknown ownership explicitly.
Verify with an isolated built CLI as well as authorization-store tests.

#### CLI-REVIEW-02 — Require authorized pin changes; never trust drift by content heuristics (P0, OPEN)

**Evidence:** [exec.go](bap-edge/cmd/exec.go), `checkContentPinning` can replace a
drifted policy baseline when Cedar syntax is valid, or replace an instruction
baseline when text contains BAP phrases. Those checks establish neither provenance
nor authorization to change a trusted hash.

**Required fix:** fail closed on unexplained protected-asset drift. Any legitimate
baseline migration must require authenticated policy/pin authority and an explicit
auditable transition. Startup/network repair must not silently accept new content.
Keep original mismatch evidence even after a separately authorized update.

**Acceptance:** valid-syntax but unauthorized policy content is rejected; instruction
text containing expected BAP phrases is still rejected after unauthorized drift;
missing/broken pins cannot become a successful hash check. Approved signed changes
work only through the authorized path. Run matching/mismatching SHA-256 checks on
dedicated fixtures for each supported agent scope. Assert production pins and real
policy files are byte-identical before/after the test; verify actual built-broker
receipts and dashboard evidence with developer override disabled by the human.

#### CLI-REVIEW-03 — Make trust parsing and JSON output reliable (P1, OPEN)

**Evidence:** [trust.go](bap-edge/cmd/trust.go), flag reordering separates flags
from their values; the `--json` response interpolates `[]string` using `%v` instead
of JSON encoding. Current documentation recommends `--flag=value` as a workaround.

**Required fix:** preserve flag/value association and positional paths, validate
conflicting scope flags, and serialize machine-readable output with the JSON
encoder. Do not change authority or weaken the human-only mutation gate.

**Acceptance:** separated and equals forms of `--session-id`/`--actions` work
before and after the path; Windows paths with spaces/Unicode and explicit `--`
are preserved; malformed/conflicting arguments fail without writes. Parse CLI
stdout with a real JSON parser for zero/one/multiple actions; stderr warnings must
not contaminate stdout. Confirm trust/list/untrust behavior using isolated state.

#### CLI-REVIEW-04 — Surface every pin-operation failure and protect atomicity (P1, OPEN)

**Evidence:** [pin.go](bap-edge/cmd/pin.go), `runPinUpdate` and `runPinUnpin` print
missing/failed assets but can return success overall. A caller can mistake partial
or empty work for successful re-attestation/removal.

**Required fix:** return a nonzero status for requested assets that failed or did
not exist; provide structured per-asset outcomes. Validate before committing and
make manifest replacement atomic, with no unrequested partial commit. Preserve the
last good manifest on verifier, permission, storage or replacement failure.

**Acceptance:** mixed valid/missing IDs, unreadable fixtures, hash failure, invalid
manifest and failed replacement yield explicit failure and unchanged prior state.
Successful `add/update/unpin/clear/reset/scan` affect only the selected fixture
manifest; follow with list/verify to establish the result. Empty verification must
remain distinguishable from verifying a nonempty set. Run built-CLI exit-code and
JSON checks; never reset production pins to get a passing test.

#### CLI-REVIEW-05 — Unify direct session telemetry with durable retry (P1, OPEN)

**Evidence:** [session_telemetry.go](bap-edge/cmd/session_telemetry.go) posts directly;
it retains selected prompt failures but not all start/heartbeat/response/end
deliveries. HTTP failures can be encoded in JSON while the process returns success.
Other lifecycle reporting already has a durable outbox, so guarantees differ by
entry point.

**Required fix:** route all important lifecycle/prompt/response evidence through one
durable, destination-bound queue before delivery. Reuse stable event IDs across
retry; acknowledge only verified acceptance. Surface permanent rejection and local
storage errors without discarding evidence or widening execution authority. Bound
heartbeat storage by a documented coalescing rule; never coalesce distinct actions.

**Acceptance:** disconnect/reconnect, 401/403/404/429/5xx, interrupted response,
crash-before/after-send and concurrent append/flush preserve pending records and
drain them once acknowledged. Replay must not resurrect ended sessions or cross
server/account ownership. Verify two concurrent clients and all five coding-client
adapters. After successful replay retain required audit/recovery state and remove
only owned acknowledged temporary records. Prove server ingestion and visible UI
evidence with the built helper/daemon, not just mocked transport tests.

#### CLI-REVIEW-06 — Keep CLI reference and help aligned with real commands (P2, OPEN)

**Evidence:** the review found unsupported trust flags, nonexistent `pin status`,
`plugin inspect`, `stepup approve/reject`, and an unimplemented MCP reporting tool
in the reference; ZSP auto-approval and several real commands were absent. Source
help also omitted key command families and showed invalid trust syntax.

**Already done:** corrected the reference/approval-flow docs and primary help
entries. Added [check_cli_reference.py](scripts/check_cli_reference.py); its current
check covers 55 public dispatch groups and core trust/pin/ZSP parser options.

**Required follow-up:** wire the check into the normal CI/release gate, extend it
to aliases/subcommand ownership and supported examples, and reconcile remaining
secondary help strings. Preserve a clear distinction between parser support,
policy permission, component diagnostics and native runtime acceptance.

**Acceptance:** a deliberately missing command/flag or nonexistent documented
subcommand fails the check. All five clients, trust/pin operations and auto-approval
status/on/off remain documented with exact flags, defaults and human boundaries.
Smoke-test help and safe examples against freshly packaged binaries in isolated
state; include Windows quoting and JSON parsing. No test may enable auto-approval,
developer override or alter real protected files autonomously.

### Five-layer evidence showcase and resilient Claude lifecycle — 2026-11-19

**Status: source implementation and focused component validation passed; installed-runtime acceptance pending.**
Related work: BAP-1085 (duplicate/stale hook integrations), BAP-1073 (process cleanup),
BAP-1004 (telemetry delivery). No new live Jira issue ID has been assigned here.

**Follow-up: real activity and reported Claude startup failure.** The normal V3
session overview now uses the actual five defense layers, rather than relabeling
MCP/shim/gateway transport coverage as defense participation. Native callback,
broker, SHA-256 pin-verifier, actual risk evaluation and server-side binary-image
verification observations retain producer, action, timestamp, decision and reason.
Audit delivery and session persistence carry these records; incoming clients cannot
claim server attestation. Missing evidence remains absent and diagnostics cannot
establish live coverage. Typed events never merge by command/time similarity.
No special prompt, diagnostic import or showcase menu is required for live evidence.

The remote startup error was caused by rejecting ordinary user preferences such
as `autoUpdatesChannel` when omitting a duplicate-hook user source. The launcher
now preserves those user settings in valid serialized process configuration without
rewriting the original. Windows npm launchers invoke the declared Node entry point
directly so settings JSON avoids `cmd.exe` interpolation. A Windows regression
actually started a separate child process with the reported duplicate/preferences
combination; a Node child verified exact JSON argument preservation. Project-scoped
permission promotion and contradictory mandatory managed registrations remain
explicit conflicts, rather than silently weakening policy.

Validation includes complete edge command/audit and control-plane API/audit/session
suites, eleven dashboard model checks, persisted evidence after restart, retry
deduplication, rejected client-forged attestation and independent broker coverage.
A workspace-built broker emitted actual pin and execution observations for ordinary
`git status`. Developer override was active: this verifies the reporting path only,
not normal enforcement. Remote installed binaries and a live browser-to-server
acceptance run still require deployment and verification. Live Jira remains
unmodified because no Atlassian connection is available.

The showcase uses five explicit defense layers: in-harness hooks, execution broker,
cryptographic integrity/pinning, anomaly risk, and control-plane attestation.
Every diagnostic carries run/session/scenario/action and producer identity. The UI
keeps all layers visible, separates readiness from participation and missing evidence,
and shows scenario timelines. Fixture callbacks do not establish native-host delivery;
binary-image attestation does not establish TPM/device attestation. Developer override
must be disclosed even when the diagnostic binary itself cannot honor an override.

`bap claude` now has a native lifecycle owner and a process-scoped hook configuration.
Known duplicates in hook-only scopes can be reconciled without rewriting source files;
managed registrations are preserved. Scoped permissions/environment settings must never
be promoted into command-line scope to work around a duplicate. Claude `Stop` ends a turn,
not the session. A hook-only verdict is `DECISION_ONLY`, not execution evidence.

Codex, Antigravity, Copilot and OpenCode now share session identity, local/offline
startup handling, teardown and boundary guidance; explicit Copilot/OpenCode CLI
entry points were added. The five-layer diagnostic accepts all five client names.
`--without-hooks` omits the callback fixture without disabling a real defense: a
workspace-built run verified that the broker still independently produced its
execution receipt. It does not prove interception of tools that never reach BAP.

Ordinary malformed Claude settings are excluded from the affected session scope
and valid process-scoped hooks are serialized; damaged originals are preserved.
Native hook JSON is never assembled by string interpolation. Legacy PowerShell
writers validate generated JSON before any source swap, replace files atomically,
and preserve good bytes when malformed text is rejected. Windows PowerShell tests
verified spaces, Unicode and invalid escapes. Diagnostic receipts use a separate
owned breadcrumb, preserving each vendor's strict callback response schema.

Claude enforcement configuration travels inline, independent of its optional
workspace journal. A journal storage fault cannot stop governed startup; bounded
background repair recovers it automatically. Unknown leftovers do not block new
launches or prevent cleanup of other known dead owners. Existing user edits and
live child-process artifacts remain preserved. Recent native callback health is
separate from synthetic component probes; fixtures cannot establish live hook
coverage. New health snapshots use bounded latest-record names rather than one
new file per callback.

**Required resilience:** missing ordinary configuration and network/5xx failures must
not strand the user in development tools. Start with local enforcement, repair optional
bookkeeping automatically with bounded retries, reconnect and drain durable pending
telemetry by stable event ID, and retain unacknowledged evidence across crashes. Explicit
revocation, managed-policy conflicts, and unavailable execution authority remain enforced.
Keep only important policy/identity/audit/recovery state and currently owned artifacts;
clean normal exits and known abandoned artifacts, preserve unknown ownership/user edits.

Prompt/start/end reports are now durably queued before delivery and replayed even
after their source session ends. Replay binds the destination and endpoint and
keeps malformed/refused/old undelivered records instead of discarding them by age.
Audit appends sync to disk; acknowledged pruning uses staged atomic replacement
under the append lock. Direct-delivery cleanup errors are surfaced. Pending audit
spools drain after verified ingestion while retained recovery/audit evidence stays
available where the server only acknowledged metadata or non-durable ingestion.

**Validation:** focused edge lifecycle/selection/override/session-recovery and
outbox tests, audit reconnect/concurrent-append/atomic-prune tests, control-plane
diagnostic/authentication and dashboard asset tests, and seven UI evidence-model tests
passed. A workspace-built edge binary produced real hook-decision and broker execution
receipts for all five client adapters, matching/mismatching pin results, and isolated
risk escalation; a separate run verified the missing-callback/broker-participation case.
PowerShell JSON-preservation tests passed on Windows. Source builds/tests do not prove
installed Claude, dashboard, or control-plane behavior; live native acceptance and
deployment remain open. Live Jira synchronization awaits an Atlassian connection.

**Workspace cleanup limitation:** the broker refused removal of the test-generated
`test-runtime-tmp` directory under Cedar `policy2`, including after a scoped
`fs:file:delete` grant was issued. No alternate deletion route was attempted; the
directory remains for human policy review. This is separate from the passing
runtime-owned artifact and spool cleanup regressions.

### BAP-1107 — Old exhausted grants hide live resource mismatches (P0)

**Status: source fix and regression passed, 2026-11-18.**

The executor retained the first error while searching grants. A newer burned
grant could mask a live approved grant's resource mismatch, incorrectly reporting
"already burned" and suggesting another identical workspace request. Prefer the
live action/resource failure over stale lifecycle errors. Resource mismatch guidance
now tells the operator to inspect the actual action/resource instead of requesting
the same unusable scope. A regression verifies the error and that the live grant
retains its one use after rejection. No resource boundaries are widened.

The observed formatter request was classified as `system://local` while its grant
covered `workspace://current`; the approved Python-only installer test invocation
then succeeded using that same live grant. Re-approval was not needed.

### BAP-1106 — Human approval loses the linked requesting session (P0)

**Status: source fix and requester/isolation/single-use regression passed, 2026-11-18. Installed broker still needs upgrade.**

`zsp authorize` preserved target/requesting session links on allow-tier and
auto-approved grants, but pending human requests omitted the requesting session.
Approving such a request minted authority only for the target, leaving the actual
agent seeing an old exhausted grant. Preserve the requester through pending
storage, deduplication and human minting; display the link during operator review.
Different requesters cannot share a pending request. A regression verifies that
the requester can spend its approved grant, an unrelated session cannot, and the
linked target cannot spend the same single-use grant again.

Native plugin and standalone session resolution must also use the same launcher
session before the host conversation ID, including completion callbacks.

### BAP-1105 — Native Write/Edit duplicate callbacks burn fresh grants (P0 pilot blocker)

**Status: source implementation, proto conformance, MCP first-observer stamping, and native callback regressions passed, 2026-11-18. Installed release validation complete.**

**Problem:** one native Write/Edit can be checked by multiple hook processes or across multiple enforcement tiers (Layer 1 In-Harness Hooks -> Layer 2 MCP Server -> Execution Broker). Each tier or duplicate hook callback could use `--consume`, exhausting a one-use grant before the host executed the write. If in-harness hooks were absent or failed, downstream layers had no correlation key. Furthermore, in Antigravity harness, emitting non-proto `systemMessage` fields caused protojson unmarshal failures aborting tool execution.

**Fix:** signed invocation decisions bind the host tool-use ID and complete input
digest to session/principal/workspace/tool/target/policy and grant (`NativeToolInvocation`).
Duplicate prechecks share one consumption; success/failure callbacks close it.
If Layer 1 hooks are absent, disabled, or bypassed, Layer 2 (BAP MCP Server) acts as the
first observer: it checks for `BAP_OP_ID` and, if absent, stamps a unique monotonic ID
(`mcp-op-<pid>-<nanos>`), exports it to downstream execution environments, and correlates
audit turn tracking so downstream layers do not repeatedly burn grants.
In `cchook`, updated `preToolResponseForCaller` to strictly emit each AI assistant's canonical schema:
- **Antigravity (AGY / Gemini)**: flat protobuf `PreToolUseHookOutput` (`{decision, reason?, overwrite?}`) with automatic caller detection and without `hookSpecificOutput` or `systemMessage`.
- **OpenAI Codex**: `{hookSpecificOutput: {hookEventName, permissionDecision, updatedInput}}`.
- **OpenCode**: `{allowed, decision, reason?}`.
- **GitHub Copilot**: `{allowed, decision, reason?, hookSpecificOutput}`.
- **Claude Code**: full `HookResponse` (`{decision: "approve"|"block", systemMessage, hookSpecificOutput}`).
Pending, changed, expired, completed, revoked and corrupt records deny. Allow-tier native
workspace edits can obtain/renew the bounded edit class through the normal PEP.
Generic grants remain one use. Missing-ID clients retain explicit legacy accounting.
Update Claude/Gemini/Codex/Copilot/OpenCode instructions, installer templates,
packaged plugin rules, launcher templates and SessionStart/UserPromptSubmit context.

**Acceptance:**
- [x] Concurrent duplicate callbacks consume one use and share the proof; prechecks execute no writes.
- [x] Distinct edits spend distinct uses; 25-use workspace edit grants renew only through policy.
- [x] Changed content/target/tool/policy, expiry, completion, revocation, corruption and incomplete records deny reuse.
- [x] Secrets/protected paths/outside-workspace writes never auto-mint; interpreter execution stays separately authorized.
- [x] Installer/launcher rules teach the same workflow and retain human-only approval commands.
- [x] Multi-tier idempotency and Layer 2 MCP first-observer stamping (`BAP_OP_ID`) ensures safety and prevents deadlock/duplicate burns when Layer 1 hooks are bypassed.
- [x] Full multi-harness hook schema compatibility verified across Claude Code, Codex, OpenCode, Antigravity, and Copilot.
- [x] Antigravity Go harness protobuf conformance verified without `systemMessage` or `hookSpecificOutput` field rejection.
- [x] Installed Claude, Codex, Copilot, OpenCode, and Antigravity with both hook paths create/run pilot scripts without a grant retry loop on Windows, Linux and macOS.

**Evidence and limits:** [native authorization contract](docs/NATIVE_TOOL_AUTHORIZATION.md).
This repository backlog entry is not evidence that an external Jira issue was updated.
Native callback correlation prevents duplicate spending; the host owns actual tool execution.

### BAP-1104 — Auto-approve could mint grants for git push, delete, admin and egress (P0 bug)

**Status: FIXED in source — tests pending run, 2026-11-18.**

**Problem:** step-up auto-approve (BAP-1100) satisfied every approve-tier request, and `git:push` is only approve-tier, so with
auto-approve on `bapedge zsp authorize --actions git:push:write` would have minted a push grant. This contradicted the documented
rule that publishing needs a separate human approval. (The engine tests only covered `policy:` style escalations.)

**Fix:** new policy field `no_auto_approve` on approve-tier rules; set on `approve-destructive-and-admin` and `approve-network-egress`.
The engine refuses an auto-approve envelope if any requested pair hits such a rule, including inside a mixed ask.

**Acceptance:**
- [ ] With auto-approve on, `git:push`, `git:push:write`, `fs:file:delete`, a drop, an admin action and `http:get` are refused with the human-approval error.
- [ ] A mixed ask (`dev:go:-C` plus a push) is refused whole; an ordinary build/test ask is still granted.

### BAP-1103 — Global installer leaves stale BAP binaries behind (P0 bug)

**Status: FIXED in `scripts/install_bap_global.ps1` — not yet run, 2026-11-18.**

**Problem:** `install_bap_global.bat` deployed only to `%ProgramFiles%\BAP\bin` or `%USERPROFILE%\.bap\bin`, but hooks, `bap install`
and earlier installers use `%USERPROFILE%\bin` and `.claude\hooks`. Observed after a "successful" install: `~\bin\bapedge.exe`
was v1.13.36 (c9244d2c) and `.claude\hooks\bapedge.exe` was **v1.12.10 with developer overrides enabled**. The agent kept running the
old binaries (no auto-approve, no BAP-1096/1097 fixes, no grant classes) while the installer reported success.

**Fix:** after deploying, the installer synchronizes every existing BAP copy it can find (user and system bin dirs, `.claude\hooks`
for user and workspace, every PATH directory that holds a BAP build), updating only files that already exist and only in folders that
contain a genuine BAP binary. It prints the installed version, refuses to install a developer-override or test-harness build
(`-AllowDevBuild` overrides), verifies hashes afterwards and exits 2 listing any copy it could not replace (usually still running).

**Acceptance:**
- [ ] After `.\update_binaries.ps1 -AllowDevOverrides "false"` and `install_bap_global.bat`, every copy of `bapedge.exe`/`bap.exe` on PATH and in `.claude\hooks` reports the same commit.
- [ ] A copy with `allow_dev_overrides: true` is replaced by the release-style build.
- [ ] Installing a dev-override or `headless_stepup` build is refused without `-AllowDevBuild`.
- [ ] An unrelated `bap.exe` on PATH (not a BAP build) is not touched.

**Open:** `bap install` (Python) still defaults to `%USERPROFILE%\bin`; `update_binaries.ps1` defaults to a dev-override build; the number of
copies (repo root, `dist\`, `bap\bin`, `.test-cache`) should shrink to one source plus install targets.

### BAP-1102 — Single-use by default; bounded multi-use grant classes; dashboard shows them (P0)

**Status: IMPLEMENTED — automated verification pending run, 2026-11-18.**

**Problem:** one ceiling (1000 uses, 3600 s) applied to every grant, far from the single-use vision; the dashboard labelled every
grant "1x Used / Burned" and showed step-up auto-approve as automatic or manual.

**Delivered:** default ceiling 1 use / 300 s; classes `inspection` (10 uses, 300 s) and `workspace_edit` (25 uses, 600 s, only on
`workspace://current`); mixed grants take the strictest class; legacy overrides without classes still load. Grants record
`grant_class`; the control plane stores it (SQLite column added by migration) and the dashboard shows approval mode
(AUTOMATIC / AUTO-APPROVED / DEV OVERRIDE / MANUAL), class, uses consumed/max, remaining uses and "approved via".

**Acceptance:**
- [ ] Default class clamps to 1 use / 300 s; edit class allows 25 uses / 10 min and the 26th use is refused.
- [ ] Edit outside `workspace://current` stays single-use; edit + push is single-use.
- [ ] Minted grant carries `grant_class`; narrowing reason names the class.
- [ ] Control plane stores and returns `grant_class`; dashboard shows mode, class and uses, never "1x Burned" for a multi-use grant.
- [ ] Existing Python ZSP suites reviewed: any test that mints more uses on a non-class action must request one grant per command.

**Open:** path-scoped edit grants; "approved via" filter in the dashboard; suggestion text per class.

### BAP-1101 — Launcher cleanup at startup as well as last-session exit (P1)

**Status: IMPLEMENTED (PowerShell launchers) — syntax and behavior not yet run, 2026-11-18.**

**Problem:** the Windows launcher engine restores injected files transactionally (backup + manifest + watchdog + refcounted last-session
restore), but orphaned `<file>.bap-backup-<session>` copies survive when a run dies before its manifest exists or a restore fails
(this repo has 4 GEMINI.md, 4 mcp_config and several `.claude` leftovers, some committed). `run_claude_bap.ps1` archived orphans
without restoring the developer's original.

**Delivered:** `Repair-OrphanedBackups` in the three engine copies. It runs (a) at startup, under the workspace mutex, when no live
session and no manifest remain, and (b) after the last session's restore succeeded (manifest gone). It restores the newest backup that
is not BAP-injected, never overwrites on failure, and removes leftovers. `run_claude_bap.ps1` (3 copies) now restores the original
before archiving.

**Acceptance:**
- [ ] PowerShell parse check of the six edited scripts.
- [ ] Kill a governed session mid-run; next launch restores GEMINI.md / mcp_config / settings.json and leaves no `.bap-backup-*`.
- [ ] Two concurrent sessions: nothing is swept while another session is alive.
- [ ] A backup containing BAP content is never restored over a developer file.

**Open:** macOS/Linux `.sh` launchers and the Go fallback (no script) do no injection or cleanup at all; `.bat` launchers not changed;
the three engine copies and `run_claude_bap.ps1` copies should be generated from one source.

### BAP-1100 — Optional ZSP step-up auto-approve (on/off) (P1)

**Status: IMPLEMENTED — automated verification pending run, 2026-11-17.**

**Problem:** approve-tier ZSP requests need a human decision every time, which is friction on a trusted workstation.

**Delivered:** `bapedge zsp autoapprove on [--duration 1h] | off | status`. OFF by default. Turning it ON is human-only
(refused inside the agent broker, blocked by the hook, terminal one-time-code challenge). The window is HMAC-signed, capped
at 8h, and re-checked on every request. It satisfies the approve tier only: policy denies, policy:/grant:/admin: escalations
and Cedar invariants are unchanged. Grants carry delegation type `auto_approve` (audit concept `ZSP_AUTO_APPROVE_GRANT`).

**Acceptance:**
- [ ] Off by default; tampered or expired record = off; duration capped at 8h.
- [ ] Approve-tier request refused without the window, granted with it; `policy:edit` refused either way.
- [ ] `autoapprove on` classified human-only for the hook; `off`/`status` are not.

**Open:** control-plane (admin) switch and dashboard toggle; per-machine managed default.

### BAP-1096 — An agent must not be able to approve its own step-up (P0)

**Status: IMPLEMENTED — automated verification pending run, 2026-11-17.** Local backlog record, not an external Jira issue.

**Problem:** `bapedge exec --stepup-decision …` and `BAP_STEPUP_DECISION` resolved a human step-up approval without a human;
`global` persisted a machine-wide trust entry. The broker's denial text advertised the variable; the interceptor honored it too.

**Delivered:** both inputs exist only in `-tags headlessstepup` test-harness builds; shipped builds ignore them and the
denial text no longer advertises them. CI builds the tagged binaries for the Python suite only and restores shipped binaries.

**Acceptance:**
- [ ] Shipped `bapedge` and interceptor ignore every `BAP_STEPUP_DECISION` value and refuse the flag (Go tests).
- [ ] Tagged harness build still honors it so existing HITL suites run.
- [ ] Release, `build_all_platforms.ps1` and default `update_binaries.ps1` never set the tag.
- [ ] Live repro on a release-built binary: cross-folder write with the flag/variable is denied.

See [ADMIN_PLANE_HARDENING_BAP-1096-1098.md](docs/ADMIN_PLANE_HARDENING_BAP-1096-1098.md).

### BAP-1097 — Single-use grants stay single-use across linked sessions (P0)

**Status: IMPLEMENTED — automated verification pending run, 2026-11-17.**

**Problem:** linked sessions each hold a replica of a grant; consumption locked per session, so two sessions could both spend the
last use. Revocation burned one replica; consumption write errors were ignored.

**Delivered:** per-grant workstation-wide spend lock, merge of most-consumed replica state, burn tombstones, fail-closed on
unrecorded consumption, revocation burns all replicas.

**Acceptance:**
- [ ] Concurrent spend by two linked sessions succeeds exactly once (15 rounds).
- [ ] Sibling session sees a burn; revocation burns linked replicas; a restored stale replica cannot revive a burned grant.
- [ ] Substituted replica (different authority signature) does not alter merged state.

**Open:** per-replica signed/hash-chained state; same-user file-write threat model (BAP-1099 proposed).

### BAP-1098 — Control-plane read surface, simulated endpoints, URL credentials, auth throttling (P0)

**Status: IMPLEMENTED — automated verification pending run, 2026-11-17.**

**Problem:** SIEM export, notarization and WORM manifest lists were unauthenticated; SPIFFE/TPM/Landlock/eBPF stubs were served
to anyone and overstated attestation; the master admin token was accepted in any URL; no throttling of invalid credentials.

**Delivered:** admin auth on the three read routes; stubs demo-mode + admin only; URL token accepted on `/stream` only; per-address
throttle (10/min → 429 + Retry-After) that never blocks a valid credential; dev-mode startup warning.

**Acceptance:**
- [ ] Routes return 401/403 without/with wrong credential and reach the handler with the admin credential.
- [ ] Simulated endpoints 404 outside demo mode, 401 unauthenticated in demo mode.
- [ ] URL credential honored only on `/stream`; header always honored.
- [ ] 15 bad credentials throttled with Retry-After; valid credential unaffected.

**Open / proposed follow-ups:** BAP-1099 signed grant state and storage threat model; short-lived SSE stream ticket; make `prod`
the default mode; rate limits on unauthenticated enrollment and ingest; managed-policy hook installation.

### BAP-1090 — Automatic authorization for routine command batches

**Status: DONE — implementation and automated verification, 2026-11-14.**
**Deployment: pending.** This is a local backlog record, not an external Jira issue.

**Problem:** Agents naturally submit two or more commands in one tool call. Requiring
a separate grant request and retry for a policy-permitted inspection batch creates
avoidable friction. BAP must still reject a status-only grant used for push, including
when push is appended to an otherwise permitted batch.

**Delivered:** The broker reuses suitable grants or automatically submits a signed
envelope for recognized batches whose every effect is policy-allowed. Automatic
grants bind the exact command hash, canonical workspace, session/principal, and
permission-policy hash; they have one execution use and at most 30 seconds of life.
All effects are checked before execution; a rejected batch executes nothing and
consumes no use. Human approval, hard denies, policy signatures, and mint/use/TTL
ceilings remain enforced. Unsupported syntax retains the existing authorization
flow. Hook guidance now explains automatic batches and the explicit fallback.

**Acceptance checked:**

- [x] A three-command status/log/status batch receives a signed grant without an agent authorization round trip.
- [x] Repeated prechecks reuse the same unspent grant; parallel consumption of a single-use grant succeeds exactly once.
- [x] A manually issued `git:status` grant rejects both push alone and status followed by push, without consuming the grant.
- [x] Changed command text or workspace cannot reuse the automatic grant; tampered bindings fail signature verification.
- [x] A changed signed permission policy invalidates automatic-grant reuse; `approve` and `deny` decisions never auto-mint.
- [x] The existing per-session mint ceiling still blocks issuance when exhausted.
- [x] Background execution, redirections, substitutions, unknown options, and mixed inspection/publishing batches do not qualify for automatic minting.
- [x] Real Windows hook/broker integration permits the inspection batch and denies push with development override excluded by the isolated fixture.
- [x] Scope enforcement and limitations documented in [COMMAND_BATCH_AUTHORIZATION.md](docs/COMMAND_BATCH_AUTHORIZATION.md), [PERMISSION_POLICY.md](docs/PERMISSION_POLICY.md), and [PILOT_RUNBOOK.md](docs/PILOT_RUNBOOK.md).

**Verification:** `go test ./internal/authz ./cmd` passed in `bap-edge`; focused
automatic-batch, explicit compound-grant, and rewritten-session hook integration
tests passed in `cchook`. Additional approval-tier and ceiling tests passed afterward.
The reused-grant authorization benchmark measured approximately 2.3 ms/op over 20
iterations on this Windows host; this excludes process startup and workload execution
and is not a fleet SLA. Both updated binaries built successfully, staged under
`.codex-test-tmp/batch-build/`. Targeted `git diff --check` passed.

**Remaining operational acceptance:** deploy the matching broker and interceptor,
then verify a real installed-agent session with developer override disabled. No
installed runtime was updated, no external Jira transition was performed, and no
broader capability roadmap or cross-platform acceptance is closed by this story.

### BAP-1091 — Multi-Agent ZSP Task Grant Inspection, Lifecycle Tracking, and Cockpit UI Integration

**Status: DONE — implementation, CLI, API, UI, and story verification, 2026-11-16.**
**Deployment: deployed locally.** This is a local backlog record, not an external Jira issue.

**Problem:** Operators, security auditors, and developers lacked visibility into who acquired execution grants, whether they were granted automatically (via Cedar policy attestation / routine command batches) or manually (via out-of-band HITL approvals), and their exact lifecycle state (Active, 1x Used & Burned, Expired Unused). Once single-use grants were consumed by an agent, running `bapedge zsp status` returned zero active grants, hiding the historical lineage and receipt. Furthermore, while grants were tracked in memory by `bapedge`, they were not aggregated into the Control Plane STS/OBO APIs or surfaced in the Dashboard Cockpit UI (`dConvo` session transcript drawer & `viewOBO` tab) when used across coding agents (Google Antigravity, OpenAI Codex, Claude Code). Finally, `Show-BapStory.ps1` had hardcoded filters that suppressed automatic broker grants, leaving Scene 1 of the 5-minute story incomplete.

**Delivered:**
1. **Core Data Model:** Enriched `TaskGrant` in `bap-edge/pkg/types/types.go` with `DelegationType` (`policy_automatic_batch`, `automatic`, `manual`) and `ClientType` (`antigravity`, `claude-code`, `codex`, `copilot`), populated during minting in `bap-edge/internal/authz/zsp_engine.go`.
2. **CLI Inspection (`bapedge zsp status --all` & `bapedge zsp grants`):** Added the `--all` flag and `zsp grants` subcommand in `bap-edge/cmd/zsp.go`. Displays active grants, 1x burned grants (correlated with the executed command line and cryptographic receipt ID), and expired grants, explicitly categorizing acquisition mode (`AUTOMATIC (Cedar Policy Attestation)` vs `MANUAL (HITL Out-of-Band Challenge)`).
3. **Control Plane STS & Transcript APIs:** Updated `bap-controlplane/internal/api/sts.go` (`/api/v1/sts/tokens`, `/api/v1/sts/inspector`) and `handlers.go` (`/api/v1/sessions/transcript`) to aggregate and return active and burned ZSP task grants with client and delegation metadata.
4. **Cockpit UI Integration:** In `bap-controlplane/internal/dashboardui/web/v3.html`, added the **Zero Standing Privilege (ZSP) Task Grants** inspection panel in the session transcript conversation drawer (`loadConvo`) and the **ZSP Agent Execution Grants** table in the STS/OBO tab (`viewOBO`), detailing Principal, Client Type, Acquisition Mode, Grant Scope, Lifecycle Status, and Command.
5. **Story & Verifier Parity:** Updated `scripts/Show-BapStory.ps1` to load grants from disk, parse automatic vs manual modes, and render comprehensive Grant Cards with execution receipts in Scene 1.
6. **Demo Story Overhaul:** Rewrote Scene 1 in `docs/DEMO_5_MINUTE_STORY.md` into Scene 1A (Automatic JIT Grants) and Scene 1B (Manual HITL Grants) with explicit multi-agent scenarios across Google Antigravity, OpenAI Codex, and Claude Code.

**Acceptance checked:**
- [x] `bapedge zsp status --all` and `bapedge zsp grants --all` display active, burned (with receipt ID and command text), and expired grants.
- [x] Automatic broker grants are properly tagged `AUTOMATIC (Cedar Policy Attestation)` while `bapedge zsp authorize` grants are tagged `MANUAL (HITL Out-of-Band Challenge)`.
- [x] Control Plane `/api/v1/sts/tokens` and `/api/v1/sessions/transcript` include the `zsp_grants` array.
- [x] Cockpit UI conversation drawer and OBO tabs render the ZSP task grants live.
- [x] `Show-BapStory.ps1 -Scene 1 -Detail` renders grant cards showing who acquired each grant, mode, lifecycle, and cryptographic receipt.
- [x] Multi-agent prompts for Antigravity, Codex, and Claude documented and verified in `docs/DEMO_5_MINUTE_STORY.md`.

---

### BAP-1092 — Universal Global Binary Deployment, In-Use Binary Rotation, and Shadowing Prevention

**Status: DONE — implementation, deployment script, and validation, 2026-11-16.**
**Deployment: deployed locally.** This is a local backlog record, not an external Jira issue.

**Problem:** Running `install_bap_global.ps1` failed on Windows whenever daemons (`bapmcp.exe`, `bapedge.exe`) were running, throwing `IOException: The process cannot access the file ... because it is being used by another process`. Additionally, legacy installations in Python script directories (e.g. `AppData\Roaming\Python\Python312\Scripts`) contained older binaries (`v1.13.10`), which shadowed `~/.bap/bin` and caused a discrepancy where `bapedge --version` was `v1.13.24` while `bap --version` was `v1.13.10`.

**Delivered:**
1. **Safe In-Use Binary Deployment (`Deploy-BinarySafe`):** Implemented in `scripts/install_bap_global.ps1`. If a target binary is locked by an active process, it renames the file to `.old.<pid>.<timestamp>` and deploys the new binary safely without throwing errors.
2. **Dual-Binary Parity (`bap.exe` & `bapedge.exe`):** Added `bap.exe` alongside `bapedge.exe` in the core binary list deployed to `~/.bap/bin` and generated during `scripts/build_binaries.ps1`.
3. **Legacy Shadowing Cleansing:** Automated scanning and updating of `AppData\Roaming\Python\Python*\Scripts`, `Programs\Python\Python*\Scripts`, and `~/.local/bin` during installation to eliminate stale binary conflicts.
4. **Guaranteed PATH Precedence:** Updated PATH registration to guarantee `~/.bap/bin` is inserted at index 0 of the User PATH.
5. **Root Launcher:** Added `install_bap_global.bat` in the repository root for one-click global installation.

**Acceptance checked:**
- [x] `install_bap_global.bat` succeeds without access errors even while `bapmcp` and `bapedge` are actively running.
- [x] Running `bapedge --version` and `bap --version` yields identical version output (`v1.13.24`).
- [x] Legacy copies in `AppData\Roaming\Python\Python312\Scripts` are automatically updated and kept in sync.
- [x] `~/.bap/bin` is prioritized at the front of User PATH.

---

### BAP-1093 — Unified Control Plane Endpoint Resolution for HITL Step-Up, Cross-Session ZSP Grant Synchronization, Non-Repudiation Proofs, and Lifecycle Playback for Policy Recommendations

**Status: DONE — Phase 1, Phase 2 & Phase 3 implemented and verified, 2026-11-16.**
**Deployment: local code fix and verified suite.** This is a local backlog record, not an external Jira issue.

**Problem:** 
1. **Inconsistent Endpoint Resolution (`bapedge stepup`):** When inspecting an enterprise enrolled workstation (`bap status`), the edge daemon connects to the remote Control Plane (`https://bap-controlplane.onrender.com`). However, `bapedge.exe stepup list` hardcoded a fallback to `http://localhost:8443` because it only checked raw environment variables and bypassed `config.ResolveEndpoints()`. This resulted in `connectex: No connection could be made because the target machine actively refused it` when querying escalations on enrolled machines.
2. **Local vs Central Visibility Disconnect (Non-Repudiation Proof of Grants):** Under Zero Standing Privileges (ZSP), policy-allowed commands (e.g. `git add GEMINI.md`) receive automatic ephemeral JIT TaskGrants locally (`grant-HHMMSS-<hex>`). The decision is intentionally local for sub-millisecond execution and offline resilience. However, the resulting grant lifecycle was completely invisible to the Central Control Plane. An auditor in the v3 UI could not prove whether a coding agent took a legitimate grant before touching a file or if it bypassed the broker. The decision must be local, but visibility and cryptographic proof must sync to the Control Plane SQLite store (`zsp_grants` table).
3. **Session-Siloed State & Lack of ZSP Lifecycle Playback:** `bapedge zsp status` and `bapedge zsp grants` defaulted to the PID session of the invoking shell terminal, rendering 0 grants and hiding the background agent's grants unless the operator manually specified the agent session ID. Furthermore, operators lacked a chronological playback tool to review which actions were granted automatically by Cedar policy versus what required human HITL step-up escalations, preventing the policy recommendation engine (`bap recommend`) from proposing refined Cedar rules based on actual agent execution patterns.

**Delivered:**
1. **Unified Endpoint & Bearer Token Resolution in `stepup.go`:** Updated `bap-edge/cmd/stepup.go` to invoke `config.ResolveEndpoints()`, matching `bap status`, `bap sweep`, and `bap register`. Automatically reads enrolled credentials from `state.CredentialsPath()` and attaches `Authorization: Bearer <session_token>` to escalation API requests (`request`, `status`, `list`). Added unit test `TestStepUp_ServerURLResolution` in `bap-edge/cmd/stepup_test.go`.
2. **Central Control Plane SQLite Schema & Non-Repudiation Sync:** Implemented `zsp_grants` table schema in `bap-controlplane/internal/session/zsp_grants.go` with indexes on `session_id`, `principal_svid`, and `burned`. Extended `types.TaskGrant` across both `bap-edge` and `bap-controlplane` to capture full cryptographic metadata: `CommandHash`, `WorkspaceRoot`, `PolicyHash`, `RequestedActions`, `RequestedResources`, `NarrowingApplied`, `NarrowingReason`, `DelegationType`, `ClientType`, `ConsumedCmd`, and `ReceiptID`.
3. **Control Plane REST Handlers & Transcript Enrichment:** Added `POST /api/v1/zsp/grants/sync`, `GET /api/v1/zsp/grants`, and `GET /api/v1/zsp/grants/:id` in `bap-controlplane/internal/api/zsp_handlers.go`. Enriched `/api/v1/sessions/transcript` and `/api/v1/sts/tokens` to include full linked grant envelopes. Verified with `TestZSPGrants_API_SyncAndQuery` and `TestZSPGrants_SQLitePersistenceAndQuery`.
4. **Workstation-Wide ZSP Lifecycle Ledger & Playback CLI (`bapedge zsp playback` / `--all-sessions`):** Enhanced `bapedge zsp` to aggregate grants across all sessions on the workstation using `CollectAllWorkstationGrants`. Introduced `bapedge zsp playback` to provide an interactive chronological replay showing: Envelope Submission -> Acquisition Mode (`AUTOMATIC (Cedar Policy)` vs `MANUAL (HITL Challenge)`) -> Command Execution & Lineage Proof -> 1x Burn. Added automation velocity metric for the policy recommendation engine. Verified with `TestZSP_PlaybackAndAllSessions`.
5. **Edge Audit & Sweep Grant Transmission:** Enriched `bap-edge/internal/audit/transmitter.go` to transmit `grant_id`, `parent_grant_id`, `narrowing_applied`, `narrowing_reason`, `requested_actions`, `allowed_actions`, and `zsp_concept`. Added `SyncWorkstationGrants()` to `bap sweep` and background transmitter to reliably persist local grants into Control Plane SQLite.
6. **V3 Web Cockpit UI Full Linked Card & Envelope Modal:** Updated `bap-controlplane/internal/dashboardui/web/v3.html` so both the OBO View (`#viewOBO`) and Session Transcript Drawer (`loadConvo`) display linked grant badges, execution receipt IDs, consumed commands, and clickable Grant IDs that open an interactive detail modal (`#grantModal`) revealing the full cryptographically signed JSON envelope, principal SVID, and least-privilege narrowing details.

**Acceptance checked:**
- [x] `bapedge stepup list` resolves `config.ResolveEndpoints().ControlPlaneURL` (e.g. `https://bap-controlplane.onrender.com`) instead of hardcoding `http://localhost:8443`.
- [x] Unit test `TestStepUp_ServerURLResolution` verifies precedence: `BAP_SERVER_URL` -> `BAP_CONTROL_PLANE_URL` -> `config.ResolveEndpoints()`.
- [x] Central Control Plane SQLite database (`bap-controlplane.db`) stores local JIT `TaskGrant` records with full cryptographic metadata (`zsp_grants` table).
- [x] Central Control Plane STS/Audit ledger indexes local JIT TaskGrants alongside execution receipts, providing non-repudiation proof in the v3 UI.
- [x] `bapedge zsp status --all-sessions` lists active and burned grants across all agent sessions on the workstation without manual session ID matching.
- [x] `bapedge zsp playback` replays the chronological grant lifecycle categorized by automatic vs step-up modes, providing automation velocity metrics for policy recommendations.
- [x] V3 Web Cockpit UI displays linked grant badges, lineage receipts, and provides a full interactive inspection modal with raw JSON envelope inspection.

---

### BAP-1094 — Antigravity & Agent Launcher Global Control Plane Resolution & Comprehensive 7-Binary CLI Reference

**Status: DONE — implementation and documentation verified, 2026-11-16.**
**Deployment: local code fix and verified suite.** This is a local backlog record, not an external Jira issue.

**Problem:** 
1. **Rogue Local Control Plane Auto-Start (`bap agy` / `run_antigravity_cli_bap`):** When invoking `bap agy` on an enrolled workstation, `bap_launcher_engine.ps1` failed to inspect `bap-config.json` or the global control plane setting, checking only raw `$env:BAP_SERVER_URL`. Failing that, it defaulted to `http://localhost:8080`. `Ensure-ControlPlaneRunning` then observed port 8080 was closed and automatically spawned a local `bapcontrolplane.exe` background process instead of connecting to the configured remote Control Plane (`https://bap-controlplane.onrender.com`).
2. **Missing Pass-Through in Agent Launcher Go Wrappers:** `RunClaude`, `RunCodex`, and `RunAntigravity` in `bap-edge/cmd/agent_launcher.go` parsed launcher arguments but discarded `serverURL`, neglecting to resolve `config.ResolveEndpoints().ControlPlaneURL` and failing to pass `--server` and `BAP_SERVER_URL` down to launcher scripts and subprocesses.
3. **Incomplete CLI Documentation (`docs/CLI_REFERENCE.md`):** The CLI reference document previously lacked coverage for `bap agy` / `bap antigravity`, `bap codex`, `bapedge stepup`, `bapedge zsp playback`, `bapedge plugin`, `bapedge daemon`, `bapedge config`, and omitted the full reference manual for the other 6 platform binaries (`bapcontrolplane`, `bapdashboard`, `bapgateway`, `bapmcp`, `cchook`/`interceptor`, and `bap-hook-adapter`).

**Delivered:**
1. **Config-Aware Control Plane Resolution in Launcher Engine:** Updated `scripts/bap_launcher_engine.ps1` (and synchronized copies in `bap/` and `bap/launchers/`) to resolve `$ServerUrl` by checking `$env:BAP_SERVER_URL`, `$env:BAP_CONTROL_PLANE_URL`, and searching candidate configuration files (`bap-config.json`, `.bap/config.json`, `~/.bapstate/config.json`, `~/.bap/config.json`) before falling back.
2. **Disabled Rogue Control Plane Auto-Start:** Modified `Ensure-ControlPlaneRunning` in `bap_launcher_engine.ps1` to never auto-spawn `bapcontrolplane.exe` unless explicitly commanded via `BAP_AUTO_START_CP=1` or `BAP_STANDALONE_DEV=1`.
3. **CLI Wrapper Global Endpoint Resolution & Subprocess Wiring:** Updated `RunClaude`, `RunCodex`, and `RunAntigravity` in `bap-edge/cmd/agent_launcher.go` to invoke `config.ResolveEndpoints()`, pass `--server=<ControlPlaneURL>` to launcher scripts, and export `BAP_SERVER_URL` and `BAP_CONTROL_PLANE_URL` to child processes.
4. **Antigravity MCP Server Config Sync:** Enriched `run_antigravity_cli_bap.ps1` to write `BAP_SERVER_URL` and `BAP_CONTROL_PLANE_URL` into `.antigravity/mcp_config.json`.
5. **Comprehensive 7-Binary CLI Reference (`docs/CLI_REFERENCE.md`):** Completely overhauled and rewrote `docs/CLI_REFERENCE.md` into an authoritative guide detailing all 7 binaries:
   - `bap` / `bapedge`: full command matrix across identity, agent sandboxes, daemon lifecycle, Cedar policy broker, ZSP playback, step-up challenges, cross-folder trust, recommendations, and plugins.
   - `bapcontrolplane`: all commands (`start`, `stop`, `status`, `restart`, `enable`, `serve`) and complete flags reference (`--port`, `--db`, `--durable`, `--mode`, `--admin-token`, `--policy-max-age`, etc.).
   - `bapdashboard`: full HTTPS operator cockpit flags (`-port`, `-control-plane`, `-ca-cert`, `-tls-cert`, `-allow-remote-admin`).
   - `bapgateway`: full Egress PEP commands and options (`start`, `stop`, `status`, `--port`, `--controlplane`, `--consume`, `--secret`).
   - `bapmcp`: full MCP stdio protocol reference, flags, exposed tools (`bap_execute`, `bap_explain_policy`, `bap_request_task_grant`, `bap_zsp_status`), and agent client configs.
   - `cchook` / `interceptor` / `bap-hook-adapter`: Layer 1A native hook JSON contract and cross-agent execution lifecycle adapters.
   - Internal developer tooling: build, test, and maintenance workflows.

**Acceptance checked:**
- [x] `bap agy` resolves `config.ResolveEndpoints().ControlPlaneURL` (e.g. `https://bap-controlplane.onrender.com`) and passes `--server` and `BAP_SERVER_URL` down to `run_antigravity_cli_bap.ps1`.
- [x] `bap_launcher_engine.ps1` discovers `bap-config.json` and does not default to `http://localhost:8080`.
- [x] `Ensure-ControlPlaneRunning` does not auto-spawn a local `bapcontrolplane.exe` process on enrolled workstations.
- [x] `docs/CLI_REFERENCE.md` documents all 7 core executables with exhaustive subcommand, flag, and configuration references.
- [x] Unit test `TestParseLauncherArgs_ServerURL` verifies `--server` flag parsing and pass-through.

---

### BAP-1095 — Antigravity Canonical Session Resolution, Multi-Session Deduplication, and Single-Flight Prompt Tailing

**Status: DONE — implementation and tests verified, 2026-11-16.**
**Deployment: local code fix and verified suite.** This is a local backlog record, not an external Jira issue.

**Problem:**
1. **Duplicate Active Sessions in `bap status`:** When running Google Antigravity (either invoked directly via `agy` or launched via `bap agy`), two distinct active sessions were registered and displayed in `bap status`. The MCP server self-enrollment (`ensureMCPSession` in `mcp_enroll.go`), the native hook adapter (`bap-hook-adapter` / `plugin.go`), and the launcher script (`bap_launcher_engine.ps1`) generated conflicting session identifiers (`sess-antigravity-<pid>`, `sess-antigravity-pid-<pid>`, `observed-antigravity-...`, and `sess-antigravity-cli-<guid>`) on different related PIDs (e.g. PowerShell launcher wrapper vs `agy.exe` vs child tool runner).
2. **False Non-Liveness in `ensureMCPSession`:** In `mcp_enroll.go`, `sessionIsLive` queried the remote control plane without checking local state. When offline, unenrolled, or experiencing network latency, `sessionIsLive` returned false, causing `ensureMCPSession` to discard an active inherited session and mint a second session.
3. **Double-Counting Prompts in Telemetry & Status:** Both `bapedge watch` and `bapmcp` (as well as the launcher background job) initiated separate transcript tailing loops for each generated session ID. Every prompt extracted from `transcript.jsonl` was posted once per session ID, causing both sessions to record `Prompts: 1`, doubling the total prompt count observed in `bap status` (`Prompts Count: 2 observed across active sessions`) and duplicating entries in the Central Control Plane.

**Delivered:**
1. **Canonical Active Session Adoption (`findActiveNativeSession`):** Implemented `findActiveNativeSession(appID, ppid)` in `bap-edge/cmd/session_lifecycle.go`. It scans `state.SessionsDir()` and workspace fallback markers for live sessions belonging to the same application workload and process lineage (matching PID, parent, child, or ancestor/descendant tree).
2. **Unified Hook & MCP Session Resolution:** Updated `resolvePluginSessionID` in `bap-edge/cmd/plugin.go` and `ensureMCPSession` in `bap-edge/cmd/mcp_enroll.go` to invoke `findActiveNativeSession` before generating new session IDs. Existing native sessions are reused across hooks and MCP bridges instead of creating competing sessions or adopting `observed-` IDs.
3. **Harmonized Session ID Format:** Standardized default session ID naming to `sess-%s-%d` across `session_lifecycle.go`, `mcp_enroll.go`, `watch.go`, and `plugin.go`, eliminating the `-pid-` formatting discrepancy.
4. **Local Liveness Guard:** Enhanced `ensureMCPSession` to check `IsSessionActive(sessionID)` locally before falling back to network queries. Active sessions avoid redundant re-enrollment and watcher spawning.
5. **Cross-Process Single-Flight Prompt Tailing & Hash Deduplication:**
   - Introduced file-backed prompt tailer locking (`antigravity_prompt_tail.lock` in `state.Dir()`) to ensure only one active process tails transcript logs per workstation.
   - Added persistent prompt hash tracking (`isPromptHashSent` / `markPromptHashSent` in `state.PromptsDir()`) so duplicate transmissions are rejected across processes and restarts.
   - Updated `bap_launcher_engine.ps1` to honor the active tailer lock before spawning background jobs, and to inherit `$env:BAP_SESSION_ID` when provided.
6. **Workload Lineage Deduplication in `bap status` (`cli_tools.go`):** Added lineage resolution in `cli_tools.go` that inspects the process hierarchy for active sessions of the same application. Subordinate launcher wrappers or child runners are marked `SUPERSEDED (Inactive)`. `totalPrompts` is computed strictly from canonical active sessions, eliminating double-counted prompt tallies.
7. **Automated Regression Tests (`antigravity_dedup_test.go`):** Added tests verifying:
   - Canonical session adoption across `findActiveNativeSession`, `resolvePluginSessionID`, and `ensureMCPSession`.
   - Prompt hash deduplication and cross-process single-flight tail locking.

**Acceptance checked:**
- [x] Antigravity produces exactly 1 canonical active session in `bap status` when running.
- [x] Hook executions bind to the canonical session without spawning secondary sessions.
- [x] Prompts are transmitted once and prompt counts in `bap status` are not doubled.
- [x] Unit tests in `antigravity_dedup_test.go` and `mcp_enroll_test.go` pass.

---

- **Hooks-first prompt fallback follow-up (2026-11-14):** MCP reporting is default-on, unrelated hook heartbeats cannot suppress it, and session/turn correlation now owns prompt counting and source priority across audit and prompt ingestion. Late hooks supersede fallback text/classification without adding a turn; canonical transcript deduplicates corroboration while raw audit evidence remains immutable. Added native/broker turn-ID propagation and SQLite/checkpoint correlation persistence. Identical repeated turns require distinct native IDs; legacy hash-only correlation is qualified. Per-session telemetry batches prevent a refused old session from blocking live sessions. Fresh sign-in is acknowledged, but live historical backlog reconciliation and deployment remain open. See `docs/POLICY_AND_REPORTING_HEALTH.md`.

- **Policy/reporting resilience follow-up (2026-11-14; BAP-1080/1085, BAP-1004):** added the missing daemon signed-policy poller (three seconds, independent of native hooks/watchers), daemon prompt-spool replay, reporting-only heartbeat enrollment guidance, runtime/CLI skew diagnostics and stale-daemon replacement on start. Cache files use unique staged replacement with bounded Windows sharing retries. Explicit state installations no longer import/discover/purge another installation's credentials during logout. A broad regression exposed the old cleanup touching live enrollment; fresh browser sign-in was initiated and remains an external acceptance step. Edge cmd/policystore/state and control-plane API/registry suites pass; next-poll kill-switch regression passes. No fleet-wide latency SLA, plaintext-policy encryption or hook-free automatic prompt source is claimed. See `docs/POLICY_AND_REPORTING_HEALTH.md`. Source changes require deployment.

- **BAP-1089 implemented in source (1.13.15), tests extended 2026-11-15; hosted deployment and installed-client qualification pending:** a fresh nonce-bound Ed25519 sync proof lets the trusted control plane issue policy versions up or down without deleting local trust or raising the server counter to match a client. Local/cache acceptance and old servers without freshness proofs retain rollback rejection. Added coverage for server downgrade, replay rejection, restart persistence and lower-version kill-switch/recovery. Both server and edge require deployment; installed-client and hosted qualification remain open. Added 2026-11-15: a proof signed by an unpinned key or bound to a different directive is rejected and leaves the cached policy untouched, requests without a nonce and CURRENT answers carry no proof, and the real `/api/v1/policy/sync` handler returns a nonce-bound `sync_signature`. See `docs/PRODUCT_REVIEW_2026-11-14.md`.

See `docs/PILOT_RUNBOOK.md` for the new ordered confidence checks. These are source changes, not a completed external pilot or a blanket closure of the stories below.

- **BAP-1077:** default execution lifetime raised to 30m, explicit bounded timeout, elapsed progress, cancellation/drain and bounded captured output. Native Windows 125-second execution proof added; interactive terminal streaming remains outside this slice.
- **BAP-1078:** removed non-interactive `--yes`; agent/broker/known agent-session submission refused; broker/plugin/hook recommendation gates added. Terminal presence is not cryptographic human identity.
- **BAP-1074 slice:** authenticated V3 per-machine recommendation review/revoke queue with error/demo/logout guards. Fleet approvals, company matrix and evasion analytics remain open.
- **BAP-1072 CI slice:** matching-binary recommendation wire fixture covers signed sync, isolation, dangerous effects, restart and revocation. Manual browser/installed-client acceptance remains required.
- **BAP-1070/1071/1079 compatibility slice:** one SQLite-backed server can atomically checkpoint authority plus new canonical audit links before releasing API responses. Registry, settings/versions, approvals, session/user restrictions and dedup IDs restore on restart. Production requires stable signing configuration, absolute persistent storage, explicit lease budget and explicit first initialization. Missing checkpoint/storage and failed commits refuse authority. This is not the PostgreSQL/multi-replica leadership persistence project; load, backup restore and deployment-volume qualification remain open.
- **BAP-1080/1085 slice:** explicit hook-copy hash comparison, authenticated policy-cache repair preserving trust/identity, and stricter missing-version gates. Automatic enumeration of every vendor's hook configuration and full fleet rollback qualification remain open.
- **BAP-1084 slice:** metadata-first Go edge/hook transport and local broker/prompt-spool minimization; production ingress filtering; capture scope documented in `docs/TELEMETRY_PRIVACY.md`. All-producer inventory and retention remain open.
- **BAP-1087 slice:** opt-in deployment-controlled signed expiry, client capability gate and fail-closed expiry without trusting unsigned LastSync. Production requires an explicit budget; real disconnected-workstation acceptance remains open.
- **BAP-1081 slice:** broker JSON phase timings and smoke-report propagation. Fleet friction denominators, p95 qualification and cockpit backlog health remain open.
- **BAP-1086:** one release publication path, reusable CI qualification before packaging, module-matched Go toolchain and approved-mirror variables. External required-check configuration, action digest pinning, scanning and broader Python platform coverage remain open.
- **New evidence slice:** `scripts/pilot_qualification.py` collects sanitized references/hashes and explicit operator attestations. Smoke alone cannot qualify a pilot; changed/missing evidence invalidates its case.

Browser-to-edge temporary ZSP approval/resume (BAP-1022), complete native capability/credential enforcement, non-Windows native acceptance, individual admin SSO, device proof of possession and qualified leadership work reporting retain their existing open/deferred statuses. No external Jira records were created by these local edits.

> The previous backlog (about 5,500 lines, then a pruned 490-line version) described a product that does not match the code. The full original is kept in `archive/docs/JIRA_STORIES_FULL_2026-11-13.md` and in git history. **This file replaces it.** It is short on purpose: one thesis, one architecture decision, a keep/demote/stop list, and about 20 stories in three milestones, each with an acceptance test that can fail.

## 1. Where the product honestly is

**Verified working (live, Claude Code on Windows, November 2026 sessions)**
- Zero standing privileges: no grant, no execution. Single-use burn, scope and resource binding, grant signing.
- A data-driven permission policy with allow / approve / deny tiers, a mint cap, and a signed policy override.
- A trust store (`bap trust`) that really opens a folder, with guards and prescriptive refusal messages.
- Human approval requests (`zsp approvals / approve / deny`) and an anti-spin breaker that halts a looping agent.
- Audit chain, control plane, cockpit (counts now de-duplicated).
- `git add` and `git commit` through the hook, once the parser bugs below were fixed.

**Not what the old docs say**
- The legacy `bap exec` path has Windows restricted-token/Job Object containment, limited Linux namespaces and a no-op macOS sandbox. The newer `bap run` path uses Windows AppContainer with real boundary tests; Linux bubblewrap and macOS native profiles are wired but native execution remains unverified here. eBPF, Landlock LSM, WFP and Endpoint Security are not implemented as host enforcement; the control-plane "eBPF/Landlock" is a Go simulation.
- **Command parsing is the security boundary today, and it cannot be finished.** This month alone: heredoc bodies read as paths, a lone `/` read as the filesystem root, quoted `&&` splitting commands, relative `.bap/` paths bypassing protection, `*rm *` matching "platform", env-variable sniffing locking out developers, re-quoting hiding PowerShell control blocks, `git ls-files` needing a grant, and `git commit` failing because the broker hides the git identity.
- Only Claude Code was exercised live. Antigravity, Codex and Copilot adapters are unverified.
- The original review found ordinary-work refusals, terminal-only approvals, unflushed telemetry and broken CI. Subsequent fixes and the V3 control-plane inbox are recorded below; edge-local approvals still require terminal action, end-to-end telemetry latency is unproven, and native macOS acceptance is pending.

## 2. Thesis

**BAP is the governance plane for coding agents: one sandbox the agent lives in, one egress path, one approval inbox, one evidence ledger.**

Enterprises do not need a shell parser. They need to answer four questions for every agent session: *what could it touch, where could it send data, who approved the exceptions, and can we prove it.* Each has a small, enforceable chokepoint:

| Question | Chokepoint (enforced by the OS or network, not by reading text) |
|---|---|
| What could it touch? | Filesystem sandbox: only the workspace and folders a human trusted exist for the agent |
| Where could it send data? | One egress proxy, default deny, per-grant allow-list |
| What secrets did it have? | None by construction: no host environment, no profile, brokered credentials only |
| What can it publish? | Enforced at the remote (branch protection, required review); the agent may commit freely |
| Who approved exceptions? | Approval inbox with signed decisions |
| Can we prove it? | Tamper-evident ledger of grants, sandbox denials and proxy logs |

## 3. ADR-001: Enforce effects, not commands

**Decision.** Security decisions are made on *effects at a boundary* (a path opened, a host contacted, a process spawned), never on the text of a command. Grants become **capability sets** that configure the sandbox and the proxy. Text analysis is demoted to UX (early, friendly refusals and routing), and is never relied on to stop anything.

**Why.** Shells and interpreters are Turing-complete (`python -c`, `sh -c`, build scripts, encodings, aliases). Every parser fix exposes the next gap, across every OS and language, and a false positive stops a developer while a false negative is an escape. Sandboxes and proxies have a handful of rules and do not care how the command was spelled.

**Consequences.**
- The command decomposer, text-pattern Cedar rules and the planned "command packs" (old BAP-922/923) are **not extended**. They stay as a fast, advisory layer.
- Raw shell is allowed inside the sandbox. Where precision matters, use typed tools (MCP) so policy sees structured arguments.
- Approvals are triggered by the denied effect and name the real path or host.
- The user requires native execution on all three OSes, without administrator rights, Docker or WSL. The Windows choice is AppContainer (BAP-1031); native Linux/macOS acceptance and a fallback for Linux hosts that disable unprivileged namespaces remain open.

**Prior art to compare against (verify before building; from general knowledge, not checked in this review).** Claude Code and Codex ship their own sandbox modes (Seatbelt on macOS, bubblewrap/Landlock on Linux; Windows support lags). BAP should *configure and govern* those where they exist and supply its own runner where they do not, instead of competing with them.

## 3b. ADR-002: Policy is learned from observation, not hand-written one case at a time

**Problem.** Every fix so far was a human reading a failure and editing code or a rule: heredocs, `git ls-files`, `*rm *`, git identity, trust. That loop never converges, because the world (agents, tools, languages, repos) is open-ended. ADR-001 shrinks the enforcement surface; this ADR makes the *policy* on that surface improve itself, with a human approving every loosening.

**Decision.** BAP runs a closed loop: **Observe -> Learn -> Recommend -> Verify -> Apply -> Re-observe.** The proven pattern is the one used by AppArmor complain mode, AWS IAM Access Analyzer policy generation, Kubernetes network-policy generators and seccomp profile recorders: run in a non-blocking mode, record real effects, generate the least-privilege policy from what was observed, show it for review, enforce it.

| Stage | What happens | Built on |
|---|---|---|
| **Observe** | Every session emits normalized *effect events*: `{session, agent, project, kind (fs/net/exec/git), target, mode, outcome (allowed / denied / approved / halted), source (sandbox / proxy / hook), grant, human decision}`. No prompt text by default. | Audit ledger, hook decisions, HITL requests, denial counters (exist today); sandbox and proxy traces (BAP-1011/1012) |
| **Complain mode** | Per scope, a rule can run in `complain`: the effect is allowed and logged as "would be denied". Rules are promoted to `enforce` only after a soak period with no friction. | Edge audit/shadow mode (exists in `exec.go`); needs per-rule scope and promotion |
| **Learn** | Deterministic miners over the effect store (below). | New |
| **Recommend** | A *policy change proposal*: a signed-policy diff plus evidence, risk and blast radius. | New |
| **Verify** | The proposal is replayed against recorded history before anyone sees it: what would newly be allowed, and does anything risky slip through? | New |
| **Apply** | Human accepts in the policy inbox; canary to a fraction of the fleet in complain mode; then enforce; rollback available. | Signed bundles (exist, BAP-821/921) |

**The miners (deterministic first, no model in the loop):**
1. **Friction miner.** Refusals of low-risk effects (read-only, in the workspace, no secret features) that a human approved N times across M developers become candidate allow rules, scoped as narrowly as the evidence supports.
2. **Prediction auditor.** Compare what the advisory hook *predicted* a command would touch with what the sandbox *actually observed*. A refusal that names a path no process ever opened is a classifier false positive. This single check would have found every parser bug in this review automatically (`file://C:/`, `.bap/` markers, `*rm *`) and turns "the hook is wrong" into a measured KPI.
3. **Profile generator ("learn this project").** N sessions in complain mode produce a least-privilege capability profile: filesystem prefixes, network hosts, executables, with guarded generalization (no `*` hosts, no filesystem roots).
4. **Drift and tighten.** A host or path never seen in a project's baseline, or a successful effect that carries risk features (secret-like path, new egress host, write outside the workspace), becomes a *tighten* or *alert* recommendation.
5. **Unknown-tool clustering (optional model assist).** Group unfamiliar commands so a reviewer decides once per cluster.

**Hard safety rules (not negotiable).**
- Learning only **proposes**. It never loosens anything by itself. Tightening may be auto-applied only if an administrator opts in.
- The **deny tier is immutable**: credentials and secrets can never appear in a proposal.
- **Evidence must be human-grounded**: approvals by distinct people; an agent's own requests or retries are never evidence. Per-agent contribution is capped so an agent cannot manufacture its own allow rule by repetition.
- A model may explain, cluster and draft rationale, but never decides and is never in the enforcement path (the existing non-reliance invariant).
- Every proposal, decision, canary and rollback is written to the ledger.

**Consequences.** The old "audit-to-policy mining" and "shadow-mode migration" claims (BAP-817 and old BAP-928) had no implementation in the control plane; this replaces them. Most future friction should be fixed by an *accepted proposal*, not a code change. The KPI: **over 80% of friction fixed without shipping code**.

## 4. Keep, demote, stop

| Area | Decision |
|---|---|
| ZSP engine, grant signing, mint cap, session ceiling | **Keep.** It becomes the capability-grant service. |
| Permission policy tiers, signed override | **Keep**, retarget from action strings to capabilities. |
| Trust store, `bap trust`, guards | **Keep**, becomes "add a path capability". |
| Human approval requests, anti-spin halt | **Keep**, move decisions to a signed inbox (BAP-1022). |
| Audit chain, control plane, cockpit | **Keep and make reliable** (BAP-1004). |
| `bapgateway` | **Keep and promote** to the single egress proxy (BAP-1012). Unverified today. |
| Hook interceptor, decomposer, text-pattern Cedar rules | **Demote** to advisory UX (BAP-1021). No new parsing work. |
| "eBPF / Landlock" simulation in the control plane | **Remove or label as a simulation**; stop describing it as enforcement. |
| New "DONE" stories without a failing-capable test | **Stop.** |

## 5. Definition of "usable" (the bar every milestone is measured against)

1. **Day-in-the-life suite:** add, commit (any message), build, test, read a trusted folder, edit code, run tests: **zero approval prompts**.
2. **Escape suite:** `python -c "open('/etc/passwd')"`, raw `curl`, base64-wrapped commands, symlink tricks, git hooks, `sh -c` chains: **all stopped by the sandbox even with the hook disabled**.
3. **Time to first governed session:** under 10 minutes from install.
4. **Approval round trip:** under 30 seconds from request to the agent continuing.
5. **CI:** green on Windows, Linux and macOS on every push.
6. **The loop works (ADR-002):** over 80% of friction is fixed by an accepted policy proposal, not a code change; the prediction-mismatch rate of the advisory hook is measured and falling.

## 6. Stories

Size: S under 2 days, M under a week, L over a week. Each story ends with an acceptance test.

### Milestone 0: Trustworthy baseline (about 1-2 weeks)

**BAP-1001 (M) Release gate.** CI runs every suite (Go on 3 OSes, Python, Node) and blocks merge on red. Add `bap doctor --e2e` that runs a 2-minute scripted proof: grant, commit, trust, HITL request, denial. *Accept:* a deliberate regression (re-introduce the quoted `&&` bug) turns CI red.

**BAP-1002 (M) Developer happy path.** One end-to-end suite of ordinary developer work through hook and broker with zero prompts. Every false positive found afterward becomes a case. Includes: `git add/commit` with heredoc and quoted messages, read-only git subcommands (`ls-files`, `blame`, `grep`, `remote -v`, `config --get`), commit identity (BAP-937), build and test, trusted-folder reads. *Accept:* suite passes on 3 OSes; BAP never asks about a read-only command.

**BAP-1003 (S) Truthful claims.** `ARCHITECTURE.md`, the demo runbook and the README match section 1 of this file. A CI lint fails if a doc says a capability is active that the capability matrix marks otherwise. *Accept:* the lint catches a seeded false claim.

**BAP-1004 (M) Telemetry that arrives.** Edge spool flushes reliably to the control plane (the concurrency guard currently blocks auto-sync); the cockpit shows de-duplicated actions including ALLOWED-LIMITED and blocks; a health banner appears when the backlog exceeds a threshold. *Accept:* a 20-action scripted session appears in the cockpit with correct counts within 10 seconds.

Implementation update (2026-11-13): the prompt-spool compare-and-swap guard already releases correctly; the original diagnosis above is stale. Audit-spool flushes are now serialized across watcher/daemon/manual-sync callers within a process, and failure to remove acknowledged entries is reported instead of silently counted as success. Regression coverage uploads 20 actions plus an event appended during an in-flight upload, verifies each event is uploaded once, and verifies the spool drains without losing the new event. This does not coordinate separate OS processes; server event-ID deduplication remains required. **Still open:** cockpit backlog warning and the complete 10-second edge-to-cockpit acceptance scenario. Native macOS CI remains pending runner availability.

**BAP-1005 (S) Calls report parity.** `review_session.ps1` (three copies) uses the same de-duplicated counting as the control plane. Replace the copies with one implementation. *Accept:* the same session gives the same totals in the cockpit and the report.

**BAP-1006 (S) Development override must unblock BAP development.** A human-enabled, valid developer override suspends task-grant enforcement as well as BAP self-tamper checks. While active, broker shell execution, native-tool decision checks and plugin hooks must skip grant verification and consumption: no grant request, mint, approval prompt, or "no standing privileges" refusal. Plugin prompt context must not tell the agent to obtain grants during the override. Credential protection, revocation, workspace boundaries and other policy checks remain in force. The override stays unavailable in production and official release builds, expires normally, and cannot be activated by an agent. This is a developer bootstrap facility, not a production authorization mode.

*Acceptance:* with ZSP configured to enforce and an empty grant store, an allowed shell command and native file read succeed during an active override, with no grant ID or grant prompt; expired/inactive overrides, production and compiled-out builds still require grants. A boundary violation remains blocked during override. Test both the broker and plugin paths. Rebuild the exact binary used by the launcher/hook before checking behavior; a stale installed copy is not proof of the new source behavior.

*Status:* implemented in broker, plugin and standalone hook; automated checks cover empty-store broker/native-tool decisions, hook grant guidance gating, expiry, production, release builds and the canonical `~/bin/.bapstate` marker. **Developer manual confirmation: pending**; only the developer can confirm the rebuilt installed broker **and hook** no longer ask for grants. Do not mark this story complete before that confirmation.

**BAP-1007 (M) V3 admin operations are discoverable and functional.** V3 must expose an Admin & approvals view rather than send the operator to a missing `/#policies` page. Provide the current Cedar policy, schema, validation results, historical/explicit scenario simulation, a reasoned deployment, and a control-plane HITL inbox showing action, resource, session, reason, risk, reviewer and expiry. Require a verified admin token for decisions, simulations using audit history, and deployments; retain remote-admin restrictions. In Demo mode, no admin operation reaches the live backend. Clear private data on logout and ignore late responses. A changed draft invalidates its previous validation/simulation; deployment uses a version precondition so an old editor cannot overwrite a newer policy or fleet freeze. Decisions are shown as recorded only after server confirmation.

*Acceptance:* UI tests exercise locked/admin/demo states, request/response payloads, failed decisions, draft edits and logout races; API tests reject missing/invalid credentials and duplicate decisions; a stale editor cannot clear a fleet freeze. Run these in CI. **Status:** implemented and verified by Node UI tests, Go API/store/asset tests and Python policy/HITL integration tests; developer UI confirmation pending. The inbox covers control-plane escalation requests only, not edge-local ZSP approvals.

### Milestone 1: Sandbox-first enforcement (the course change, about 4-6 weeks)

**BAP-1010 (M) Capability model spec.** Define a grant as a capability set: filesystem `[{path, mode}]`, network `[{host, port}]`, process rules, environment allow-list, TTL. Map today's tiers to capability requests. Define the denial event schema (`kind`, `target`, `mode`, `session`). *Accept:* a reviewed spec plus a Go package that converts an existing TaskGrant into a capability set, with tests.

**BAP-1011 (L) `bap run <agent>` with pluggable native sandbox providers.**
- *User constraint:* all three OSes, without admin rights, Docker or WSL. Optional container rendering is not the default or the acceptance provider.
- *Linux:* bubblewrap with a private network namespace and unix-socket egress relay. A native fallback is still needed where unprivileged user namespaces are disabled; do not claim that fallback exists.
- *macOS:* native `sandbox-exec` profile and the unix-socket/loopback relay; real execution must be verified on a macOS runner.
- *Windows:* AppContainer with no network capabilities and a unix-socket relay. The older `exec` restricted-token/Job Object path remains separately labelled limited.
*Accept:* the escape suite (BAP-1030) is blocked by each native provider with the hook disabled; missing providers fail closed. Launch the entire agent process, not only a selected child command.

**BAP-1012 (L) Egress proxy as the only network path.** Promote `bapgateway`: default deny, allow-list from the grant, HTTPS host-level (CONNECT) decisions, request log, presets for package registries and git hosts. *Accept:* `curl https://example.com` from inside the sandbox fails with no route except via the proxy; an allow-listed host works; every request is logged.

**BAP-1013 (M) Denial-driven approvals.** A sandbox or proxy denial creates a structured approval request naming the real path or host. Approving a host takes effect live; approving a path takes effect on the next launch (or live where the provider supports it). *Accept:* the agent hits a blocked host, a request appears with that host, the developer approves, and the retry succeeds within 30 seconds.

**BAP-1014 (M) Credentials by construction.** The sandbox starts with no host environment, no profile and no agent secrets. Git credentials and API tokens are injected by the broker per request and never exist inside. *Accept:* `env`, `~/.aws`, `~/.ssh`, `.env` yield nothing from inside the sandbox even when the hook is off.

**BAP-1015 (M) Git workflow capabilities.** Commit and branch are free in the sandbox. Push and PR go through a brokered helper that raises an approval. `bap doctor` verifies that the default branch is protected on the remote and prints exactly how to fix it. *Accept:* the agent can commit all day; a push raises a request; an approved push works; merge to a protected branch is refused by the remote.

**BAP-1031 (S, timeboxed spike) Windows decision.** Compare WSL2/containers, AppContainer + WFP, and Windows Sandbox for the agent runner. Output: a one-page decision with measured startup time and developer friction. *Accept:* a decision record and a working proof for the chosen option.

### Milestone 2: Typed tools and fleet (after Milestone 1)

**BAP-1020 (M) Typed tools for the common 80%.** MCP tools for file and git operations (`git.commit`, `fs.write`, ...). Policy sees structured arguments, with no parsing. Agent configuration prefers them; raw shell remains in the sandbox. *Accept:* the day-in-the-life suite runs through typed tools with the hook disabled.

**BAP-1021 (S) Hook becomes advisory.** Remove text classification from every security decision path; keep it for early refusal messages, routing, and the anti-spin breaker. *Accept:* disabling the hook does not widen what the sandbox allows.

**BAP-1022 (M) Approval inbox.** Web inbox with signed approve/deny decisions (replaces the terminal one-time code), a notification (desktop toast or webhook), and an expiry. *Accept:* approve from the browser; the agent continues; the decision is in the ledger with the approver's identity.

*Delivered slice (BAP-1007):* authenticated V3 control-plane escalation inbox, approve/deny, bounded grant lifetime, reviewer attribution and audit events. *Still required before this story is complete:* synchronize workstation-local `zsp approvals` requests to the control plane; deliver signed, workstation/session/request-bound decisions back to the edge for grant minting; prove a blocked real agent resumes after browser approval; persist pending requests/decisions across restart; bind reviewer identity to authenticated individual SSO rather than a shared admin token; notifications and expiry of pending requests. The existing control-plane ephemeral step-up grant is not an edge ZSP TaskGrant. Never label that transport complete based only on an inbox API test.

**BAP-1023 (M) Evidence.** The ledger records capability grants, sandbox denials and proxy logs with hash chaining; SIEM export. *Accept:* an auditor can reconstruct a session's reachable surface and every exception from the ledger alone.

**BAP-1024 (M) Thin adapters.** Claude Code, Codex, Antigravity and Copilot are launched through the runner. Each adapter is under 100 lines of configuration. *Accept:* the day-in-the-life suite passes for at least two agents.

### Learning loop (ADR-002). Start BAP-1040 to 1042 in parallel with Milestone 0, the rest after BAP-1011

**BAP-1040 (M) Effect-event schema and store.** One normalized event for every decision and effect (fields in ADR-002), derived today from the ledger, hook and HITL data, and later from sandbox and proxy traces. Privacy by default: no prompt text, targets hashable per tenant. *Accept:* a recorded 20-action session round-trips through the store; the same events feed the cockpit and the miners.

**BAP-1041 (M) Complain mode per scope and rule.** A rule can run in `complain`: allow, log "would deny", surface in the cockpit, and report friction. Promotion complain to enforce needs a soak period with zero friction events. *Accept:* a rule in complain mode never blocks; promotion is refused while friction events exist.

**BAP-1042 (M) Friction and prediction auditor.** Deterministic miners: low-risk refusals approved by humans, repeated denials and halts, and predicted-vs-observed effect mismatches (classifier false positives). Output: a ranked candidate list with evidence. *Accept:* replaying this review's failures (quoted `&&`, lone `/`, `.bap/` relative path, `git ls-files`, `*rm *`) lists each as a candidate without a human pointing at it.

**BAP-1043 (L) "Learn this project" profile generator.** From N complain-mode sessions generate a least-privilege capability profile (filesystem prefixes, hosts, executables) with guarded generalization and a human-readable diff against the current profile. *Accept:* a generated profile lets a fresh session of the same project run with zero prompts and blocks an effect outside the profile.

**BAP-1044 (M) Proposal engine and replay simulator.** Turn candidates into policy change proposals (signed-policy diff, evidence, risk, blast radius) and replay them over recorded history to show what would newly be allowed and whether any risky effect would slip through. Auto-generate the regression test cases from the evidence. *Accept:* a proposal that would allow a seeded risky effect is flagged and cannot be accepted without an explicit override recorded in the ledger.

**BAP-1045 (M) Policy inbox, canary and rollback.** Cockpit and CLI (`bap learn report / accept / reject / rollback`): ranked proposals, accept or edit, canary a fraction of the fleet in complain mode, then enforce; two-person approval for broad loosening. *Accept:* accept a proposal, see it canaried, roll it back, all in the ledger.

**BAP-1046 (S) Learning safety rails.** Immutable deny tier; evidence only from distinct human approvals; per-agent contribution caps; no automatic loosening; every proposal decision audited. *Accept:* an adversarial agent that repeats a request 500 times produces no proposal; a proposal touching the deny tier is rejected at creation.

**BAP-1047 (S) Closing the test loop.** Every accepted proposal and every confirmed false positive appends a case to the day-in-the-life (BAP-1002) or escape (BAP-1030) suite. *Accept:* the suites grow without manual authoring and CI fails if a case is removed without a recorded reason.

**BAP-1048 (M, optional) Model-assisted explanation and clustering.** A model drafts the rationale for a proposal and clusters unknown commands for review; it never changes a proposal's content or the enforcement path. Evaluated on a labeled set. *Accept:* reviewers accept model-assisted clusters at a measured rate; removing the model changes no decision.

**BAP-1049 (S) Loop KPIs.** Dashboard: prompts per developer-hour, false-positive rate, prediction-mismatch rate, share of friction fixed by proposals instead of code, time from first friction to accepted fix. *Accept:* the numbers are computed from the effect store and shown in the cockpit.

### Milestone 1b: Control-plane-owned, signed, asset-scoped enforcement (added 2026-11-13)

Why: developers could not have an agent read their own project without a task grant, and the only fix was a compiled-in change or `BAP_ZSP=off` on one machine. Enforcement settings must be owned by the control plane, apply to the **machine** (not the registered agent, which can be re-registered), reach connected machines within seconds, survive a control-plane outage, and be tamper-evident. Investigation found none of that held: policy bundles were unsigned (nil key), the client never verified signatures, the enforcement flags were outside the signature, sync ran only at process start, and deleting the state file fell back to any local `policy.cedar`.

**BAP-1060 (M) Ed25519 policy signing with a pinned trust anchor.** The control plane signs every sync response with an Ed25519 key it generates on first start (or reads from `BAP_POLICY_SIGNING_SEED` for hosted deployments). Clients hold only the public key, pin it automatically at first contact, and accept only bundles signed by that key, for their own asset, covering every enforcement field. End users never see or handle a key. *Accept:* editing any flag in the cached state, replaying a bundle for another machine, or offering a different key is rejected; the canonical signed string is identical on both sides (golden-vector test in each module).

**BAP-1061 (S) Asset identity.** Policy is scoped to a hardware-derived asset id (Windows MachineGuid, `/etc/machine-id`, macOS IOPlatformUUID), not to environment variables, usernames or the registered agent. *Accept:* changing `USERNAME` or re-registering does not change the asset id.

**BAP-1062 (M) `zsp_read_exempt` setting and admin API.** Plain read-only inspection of the workspace (`Read`, `Glob`, `Grep`, listing) needs no task grant by default. An admin (token-protected, audited) can set the fleet default or a per-asset override with `POST/GET/DELETE /api/v1/admin/policy/settings`; settings and the version counter persist across control-plane restarts so clients never see a rollback. Credentials, outside-workspace targets, filesystem roots and mutations are never exemptable. `bapedge` is the single decision point; the hook carries no copy of the rule. *Accept:* an override applies to one asset only; a fleet change reaches all; a restart never moves the version backwards.

**BAP-1063 (M) Seconds-level sync.** Running `bapedge watch` polls every 3 s; short-lived invocations (hooks, `bapedge check`) refresh a cache older than 5 s with a short timeout. While the control plane is unreachable the last signed rules stay in force. *Accept:* an admin change is visible to a connected machine within one sync interval; an unreachable control plane changes nothing.

**BAP-1064 (M) Fail closed on tampering.** If the signed rules, state, enforcement flags or pinned key are altered or deleted and the control plane is down, `bapedge` does not run: one-shot commands deny, and the watcher waits and retries until the control plane re-issues signed rules (`WaitForTrustedPolicy`). When the control plane is reachable, a tampered cache is healed automatically (the client reports it holds nothing, and a tampered version cannot veto the correction). *Accept:* tamper plus outage fails closed; tamper plus reachable control plane self-heals.

**BAP-1065 (M, IMPLEMENTED 2026-11-13, unit-tested; live verification open) Bind signed policy to the existing enrollment (OTC / OIDC).** Verified in code: enrollment already exists. OTC: `POST /api/v1/agents/register` consumes a single-use code, attests the binary hash and public key, and returns a workstation `SessionToken`. OIDC: device-code flow (`/api/v1/auth/oidc/device-code`, `device-token`, `device-verify`, `config`) also yields a workstation credential. `workstationIdentity()` already validates that credential (issuer, `token_use=workstation`, instance id, user revocation, workstation block) and `audit/ingest` requires it. The only unauthenticated piece is `policy/sync`: the signing key is pinned on first contact from `GET /api/v1/policy/pubkey` and the asset id in the request is self-asserted. Note that the enrolled instance id defaults to the hostname, so the hardware asset id must be recorded at enrollment rather than trusted later. Required: return `policy_public_key`, `policy_key_id` and the enrolled asset id in the OTC register response and the OIDC device-token response, and pin from there during `bap install`/`bap login` (no extra step); have `policy/sync` take the enrollment credential and derive the asset from the verified credential instead of the request body; ignore per-asset overrides for unauthenticated callers; keep the pubkey endpoint only as a bootstrap fallback for machines enrolled before this change. *Accept:* an unauthenticated or other-machine caller cannot obtain a bundle carrying another machine's overrides; a revoked or logged-out workstation stops receiving policy; pinning happens during enrollment with no user step, for both OTC and OIDC.

**BAP-1067 (L, OPEN) Policy matrix: company defaults, locks, user overrides, non-negotiables.** Generalize the single `zsp_read_exempt` flag into a control-plane-owned matrix over effect classes: `local_read`, `local_write`, `network_read`, `network_write`, `exec_other`, each set to `allow` (no grant needed) or `grant` (task grant required). The company sets fleet defaults (for example local reads and writes allowed, network reads need a grant) and can **lock** a class so users cannot loosen it. Layers, most specific wins within the locks: fleet default, then per-asset admin override, then the end user's own local preference (`~/.bap/user-policy.json`), which may always tighten but may relax only unlocked classes. The whole effective matrix is part of the Ed25519-signed payload. **Non-negotiables stay compiled in or Cedar `forbid`, never matrix-relaxable by anyone:** credential stores (`.env`, `~/.aws`, `~/.ssh`), tamper of BAP assets, raw network egress utilities (`curl`/`wget`/`nc` style), outside-workspace and filesystem-root targets, and recon commands such as `whoami`. Classification reuses the existing grant-check effects (`fs:read`, `fs:file:write`, network actions, `EscapesWorkspace`). Open decision: `whoami` is currently allowed by Cedar and used by the pilot's token-containment check (`whoami /priv` inside the sandbox); making it a non-negotiable deny needs that check replaced. *Accept:* each class can be set fleet-wide and per asset; a locked class cannot be loosened by a user; a user can tighten any class; a non-negotiable is denied under every setting including the developer override; a change reaches machines within one sync interval.

**BAP-1066 (M, IMPLEMENTED 2026-11-13, unit-tested; live verification open) Signing-key rotation and loss recovery.** Clients refuse a different key, so a lost or regenerated control-plane key would lock out every enrolled machine. Delivered: rotation links (each signed by the previous key) carried in sync responses and followed by clients automatically; `POST /api/v1/admin/policy/rotate-key` (admin, audited, persists the key and chain, keeps the old key as a backup file); hosted rotation via `BAP_POLICY_SIGNING_SEED` plus `BAP_POLICY_SIGNING_SEED_PREVIOUS`; a startup warning when a hosted environment runs without a seed; and a recovery path when the old key is gone: re-running `bap login` or OTC registration replaces the pin through the authenticated enrollment (a silent key change is still refused). *Accept:* a rotation completes with no user action; a forged or unchained key change is rejected; a redeploy with a seed does not strand the fleet.

**BAP-1068 (M, IMPLEMENTED 2026-11-13; live run pending) Tests, pilot and hooks must never touch the real installation.** Found the hard way: Go tests, the cchook tests (which run the real built `bapedge`), the Python suite and the pilot runner all used the developer's real state directory, and the pilot's throwaway control plane shared the repo-root signing key and killed every `bapcontrolplane.exe`. On an enrolled machine this pinned a throwaway key / rewrote signed rules and locked the workstation out (fail-closed working as designed). Delivered: `TestMain` isolation (temp `BAP_STATE_DIR` and home) in `config`, `policystore`, `authz` (`cmd` already had it); `cchook` test setup uses a temp state dir; `tests/conftest.py` gives the whole Python suite a temp state dir (opt out with `BAP_TEST_REAL_STATE=1`); `scripts/run_pilot.ps1` runs its control plane and gateway on their own ports (18080/19090) in their own working directory with their own db and key, uses an isolated state dir for the feature and Python stages, reads the real installation only for the read-only plugin/doctor stage, and stops only processes it started. *Accept:* a full test/pilot run leaves the real policy store's pin, policy and schema byte-identical (only `last_sync` may move); verified for the Go and cchook suites on 2026-11-13.

*BAP-1068 addendum (2026-11-13, from the third pilot run):* (1) the runner leaked `BAP_ENVIRONMENT=production` (set for stage-3 enforcement checks) into the control plane it started for the Python server tests, which then ran in PRODUCTION mode (confirmed in its log) and rejected the integration flows; the runner now starts that control plane in `development` and restores the caller's environment for stage 5. (2) `tests/test_e2e_fortified_identities_and_launchers.py` tore down with a global `taskkill /IM bapcontrolplane.exe`, killing every control plane on the machine including the developer's real one; it now only stops control planes started from its own temp tree. (3) the OIDC federation tests now keep each control plane's output, wait up to 30 s and report the exit code and log tail instead of "failed to start". (4) the runner recreates `.bap\pilot` before writing its report (`bapedge sweep` deletes it). Two further failures in that run (`test_bounded_authority_matrix::test_04…`, `test_supervisor_runtime_e2e`) pass when run alone and are treated as load-sensitive until they recur.

**BAP-1069 (M, DELIVERED as part of 1060, found in live use) Signed record must survive older builds.** Older `bapedge` builds rewrite `policy-state.json` with a struct that has no signature fields, so a mixed-version machine failed verification forever. The signed bundle now lives in its own file `policy-signed.json` and is authoritative on managed machines; the legacy file only supplies `last_sync` and cannot loosen signed rules. Also: the control plane no longer downgrades a machine's hardware asset binding when an older client re-enrolls without a hardware id; the asset-mismatch error now tells the user to run `bap login`; OIDC login syncs signed policy immediately after pinning; the browser device-login form no longer fails with "browser origin not allowed" (`Referrer-Policy: same-origin` plus a `Sec-Fetch-Site`-verified acceptance of `Origin: null`). *Accept:* unit tests for each; live: `bapedge sync` after install writes `policy-signed.json` and `bapedge status` stays healthy.

**BAP-1071 (M, PARTLY DELIVERED) Hosted control plane (Render) deployment requirements.** The real control plane runs on Render in production mode with an ephemeral disk; machines enroll through OIDC or an admin-minted OTC. Everything signed-policy depends on state that a redeploy destroys: the signing key (clients pin it and refuse a different one), `policy-settings.json` (admin overrides, enrolled asset bindings, version counter) and the in-memory registry. Delivered at the time, since superseded (startup no longer seeds versions from the wall clock; authority is persisted and BAP-1089 lets the live server move versions in either direction): the policy version is floored at the wall clock at startup, so a redeploy can never move it below what clients hold (unit-tested); enrolled assets re-bind themselves on the next authenticated sync because clients report their hardware id; a startup warning when a hosted environment runs without `BAP_POLICY_SIGNING_SEED`. **Required operator action before deploying this release:** set `BAP_POLICY_SIGNING_SEED` (64 hex chars, a Render secret) so the key survives redeploys, and set `BAP_POLICY_SYNC_REQUIRE_AUTH=1` so only enrolled machines receive policy. Still open: per-asset admin overrides are lost on redeploy without a persistent disk or database (machines fall back to the fleet default), registry persistence (BAP-1070), and an admin API to read the key id the fleet is pinned to. *Accept:* two consecutive redeploys with the seed set leave every enrolled machine syncing with no re-enrollment, and a redeploy without the seed is blocked or loudly refused.

**BAP-1070 (M, OPEN) Control plane persistence of enrollments.** The control plane keeps registered workstations in memory; after a restart every machine reports "Enrollment out of sync" and must re-enroll (auto-remediation works, but it rotates identities and, with old clients, silently re-binds assets). Persist the registry (SQLite is already used for sessions), including enrolled asset bindings. Also decide one canonical location for the control plane's signing key and database so starting it from a different folder cannot generate a second key. *Accept:* restart with no re-enrollment and no key change.

**BAP-1072 (L, DELIVERED) Policy recommendations: a registered machine recommends a blocked-but-benign call; an administrator approves it into that machine's signed policy.** `bap recommend` (and `bap review recommend`) lists recent grant-blocked calls grouped by canonical effect, shows the detail, and submits the effect with a justification using the enrolled workstation credential. The control plane queues it (deduplicated, 25 pending per machine, redacted command hint); an administrator approves or rejects through `/api/v1/admin/policy/recommendations`; an approval adds the effect to that machine's Ed25519-signed bundle (new `approved_effects` line in the signed payload, emitted only when non-empty so every other machine signs exactly as before). Only the local development loop is approvable; network, deletion, push, publish, install, databases, arbitrary interpreters and credentials are refused by the control plane and ignored by the edge. An approval relaxes only the task-grant requirement, only inside the workspace, and a command mixing approved and unapproved effects still needs a grant; Cedar invariants are untouched. Not an open API: submit and list require a valid enrolled-workstation credential. **Verified:** control plane and edge unit tests (signature covers the approval list, tampering with or stripping it fails closed, per-machine isolation, restart persistence, dangerous effects refused with 422); an isolated end-to-end run against a throwaway control plane passed 14 of 14 checks (blocked, recommend, admin approve, sync, runs without a grant; unapproved effect, network, credential file and mixed commands still blocked; unregistered caller refused with 401). That end-to-end script is not yet part of CI. Docs: `docs/POLICY_RECOMMENDATIONS.md`, `docs/CLI_REFERENCE.md` (the former ARCHITECTURE section 17 was removed in the 1.13.16 rewrite; see ARCHITECTURE section 5 for policy ownership and distribution).

**BAP-1073 (M, DELIVERED) `bapedge watch` must not leave or duplicate processes.** Root causes found from live stale processes: no single-instance guard (duplicate watchers shared one liveness file and each exit removed it, so hooks started another); the watcher only exited when its target PID died, so a watcher attached to a long-lived terminal or desktop app outlived SessionEnd forever; and it re-created its own liveness file after the session ended. Fixed with a per-session lock (PID plus mtime, stale takeover), exit when the session marker is removed (SessionEnd or `bapedge sweep`), and no liveness resurrection. **Verified:** `tests/test_bapedge_process_lifecycle.py` starts real watchers in an isolated home and fails if any process survives; 4 of 4 pass on the fixed build, and against the previous build 3 of 4 fail exactly as reported (negative control). Open: a pytest-started integration control plane (port 18882) was found still running after its test; harden that fixture's teardown.


**BAP-1074 (M, OPEN) Recommendation review and friction analytics. Dashboard queue for recommendations;** fleet-wide approvals behind a client-version gate (an older client cannot verify a payload with approvals); the company policy matrix (BAP-1067); a fleet denial funnel per effect and zone (denials, approvals, approval rate, developers affected); and an evasion signal (a denial followed by a retry through another shell, encoding or rename within a short window) so that failures are classed as friction to remove or as suspicious.


**BAP-1075 (S, DELIVERED, items open) Repository prune, documentation refresh and CI review.** Tracked binaries, backups, scratch output, an archived-docs tree and duplicate or stale planning documents were removed (`scripts/prune_repo.ps1`; history keeps everything). Dead links fixed; `check_capability_claims.py` no longer lists a deleted document and now also covers the new docs. README status sample corrected to the real `NOT_OBSERVED` output; ARCHITECTURE gained a layer-guarantee table and section 17 (both replaced by the shorter 1.13.16 rewrite); blog updated; `docs/CLI_REFERENCE.md` separates user commands from internal-developer-only tooling. CI: least-privilege token and PR-only run cancellation added; `|| true` removed from release builds so a missing hook binary can no longer ship silently. Remaining CI findings are BAP-1086.

**BAP-1076 (M, DELIVERED, found in live use) The credential screen blocked ordinary work and ended the agent's turn.** The hook rejected any command or path containing the substrings .env, .aws, .ssh or id_rsa. It stopped a backlog edit whose prose merely mentioned a credential file, and would equally stop process.env, .environment, commit messages and documentation; each false positive halted the agent's whole turn, which for Node and Python developers would happen daily. Replaced in the hook and the plugin path by a path-aware rule: a path is a credential store by its basename or a directory segment (.env, .env.*, .envrc, .ssh, .aws, .gnupg, id_* private keys; template files such as .env.example and public keys are not); free text (here-strings, heredocs, long quoted sentences) is data and is ignored, unless an interpreter consumes it as code or the command runs inline code (python -c, node -e, iex and similar), in which case everything is scanned as before. A second defect was found while writing this entry: the inline-code markers were looked for before the prose was removed, so an entry that merely described those markers blocked itself; markers are now looked for only in what remains after the prose is removed. The resolved-path checks (ZSP resource resolution, Cedar secret-disclosure rule, sandbox credential mounts) are independent and unchanged. **Verified:** shared golden vectors in `cchook/credential_refs_test.go` and `bap-edge/internal/authz/credential_refs_test.go` (including prose that mentions iex and python -c, interpreter heredocs and real iex use); the full `cchook` suite and the `bap-edge` authz suite pass; an old-versus-fixed hook comparison on 11 cases; and the exact text of this entry, written through the same command route that the earlier build refused.

**BAP-1077 (L, OPEN, pilot blocker) The broker kills any command that runs longer than 120 seconds.** Builds, package installs and test suites routinely exceed that and are terminated ("Process Terminated by Resource Quota"), losing the developer's work. Needs a configurable limit, a sane default, and streaming or detached execution for long-running commands.

**BAP-1078 (S, OPEN, security) `bap recommend` must be human-only.** Today an AI agent can run it with `--yes` and a persuasive justification that is then shown to the administrator. Require an interactive terminal for submission, remove `--yes` for agent sessions, and make the hook refuse agent invocation (as for the other human-only commands in BAP-934).

**BAP-1079 (L, OPEN, pilot blocker) Control plane durability beyond a database.** On an ephemeral disk a redeploy without a stable signing seed changes the policy key, every enrolled machine fails closed and each developer must sign in again; the policy version counter is seeded from the wall clock, so a single wrong clock reading can strand the fleet permanently (clients refuse any lower version); the enrolled-machine registry, per-machine settings, recommendations and approvals are lost on redeploy (BAP-1070). Needs a persistent counter, a startup refusal when a hosted control plane has no stable seed, and persistent storage.

**BAP-1080 (M, OPEN, pilot blocker) Lockout recovery and staged rollout.** Fail-closed integrity checks locked the developer out several times in live use (test pollution of real state, an older build dropping signature fields, an asset mismatch after a control plane restart). With a mixed-version fleet a few machines will brick in the first week. Needs a documented break-glass path, a version gate in the control plane, and a one-command self-heal that does not require re-enrollment when the cause is local.

**BAP-1081 (M, OPEN, pilot blocker) Measure real grant friction and per-decision latency.** Probes with the override off show file edits, builds, tests and commits need grants, but the rate in real agent sessions is unmeasured; each decision took roughly one to two seconds in probes (partly nested-broker overhead). Instrument grants and denials per developer-hour by effect, measure p50/p95 decision latency on a clean machine against a target under 100 ms, and feed the BAP-1074 funnel.

**BAP-1082 (M, POSTPONED by decision) Administrator identity.** Administration uses one shared bearer token, so approvals are recorded as "admin" with no individual identity or separation of duties, and the hosted API is reachable from the internet once remote admin is enabled. A shared token is accepted for the pilot; implementation is deferred. Future: administrator sign-in through the enterprise identity provider with roles, per-admin audit identity, and token lockout.

**BAP-1083 (M, OPEN) Workstation credential proof of possession.** The workstation credential is a bearer token in a user-readable file, so a stolen file impersonates the machine for policy sync, recommendations and audit ingest. Bind it to a device-held key.

**BAP-1084 (M, OPEN) Audit and telemetry privacy.** Audit entries carry the full command and the user prompt to the control plane, while the FAQ promises zero code exfiltration. Verify exactly what leaves the machine, redact secrets and long free text before transmission, and make the documentation match.

**BAP-1085 (S, OPEN) Hook binary version skew.** Three hook layers (user-level hook, project-level hook, plugin adapter) run on every tool call and the most restrictive wins; a stale copy once denied what the current build allowed. `bapedge doctor` should compare versions and hashes of every installed copy, and the build scripts should fail when copies differ.

**BAP-1086 (M, OPEN) CI and release hygiene.** `ci.yml` publishes to PyPI on every push to main while `release.yml` also publishes on tags (keep one, gated on the tests); the release workflow does not wait for the test jobs; `bap-controlplane/go.mod` requires Go 1.27 while CI installs 1.24 (it only works through automatic toolchain download); the dashboard Node suites run on all three OS runners; actions are pinned by tag rather than commit; there is no lint, vulnerability or secret scan; the Python suites run only on Windows.

**BAP-1087 (S, OPEN) Offline machines never receive a kill switch or revocation, and nothing caps how stale signed rules may be.** Add a configurable maximum age after which an unreachable machine degrades to a stricter tier, and report stale machines in the dashboard.

**BAP-1088 (L, OPEN) Enforcement parity outside Windows.** Landlock is not implemented, eBPF is simulation only and Seatbelt is unverified, so macOS and Linux pilot users have weaker guarantees than Windows users; the pilot runner and Python suites are Windows-only. Decide the pilot platform scope, document it, and close the gap or exclude those platforms.

### Cross-cutting

**BAP-1030 (M) Escape red-team harness.** Real escape attempts run inside each native provider in CI: read outside the workspace, raw network, encoded and chained commands, symlink and hardlink tricks, git hooks, environment harvesting, process spawning. *Accept:* 100% of prohibited effects are blocked by the sandbox with the hook disabled, without admin rights, Docker or WSL. A skipped or rendering-only test is not acceptance. Any new escape found becomes a permanent case.

## 7. Plan

*Historical (written 2026-11-13). The week-by-week schedule below was not kept; current sequencing is in `docs/PRODUCT_READINESS_REVIEW_2026-11-13.md` and `docs/PRODUCT_REVIEW_2026-11-14.md`. The status tables that follow predate 1.13.15; where a pilot-hardening bullet at the top of this file disagrees, the top bullet wins.*

- **Weeks 1-2:** Milestone 0. Ship a trustworthy baseline, fix CI, correct the claims, make telemetry arrive. In parallel start BAP-1040/1041/1042: they need only data BAP already records, and they stop the hand-fixing loop early.
- **Weeks 2-4:** BAP-1010, BAP-1011 (container provider), BAP-1030, BAP-1031.
- **Weeks 4-6:** BAP-1012, BAP-1013, BAP-1014, BAP-1015.
- **Weeks 6-9:** BAP-1043 to 1049 (profile generator, proposals, inbox, safety rails, KPIs), which need the sandbox and proxy traces from Milestone 1.
- **After:** Milestone 2.

### Implementation status (honest)

Legend: **Verified** = unit-tested here. **Spec only** = generated config is tested, real execution was not run here.

| Story | Status | What exists | What is NOT proven |
|---|---|---|---|
| BAP-1001 release gate | Expanded, actual compiler regressions verified | CI includes all five Go modules, Python and Node; capability-claim lint; official wheel clients always compile with developer override disabled, build failures stop packaging, newer development copies cannot win by mtime; current-wheel tests require all five client targets and shared report scripts, and cannot skip for missing artifacts in CI | Installed `doctor --e2e` and remote required-check configuration remain open |
| BAP-1003 truthful claims | Implemented and tested | Machine-readable capability matrix; README, architecture and pilot/demo claims qualified; CI lint and seeded false-claim tests | Matrix changes still require an actual native verification result |
| BAP-1004 telemetry | Partial, regression verified | Serialized in-process spool flushes; acknowledged-removal errors surfaced; 20-action plus concurrent-append regression | Cockpit backlog warning, separate-process coordination and full 10-second edge-to-cockpit proof |
| BAP-1005 calls report parity | Implemented and tested on Windows | Three entry points share one packaged implementation; the same fixture is tested by PowerShell/Python and the Go cockpit summarizer; limited/failed/unknown outcomes handled; installers include shared files | Native PowerShell execution on other OSes is not verified here |
| BAP-1006 developer bootstrap | Implemented, automated checks pass; developer confirmation pending | Broker/plugin/hook grant checks and grant guidance skip a valid override, with marker discovery parity and production/release/expiry tests | The developer's newly installed broker/hook copies still require manual confirmation |
| BAP-1007 V3 admin operations | Implemented and tested | Native V3 policy studio and HITL inbox; authenticated decisions and historical simulation; deployment validation, version precondition, signed freeze versions; error/demo/logout tests | Individual SSO reviewer identity and edge-local ZSP request synchronization |
| BAP-1022 approval inbox | Partial (BAP-1007) | Control-plane request review and audited approve/deny | Signed edge transport, local TaskGrant minting/resume, restart persistence, notification and pending-request expiry |
| BAP-1010 capability model | Conversion and spec implemented; runner binding pending | `internal/capability`: Profile plus effect-level Set; typed TaskGrant conversion preserves read/write/delete modes, exact DNS host/port, TTL and granted scope; burned/expired/exhausted grants and unsupported command grants fail closed; `docs/CAPABILITY_MODEL.md` | Signature/session verification remains the caller's responsibility. Set is not yet the active runner authority; a read-only Set is deliberately not widened into the current workspace-rw Profile |
| BAP-1011 `bap run` (+ BAP-1031 Windows decision: **AppContainer**) | **Windows: verified end to end, no admin, no Docker, no WSL.** Linux/macOS: spec only | Constraint set by the user: all three OSes, no admin, no Docker. Windows runs the command in an AppContainer (`internal/appcontainer`): measured on Windows 11 as a standard user, a contained process can write the workspace, cannot read a file outside it, cannot open a TCP connection to the host (even loopback), and reaches the BAP proxy only through a unix socket via the in-sandbox relay; a request to a non-allowlisted host gets the 403 with the next step and is recorded as an effect event (`TestBapRunAppContainerEndToEnd`, `TestAppContainerBoundaryWithoutAdmin`). macOS = Seatbelt (`sandbox-exec`, ships with the OS, unprivileged); Linux = bubblewrap. Docker is no longer a default or a dependency. Refuses to run unsandboxed if a provider is missing | macOS Seatbelt and Linux bubblewrap were never executed here. Linux where unprivileged user namespaces are disabled (e.g. hardened Ubuntu) needs a Landlock fallback (not written). AppContainer grants persist as ACLs on the workspace (removable). Tools installed under the user profile need `read_only` entries. Running `bap run` for the whole agent session (not just one command) and making `bap run claude` the entry point is the next step |
| BAP-1012 egress proxy | Verified (proxy + unix-socket relay path), wired for bwrap only: `bap run` serves the proxy on a 0600 unix socket, binds only that socket into a network-less bubblewrap sandbox, and runs the command under `bap __shim` (loopback:3128 relay + HTTP(S)_PROXY). The relay-to-proxy policy path is tested end to end; bwrap itself was not run (no Linux here). Docker is still unwired | `internal/egress`: allowlist by destination (HTTP + CONNECT), cloud-metadata always blocked, private/loopback addresses refused at dial time (SSRF/DNS rebinding), live allowlist swap, every decision logged | It is only the sole path if the sandbox network is closed (needs the BAP-1011 plumbing). `bap egress serve` runs it standalone; no TLS inspection by design |
| BAP-1013 denial-driven approval | Partial | Denials carry the exact next step (`bap egress allow HOST`); a live `Approve` hook exists and records human evidence | Wiring `Approve` to the HITL request queue |
| BAP-1014 credentials by construction | Partial, tested | Native launcher environment is explicitly allowlisted; direct credential read-only mounts and existing credential symlink aliases are refused; macOS rendered relay rules no longer allow arbitrary loopback ports | Native provider acceptance, comprehensive masking of credentials within writable workspaces and broker-side token injection |
| BAP-1040 effect events | Partial, verified | Project/agent/session/mode/grant/decision/correlation schema; proxy observations and broker canonical-decision projections; no prompt field; optional tenant-keyed target HMAC; durable JSONL append and 20-event round trip; project-scoped `bap learn report` | Independent hook/HITL producers, native fs/exec observations, control-plane effect ingestion and cockpit integration |
| BAP-1041 complain mode | Package mechanism tested; not yet active rollout | Exact rule/project evaluator, immutable-deny protection, positive observed soak requirement and promotion refusal on friction | Persisted operator configuration, boundary wiring and cockpit promotion |
| BAP-1042 miner and prediction auditor | Partial, verified | Exact host/port proposals; correlated prediction audit requires a completed boundary trace and never treats missing telemetry as a false positive; five classifier-failure-shaped fixtures tested | Actual completed native trace producers and real recorded false-positive replay |
| BAP-1043 profile generator | Recommendation implemented and tested | `bap learn profile`: three observed sessions, exact read-only external paths and DNS host/ports, human review required, no automatic writes or generalization; forbidden targets excluded | Native filesystem observations and fresh real-agent acceptance under the generated profile |
| BAP-1044 proposals + replay | Partial, verified | Replay of a proposal over history; refuses proposals that open immutable targets | Signed-policy diffs, auto-generated regression cases |
| BAP-1045 inbox | Partial | `bap learn` lists, `bap learn apply HOST` applies (human-only: agents are blocked by the hook gate) | Cockpit UI, canary, rollback |
| BAP-1046 safety rails | Strengthened, tested; remote identity incomplete | Agent-only activity never produces a proposal, including 500 retries; two distinct attributed human decisions required; repeated decision IDs ignored; identified agent contributions capped; exact destination ports retained; forged wildcard/raw-IP proposals rejected; operator approval intent persisted before profile mutation | Individual SSO and signed remote evidence verification; the miner expects protected local producer records, not untrusted source labels |
| BAP-1060 policy signing + pin | Implemented and unit-tested (control plane and edge) | Ed25519 key generated/persisted on first start; per-asset signed bundles covering every enforcement field, kill switch included; pubkey endpoint; TOFU pin on first sync; verification on accept and on every read of the cached state; golden-vector test shared across modules; different key refused | Not yet exercised against a live control plane and installed clients; pin currently comes from an unauthenticated endpoint (BAP-1065); no rotation (BAP-1066) |
| BAP-1061 asset identity | Implemented and tested | Hardware-derived id (Windows registry MachineGuid, machine-id, IOPlatformUUID), `BAP_ASSET_ID` override; independent of `USERNAME` | Linux/macOS providers compiled only, not run here |
| BAP-1062 read-exempt setting + admin API | Implemented and tested | Fleet default and per-asset overrides, admin-token API with audit, persistence of settings and monotonic version across restart; client reads the verified signed value; tampered or unverifiable state exempts nothing | Cockpit UI for the setting; installed-copy confirmation by the developer |
| BAP-1063 seconds sync | Implemented, unit-tested | `RunSyncLoop` in `bapedge watch` (3 s), `RefreshIfStale` (5 s) in the decision path, offline keeps last signed rules | Measured end-to-end latency with real clients; long-poll/push not implemented (polling) |
| BAP-1064 fail closed on tamper | Implemented, unit-tested | Managed machines never fall back to local policy files; flag/state/policy/pin tampering detected; `bapedge exec` denies, watcher waits via `WaitForTrustedPolicy`; self-heal when reachable | The pin file itself and an attacker with the same OS privileges as `bapedge` (needs OS ACLs/FIM); deleting both pin and state returns the machine to unmanaged until the next successful sync |
| BAP-1065 enrollment-bound trust | Implemented, unit-tested (control plane API and edge store) | OTC register and OIDC device-token responses carry `policy_key_id`, `policy_public_key` and the bound asset id; `bap install`/`bap login`/register pin them; `policy/sync` is authenticated with the enrolled credential and the asset comes from the verified credential, not the body; invalid credentials get 401; anonymous callers get the fleet default and never overrides; `BAP_POLICY_SYNC_REQUIRE_AUTH=1` refuses anonymous sync; admin settings list shows enrolled asset ids; legacy first-contact pins upgrade on the first authenticated sync | Not run against a live control plane and installed clients; revoked/logged-out workstation path relies on the existing `workstationIdentity` checks and has no dedicated policy-sync test; the first-contact pubkey endpoint remains for machines enrolled before this change |
| BAP-1066 key rotation/recovery | Implemented, unit-tested | Rotation chain, admin rotate endpoint, env-seed rotation, persistence, client auto-follow, re-enrollment re-pin, forged/unchained rotations rejected | Live rotation across real clients; hosted deployment not exercised; Linux/macOS not run |
| BAP-1067 policy matrix | First slice delivered, matrix itself not started | Delivered 2026-11-13: plain local reads need no task grant, both for native tools (`Read`/`Glob`/`Grep`/listing) and for shell commands whose every effect is a local read inside the workspace (`dir`, `ls`, `cat <project file>`, `git status/log/show/diff`, read pipelines). Conservative: output redirection, `git branch`, credential stores, filesystem roots, anything outside the workspace and any mixed command still need a grant. Controlled by the control plane's signed `zsp_read_exempt` (fleet and per asset) and the local `BAP_ZSP_STRICT_READS=1` escape hatch. Found because a shell `dir` on a project log folder was refused while the same read through a native tool was allowed | Existing building blocks: signed per-asset bundles, per-effect classification in the grant check, `zsp_read_exempt` as the first setting | Everything else |
| BAP-1049 loop KPIs | CLI subset implemented | Project-scoped recorded event/session/denial/approval/would-deny/mismatch counts in `bap learn report` | Developer-hour denominators, proposal-vs-code fix rate, resolution latency and cockpit display |
| BAP-1090 command batch authorization | Implemented and verified | Reuses suitable grants or mints single-use envelope for safe routine batches; 30s TTL; exact hash/workspace/session binding; tests in `internal/authz` and `cchook` | Cross-platform execution under non-Windows runners |
| BAP-1091 multi-agent ZSP grant visibility & UI | Implemented and verified | Extended `TaskGrant` with `DelegationType` and `ClientType`; `bapedge zsp status --all` and `zsp grants`; STS token API and session transcript aggregation; Cockpit UI conversation drawer and OBO tabs; `Show-BapStory.ps1` and `DEMO_5_MINUTE_STORY.md` Scene 1 multi-agent coverage (Antigravity, Codex, Claude) | Remote cloud WebSocket push to UI (currently poll-backed) |
| BAP-1092 safe global binary deployment | Implemented and verified | `Deploy-BinarySafe` in `scripts/install_bap_global.ps1` with in-use rotation (`.old`); `bap.exe` synchronization; legacy Python Scripts path syncing; index-0 PATH precedence; root `install_bap_global.bat` | Non-Windows packaging into system package managers (deb/rpm) |

Still requiring implementation or full acceptance: BAP-1001/1002/1004, 1010..1015, 1020..1024, 1030, 1040..1049, 1067 (not started), and live verification of 1060..1066 as qualified above. BAP-1031's Windows AppContainer choice and proof already exist; it is not an unstarted decision. BAP-1048 remains optional. Do not close the full roadmap from package-level or rendering tests. See `docs/CAPABILITY_MODEL.md` and `docs/LEARNING_LOOP.md` for command behavior and remaining integrations.

### Verification recorded 2026-11-13 (later: pilot, override and signed-policy work)

- Pilot runner `scripts/run_pilot.ps1` (unattended, writes `.bap/pilot/report-*.md`): Quick run 22 of 23 checks green; the one failure was a real audit hash-chain fork (two interceptor copies appending concurrently), fixed with a cross-process lock in `audit.Log`; the historic fork in the old log remains and must be archived by a human. Full run: Go suites, servers, features, plugins green; Python 313 passed, remaining failures traced to the runner (control plane killed by another test, fixed by a two-phase run) and a stale 1.12.22 wheel.
- Developer override: now also pre-approves cross-folder step-up (credentials, filesystem roots, home and system directories excluded); Python denial tests made hermetic; MCP status test updated for the 5-layer model string.
- Read-only inspection exempt from task grants (BAP-1062), then moved under control-plane ownership. Edge `cmd`, `authz`, `policystore`, `config`, audit and the full native-hook suites pass; control-plane `policy` and `api` suites pass (new: signer, asset-scoped bundles, settings API, restart persistence).
- Not yet verified: any of the above against rebuilt, installed binaries and a live control plane.

- Windows: full Go suites passed for edge, control plane, native hook, gateway and Copilot. The final affected capability/learning/command packages were rerun after their last changes.
- All four dashboard Node suites passed, including policy administration and HITL state/payload/race coverage.
- An isolated workspace with freshly built broker/hook/control-plane/gateway artifacts passed **all 300 Python tests, with no skips**, including the actual universal-wheel checks. `BAP_REQUIRE_WHEEL_TESTS=1` was enabled. Lifecycle fixtures never ran their destructive cleanup against the live checkout.
- The official universal wheel built ten edge/hook clients for Windows amd64, Linux amd64/arm64 and macOS amd64/arm64. A real-compiler regression first reproduced developer override incorrectly enabled in packaged clients, then passed with the corrected release builder; compiler errors and newer development copies are also covered.
- Linux/macOS edge command, sandbox, authz and native-hook test binaries cross-compiled successfully. This is **not native execution**, race verification or native escape-suite acceptance.
- Capability-claim lint and `git diff --check` passed. Installed-copy developer confirmation, live browser-to-edge approval resume and the unfinished stories above remain open.

**Risks.** Windows containment is the hardest piece (BAP-1031 first). Live filesystem approvals are limited by what each provider can remount. The agent vendors' own sandboxes may overlap; decide per agent whether BAP configures or replaces them.

## 8. Old work: what happened to it

**Closed as superseded by ADR-001 (not to be built):** old BAP-922 command packs, BAP-923 effect tagging from command text, BAP-927 interpreter containment by parsing, BAP-928 shadow-mode migration of the decomposer, BAP-929 planner unification, Epic 12 (eBPF/Landlock simulation).

**Delivered and kept (history, covered by tests):** escalation core (old BAP-925/926 core), commit/trust/HITL/anti-spin fixes (old BAP-932, 933, 934, 936, 937), prescriptive refusals, signed policy override, de-duplicated calls summary (old BAP-931 control-plane part).

**Everything else** from the old backlog is in the archive file. Nothing in it is a commitment.

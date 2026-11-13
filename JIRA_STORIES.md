# BAP Backlog: Course Correction (2026-11-13)

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

**BAP-1070 (M, OPEN) Control plane persistence of enrollments.** The control plane keeps registered workstations in memory; after a restart every machine reports "Enrollment out of sync" and must re-enroll (auto-remediation works, but it rotates identities and, with old clients, silently re-binds assets). Persist the registry (SQLite is already used for sessions), including enrolled asset bindings. Also decide one canonical location for the control plane's signing key and database so starting it from a different folder cannot generate a second key. *Accept:* restart with no re-enrollment and no key change.

### Cross-cutting

**BAP-1030 (M) Escape red-team harness.** Real escape attempts run inside each native provider in CI: read outside the workspace, raw network, encoded and chained commands, symlink and hardlink tricks, git hooks, environment harvesting, process spawning. *Accept:* 100% of prohibited effects are blocked by the sandbox with the hook disabled, without admin rights, Docker or WSL. A skipped or rendering-only test is not acceptance. Any new escape found becomes a permanent case.

## 7. Plan

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

# BAP Permission Policy (BAP-924 / BAP-925 / BAP-926)

How a request for permissions becomes a grant. Tool knowledge and risk decisions live in **data**
(`bap-edge/internal/authz/default_permission_policy.json`, optionally replaced by a signed
administrator override), not in Go `switch` statements. Hard safety invariants stay in code and are
never relaxable by policy.

## The model (AWS-style: ask, policy approves)

```
agent: bapedge zsp authorize --actions <catalog actions> --resources <scopes>
        |
        v  1. non-reliance + hard invariants (code)      policy:/grant:/admin:/iam:/sudo: always need a human
        v  2. wildcard handling (policy data)            repo:* -> repo:read ; every other wildcard rejected
        v  3. resource wildcard narrowing (policy data)  "/*", "repo://*", "workspace://*" -> workspace://current
        v  4. per (action, resource) decision (policy)   allow | approve | deny   (most restrictive rule wins)
        v  5. ceiling clamp (policy)                     max uses / TTL clamped, mint cap per session
        v  6. grant signed with the PEP secret (HMAC)
```

| Tier | Meaning |
|---|---|
| `allow` | auto-minted, no human |
| `approve` | minted only with verified human approval (one-time terminal challenge, see below) |
| `deny` | never grantable, **not even with human approval** (credential access, secrets) |

Unknown actions fall to `default_tier` (`approve` or `deny`; `allow` is rejected at load time).

## Automatic command-batch authorization

Recognized routine command batches can request their own exact, single-use grant
inside the broker after Cedar/invariant checks. Every actual effect must be allowed
by policy; push or another approval-required effect is never added automatically.
Existing suitable grants are reused. Automatic grants expire within 30 seconds and
bind the command text, workspace, session/principal, and permission-policy version.
The hook precheck does not consume the grant; broker execution checks all operations
and consumes one use atomically for the whole invocation.

For example, `git status; git log --oneline -n 10` can proceed without an agent
authorization round trip. A grant for `git:status` cannot authorize `git push`, either
alone or appended to status. See [command-batch authorization](COMMAND_BATCH_AUTHORIZATION.md)
for the scope-check walkthrough, conservative syntax limits, strict-mode settings,
revocation semantics, and regression-test interpretation. Policy tiers and ceilings
continue to apply; automation does not convert `approve` or `deny` into `allow`.

## Rule semantics

* `match`: `path.Match` globs over the lower-cased action. `:` is an ordinary character, so
  `cli:*:exec` matches `cli:python:exec`.
* A rule **without** `resource_match` applies to in-workspace resources only (`boundary_prefixes`),
  unless `"scope": "any"`. So `git:status` on `workspace://current` is allowed, but `git:status` on
  `system://local` hits the default tier and needs approval: an agent can no longer widen its own
  boundary by re-requesting with a bigger `--resources`.
* A rule **with** `resource_match` applies only to resources matching one of those globs
  (destination-aware rules).
* **Most restrictive matching rule wins** (`deny` > `approve` > `allow`). Therefore a broad
  "network needs approval" rule would beat a narrower "this host is fine" rule. Write exceptions so
  the broad rule does not also match them, for example approve only the mutating methods and
  allow-list reads:

```json
{ "id": "net-reference-get", "tier": "allow",   "match": ["http:get"],
  "resource_match": ["https://www.cnn.com/*"] },
{ "id": "net-writes",        "tier": "approve", "scope": "any",
  "match": ["http:post", "http:put", "http:patch", "http:delete"] }
```

  GET to the allow-listed host runs without a prompt; POST/upload anywhere, and GET to unknown hosts,
  still require a human. (The shipped default allow-lists no hosts: `http:*` needs approval until an
  administrator adds destinations. Note the *execution-time* Cedar rules and gateway PEP still gate
  raw `curl`; aligning them is BAP-924 follow-up work.)
* `ceiling`: `max_uses_per_grant`, `max_ttl_seconds` (requests are clamped, reported as narrowing)
  and `max_mints_per_session` (hard stop, `ErrMintCapExceeded`). The top-level values are the
  **default class: single-use, 300 s** (BAP-1102). Optional `classes` carve out bounded exceptions:

  | class | actions | max uses | max TTL |
  |---|---|---|---|
  | default (`single_use`) | everything else: exec, interpreters, network, publish, delete, packages | 1 | 300 s |
  | `inspection` | `git:status/log/diff/show/branch`, `fs:file:read`, `fs:dir:read`, ... | 10 | 300 s |
  | `workspace_edit` | `fs:file:write`, `fs:file:edit`, `fs:write` on `workspace://current` only | 25 | 600 s |

  A grant that mixes classes gets the **strictest** limits (an edit plus a push is single-use), a
  class with `resource_match` never applies outside it, and an override without `classes` keeps
  working (its grants are labelled `multi_use`). Each grant records its `grant_class`, and every use
  still produces its own lineage proof. A multi-use edit grant limits time and blast radius; it does
  not narrow *which* workspace files may be written (path-scoped edit grants are follow-up work).
  Auto-approve (BAP-1100) never raises a ceiling.

* `no_auto_approve` on an approve-tier rule (BAP-1104) means step-up auto-approve can never satisfy it.
  The default policy sets it on `approve-destructive-and-admin` (push, delete, drop, admin) and
  `approve-network-egress`, so those always need a real human even while auto-approve is on. A mixed
  ask is refused as a whole.
* `..` anywhere in a resource is never considered in-boundary.

## Overriding the policy (human operator only)

```bash
bapedge zsp policy-sign --file my-policy.json
```

Validates the document (strict: unknown fields, bad patterns, `allow` default and wildcard narrowings
to wildcards are all rejected), copies it to `<zsp dir>/permission-policy.json` and writes an HMAC
signature with the workstation PEP secret. At every mint the override is verified; a missing or
invalid signature is a **hard error** (minting stops), never a silent fallback to the default.
`policy-sign` refuses to run inside an agent session (`BAP_IN_BROKER`, or any agent-identifying
environment).

## Human approval

`approve`-tier asks (and `--oob-approve`) now require a **real terminal on stdin and stderr** and a
freshly generated one-time code that the human reads from the terminal and retypes. A flag, a piped
`y`, a redirected stdin or a script cannot satisfy it. It never runs inside the agent broker.

Known limits (tracked in BAP-926): an agent that allocates its own pseudo-terminal and reads it back
could still answer; the approval proof is not yet a signature from a separate human-held key; the
pepper file is protected by OS file permissions and location (`~/bin/.bapstate/zsp`, BAP-920), not by a
separate trust boundary. The workspace-local `.bapstate\zsp\pepper.key` seen in older checkouts is a
legacy copy and should be deleted and the live pepper rotated.

## Repeated refusals: warning, halting, and what is not limited

An agent that is refused will often retry the same request in a loop. BAP answers every
refusal immediately and never waits for input. Two mechanisms react to repetition. Neither is a
general rate limiter, and neither changes policy. Source: `bap-edge/internal/authz/denial_breaker.go`
(BAP-936).

### Anti-spin circuit breaker (identical refusals)

| Identical refusals in 5 minutes | What the agent sees |
|---|---|
| 1-2 | Normal refusal with the next step |
| 3-4 | The guidance starts with an explicit `STOP: BAP has refused this exact request N times` notice |
| 5 or more | The agent turn is **halted**: the hook returns `continue:false` with a stop reason telling the developer a human decision is needed |

* The count is per **session** and per **identical** refusal, over a rolling 5-minute window. The
  window is `denialWindow`; the thresholds are `DenialWarnAfter = 3` and `DenialHaltAfter = 5`.
  Entries older than the window are dropped the next time a refusal is recorded.
* "Identical" means the same key. For `zsp authorize` it is the sorted actions and resources. For a
  ZSP refusal in the hook/plugin path it is the refusal text, the command, the tool name and the
  file path, lower-cased and hashed.
* From the halt threshold, a repeated `zsp authorize` for the same actions and resources is not
  submitted again at all. The agent gets a refusal that points to `bapedge zsp approvals`.
* Counters are local files under the ZSP state directory (`denials/<session>.json`, mode 0600). They
  are not sent to the control plane as a separate signal. The refusals themselves are audited as
  usual. A `ClearDenial` helper exists, but counters currently end by the window expiring.
* After a halt the developer decides: review `bapedge zsp approvals` or the refusal, then resume the
  agent with new instructions. Halting does not freeze the session or the workstation.

### Session threat label (broker commands only)

For commands that go through `bapedge exec`, every denied command in a session is counted
(`recordSessionDenial`, `bap-edge/cmd/exec.go`). From 2 denials the label is `ELEVATED` and from 4
it is `CRITICAL`. The only effect is a `[CORRELATED RISK EVENT]` warning added to the response.

* It does not halt, freeze or tighten anything, and it is not sent to the control plane.
* It has no time window or decay, and it counts every kind of denial together.
* It is stored in `.bap/risk_state.json` relative to the working directory, so it follows the
  folder rather than the session or the machine.
* Native-tool and hook refusals do not update it.

### Other bounds that are not rate limits

* `max_mints_per_session` is a hard stop on grant minting (`ErrMintCapExceeded`).
* The ceiling clamps uses and lifetime per grant by grant class; a single-use grant burns on first use.
* Identical pending approval requests collapse into one, so repeated asks do not flood the
  operator.
* Credentials and other `deny`-tier actions are never grantable, however often they are requested.

### Known limits (record them; do not rely on more than this)

* **No requests-per-time limit.** Nothing caps how fast an agent can ask or try.
* **Varied attempts are not halted.** Rewording a command, changing a flag or switching shells
  produces a new key each time, so the breaker never reaches its thresholds. Each attempt is still
  refused or still needs a human, but the agent is not stopped for the volume.
* **No automatic escalation.** A burst of different violations does not raise the session's risk
  tier, freeze the session, or notify the control plane. Freezing and quarantine are administrator
  actions (or follow missing heartbeats or hook tampering).
* The breaker works only where a BAP hook, broker or CLI sees the attempt. An action that reaches no
  BAP layer is not counted.

Tests: `go test -C bap-edge ./internal/authz -run BAP936` (per-session and per-key counting, the
STOP wording) and `go test -C bap-edge ./cmd -run TestE2E_RepeatedRefusalsAreStoppedNotSpun`
(the halt after repeated refusals).

## Grant Lifecycle, Lineage, and Cockpit UI Visibility

Every grant minted in BAP adheres to Zero Standing Privilege (ZSP): single-use execution tokens that bind the exact agent, human delegator, scope, and command.

### 1. Acquisition Modes
* **AUTOMATIC (Cedar Policy Attestation / Batch Engine)**: Minted dynamically by the broker when a routine, policy-permitted command (e.g. `git status`, test runs) is evaluated. TTL is capped at 30 seconds.
* **MANUAL (HITL Out-of-Band Challenge)**: Minted when a high-risk or sensitive command (e.g., `git reset --hard`, `git push`) is blocked, requiring an interactive human operator challenge (`bapedge zsp authorize --agent <id> --action <action> --ttl 5m`).

### 2. Lifecycle States
* **`ACTIVE`**: Minted token waiting in memory. Valid until TTL or first execution use.
* **`1x USED & BURNED`**: Atomically consumed upon child process launch. Binds the consumed command text and links directly to the cryptographic audit receipt ID (`ReceiptID`). Replay is cryptographically impossible.
* **`EXPIRED UNUSED`**: TTL lapsed without execution. Retained in historical ledger for forensic auditing.

### 3. Multi-Agent Principal Attribution
Grants record:
* `AgentPrincipalSVID`: e.g. `spiffe://bap.local/.../agent-<client>-<id>`
* `ClientType`: `antigravity`, `claude-code`, `codex`, `copilot`
* `DelegationType`: `policy_automatic_batch`, `automatic`, `manual`

### 4. Visibility in CLI, Control Plane, and UI
* **CLI**: `bapedge zsp status --all` and `bapedge zsp grants` report active, burned, and expired grants with receipts and executed command lineage.
* **API**: `/api/v1/sts/tokens` and `/api/v1/sessions/transcript` aggregate ZSP grants.
* **Dashboard Cockpit UI**:
  * **Session Conversation Drawer (`dConvo`)**: Top-level **Zero Standing Privilege (ZSP) Task Grants** card displaying Principal, Agent, Acquisition Mode, Scope, Lifecycle Status, and Command.
  * **STS & OBO Inspector (`viewOBO`)**: Fleet-wide **Zero Standing Privilege (ZSP) Agent Execution Grants** table.
* **Story Ledger (`Show-BapStory.ps1`)**: Scene 1 outputs distinct Grant Cards linking requests, grants, burned statuses, and tamper-evident audit receipts.

## Behavior changes versus the previous engine

* `repo:*` narrows to `repo:read` only (previously `repo:read,repo:push`).
* Interpreters, unknown `cli:*:exec`, `git push`, deletes/drops/admin, `http:*`/`net:*` and any
  out-of-workspace resource need approval; credential actions are denied outright.
* The hardcoded fallback signing secret is removed. An engine without a secret refuses to mint or
  consume (`ErrSigningSecretMissing`).
* `BAP_INSECURE_SKIP_VERIFY` no longer disables TLS verification for non-loopback hosts
  (`bap-edge/internal/httptransport/client.go`).

## Tests

| Layer | Command | Covers |
|---|---|---|
| Unit | `go test -C bap-edge ./internal/authz` | policy parsing/validation, tier precedence, boundary, destination rule, signed override lifecycle, ceiling |
| Regression | same package, `TestEscalation_*` | each behavior from the Claude Code calls report (interpreter mint, `system://local` widening, wildcard push, mint cap, hard-deny, empty secret) |
| End to end | `go test -C bap-edge ./cmd -run TestE2E_` | real `RunZSP` CLI + real hook decision path: replay of the report, scripted `--oob-approve`, in-broker refusals, `policy-sign`, mint cap via signed override, tamper fail-closed |
| Whole suites | `go test -C bap-edge ./...` and `go test -C cchook ./...` | no regressions |

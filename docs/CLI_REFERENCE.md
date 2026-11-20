# BAP Command & Binary Reference

Comprehensive operational and reference documentation for the BAP (Bounded Authority Plane) Zero-Trust platform.

Reviewed against the source command dispatchers and argument parsers on 2026-11-19.
This describes this checkout; an installed release may expose fewer commands. Check
`bapedge version --json` before comparing behavior. Examples document syntax; they
do not grant authority to change trust, pins, policy, credentials, or approvals.

Navigation: [launchers](#22-governed-agent-launchers), [ZSP and auto-approval](#25-zero-standing-privilege-zsp--playback),
[cross-folder trust](#27-cross-folder-authority--permissions), [pins](#210a-content-pins),
[boundary and learning](#211-process-boundary-egress-and-learning), [integration commands](#213-lifecycle-and-integration-commands).

---

## 1. Architecture Overview: The 7 Core Binaries

BAP delivers enterprise-grade defense-in-depth across 7 dedicated binaries:

| Binary | Alias / Package | Role & Responsibility |
|---|---|---|
| **`bap` / `bapedge`** | `bapedge.exe`, `ltd-agent` | Workstation Local Trusted Daemon (LTD), policy engine, execution broker sandbox, and agent launcher. |
| **`bapcontrolplane`** | `bap-controlplane.exe` | Central policy authority, RFC 8693 STS token issuer, OTC enrollment authority, and audit aggregator. |
| **`bapdashboard`** | `bapdashboard.exe` | Dedicated HTTPS operator console, cockpit telemetry UI, and OBO exchange inspector. |
| **`bapgateway`** | `bapgateway.exe` | Egress Policy Enforcement Point (PEP), reverse proxy, and single-use credential consumer. |
| **`bapmcp`** | `bapmcp.exe`, `bapedge mcp` | Model Context Protocol (MCP) server exposing zero-trust execution and task grant tools to AI agents. |
| **`cchook` / `interceptor`** | `cchook-interceptor.exe` | Native hook interceptor (Layer 1A) for Claude Code, Copilot, Antigravity, and Codex. |
| **`bap-hook-adapter`** | `bap-hook-adapter.exe` | Universal cross-agent plugin runtime adapter bridging in-harness events to the BAP broker. |

---

## 2. `bap` / `bapedge` CLI Reference

`bap` and `bapedge` are the primary workstation CLI. The Python `bap` entry point
proxies the edge binary, with older launcher fallbacks; use `bapedge` when diagnosing
which native command implementation ran. Windows accepts `bapedge.exe`.

Go flag parsers generally stop at the first positional argument. Put flags before
positional arguments unless a command explicitly reorders them. For `trust` and
`untrust`, use `--flag=value` for value flags because their current reordering parser
does not reliably preserve separated flag/value pairs.

### 2.1 Set Up, Identity & Onboarding

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap login` | `[--server <url>] [--provider entra\|okta\|generic] [--force] [--no-daemon] [--type laptop\|desktop\|server] [--ca-cert <path>] [--config <path>]` | Authenticate/enroll and synchronize signed policy. Parser also accepts `--email`, `--department`, `--groups`, `--verify-now`, and development-only `--insecure`; these do not establish a verified production identity by themselves. |
| `bap register` | `[--server <url>] --code <code>` or `[flags] <code>` | OTC enrollment. Also accepts `--instance-id`, `--config`, `--ca-cert`, development-only `--dev` and `--insecure`. |
| `bap logout` | `[--config <path>] [--ca-cert <path>] [--force] [--insecure]` | Deregister and clear local enrollment (`alias: deregister`). `--force` permits local cleanup if remote deregistration fails; `--insecure` is development-only. |
| `bap setup` | `[--app claude-code\|antigravity\|codex\|copilot\|opencode\|all] [--dir <workspace>] [--server <url>] [--force]` | Persistent workstation configuration and plugin installation. Defaults to `claude-code`; writes configuration, unlike process-scoped `bap claude`. Successful setup output does not prove a native client accepted its callbacks. |
| `bap enable` | Same flags as `setup` | Alias dispatch to the setup implementation; does not itself start the daemon. |
| `bap doctor` | `[--fix] [--repair-policy] [--hook-copies-json]` | Inspect environment and hook copies; repair flags can mutate state. Health/readiness does not prove five-layer participation. |
| `bap onboarding begin` | *(none)* | Create a bounded reporting probe and print a prompt for the human to submit in a supported native Claude session. |
| `bap onboarding check` | `[--require]` | Check correlated callback/reporting observations; `--require` fails if evidence is absent. Does not automate native approvals or prove execution success. |
| `bap ensure-enrolled` | *(none)* | Run the enrollment consistency/remediation check. A genuinely unenrolled machine still needs enrollment. |

### 2.2 Governed Agent Launchers

Launch coding clients with BAP session identity and integration lifecycle. Launching
does not establish that every native tool was intercepted or that the entire client
is contained by an OS boundary. Native-hook support depends on the host integration;
received broker/MCP requests are evaluated independently when native hooks are absent.

```powershell
bap agy [args...]             # Launch Google Antigravity CLI (agy) under active governance
bap antigravity [args...]     # Alias for 'bap agy'
bap claude [args...]          # Launch Claude Code CLI under active governance
bap claude-code [args...]     # Alias for 'bap claude'
bap codex [args...]           # Launch OpenAI Codex CLI under active governance
bap copilot [args...]         # Launch GitHub Copilot CLI
bap opencode [args...]        # Launch OpenCode CLI
```

**Common Launcher Flags:**
* `--server=<url>`: Override control plane URL for this session (defaults to global setting in `bap-config.json`).
* `--no-hooks`: Restricted development option in the shared parser; requires developer override. The deterministic Claude launcher rejects it even with override.

Aliases: `openai-codex`, `github-copilot`, and `open-code` map to their respective
launchers. Claude owns `--settings` and `--setting-sources`; downstream flags that
conflict with its registration ownership are rejected. It selects one effective BAP
registration per lifecycle event, reuses managed registrations, preserves source
files, and cleans owned temporary journals on exit or later stale-owner recovery.
Ordinary user preferences such as `autoUpdatesChannel` survive duplicate-hook
reconciliation. Mandatory managed conflicts remain explicit errors. Network/5xx
outages retain local session enforcement and queued reporting; revocation, missing
authority and enrollment failures are not converted into permission to run.

### 2.3 Daemon & Service Lifecycle

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap start` | `[--foreground] [--server <url>] [--port <port>]` | Start background daemon; default local IPC port 18446. |
| `bap stop` | *(none)* | Gracefully terminate background supervisor daemon. |
| `bap restart` | *(none)* | Restart background supervisor daemon. |
| `bap status` | `[--server <url>] [--json] [--no-sweep] [--fix] [--no-fix]` | Inspect sessions, daemon, policy and pending telemetry. By default may reconcile/sweep state; use `--no-sweep --no-fix` to suppress those automatic operations. Readiness is not compliance proof. |
| `bap sweep` | `[--server <url>] [--force]` | Reconcile orphaned sessions and retry pending reports. `--force` ignores normal PID liveness checks; it is not routine concurrent-session cleanup. |
| `bap daemon` | `start`/`run`, `stop`, `status [--json]` | Low-level daemon management. Use top-level `bap restart` for restart. `daemon supervise` is an internal supervisor entry point. |

### 2.4 Policy, Inspection & Broker Sandbox

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap exec` | `[--timeout <dur>] [--progress] [--shell <shell>] [--json\|--raw] "<command>"` | Evaluate and execute a command through the broker. Flags must precede the command. See [quoting](#24a-quoting-rules-for-bap-exec). |
| `bap check` | `"<command>"` | Decision-only broker evaluation (alias: `authorize`). Does not execute the requested command; policy checks and audit/reporting can still produce state. |
| `bap why` | `"<command>"` | Explain Cedar policy decision directly in terminal with matched rules and remediation advice (alias: `explain`). |
| `bap sync` | `[--server <url>] [--policy-dir <path>] [--agent-id <id>]` | Synchronize the signed policy cache. |
| `bap config` | `show` | Display resolved control plane, API gateway, trust domain, and enforcement mode. |
| `bap config` | `set [--server <url>] [--gateway <url>] [--envoy <url>] [--mode enforce\|audit] [--global]` | Update endpoints/mode locally or in `~/.bap/config.json`. |

Broker defaults: timeout 30 minutes (or `BAP_EXEC_TIMEOUT_SEC`), bounded to 24 hours;
progress is opt-in. Shells: `auto`, `bash`, `sh`, `zsh`, `cmd`, `powershell`, `pwsh`.
Explicit shell selection does not silently fall back. Additional parser options:
`--policy`, `--source`, `--session-id`, `--server`/`--server-url`, `--audit-log`,
`--mode enforce|audit|shadow`, `--prompt`, `--skill`, `--verify-pins`,
`--decision-only`/`--check-only`, and `--cmd-b64`. Native integration handoff also
uses `--reporting-layer`, `--caller-binary`, `--caller-hash`, `--tool`, `--target`,
`--consume`, `--tool-use-id`, `--tool-input-sha256`, `--tool-outcome`, and
`--stepup-decision`. These metadata flags are not approval credentials. Workspace
and enterprise policy can prohibit changing enforcement, pin verification or audit
settings; documenting a parser option does not authorize bypassing those rules.

### 2.4a Quoting rules for `bap exec`

The command is one string. On Windows, PowerShell parses that string first, so the escape character is the
backtick (or a doubled quote), **not** a backslash. `bapedge exec "git commit -m \"msg\""` is split by
PowerShell before BAP sees it and is rejected or mangled. Prefer single quotes *inside* the double-quoted string.

| Situation | Behaviour |
|---|---|
| `bapedge exec "git commit -m 'Fix a; b'"` | Works. Operators inside quotes (`; \| & > <`) are data, not shell operators. |
| `bapedge exec "git commit -m 'Co-Authored-By: X <x@y.com>'"` | Works (build v1.13.39 / `ebc22faa` or later). Older builds fail with `exit status 1`. |
| `git status && echo done`, `git status ; calc`, `a \| b`, `a > file` | Unquoted operators still run through `cmd.exe /c` and every sub-command is evaluated by policy. |
| Unterminated quote | Never guessed at; falls back to the conservative `cmd.exe` path. |
| Unquoted commands and `cmd` builtins (`echo`, `dir`) | Unchanged, run through `cmd.exe /c`. |
| Long or multi-paragraph messages | Use a file: `git commit -F <file>`. This avoids quoting entirely and works on every build. |

A quoted command with no unquoted operator runs directly with an exact argument list when the program is on
`PATH`. Implementation: `bap-edge/internal/sandbox/argv.go` (`hasUnquotedShellOperator`, `splitArgv`).

### 2.5 Zero Standing Privilege (ZSP) & Playback

BAP operates on Zero Standing Privileges: agents start with zero authority and acquire short-lived, least-privilege JIT TaskGrants.

**Interactive approval inbox:** in your own terminal, run `bap zsp`. It automatically
finds pending requests, displays their client/session, linked session, intent,
actions, resources, use limits and expiry, and offers approve/deny/skip/quit.
Each approval still requires a separate one-time code. It waits for newly arriving
requests until Ctrl+C; no request ID needs to be copied. `bap zsp inbox` reviews the
current queue once; `bap zsp inbox --watch` keeps waiting. In noninteractive output,
bare `bap zsp` prints usage instead of opening a console. Existing explicit
`approve <id>`/`deny <id>` commands remain available.

The inbox is compiled into the normal edge binary, not a separate preview-only
program. `update_binaries.ps1` rebuilds and stages it, and the wheel builder compiles
the same source for each release target. The Windows updater and native wheel
builds check `bapedge zsp --help` for the inbox before deployment/packaging.
`bap install` copies that packaged edge binary; it does not compile new source or
upgrade an old wheel by itself. Existing installations need a newly built package
installed before `bap zsp` gains the new behavior.

The console and approve/deny operations are agent-blocked at supported hook/broker
boundaries; the console also rejects broker-marked processes and nonterminal input.
Aliases are covered, including `autoapprove enable`. Changed requests cannot be
approved against an older displayed snapshot: all reviewed fields are rechecked
under the store lock before minting. Request-provided terminal control characters
are escaped. EOF, skipped requests and invalid choices never grant authority.

**Human-authentication limit:** a terminal and a code are not cryptographic proof
of a human. An agent with same-account process/PTY control or direct authority over
local signing state is outside this guarantee. Strict separation requires a trusted
approval service or a human-held signing key outside the agent's security context.
Do not expose the approval terminal to an agent. Agent `zsp authorize` and read-only
status/list operations remain supported; restricting every ZSP command to humans
would prevent agents from requesting legitimate grants.

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap zsp inbox` | `[--watch]` | Human interactive review; no IDs required. Bare `bap zsp` watches when launched in an interactive terminal. |
| `bap zsp help` | Aliases: `--help`, `-h` | Print usage without opening the inbox or approving a request. |
| `bap zsp init` | `[--session-id <id>] [--client <client>] [--json]` | Initialize the session principal with zero standing privileges. |
| `bap zsp status` | `[--session-id <id>] [--client <client>] [--all] [--all-sessions] [--json]` | Inspect grants; `--all` includes burned/expired grants and `--all-sessions` spans sessions. |
| `bap zsp grants` | Same as `status` | Alias; `zsp list` is another alias. |
| `bap zsp playback` | `[--limit <n>] [--json]` | Replay recorded grants across the workstation; default limit 50. Does not accept `--all-sessions`. |
| `bap zsp authorize` | `--session-id <id> --mission <m> --goal "<text>" --actions <a,b> [--resources <r>] [--max-uses N] [--ttl <dur>] [--authorized-by <email>] [--client <c>] [--json]` | Submit a 4-Tuple Task Authorization Envelope to the policy engine. Defaults: `--mission TASK_EXECUTION`, `--resources workspace://current`, `--max-uses 1`, `--ttl 300s`. Run it as a **standalone** command (no `&&`, `;` or `\|`). A grant is minted, **or** a human-approval request id is raised, **or** the request is denied. |
| `bap zsp approvals` | *(none)* | Read-only list of pending requests; humans and agents may inspect. Decisions remain guarded. |
| `bap zsp approve` | `<req-id>` | Human only: approve a pending request. Requires a one-time code typed in the developer's own terminal. Blocked for agents. |
| `bap zsp deny` | `<req-id>` | Human only: deny a pending request. Blocked for agents. |
| `bap zsp autoapprove` | `[status]` | Inspect the bounded approve-tier window; no subcommand defaults to `status`. |
| `bap zsp autoapprove on` | `[--duration <duration>]` | Human only, terminal challenge required. Default 1 hour, maximum 8 hours. Alias: `enable`. |
| `bap zsp autoapprove off` | *(none)* | Close the window immediately. Alias: `disable`. |
| `bap zsp check` | `[--session-id <id>] [--client <client>] --action <action> [--resource <resource>] [--command <text>] [--consume]` | Verify coverage; `--consume` spends one use. Resource defaults to `workspace://current`; emits JSON. |
| `bap zsp revoke` | `[--session-id <id>] [--grant-id <id>]` | Revoke one grant or all grants for the resolved session. |
| `bap zsp policy-sign` | `--file <permission-policy.json>` | Human-operator path: validate, sign and install a permission-policy override. |

`zsp authorize` also accepts `--requesting-session-id`, `--prompt`, and human-only
`--oob-approve`. `zsp request` aliases `authorize`; `zsp requests` aliases `approvals`.
An approver email or `--oob-approve` flag is not proof of human approval: the latter
requires an interactive challenge. Use the real BAP session ID, not a fabricated one.

**Grant classes.** The class is chosen by the actions requested, and `--max-uses` is clamped to the class ceiling.

| Class | Actions | Uses / TTL |
|---|---|---|
| `workspace_edit` | `fs:file:write` only | Honors `--max-uses N` (request one grant sized for a batch of edits). |
| `single_use` | Anything mixed or executable (`cli:bash:exec`, `git:commit:write`, `dev:go:-C`, …) | 1 use, 300 s. One command per grant. |

**Approval flow.** A request returns one of: `JIT TaskGrant Minted` (proceed through `bapedge exec`);
`High-Risk Escalation Blocked … HITL REQUEST RAISED: req-…` (stop, tell the developer, wait for
`bap zsp approve`); or a policy denial. An approval covers only the action requested. Approving
`cli:bash:exec` does not cover `dev:go:-C`. When `BAP ZSP AUTO-APPROVE ON` appears, routine (approve-tier)
requests are eligible without a per-request prompt. Signed policy denies, protected
governance actions and rules requiring separate human approval remain enforced.
Eligibility follows the actual action/resource policy, not a promise that every
command of a particular name is eligible. An already pending request still requires
its explicit approval path; a banner is not approval. See
[ZSP_APPROVAL_FLOW.md](../ZSP_APPROVAL_FLOW.md) for the authorization workflow.

Human terminal examples (documentation only):

```powershell
bap zsp autoapprove status
bap zsp autoapprove on --duration 30m
bap zsp autoapprove off
```

Auto-approval is off by default, expires automatically and records a distinct
`auto_approve` delegation. It does not disable broker, hook, integrity or
control-plane checks. Developer override is a separate, broader development mode
and makes a run unsuitable for normal enforcement validation.

### 2.6 Human-in-the-Loop (HITL) Step-Up Escalations

When an agent requests an action outside routine policy (e.g. interpreter execution `dev:python:exec`, network egress), it triggers a step-up challenge.

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap stepup list` | *(none)* | List pending out-of-scope escalation requests from the Central Control Plane. |
| `bap stepup request` | `<task_id> <action> <resource> [reason]` | Submit an out-of-scope task escalation request to the control plane inbox. |
| `bap stepup status` | `<escalation_id>` | Query the escalation ID returned by the request. |

The CLI implements `request`, `status`, and `list` only. Central escalation decisions
use the authorized control-plane UI/API. Local `zsp approve` handles local pending
ZSP requests; these are separate workflows.

### 2.7 Cross-Folder Authority & Permissions

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap trust` | `[--project\|--global\|--session] [--session-id=<id>] [--actions=write,delete] [--json] <path>` | Human-operator cross-folder mutation authorization. Project scope is default; actions default to `write,delete`. `all` is accepted. `read` is not a grant action. Forbidden roots, home and credential locations remain protected. |
| `bap untrust` | `[--project\|--global\|--session] [--session-id=<id>] <path>` | Human-operator revocation; specify the same scope as the grant. |
| `bap permissions` | *(none)* | List all active cross-folder authorizations across session, project, and global scopes. |

`bap trust list` and `bap trust` with no path list permissions. There are no
`--path`, `--scope` or `--ops` flags in this handler. Trust expands the filesystem
boundary; it does not mint a TaskGrant or override Cedar policy or secret protection.
Agents cannot authorize their own cross-folder mutations.

```powershell
# Human terminal, only after authorizing this directory:
bap trust --project --actions=write '..\shared-library'
bap permissions
bap untrust --project '..\shared-library'
bap trust --session --session-id=sess-example --actions=write '..\shared-library'
```

Current limitations: session trust also writes the implementation's `default`
session alias; do not assume strict single-session isolation from this CLI alone.
Its `--json` formatter currently prints Go slice notation for `actions`, so consumers
must not assume the result is valid JSON. Both are code-review findings, not intended
security guarantees.

### 2.8 Native Plugin Management (Layer 1A)

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap plugin list` | `[workspace]` | List discovered and installed native plugins across Claude Code, Copilot, Antigravity, OpenCode, and Codex. |
| `bap plugin install` | `[--dir <workspace>] <claude\|copilot\|antigravity\|opencode\|codex\|all>` | Persist native plugin integration files. |
| `bap plugin uninstall` | `<claude\|copilot\|antigravity\|opencode\|codex\|all>` | Safely remove native plugin registrations. |
| `bap plugin verify` | `[client]` | Inspect configuration/health; synthetic component checks do not prove native-host acceptance. |
| `bap plugin status` | `[--dir <workspace>]` | Report plugin health/status. `plugin inspect` is not implemented. |
| `bap plugin layers` | *(none)* | Print layer descriptions/readiness, not proof that each layer evaluated an action. |

### 2.9 Closed-Loop Policy Recommendations

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap recommend` | `[--limit <n>] [--audit-log <path>]` | List recent blocked effects; default limit 15. |
| `bap recommend` | `--pick <n> --justify "<reason>"` | Submit a recommended policy relaxation for routine build/test commands to administrator. |
| `bap recommend` | `--status` | Check status of recommendations submitted by this workstation. |
| `bap review recommend` | *(none)* | Same recommendation flow accessible directly from the session reviewer. |

### 2.10 Enterprise Security, Forensics & Integrity

| Command | Arguments / Flags | Description |
|---|---|---|
| `bap rollback` | `[--session-id <id>] [--checkpoint-id <id>] [--file <path>] [--list] [--json]` | List checkpoints or restore approved files. There is no `--dry-run`; use `--list` for inspection. |
| `bap pin` | See [content pins](#210a-content-pins) | Manage content hash baselines; `pin status` is not implemented. |
| `bap scan` | `[--json] [--fail-on critical\|high\|medium\|low] [--manifest <path>] [--fix] [workspace]` | Injection/drift scan. Default failure threshold `high`; `--fix` pins clean discovered assets. No `--dir` or `--strict`. |
| `bap shield` | `scan [dir]`, `plant-canary [dir]`, `check-canary <payload>` | Operator credential-discovery/canary utilities. Do not run a scan where workspace policy forbids credential access. These commands do not prove ambient OS credential isolation. |
| `bap antibypass` | `status` or `check "<command>"` | Inspect/check command-pattern rules. The status banner does not prove all network paths are mediated; there is no `verify` or `enforce` subcommand. |
| `bap delegate` | `mint`, `run`, `status`/`tree`, `help` | Attenuated child grants and lineage. `mint`/`run` accept `--child-agent`, `--child-app`, `--session`, `--scopes`, `--action`, `--resource`, `--ttl` (minutes; default 15), `--server`, and `--parent-token` (prefer the `BAP_GRANT_TOKEN` environment binding over exposing a token in arguments). `mint` also accepts `--json`; `run` separates its command with `--`. |
| `bap verify-log` | `[--file <audit.jsonl>]` | Verify the audit hash chain; default resolves the configured local audit log. |
| `bap dev-override` | `on [--duration <duration>] [--reason <text>]`, `off`, `status` | Human-controlled development override; default 4 hours, maximum 12 hours. Requires a permitted development build/environment (`allow_dev_overrides=true` in version JSON). Agents must never enable it. See [build modes](#81-build--package). |
| `bap version` | `[-v] [--version] [--json]` | Display semantic version, git commit, build date, and architecture. |

### 2.10a Content Pins

`pin` selects the workspace manifest when present; otherwise it uses the default
state manifest. Inspect the reported manifest path before any mutation. Empty or
missing pins cannot prove protected-file coverage. Agent scope filters apply to
verification results; `verify --scope` currently calls `VerifyAll` before filtering.

| Command | Flags / operands | Effect |
|---|---|---|
| `bap pin list` | `[--json]` | Inspect assets, IDs, scopes, paths, hashes and attestation metadata. |
| `bap pin verify` | `[--scope <agent>] [--json]` | Verify hashes; mismatch returns nonzero. Alias: `pin check`. An empty result can be clean without verifying any asset; inspect counts. |
| `bap pin add` | `[--id <id>] [--type skill\|mcp_tool\|prompt\|script] [--scope <agent>] <path>` | Compute and persist a new baseline. Default type `skill`; scope is inferred if omitted. Use an explicit scope for shared `AGENTS.md` assets. |
| `bap pin update` | `[--all] [asset-id ...]` | Recompute approved baselines; `--all` updates every asset. Review modifications before re-attesting. |
| `bap pin scan` | `[--dir <workspace>]` | Discover and pin workspace assets; this writes the manifest and can replace discovered IDs. |
| `bap pin unpin` | `[--all] [asset-id ...]` | Remove selected entries or every entry. |
| `bap pin clear` | *(none)* | Persist an empty manifest. |
| `bap pin reset` | `[--dir <workspace>]` | Clear then rediscover/re-pin the workspace. |

Read-only examples:

```powershell
bap pin list --json
bap pin verify --scope codex --json
```

Mutation syntax, for an authorized operator and a disposable example file:

```powershell
bap pin add --id script:example --type script --scope all './diagnostic-fixture.txt'
bap pin update script:example
bap pin unpin script:example
```

Do not clear, reset or update real protected-file pins to make a failing check pass.
These are baseline changes, not repairs of the original content. Current `update`
and `unpin` handlers can print per-asset failures while returning success overall;
check the subsequent list/verify results. The broker's pre-existing content-pinning
path also contains automatic baseline reconciliation for some instruction/policy
files; a successful broker result alone is therefore not proof that no prior drift
occurred. Review the verifier observations and baseline provenance.

### 2.11 Process Boundary, Egress and Learning

These are human-operator profile controls. They are separate from TaskGrant issuance
and do not replace signed policy or corporate egress requirements.

| Command | Flags / operands | Behavior |
|---|---|---|
| `bap run` | `[--provider <provider>] [--print] [--image <image>] [--docker-network <name>] -- <command> [args...]` | Execute with the selected boundary. `auto` selects AppContainer on Windows, bubblewrap on Linux, Seatbelt (native execution unverified) on macOS. Missing providers fail instead of running unsandboxed. `--print` renders a specification only. Docker defaults to network `none`; it is not the default provider. |
| `bap egress list` | *(none)* | Show the current workspace profile and allowed destinations. |
| `bap egress allow` | `<host[:port]>` or `<*.domain>` | Persist an operator-approved profile destination and approval event. Does not authorize bypassing a required enterprise gateway. |
| `bap egress serve` | `[--addr <address>]` | Start the standalone profile proxy; default `127.0.0.1:3128`. A proxy alone does not close other network paths. |
| `bap learn` | *(none)* | Propose changes from recorded effects belonging to this workspace. |
| `bap learn report` | *(none)* | JSON metrics, proposals and prediction mismatches. |
| `bap learn profile` | *(none)* | JSON profile recommendation; does not apply it. |
| `bap learn apply` | `<host>` | Apply a matching mined proposal and record an operator decision. |

Provider values are `auto`, `appcontainer`, `bwrap`, seatbelt (native execution unverified), and `docker`.

See [capability model](CAPABILITY_MODEL.md) and [learning loop](LEARNING_LOOP.md)
for provider and authority limitations. Rendering a Linux/macOS spec is not native
runtime acceptance on those operating systems.

### 2.12 Actual Layer Evidence and Diagnostics

The normal dashboard derives five layers from live producer observations:
in-harness hooks, execution broker, cryptographic integrity/pinning, anomaly risk,
and control-plane attestation. A layer is evaluated only when its own evidence is
present; installation/readiness and transport labels do not establish participation.
An early denial need not reach downstream layers. Missing native-hook evidence does
not prevent an independently received broker request from being evaluated.

`bap showcase [--client claude-code|codex|antigravity|copilot|opencode]
[--output <workspace-report.json>] [--without-hooks]` runs isolated diagnostic
fixtures. It is a developer diagnostic, not a requirement for ordinary telemetry.
`--without-hooks` omits the callback fixture without disabling defenses. The edge
cannot generate a control-plane verdict: its report marks attestation unavailable
until the authenticated control-plane diagnostic path is exercised. Fixture results
are marked diagnostic and cannot prove native endpoint acceptance or live coverage.

### 2.13 Lifecycle and Integration Commands

These commands normally run from launchers/hooks. Keep the BAP-supplied identity;
do not manufacture another session to evade policy.

| Command | Purpose |
|---|---|
| `bap review` | Review session decisions/performance. Aliases: `review-session`, `review-sessions`, `sessions`; `review recommend` opens the recommendation flow. |
| `bap adapter` | `cursor`, `gemini`, `browser`, `hook`/`plugin`, or `emit`; invoke without operands for adapter-specific syntax. Emitted/self-reported telemetry is not native interception proof. |
| `bap watch` | `[--pid <pid>] [--server <url>] [--session-id <id>] [--app-id <client>] [--instance-id <id>] [--detach]`; launcher-owned watcher/replay process. |
| `bap session-start` | `[--server <url>] [--session-id <id>] [--app-id <client>] [--instance-id <id>] [--pid <pid>] [--prompt <text>] [--hooks-disabled]`; the last option is restricted development behavior. |
| `bap session-end` | `[--server <url>] [--session-id <id>] [--reason <text>]`; end/report a session. Claude `Stop` is turn completion, not session termination. |
| `bap session-telemetry` | `[--server <url>] --kind start\|heartbeat\|prompt\|response\|end`; reads valid JSON up to 1 MiB on stdin. Current helper retains failed prompt deliveries, but does not durably queue every other kind; its HTTP status is in the returned JSON and is not necessarily the process exit status. |
| `bap policy-setting prompt-capture` | Print the effective signed setting; does not change it. |
| `bap serve` | `[--socket <path>] [--allowed-hash <sha256,...>]`; start the local attestation transport server, default socket `/tmp/ltd.sock`. |
| `bap attest` | `[--socket <path>] [--timeout <seconds>]`; client for local attestation/OBO transport, default timeout 5 seconds. Distinct from control-plane binary-image verification evidence. |
| `bap help` | Top-level usage. Aliases: `-h`, `--help`. |

Other aliases: `clean-sweep` → `sweep`, `subagent` → `delegate`, `dev` →
`dev-override`, `explain` → `why`, `deregister` → `logout`, `-v`/`--version` →
`version`. `__shim` is the internal in-sandbox egress relay, not a user entry point.

---

## 3. `bapcontrolplane` CLI Reference

The central policy authority, RFC 8693 STS token issuer, and audit repository (`bap-controlplane`).

### 3.1 Commands

```powershell
bapcontrolplane start [flags]       # Start the HTTP/TLS Central Control Plane server
bapcontrolplane stop                # Gracefully terminate running background instance
bapcontrolplane status              # Query status, health, port, uptime, and database metrics
bapcontrolplane restart [flags]     # Restart the Central Control Plane instance
bapcontrolplane enable              # Initialize environment, admin tokens, and state stores
bapcontrolplane serve [flags]       # Run server in foreground (alias for 'start --foreground')
bapcontrolplane version             # Display semantic version, git commit, and build info
```

### 3.2 Flags & Options for `start` / `serve`

| Flag | Default | Description |
|---|---|---|
| `--port <p>` | `8080` / `$PORT` | Port for HTTP/TLS server. |
| `--detach`, `-d` | `false` | Run as detached background daemon. |
| `--foreground`, `--fg` | `false` | Run in foreground. |
| `--mode <prod\|dev>` | `prod` | Environment mode: `prod` (default; strict OTC, OIDC required) or `dev` (open self-service OTC, local development only). An explicit `--mode` overrides `BAP_MODE` / `BAP_ENVIRONMENT`. Prod requires `BAP_SECRET_KEY` (32+ chars), `BAP_POLICY_SIGNING_SEED` (64 hex), `--policy-max-age` / `BAP_POLICY_MAX_AGE` and an absolute `--db`; otherwise startup fails. |
| `--demo-mode` | `false` | Enable synthetic demo data in the activity views (`?demo=true`). Also `BAP_DEMO_MODE=1`. Never in production. The destructive demo endpoints (`/sessions/reset`, `/demo/*`) were removed. |
| `--enable-simulated-endpoints` | *(no-op)* | **Deprecated.** The simulated SPIFFE, TPM, Landlock (not implemented) and eBPF (simulation only) endpoints were removed; the flag is accepted so old launch scripts still start. |
| `--db <path>` | `bap-controlplane.db` | Path to persistent SQLite database (`memory` for in-memory). |
| `--durable` | `false` | Commit authority and audit history to disk before acknowledging API calls (mandatory in prod). |
| `--admin-token <token>` | auto-generated | Administrative secret token for control APIs (`$BAP_ADMIN_TOKEN`). |
| `--allow-remote-admin` | `false` | Allow non-localhost callers with valid admin token to execute admin APIs. |
| `--secret <key>` | auto-generated | HMAC signing secret for session tokens (`$BAP_SECRET_KEY`). |
| `--policy <path>` | *(embedded)* | Path to authoritative Cedar policy file. |
| `--schema <path>` | *(embedded)* | Path to authoritative Cedar schema file. |
| `--trust-domain <dom>` | `bap.internal` | SPIFFE Trust Domain for agent workload identities. |
| `--ttl <minutes>` | `30` | Default grant TTL in minutes. |
| `--tls`, `--https` | `false` | Enable HTTPS/TLS (auto-generates dev certs if none provided). |
| `--tls-auto` | `false` | Request development self-signed TLS generation. |
| `--tls-cert <path>` | *(empty)* | Path to TLS certificate PEM file. |
| `--tls-key <path>` | *(empty)* | Path to TLS private key PEM file. |
| `--allowed-origins <origins>` | *(empty)* | Comma-separated browser origins for CORS (default: same-origin only). |
| `--oidc-provider <prov>` | `entra` | Enterprise OIDC provider: `entra`, `okta`, or `generic`. |
| `--oidc-issuer <url>` | *(empty)* | OIDC issuer / discovery URL. |
| `--oidc-client-id <id>` | *(empty)* | OIDC application client ID. |
| `--oidc-tenant-id <id>` | *(empty)* | Microsoft Entra tenant ID or Okta org. |
| `--oidc-allowed-domains <doms>`| *(empty)* | Comma-separated corporate email domains permitted. |
| `--min-edge-version <ver>` | *(empty)* | Enforce minimum edge client version. |
| `--pilot-roster <path>` | *(empty)* | Path to operator-assigned pilot roster JSON file. |
| `--initialize-authority` | `false` | Explicitly initialize a new durable authority (first start only). |
| `--policy-max-age <duration>` | `0` | Signed offline policy budget (e.g. `24h`; mandatory in prod). |

### 3.3 Read-API authentication & stream tickets

* **Admin-only read routes** (header `Authorization: Bearer <token>`, `X-BAP-Admin-Token`, or the dashboard cookie):
  `/api/v1/agents`, `/sessions`, `/audit/events`, `/audit/risky-events`, `/inspector/data`, `/sts/tokens`,
  `/sts/inspector`, `/principals`, `/saas/tokens`, and all `/api/activity/*` and `/api/v1/activity/*` reads.
  Missing credential: `401`. Wrong credential: `403`. Repeated bad credentials from one address: `429` with `Retry-After`.
* **No credential in the URL.** `?token=` and `?admin_token=` are not accepted on any route.
* **Streams** (`/api/activity/stream`, `/api/v1/activity/stream`): exchange the admin credential for a
  single-use ticket, then pass only the ticket.

```powershell
# 1. admin credential -> ticket (valid 30 s, single use)
Invoke-RestMethod -Method Post -Uri "$cp/api/v1/auth/stream-ticket" -Headers @{ Authorization = "Bearer $tok" }
# 2. open the stream with the ticket
"$cp/api/activity/stream?ticket=bap_stk_..."
```

* **Workstation reporting is a separate authentication path.** Session start,
  heartbeat, prompt, response and end routes require session/workstation identity;
  they are not anonymous just because they are called by edge agents. Resume and
  transcript handlers perform their own checks. `/health` and enrollment bootstrap
  have different rules. Consult the route/handler for the specific endpoint rather
  than treating an absent admin middleware wrapper as proof of anonymous access.
* **Removed:** `/api/v1/spiffe/*`, `/attestation/tpm-quote` and the simulated `/api/v1/sandbox/*` endpoints,
  the destructive demo endpoints (`/sessions/reset`, `/demo/exec-safe`, `/demo/exec-attack`, `/demo/fleet-scale`),
  and the simulated Google/GitHub login pages. `/auth/oauth/start` returns `503` when no provider client ID is configured.
* **Identity must be verified in prod.** In `--mode prod`, `/auth/oauth/google-complete` and `/github-complete`
  (typed-email forms) return `403`, and the Google/GitHub callbacks return `403` unless the provider returned a
  verified email. In `--mode dev` the placeholder identities (`developer@gmail.com` / `developer@github.com`) still work.
* **Dashboard token.** `start_inspector.bat` no longer puts the admin token in the URL; paste it at the dashboard's admin login prompt.

---

## 4. `bapdashboard` CLI Reference

Dedicated operator web console and telemetry inspector (`bapdashboard`).

### 4.1 Flags & Options

```powershell
bapdashboard [flags]
```

| Flag | Default | Description |
|---|---|---|
| `-port <p>` | `8444` | HTTPS port for the standalone dashboard server. |
| `-control-plane <url>` | `https://localhost:8443` | Upstream BAP Control Plane base URL. |
| `-ca-cert <path>` | `$BAP_CA_CERT` | CA certificate file used to verify control plane TLS. |
| `-tls-cert <path>` | auto-discovered/generated | Dashboard certificate; otherwise look for control-plane certs, then generate `dashboard-cert.pem`. |
| `-tls-key <path>` | auto-discovered/generated | Paired private key; explicit cert/key options must be supplied together. |
| `-client-cert <path>` | *(empty)* | Optional mTLS client certificate presented to control plane. |
| `-client-key <path>` | *(empty)* | Optional mTLS client private key presented to control plane. |
| `-allow-remote-admin` | `false` | Allow remote dashboard clients to invoke administrative APIs. |

---

## 5. `bapgateway` CLI Reference

Zero-Trust Policy Enforcement Point (PEP) and egress reverse proxy (`bapgateway`).

### 5.1 Commands

```powershell
bapgateway start [flags]       # Start the Gateway PEP HTTP server
bapgateway stop                # Gracefully terminate running background instance
bapgateway status              # Query status, health, port, and upstream control plane
bapgateway restart [flags]     # Restart the Gateway PEP instance
bapgateway enable              # Validate configuration and connectivity
bapgateway serve [flags]       # Run in foreground (alias for 'start --foreground')
bapgateway version             # Display version and build info
```

### 5.2 Flags & Options for `start` / `serve`

| Flag | Default | Description |
|---|---|---|
| `--port <p>` | `9090` / `$BAP_GATEWAY_PORT` | Port for Gateway PEP server. |
| `--detach`, `-d` | `false` | Run as detached background daemon. |
| `--foreground`, `--fg` | `false` | Run the gateway in the foreground. |
| `--controlplane <url>` | `http://localhost:8080` | BAP Control Plane base URL. |
| `--secret <key>` | *(empty)* | HMAC secret key for offline JWT verification. |
| `--consume` | `true` | Atomically consume single-use task grants via control plane on egress. |

---

## 6. `bapmcp` CLI Reference

Model Context Protocol (MCP) broker for Claude Code, Antigravity, Cursor, and Copilot (`bapmcp` / `bapedge mcp`).

### 6.1 Usage & Commands

```powershell
bapmcp --stdio                # Run stdio JSON-RPC 2.0 server (default when launched by agent)
bapmcp status                 # Inspect MCP configuration, policy rules, and audit status
bapmcp help                   # Display onboarding instructions and sample configs
```

### 6.2 Flags & Options

| Flag | Default | Description |
|---|---|---|
| `--stdio` | `false` | Run in stdio JSON-RPC 2.0 protocol mode. |
| `--server <url>` | from config | Central control plane URL for telemetry streaming. |
| `--session-id <id>` | auto-detected | Session identifier for grouping agent actions. |
| `--mode <enforce\|audit>` | from config | Enforcement mode: `enforce` (block violations) or `audit` (log violations). |
| `--policy <path>` | `./policy.cedar` | Path to local Cedar policy file. |
| `--audit-log <path>` | `.bapstate/audit.jsonl` | Path to audit log file in JSON Lines format. |

### 6.3 Exposed MCP Tools

* **`bap_execute`**: Evaluate command against Cedar invariants and execute inside sandboxed broker.
* **`bap_explain_policy`**: Dry-run evaluate Cedar policy without execution; returns decision and suggestions.
* **`bap_status`**: Inspect edge daemon health, active sessions, and local policy cache.
* **`bap_request_task_grant`**: Submit 4-Tuple Task Authorization Envelope (Who, AuthorizedBy, Intent, Ask) to mint ephemeral JIT TaskGrants.
* **`bap_zsp_status`**: Inspect agent's SPIFFE SVID principal, human owner binding, and active grants.
* **`bap_read_file`**, **`bap_write_file`**, **`bap_edit_file`**, **`bap_list_dir`**: Policy-governed workspace filesystem tools.

The current server exposes the nine tools above. `bap_report_request` is not an
implemented MCP tool; launcher/session reporting uses separate telemetry paths.

### 6.4 Client Configurations

**Claude Code:** register through its MCP configuration command rather than
inserting an MCP server block into the hook settings file:

```powershell
claude mcp add bap-zero-trust -- bapedge mcp --stdio
```

**Google Antigravity (`.antigravity/mcp_config.json`):**
```json
{
  "mcpServers": {
    "bap-zero-trust": {
      "command": "bapmcp.exe",
      "args": ["--stdio"],
      "env": {
        "LTD_SOURCE": "antigravity",
        "BAP_SESSION_ID": "sess-antigravity-active"
      }
    }
  }
}
```

**Cursor IDE (`~/.cursor/mcp.json`):**
```json
{
  "mcpServers": {
    "bap-zero-trust": {
      "command": "bapmcp",
      "args": ["--stdio"]
    }
  }
}
```

---

## 7. `cchook` & `bap-hook-adapter` Reference

Layer 1A In-Harness Native Hook Extensions (`cchook`, `interceptor`, `bap-hook-adapter`).

### 7.1 Architecture & Interception Events

`cchook` and `bap-hook-adapter` receive JSON payloads on standard input from agent harnesses during execution lifecycle events:

1. **`PreInvocation` / `UserPrompt`**: Captures user intent and prompts for continuous telemetry.
2. **`PreToolUse` / `PreToolExecution`**: Intercepts shell and filesystem tool calls (`Bash`, `exec`, `write_file`, `git`, etc.) *before* execution.
3. **`PostToolUse`**: Records exit code, output hash, and execution duration.
4. **`SessionStart` / `SessionEnd`**: Manages session enrollment, heartbeat monitors, and cryptographic cleanup.

### 7.2 `bap-hook-adapter` Execution

```powershell
bap-hook-adapter --client <claude|copilot|antigravity|opencode|codex> --event <PreToolUse|PostToolUse|PreInvocation|SessionStart|SessionEnd>
```

*(Or via edge CLI: `bapedge plugin adapter --client antigravity --event PreToolUse`)*

---

## 8. Part 2 – Internal BAP Developer Tooling

> **Note:** The commands below are for BAP core contributors and maintainers building from source.

### 8.1 Build & Package

| Script | Purpose |
|---|---|
| `build_binaries.bat` | Build all Windows binaries (`bap.exe`, `bapcontrolplane.exe`, `bapgateway.exe`, `bapmcp.exe`, `cchook.exe`) and deploy to testing paths. |
| `update_binaries.ps1` | `[-Version vX.Y.Z] [-AllowDevOverrides "true"\|"false"] [-HeadlessStepUp "true"\|"false"] [-SkipUserInstall]`. Builds `bapedge.exe`, `cchook` and the other binaries. **`-AllowDevOverrides` defaults to `"true"`**, which compiles in the `devoverride` tag so `bap dev-override on` works (local developer machines). Pass `"false"` for a release-style build. `-HeadlessStepUp "true"` compiles the test-harness-only step-up bypass (BAP-1096); never install or publish that build. |
| `install_bap_global.bat` / `scripts/install_bap_global.ps1` | `[-AllowDevBuild] [-Debug]`. Installs binaries and global hooks for all agents. It reads `bapedge version --json` and **refuses** a build with `allow_dev_overrides=true` or `headless_stepup=true` (exit 3) unless `-AllowDevBuild` is passed. `-AllowDevBuild` belongs to the installer, not to `update_binaries.ps1`. |
| `build_all_platforms.ps1` | Cross-compile release packages for Windows (`amd64`, `arm64`), Linux (`amd64`, `arm64`), and macOS (`darwin-arm64`, `darwin-amd64`). |
| `python scripts/build_wheel.py [--universal]` | Package Python wheel and source distribution (`bap-ltd`). |
| `python scripts/build_wheel.py --single-platform --no-sdist` | Build a native wheel for the current host. On Windows this packages the rebuilt Windows client; no source distribution is produced. |

**Build modes and which command to use**

| You want | Build | Install |
|---|---|---|
| Local dev machine, with `bap dev-override` available | `.\update_binaries.ps1` (default) | `.\scripts\install_bap_global.ps1 -AllowDevBuild` (run the `.ps1` directly if the `.bat` does not forward the flag) |
| Machine that runs real agents, approvals always enforced | `.\update_binaries.ps1 -AllowDevOverrides "false"` | `.\install_bap_global.bat` |
| Python end-to-end tests that need headless step-up | `.\update_binaries.ps1 -HeadlessStepUp "true"` | Do not install |

Why the installer refuses a dev build: a dev-override or test-harness build can be told to skip approvals,
and a global install puts that binary under every agent hook on the workstation, including agents. Check any
binary with `bapedge version --json` (`allow_dev_overrides`, `headless_stepup`). Agents may never run
`bap dev-override on`; it needs an interactive human.

The Windows updater now stops on every failed Go build and on binary-copy failure;
it cannot print successful completion after those failures. It also checks that the
rebuilt edge exposes the ZSP inbox. The wheel builder applies that safe help probe
to the native artifact and explicitly clears inherited build tags so test-only
headless approval cannot leak in through `GOFLAGS`. Cross-compiled artifacts are
not executed on the build host.
No build or package check opens an approval console, approves a request, or enables
auto-approval. Inspect an installed client safely with `bap zsp --help`.

### 8.2 Test Suites

**Windows local Python suite:** from the repository root, run:

```powershell
.\test_python.bat
```

This discovers every `test*.py` under `tests`, using the active `python` interpreter
and existing dependencies/binaries. It sets isolated BAP state and temporary paths,
uses the same development-server/content settings as the CI Python job, streams
output, and saves `output.log` plus `result.json` under `.bap/python-tests/<run>/`.
The command returns the suite's exit code; failed tests make it fail. Owned runtime
state is cleaned after execution; real enrollment state is not used. It does not
install dependencies, rebuild binaries, or enable developer override/headless mode.
Missing optional fixtures can still cause skips; inspect the final unittest summary.

Use `.\test_python.bat --require-wheel-tests` to require the packaging fixtures
that CI builds beforehand. Full CI parity also requires its matching prebuilt test
binaries and dependencies. For a focused retry:
`.\test_python.bat --pattern test_capability_claims.py`.

| Command | Purpose |
|---|---|
| `go test ./...` in `bap-edge`, `bap-controlplane`, `bap-gateway`, `cchook` | Unit and integration suites. |
| `go test -v -run TestZSP ./...` | Zero Standing Privilege and task grant tests. |
| `go test -v -run TestStepUp ./cmd` | Endpoint resolution and HITL step-up tests. |
| `python -m unittest discover -v tests` | Python integration and end-to-end regression suites. |
| `.\scripts\run_pilot.ps1 [-Quick]` | Automated end-to-end pilot runbook verifying all 5 defense layers. |
| `python scripts/check_cli_reference.py` | Check public edge dispatch commands and trust/pin/ZSP parser options for missing reference entries; does not execute privileged commands. |

### 8.3 Source Map and Review Limits

| Surface | Source |
|---|---|
| Native command/alias dispatch | [edge main](../bap-edge/main.go), [Python proxy](../bap/cli.py) |
| Trust and permissions | [trust.go](../bap-edge/cmd/trust.go) |
| Pin lifecycle | [pin.go](../bap-edge/cmd/pin.go), [pinning verifier](../bap-edge/internal/pinning/pinning.go) |
| ZSP and bounded auto-approval | [zsp.go](../bap-edge/cmd/zsp.go), [auto-approval CLI](../bap-edge/cmd/zsp_autoapprove.go), [engine](../bap-edge/internal/authz/zsp_engine_policy.go) |
| Boundary, egress and learning | [boundary.go](../bap-edge/cmd/boundary.go) |
| Launcher ownership | [Claude lifecycle](../bap-edge/cmd/claude_lifecycle.go), [other clients](../bap-edge/cmd/agent_lifecycle.go) |
| Server/dashboard/gateway flags | [control plane](../bap-controlplane/cmd/server/main.go), [dashboard](../bap-controlplane/cmd/dashboard/main.go), [gateway](../bap-gateway/main.go) |

This review checks command dispatch, parser syntax and implementation behavior. It
does not certify installed packages or native-host callback acceptance. The drift
checker detects missing entries; it cannot prove every description is semantically
correct. Runtime limitations called out above remain code issues, not documentation
fixes: trust session aliasing/JSON formatting, partial pin-operation success, legacy
automatic pin reconciliation, and incomplete retry handling in the direct
`session-telemetry` helper.

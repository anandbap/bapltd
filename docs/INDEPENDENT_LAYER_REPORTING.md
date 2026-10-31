# Workstation enrollment and independent layer reporting

Updated October 31, 2026. This extends [authenticated lifecycle and recovery](SESSION_IDENTITY_AND_RECOVERY.md).

## Master setting

`bap install` provisions the workstation components and starts the user-space daemon. `bap login` establishes the enrolled workstation identity and its control-plane destination. Enrollment is shared by edge reporting and hook lifecycle requests; an agent does not need a separate login or an approved hook before the workstation can report available evidence.

For enrolled edge clients, the enrollment destination takes precedence over repository files, shell endpoint variables and per-command reporting overrides. An administrator-locked endpoint remains authoritative. When that endpoint conflicts with enrollment, evidence stays queued and transmission reports an identity/configuration error; it must not be sent anonymously to another server. Login restarts an existing daemon when it points to the previous server. `--no-daemon` remains an explicit diagnostic/test opt-out.

The workstation proof is used only with its enrolled origin; server-side verification derives owner identity from proof. A hostname, PID, source label, prompt or session ID cannot establish ownership or confer execution authority. Gateway PEP runs under its separate ingestion-only service identity; laptop login does not turn it into a workstation lifecycle client.

First audit reports reserve previously unknown session ownership atomically before ledger admission. Concurrent reports from different workstation proofs cannot claim the same session. Recovery derives a workstation/SVID identifier when a valid legacy proof lacks its explicit SPIFFE field, then reconstructs the registry master from enrollment claims before adding producer labels as subagent observations.

## Independent evidence paths

These boundaries operate independently. They are not a serial chain in which a skipped hook automatically intercepts a different tool. Each boundary must actually receive an operation before it can enforce or report it.

| Boundary | Evidence it can report | Missing hooks/prompts | Enforcement scope |
| --- | --- | --- | --- |
| Layer 1: approved native hook | Session lifecycle, classified prompt/hash when available, shell policy verdict, direct file-hook verdict | Unapproved hooks do not execute. Missing prompt text never prevents lower-layer telemetry. | Supported native hook callbacks; workspace instruction files remain cooperative. |
| Layer 2: BAP MCP | Tool name/command, policy decision and execution result | Reports independently; prompt text is optional. | Calls routed through BAP's MCP tools. |
| Layer 3: terminal shim | Command, stable session identity and broker result, tagged `shim` | Reports independently through edge. | Commands resolving through the installed shim. Absolute paths and unmediated IDE tools need another boundary. |
| Layer 4: local broker/OS containment | Broker command, decision, result and process lineage, tagged `broker` | Reports even with no hook or prompt. Local cached policy remains applicable offline. | Brokered execution and the containment primitives actually installed. Elevation alone does not attest an OS-wide sensor/filter. |
| Layer 5: gateway PEP | Actual protected resource operation and gateway verdict, tagged `gateway` | Reports independently through its service credential. | Traffic reaching that protected resource boundary. Collector correlation cannot create/refresh workstation sessions. |
| Passive workstation observation | Recognized agent executable, PID, process birth and reporting presence, tagged `discovery` | Finds named agent processes even when their hooks are not approved. Does not read transcripts, process environments or prompt text. | Observation only. Does not grant authority or prove interception. |

Native hook trust remains under user/administrator control. BAP does not approve or silently trust hooks. Codex PreToolUse responses use its supported `hookSpecificOutput` envelope; legacy `continue`/`stopReason` fields must not invalidate a denial. The control plane accepts the existing `codex-lifecycle-hook` prompt producer under authenticated session ownership, including hash-only capture-disabled submissions.

## Identity, persistence and recovery

Without an explicit native/launcher session ID, edge attributes a command through a bounded parent-process traversal to a recognized agent executable. Its fallback session ID includes installation identity, PID and process birth. Repeated broker invocations therefore share a workload ID; PID reuse produces a different ID. Explicit native session IDs remain unchanged.

The daemon observes exact recognized executable names using Windows process metadata or Linux `/proc`. It reuses a matching native watcher marker only when PID, process birth and server destination match. Unknown helpers such as arbitrary `node` processes are not labeled as agent sessions. Process-only observations enter the same authenticated audit ingestion path, with `decision: observed`; they do not increment allowed/denied operation counters, mint grants or clear a freeze. Dead or replaced processes stop receiving local heartbeats. Existing sessions age Offline under the established lifecycle timeout.

Every broker/MCP/shim audit event retains its producer layer through immediate send, retry and retained-journal replay. Direct file-hook decisions are written atomically to a private local spool without a network wait. The daemon promotes a bounded batch into the shared journal and synchronizes it before deleting the producer record. Failed handoff preserves the source file. Prompt spooling and prompt-capture policy remain separate.

Live daemon delivery uses eight workers and a bounded 256-event queue. An event is persisted before enqueue; queue saturation falls back to the existing spool. There is no goroutine per live upload. Hash version 3 binds reporting-layer metadata into new central audit links while preserving version 1/2 verification. Sessions retain a bounded set of received layer labels in memory and, when configured, their existing SQLite store.

The dashboard displays **Discovered**, **Evidence received** or **Coverage unknown**, separately from Live/Offline/Frozen. It states whether prompt text was reported or capture was disabled. These labels describe evidence received during the session, not proof that the layer is currently active or that every workstation operation was intercepted. Absence of a callback cannot distinguish pending approval, disabled hooks, an unsupported client or a stopped component.

## Latency and limits

Authorization continues to evaluate locally. Discovery and delivery run outside command execution and do not hold session locks during network calls. Named process discovery runs initially and every ten seconds; newly discovered evidence is queued immediately. Session heartbeats retain the four-second cadence. Direct file-hook promotion and offline retries use the five-second spool cadence. These are observation/retry intervals, not a claim of millisecond end-to-end freshness or a Render latency guarantee.

Remaining work is explicit in [the implementation plan](../implementation_plan.md): persistent authoritative central state; actual OS-wide enforcement/attestation; native macOS process discovery and generic hosted-agent integrations; durable service startup after reboot; backlog/retention management and representative p95/p99 load measurements. Installing hooks, setting PATH, or elevating a process alone cannot supply those guarantees.

## Verification and deployment

Automated coverage includes authenticated process-only ingestion, no-prompt commands, Codex prompt acceptance with capture disabled, cross-workstation rejection, duplicate event retries, frozen-session preservation, SQLite coverage restoration, audit metadata tamper detection, PID reuse, native-marker correlation, file-hook journal handoff and UI coverage labels. The real edge-to-control-plane delivery harness covers rejection/retry, server-state loss and retained replay without a user prompt.

Local verification passed for both complete Go modules, the interceptor suite, both cross-module E2E harnesses, UI tests, five Python launcher/identity-transport tests and parsing/equality of the three launcher-engine copies. Latest authenticated local SQLite benchmark means were 0.30–0.35 ms for heartbeat and 1.27–2.13 ms for single-event ingestion; see the implementation plan for fixture sizes and batch timings. These tests did not deploy Render or approve this laptop's pending hooks.

Deploy the matching control-plane, edge, interceptor and all distributed launcher engine copies. Existing installed binaries are not changed by editing this repository. Upgrade/restart the installed daemon, then verify with an unapproved-hook Codex session: process presence should appear first; a broker/MCP/shim operation should add that layer's evidence; no prompt is expected until a supported approved hook submits one. Verify freeze and outage/reconnect independently. Keep the server signing key stable across deploys.

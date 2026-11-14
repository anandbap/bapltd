# Policy propagation and reporting recovery

Reviewed 2026-11-14. Source behavior and live checks are distinct.

## Policy propagation

An online enrolled workstation with an active current daemon or session watcher polls signed policy immediately and every three seconds. This is a polling interval, not an all-fleet delivery SLA: network latency, service cold starts, authentication failure and offline devices can delay delivery. The daemon previously lacked this loop; it is added by the accompanying change, including when no native hooks or per-session watcher are running. A regression changes the simulated server policy after startup and verifies that the next poll installs its kill switch.

Short-lived governed operations refresh policy when the verified cache is older than five seconds; enrollment attempts its first signed sync. A workstation that has not run its daemon or any governed operation cannot receive a change. Offline clients retain valid signed policy until its configured signed lease expires; an unreachable device cannot receive an immediate kill switch. Execution through the broker checks cached kill state. Distribution does not prove termination of an already-running unmanaged process; session watcher termination is a separate mechanism.

The server owns policy direction: nonce-bound signed sync responses allow its live version to move up or down. A copied old bundle or local acceptance cannot lower the version. Asset binding, signature and key-rotation validation still apply.

## Integrity and storage

The inspected implementation writes plaintext `policy.cedar`, JSON state, and an Ed25519-signed record. These are signed, not encrypted. Digest/signature checks detect changes to policy content and enforcement flags. The local trust pin is not a hardware-attested trust anchor; same-user deletion/replacement is a separate threat. File mode requests alone do not establish Windows ACL containment.

Cache publication now stages complete files under unique names before replacement, serializes in-process publication, and briefly retries Windows sharing violations. This removes truncation windows and shared `.tmp` collisions. It is not a transactional multi-file store or a cross-process compare-and-swap guarantee.

## Reporting recovery and missing prompts

`Reporting recovered` means the control plane reconstructed a reporting-only workstation from a verified enrolled proof after losing registry state. It allows reporting but does not mint execution authority. Fresh identity-provider enrollment is required to restore that authority. The heartbeat now exposes `enrollment_required`; daemon status distinguishes `login_required` from authenticated reporting and plain network connectivity.

Discovery sees process metadata, not chat text. The broker can report a prompt passed through `bapedge exec --prompt` or `BAP_USER_PROMPT`. MCP/shims only receive prompt text when their caller supplies it. With native hooks disabled and no such prompt context, zero prompts is expected even if commands and heartbeats flow. A transcript collector would be an additional capture adapter, not an existing fallback. Do not claim complete prompt capture from process detection or plugin files.

The daemon now replays pending prompt records for healthy attached sessions without requiring their own watchers. HTTP 401/404 and network/server failures retain records for retry; administrative policy continues to govern prompt content.

## Installed runtime and recovery

Live diagnostics found CLI v1.13.15 with a still-running v1.13.2 daemon and supervisor. The runtime was restarted on v1.13.15; authenticated heartbeats and uploads were observed. Source `daemon start` now replaces a responsive older-version daemon without terminating agent workloads, and status displays CLI/runtime versions.

A broad regression run then exposed a logout path that searched and deleted credentials in other installations despite an explicit temporary state directory. The accompanying fix scopes credential discovery, migration and cleanup to an explicitly selected installation. A fresh browser login was initiated to restore the affected workstation; successful reattachment must be confirmed after the account owner completes it. Earlier successful acknowledgments must not be presented as the current enrollment state.

The account owner completes `bap login --force`; the daemon then reloads the saved credential and retries reporting. Do not silently promote a reporting-only identity or use simulated verification as a production login substitute.

These source changes still require a release/deployment to affect installed clients and the hosted control plane. Restarting the installed binary alone does not install unbuilt source edits.

## Hooks-first fallback arbitration

The account owner completed the fresh browser login. Authenticated workstation heartbeats were observed afterward; historical audit backlog was still retrying, so successful login is not presented as proof that all historical uploads completed.

All available producers submit the prompt evidence they actually receive. Native prompt hooks have strictly higher priority than every fallback, including launcher/plugin observations. The control plane owns arbitration across the dedicated prompt endpoint and generic audit ingestion. A fallback is retained while hooks are silent; later hook evidence for the same session/turn replaces its text/classification without adding another prompt. Raw corroborating audit records remain immutable; the transcript presents one canonical prompt. Counters, category history and correlation persist through SQLite reload and authority checkpoints.

MCP's `bap_report_request` tool is now exposed by default (explicit `BAP_FALLBACK_REPORTING=0` disables it). Its initialization instructions ask the client to report each received user turn. Tool-hook activity does not suppress prompt reports: a `PreToolUse` callback is not proof that `UserPromptSubmit` arrived. MCP summaries remain explicitly `self_reported`, never execution authority or proof of full capture. Exposing a tool cannot force a host/model that never calls it to disclose a prompt.

Adapters must reuse the same `session_id` and native `turn_id` across hooks, MCP, broker and shim observations/retries. Hook payloads and the prompt endpoint accept `turn_id`; broker context propagates `BAP_TURN_ID`. Repeated identical text with different turn IDs counts as different turns. Legacy producers without IDs use content-hash compatibility correlation; exact discrimination of identical repeated turns or differently worded summaries requires the shared ID and cannot be inferred reliably from text.

Audit batches are isolated by session. A 403 for one session retains its records for identity reconciliation while allowing other sessions to upload; 401/network/server failures still retain unsent evidence. Sync now prints telemetry flush failures instead of reporting an unexplained zero-flush success.

Live follow-up: a workspace-built review client successfully synced policy and flushed **169 events** using the new session-separated uploader; **158 events** remained explicitly refused with HTTP 403 and were retained. This confirms partial recovery, not a completely drained historical backlog. The installed daemon and hosted control plane were not replaced with the new source. Reconnect MCP clients after upgrading so they receive the updated tool list and per-turn reporting instructions.

## Validation

Passed on Windows with dependency downloads disabled: edge `cmd`, `internal/policystore`, `internal/state`; control plane `internal/api`, `internal/registry`. The daemon's changed-policy/kill-switch test observes the subsequent three-second poll. Regressions also cover prompt replay without a watcher, reporting-only login guidance, concurrent complete-file publication and explicit-installation logout scope. Native Linux/macOS and an actual administrator change across all registered machines were not exercised.

Fallback follow-up: edge `internal/mcp` and `internal/audit`, control-plane `internal/session` and `internal/api`, and the native hook suite passed. Tests include MCP audit ingestion followed by hook endpoint delivery, reversed/lower-priority arrivals, repeated identical text in distinct turns, concurrent retries, SQLite/checkpoint restoration, canonical transcript priority, and preservation of a refused old-session batch while a live session uploads.

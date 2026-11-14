# Independent layer reporting

Reviewed 2026-11-14. See [architecture](../ARCHITECTURE.md), [prompt arbitration](LAYERED_FALLBACK_REPORTING_DESIGN.md) and [privacy](TELEMETRY_PRIVACY.md). This contract describes evidence a boundary actually receives, not a serial chain of guaranteed fallback interception.

## Identity and destination

Installation provisions components; enrollment establishes workstation proof and its control-plane origin. Hooks are not a prerequisite for the daemon to report received evidence. Protected reporting requests use enrolled proof, and the server binds session ownership to that proof.

A hostname, email, session ID or source label in a body is not ownership proof. Gateway ingestion uses a separate service identity. Source checkout changes must be built and deployed before an installed runtime implements them.

## Boundaries

| Boundary | Available evidence | Missing evidence / limit |
|---|---|---|
| Native plugin/configuration hook | Supported lifecycle, prompt and tool callbacks | Installed files do not prove approval, invocation or complete callbacks. Decision-only hooks do not contain execution. |
| MCP | BAP tool calls and cooperative request reports | Built-in tools/other servers do not automatically pass through BAP. A model summary is self-reported. |
| Terminal shim | Commands actually resolving through the shim | Absolute paths and other process routes can bypass PATH. |
| Broker | Received command/context, decision, result and selected process lineage | No chat text unless supplied. Legacy containment and parser limits remain. |
| Gateway | Requests reaching its protected resources and their verdicts | Not universal desktop egress or backend completion proof. |
| Passive discovery | Recognized process/PID/birth metadata and presence | Does not read agent memory, environments or arbitrary transcripts; never an execution grant. |

Native plugins and configuration hooks are two integration surfaces within the callback layer, not proof that two independent enforcement boundaries ran. A short-lived callback cache is not a general exactly-once execution protocol.

## Prompt selection

All producers submit the prompt evidence they receive. The control plane correlates by session/turn, prefers hooks, and keeps fallback evidence while native prompt callbacks are absent. A later hook report can upgrade the canonical prompt without another logical prompt count. Raw corroborating audit records are retained.

MCP `bap_report_request` is exposed by default in current source; explicit `BAP_FALLBACK_REPORTING=0` disables it. Initialization instructions ask the client to call it per turn. BAP cannot force a host/model to call a tool it ignores. A recent tool-hook heartbeat does not establish delivery of a prompt callback.

Exact deduplication needs the same native turn ID in each source. Broker context can carry `BAP_TURN_ID`; hook/prompt payloads accept `turn_id`. Hash-only legacy reports cannot reliably distinguish identical repeated turns or differently worded summaries. Reporting does not override the signed administrator prompt-capture setting.

## Delivery, storage and recovery

Received events are persisted before bounded live delivery. The daemon has a bounded queue and eight delivery workers. A full queue relies on the spool rather than claiming successful upload. Prompt retry envelopes and audit/recovery journals are different stores.

Immediate send, retry and recovery replay preserve the source label. Central hash versions bind the supported identity/reporting fields while preserving legacy verification. A hash chain is retained-record tamper evidence, not completeness or a device attestation.

Current-source session-separated uploads keep an identity refusal for an old session from blocking unrelated live sessions. Refused evidence remains attributed to its original identity and retained for reconciliation. An acknowledged non-durable upload has a retained recovery copy; `durable:true` is a separate server/storage contract.

Reporting-only recovery does not clear administrative restrictions or reissue execution authority. Enrollment renewal requires a valid authentication flow, not an agent asserting an owner.

## Coverage and timing

Coverage describes received layer evidence; liveness describes recent check-ins. Neither proves every action was intercepted. An absent callback cannot uniquely identify disabled hooks, pending approval, an unsupported client or a stopped integration.

| Mechanism | Default interval |
|---|---|
| Policy poller in watchers/current-source daemon | 3 seconds |
| Daemon session/workstation heartbeat | 4 seconds |
| Named-process observation | 10 seconds |
| Prompt/audit retry scheduling | Watcher/daemon path dependent; daemon spool worker uses 5 seconds |

Network delays, authentication, server state and backlog affect delivery. These intervals are not a freshness SLA. Native macOS discovery/integration acceptance and complete fleet capture are not established here.

## Acceptance

Verify the actual installed versions, real IdP login, current daemon readiness, authenticated heartbeat and central upload acknowledgment. Then exercise approved native callbacks and an unapproved-hook session separately. A lower layer should report only what it receives; prompts require supplied context or an actual prompt callback.

Confirm retries do not inflate counts, late hook evidence wins, a distinct turn with identical text remains distinct, and ownership refusals preserve evidence. Test outage/reconnect, signed-policy expiry and freeze behavior independently. Full native/client acceptance remains distinct from source fixtures.

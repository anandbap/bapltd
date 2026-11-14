# Hooks-first prompt fallback design

Status: **implemented in the current working tree; deployment/native-client acceptance pending**.
Reviewed 2026-11-14. This replaces the older proposal that suppressed fallback based on any recent hook activity.

## Contract

Every boundary may report the prompt/context it actually receives. Native prompt hooks are preferred. If those callbacks do not arrive, MCP, broker, shim, launcher or SDK evidence can fill the gap. Reporting priority is independent of authorization.

No layer can invent observation of chat text it never received. Discovery is process metadata. MCP summaries remain `self_reported`. A tool definition or initialization instruction cannot compel an uncooperative host/model to call it.

## Identity and correlation

| Field | Meaning |
|---|---|
| `session_id` | Workload correlation within authenticated workstation ownership |
| `turn_id` | Native user-turn identity shared across transports and retries |
| `prompt_hash` | Content identity/legacy compatibility; not unique user-turn identity |
| `reporting_layer` / producer | Observation source, not authority |
| `event_id` | Delivery/ledger replay identity; distinct from logical-turn identity |
| `evidence_grade` | Observation provenance label; never permission |

For the same session/turn, source preference chooses a canonical prompt. Hooks strictly outrank every fallback. Existing relative priority among other layers is defined in [coverage.go](../bap-controlplane/internal/session/coverage.go). Gateway evidence has independent resource scope.

Distinct native turn IDs preserve identical text submitted twice. A report without a turn ID can corroborate known content through its hash. Exact matching between differently worded summaries or identical repeated turns cannot be inferred from a content hash. Adapters must propagate the native ID for the full contract.

## Source paths

| Component | Implementation |
|---|---|
| Native callback `turn_id` propagation | [cchook/interceptor.go](../cchook/interceptor.go) |
| Broker context `BAP_TURN_ID` | [exec.go](../bap-edge/cmd/exec.go) |
| MCP reporting tool / local retry gate | [report_request.go](../bap-edge/internal/mcp/report_request.go) |
| MCP tool exposure and instructions | [server.go](../bap-edge/internal/mcp/server.go) |
| Common session counting and promotion | [prompt_observation.go](../bap-controlplane/internal/session/prompt_observation.go) |
| Canonical transcript projection | [prompt_view.go](../bap-controlplane/internal/session/prompt_view.go) |
| Prompt endpoint and generic audit ingestion | [handlers.go](../bap-controlplane/internal/api/handlers.go) |
| Checkpoint persistence | [checkpoint.go](../bap-controlplane/internal/session/checkpoint.go) |

MCP reporting is default-on in current source; an explicit `BAP_FALLBACK_REPORTING=0` disables it. The tool schema requests a summary and turn ID. Legacy missing-ID calls retain qualified content-hash compatibility. Do not suppress reports because `PreToolUse` or another unrelated callback touched a heartbeat.

A successful local MCP report means its evidence was persisted for delivery/retry, not necessarily acknowledged centrally. Failure to persist returns an error and releases the local dedup reservation so retry is possible.

## Ingestion and selection

```mermaid
sequenceDiagram
    participant MCP as MCP / other fallback
    participant CP as Control plane
    participant Hook as Native prompt hook
    MCP->>CP: Session + turn ID + received summary
    CP->>CP: Count one logical turn; retain fallback
    Hook->>CP: Same session + turn ID + prompt
    CP->>CP: Promote canonical text/category; do not add a turn
    MCP->>CP: Retry or corroboration
    CP->>CP: Keep hook primary; do not add a turn
```

Both the prompt endpoint and prompt/context carried in audit events use session-locked correlation. New turns update prompt counters/category history. Higher-priority evidence can promote a previously counted turn. A delayed older-turn retry must not replace the active newer prompt. Correlation is persisted through the tested SQLite and authority-checkpoint paths.

The audit ledger retains corroborating input records. Derived transcript views present one canonical prompt and preserve original command actions. Prompt deduplication does not prove exactly-once command execution or complete cross-layer operation identity. Command correlation still includes heuristic behavior and must be described separately.

## Privacy, failures and limits

The administrator's signed prompt-capture mode controls content. Hashes and classification can still be identifying metadata. Generic metadata mode does not automatically suppress prompt text; the default prompt mode is `required`.

Authentication/ownership failures must not rebind evidence to a new owner. Audit uploads are session-separated so a 403 for one session preserves that session's evidence without stopping unrelated uploads. Network/server failures retain unsent records. Prompt spool replay does not require a dedicated watcher in current daemon source.

Same-user tampering, fabricated summaries, a model skipping MCP reporting, absent callbacks, mismatched session/turn IDs and unsupported hosts remain limits. A source label called `hook` is not itself independent cryptographic proof that a vendor callback ran.

## Verification and rollout

Tests cover fallback-to-hook promotion, lower-priority late arrivals, identical text in distinct turns, concurrent retries, session separation, SQLite/checkpoint restore, canonical transcript selection and the mixed MCP-audit/native-prompt API path. Native-hook, edge command, MCP/audit and central session/API suites were exercised during this change.

Deploy matching edge, hook and control-plane builds. Restart/reconnect existing MCP clients to obtain the updated tool list and instructions. Validate actual native turn-ID propagation and received callback evidence for each advertised host. Source tests do not complete that rollout.

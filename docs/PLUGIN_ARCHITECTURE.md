# Agent plugins and native callback adapters

Reviewed 2026-11-14. [Architecture](../ARCHITECTURE.md) defines the component boundaries; [execution](EXECUTION_MODEL.md) and [reporting](INDEPENDENT_LAYER_REPORTING.md) define their actual guarantees.

## Integration is conditional

BAP distributes client adapters/manifests for Claude Code, Copilot, Antigravity, OpenCode and Codex. Their presence in the repository or an installed plugin list does not prove that a particular client/version approved or invoked them.

A native plugin and a configuration hook are integration surfaces in the same callback layer. Do not describe them as independent kernel boundaries or infer that one automatically executes when the other is disabled. Vendor formats, supported callbacks, user approval and actual payload/response envelopes need native acceptance.

Relevant code and artifacts: [plugins](../plugins/), [interceptor](../cchook/interceptor.go), [Copilot adapter](../copilot/), [installer](../bap/bap_install.py), [launchers](../bap/launchers/).

## Callback responsibilities

| Callback/path | Available behavior | Limitation |
|---|---|---|
| Session lifecycle | Correlate start/end, report presence and arrange watchers where supported | Session IDs and source labels do not establish ownership without enrolled proof |
| Prompt callback | Receive prompt text/hash and classify/report it | Missing callbacks provide no prompt capture |
| Pre-tool callback | Check supported native operations or rewrite supported shell commands | A decision-only verdict does not execute or sandbox the original tool |
| Post-tool callback | Report supplied outcome metadata | Cannot attest effects absent from that callback |
| Launcher | Establish environment/session context and supervise configured runtime | Not proof that every host built-in tool is mediated |
| MCP/shim/broker | Report received fallback evidence independently | Only the calls/context actually received are covered |

Source-specific callback caches and delivery event IDs are not universal exactly-once command-execution guarantees. If both plugin and configuration hooks are active, qualify duplicate handling with the actual native host and matching adapter versions.

## Stable identities and prompt fallback

Enrollment supplies workstation ownership proof and the intended control-plane origin. Native session/turn identity should propagate across each adapter; broker fallback process identity is an alternative correlation mechanism, not a new human identity.

Current prompt arbitration prefers native prompt hooks. Other layers may send available prompt evidence even when tool hooks are active: a tool callback does not prove that the prompt callback arrived. The control plane counts one logical session/turn, promotes later hook evidence and retains corroborating records.

MCP reporting is cooperative and self-reported. It cannot read an agent's entire conversation merely because the server is connected. Exact cross-layer deduplication requires shared native turn IDs; hashes alone have compatibility limits. See [fallback design](LAYERED_FALLBACK_REPORTING_DESIGN.md).

## Trust and observed status

File presence, plugin installation, callback approval, process liveness and received evidence are separate facts. A stale hook copy can deny work that a newer copy allows. Check active copies and hashes, but do not claim the current doctor enumerates every vendor configuration automatically.

A source label or binary hash in a report is not independent hardware attestation. Local configuration is cooperative and same-user tampering remains a limitation. Neither installation nor elevated privilege supplies universal mTLS, host-wide interception or a kernel packet filter.

## Rollout and qualification

Deploy matching edge, interceptor and distributed adapter/launcher copies. Restart the actual daemon and reconnect MCP hosts after an update. Record the host version and observed callback sequence; configuration validity alone does not prove approval.

Verify one real prompt and tool operation, a blocked operation, a repeated delivery, a missing-hook fallback, separate identical-text turns, outage/reconnect and independent freeze behavior. Keep client-specific failures visible. Browser-to-edge temporary ZSP approval/resume, universal client parity and complete prompt capture remain open unless separately accepted.

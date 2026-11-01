# Shadow IT and MCP discovery in UI v3

Updated October 31, 2026. Status: bounded discovery implementation and automated validation complete; installed-fleet qualification and P3 authoritative persistence remain open. This is not a universal observation/enforcement guarantee.

## Implementation record

Implemented in `internal/discovery/inventory.go`, `internal/api/discovery_api.go`, edge `internal/discovery`/`cmd/discovery_worker.go`, native-hook `discovery_evidence.go`, installer registration and v3 `discovery.js`.

- Workstation report identity/owner comes from enrollment claims. Strict 1 MiB JSON reports allow at most 64 scopes/512 observations; legacy filesystem paths, environment maps and arbitrary finding metadata are rejected. Reads, triggers and dispositions require the existing admin gate. V3 uses auth headers without appending the admin secret to request URLs.
- Independent startup and periodic collection uses one daemon worker. Master heartbeat directives are consumed without executing scans inside the heartbeat worker. Requests for different workstations persist independently. Empty scans produce completion records; incomplete scopes cannot verify absence. A late replay cannot resurrect an asset after a newer complete absence check.
- Metadata collection supports project `.mcp.json`, `.vscode/mcp.json` (`servers` schema), `.cursor/mcp.json`, `.claude/mcp.json`, and user `.cursor/mcp.json`/`.claude/mcp.json`. The installer registers up to eight explicit workspace roots in `discovery-roots.json`. Paths/arguments/env values/URLs are not uploaded. Auth-bearing `.claude.json`, `.env`, generic home recursion and credential stores are excluded. Symlink ancestors, oversized/nonregular/malformed files are rejected as incomplete scopes. Unknown schemas are partial rather than verified clean.
- The default inventory cadence is five minutes plus jitter; the existing session/process observer still runs every ten seconds. Process **inventory** refresh follows the five-minute/directive scan cadence. Native MCP hook records are locally spooled immediately and delivered by a five-second background retry loop, with network timeouts. These reporting cadences are not a millisecond freshness promise.
- Known named agents use PID + birth identity. Claude native MCP callbacks record attempted/succeeded/failed/denied outcomes only when `tool_use_id` and session identity exist. Tool inputs/results are omitted. Inventory retains the latest observation per workstation/tool; run records preserve the individual operation evidence. Generic Python/Node attribution, encrypted/stdio decoding without an observer, and resource-policy receipt correlation remain unsupported.
- SQL transaction commit precedes cache mutation and ACK. Discovery reuses the configured session SQLite pool, including separate latest-scan state, persistent directives, stable multi-server assets and review/exception state. Explicit memory mode is labeled memory/non-durable; a configured SQL initialization failure makes discovery unavailable. No PostgreSQL migration or Render disk provisioning was performed. ACKs remain `durable:false`, so edge reports move to retained recovery history and replay after restart/server epoch changes. Retained reports recover inventory, **not** lost operator dispositions or security policy.
- V3 adds a separate home summary and Discovery & coverage tab, workstation links, server filters, 50-row pages with a dataset revision/cursor, safe text rendering, evidence drawer, scan requests, acknowledgment/reopen and exceptions expiring within 30 days. Admin-off/Demo clears Live discovery data. Scan status displays explicit completion/partial scope results, not a success toast on request acceptance. Summary refresh is 30 seconds and inventory is fetched on demand. Latest scan coverage is bounded to 100 workstations; full historical scan pagination/export, rich policy filters/approval catalogue and printable historical reports remain follow-up work.
- Inventory admission is bounded to 20,000 assets/2,000 workstation latest states; excess is rejected for edge retry. Delivery attempts at most 16 reports per pass with two-second request timeouts. Recovery journals intentionally retain non-durable reports; disk budgeting, compaction/retention and longer load qualification remain release work before broad deployment. The queue is not permission to discard evidence silently.

Validation: full local Go control-plane, edge and hook suites; JS controls/discovery contracts; six real-binary Python discovery integration cases including 20 enrolled concurrent workstations; real edge collector → control-plane failure/retry/state-loss/replay; SQLite reopen/disposition/lifecycle tests; isolated no-session daemon startup/directive test. No interactive refused-hook Claude session or Render deployment was exercised by these tests. Hosted race checks remain CI responsibilities on this Windows environment.

Local benchmark sample (20 iterations, Windows Ryzen 7 5700U): authenticated heartbeat at simulated fleet 1,000/10,000: ~0.22/~0.31 ms per handler request. Existing telemetry ingestion: ~1.0–1.4 ms single event and ~40–41 ms per 50-event batch. These are local microbenchmarks, not sustained throughput or network p95/p99 guarantees.

The following sections retain the original target design and acceptance requirements. Unimplemented target details above remain open rather than implicitly marked delivered.

## Agreed behavior

Workstation enrollment is the common reporting identity. The installed workstation daemon should collect supported discovery evidence even when an agent does not use the BAP SDK, MCP tools or starter. Participating integrations provide richer operation evidence; other collectors provide presence/configuration observations and explicit coverage gaps.

Do not infer that missing BAP mediation was deliberate. Show what was observed and the missing control. Finding a configured MCP server is not proof that it ran, finding a process is not proof that it called a tool, and neither establishes that an operation was blocked. An arbitrary custom program cannot always be identified as an AI agent from its executable name.

This plan adds discovery to the existing v3 experience. It does not replace the activity/workstation views, create another dashboard, or claim that discovery supplies mandatory OS enforcement.

## Current source findings

| Existing component | What is there | Exact gap |
| --- | --- | --- |
| `bap-controlplane/internal/dashboardui/web/index.html`, `VIEWS.rollout` | Classic rollout funnel and Unmanaged Shadow Agents panel | `S.shadow` is seeded; Enroll adds a browser-side agent and marks all five layers present. This is not a verified workstation remediation flow. Reuse the information design, not those data/actions. |
| `bap-controlplane/internal/dashboardui/web/v3.html` | Activity and Workstations tabs; session coverage displays discovered/evidence/unknown | No dedicated discovery inventory or calls to the existing discovery endpoints. `S.shadow` already means audit/shadow-mode counts; it must not become the discovery collection. |
| `bap-controlplane/internal/discovery/scanner.go` | Finding/report models, MCP config detection, bounded in-memory history and scan epochs | The server can scan its own environment/files; remote paths are inappropriate laptop inventory. Findings lack a full stable lifecycle, and multiple MCP servers in one config can collide under the current dedup key. State disappears on restart. |
| `internal/api/handlers.go`, shadow-it routes | Scan, trigger, findings and reports routes | The shown routes have no enrollment/ownership/admin wrappers. Report identity comes from client fields; reads use raw `writeJSON`. Add access control before exposing the data in v3. |
| `bap-edge/cmd/watch.go`, `performLocalClientShadowScan` | Session heartbeat can launch an asynchronous laptop scan for a new epoch | Depends on a participating session watcher. A bypassed client with no watcher should not disable workstation discovery. Only nonempty findings are uploaded; a clean/failed/not-run scan cannot be distinguished. Failed uploads have no discovery-specific durable replay. |
| `bap-edge/cmd/daemon.go` | Workstation heartbeat, delivery and session workers | Workstation heartbeat ignores scan directive response content; it does not own the existing shadow scan lifecycle. |
| `bap-edge/cmd/agent_observation.go` | Named process observations independent of hooks | These become audit/session presence, not the canonical shadow finding inventory. Generic Python/node processes are intentionally not identified as agents by name alone. |
| `cchook/interceptor.go` | All-tool pre-hook matcher, shell/file checks and evidence paths | Non-shell MCP calls may be permitted generically without an operation discovery record. Add explicit MCP observation/pre-post handling; observing a callback must not claim BAP resource authorization. |
| `internal/httptransport/identity.go` | Enrollment proof added to selected edge reporting paths | Discovery submission is not included in that authenticated path selection. Extend transport and server validation together. |
| `bap-edge/internal/scanner/addon_scanner.go` / `bapedge scan` | Separate add-on/content security scanner | Not the same as independent workstation MCP/process discovery; do not label a local content scan a completed fleet inventory scan. |

Additional correctness issues: management is inferred from command substrings containing `bapedge`/`bapmcp`; raw MCP command arguments and secret previews can enter finding details; bounded-array replacement can leave stale finding-index entries. These must not become the new UI's source of truth.

## Information model: keep independent facts separate

Each asset row has four axes:

1. **Evidence:** configured, running, invocation observed. Each level cites its own source/time; do not infer the higher level.
2. **Mediation:** BAP policy enforcement observed, observation only, or not observed/unknown. A source label or process name alone cannot establish policy enforcement.
3. **Approval:** approved, unreviewed, exception or disallowed, derived from an authoritative operator/catalogue policy. Non-BAP does not automatically mean malicious.
4. **Freshness:** current, stale, offline/unknown, with last scan/observation and errors shown separately.

Inventory is not limited to open findings: include approved/BAP-associated and unreviewed assets so the UI can explain what was examined. Report collection scope/limits; zero open findings is not zero blind spots.

Stable identity:

- Workstation owner/instance comes from authenticated enrollment claims, never hostname/email or the report's `agent_id`.
- MCP asset key includes workstation, approved config scope/path, server key and transport. Two servers in the same file remain separate assets; configuration revisions keep history rather than changing the identity at every scan.
- Process presence uses workstation + PID + process birth and supported application evidence. A reused PID is a different process.
- Operations use native tool-use/operation/trace IDs and event IDs; config/process findings never increment action or allowed/denied counts.
- Store first seen, last seen, last complete scan, configuration revision, evidence source, confidence where inferred, finding disposition, operator/reason, and any actual enforcement receipt.

## DISC-1. Secure and narrow discovery APIs

Keep existing route names where compatible, with an explicit versioned report schema:

| Route | New contract |
| --- | --- |
| `POST /api/v1/discovery/shadow-it/scan` | Enrolled workstation report ingestion only; bounded sanitized observations/completion records; strict JSON; derive owner from proof. No arbitrary server-side `workspace_root`, `config_paths` or environment values supplied by remote callers. |
| `POST /api/v1/discovery/shadow-it/scan/trigger` | Authenticated operator request for selected workstation IDs or an explicit fleet scope. Return queued request/epoch, not scan complete. Audit actor and targets. |
| `GET /api/v1/discovery/shadow-it/findings` | Authorized, redacted, server-filtered and bounded cursor pagination; workstation/type/state/evidence/freshness filters. Stable snapshot semantics. |
| `GET /api/v1/discovery/shadow-it/reports` | Authorized paginated scan status/history, including clean, partial, failed, unsupported and offline targets. |
| `GET /api/v1/discovery/shadow-it/summary` | New lightweight summary for v3: fresh/stale/not-scanned workstation counts, findings by state/type and data availability. No raw sensitive details. |

Use authenticated observer/team scope for reads as that role ships; until then use the existing authenticated operator gate, not anonymous raw findings. Administrator mutations remain separate from read access. Gateway collector identity cannot impersonate a workstation discovery collector.

Extend exact-origin/HTTPS-bound edge identity transport to report ingestion. Reject forged workstation/asset ownership and cross-origin redirects. Do not permit an operator/UI request to read arbitrary files on Render. Keep synthetic local-scanner tests behind isolated test interfaces, not a public scan-your-server endpoint.

Generate safe details server-side from typed fields. Do not accept arbitrary free-text metadata as an authorization or governance claim. Never serialize secret values, secret prefixes, environment contents or unrestricted MCP command arguments. Remove existing preview behavior from this production reporting path; redact legacy records before display or migration. Scope the initial feature to approved MCP configuration/process metadata, respecting prohibited credential-file access.

Gate: anonymous/foreign-workstation ingestion fails; unauthorized trigger/read fails; malformed/oversized reports fail; secrets and forged managed flags cannot reach UI, journal, log or database.

## DISC-2. Move scan ownership to the workstation daemon

Implement one bounded workstation scan scheduler, independent of active agent sessions:

- Run an initial scan after enrollment/daemon startup, then a configurable periodic scan; proposed pilot default five minutes with jitter. Reuse the existing ten-second named-process observer for faster supported process presence. These cadences are proposed settings, not current fleet guarantees.
- Consume directives on the master workstation heartbeat, maintain a durable pending epoch, and acknowledge completed/uploaded epochs correctly. Do not mark an epoch done before a scan/upload succeeds. A directive arriving during a scan must remain pending.
- Scan only approved local configuration locations and enrolled workspace roots. Use client/schema-specific parsers, including the relevant Claude Code project configuration; the current watcher misses some locations and assumes one MCP JSON shape for different clients.
- Collect sanitized asset inventory without starting discovered MCP servers or executing their tools. Respect file type/size/root boundaries and unsupported/permission-denied paths. Never turn this into an unrestricted disk, credential-file or process-environment scan.
- Emit an explicit completion record even with zero assets/findings, including requested scope, completed/skipped/error scopes, scanner version, run ID, epoch and duration.
- Persist sanitized report chunks/completion records before sending, retain until a valid acknowledgement, and replay idempotently through bounded delivery. Preserve the same run/event IDs on retry.
- Retire watcher-owned duplicate scans after daemon capability negotiation; older clients remain explicitly legacy/partial. Avoid one scan per session and network waits inside heartbeat/session locks.

An interrupted/partial scan cannot resolve old findings. For chunked runs, mark completion only after all expected chunks have been admitted. A pending upload is not a failed scan, and an offline workstation is not clean.

Gate: discovery reports supported assets with all native hooks disabled and no agent session watcher; clean scans are acknowledged; offline/failed upload recovers without duplicate rows or a lost rescan directive.

## DISC-3. Observe runtime MCP use where an actual source exists

Bridge existing process observations into inventory. Distinguish configured-not-running from currently observed runtime presence. A generic Python/node executable is only an unclassified candidate unless a supported collector, declared workload or other concrete evidence identifies it.

Add explicit native MCP hook handling for supported clients: record server/tool identity and pre-tool attempt plus post-tool success/failure, correlated to the same operation. This can expose a third-party MCP call even when it did not use BAP's MCP server, provided the native observation hook actually runs. Store minimal permitted metadata, not unrestricted tool inputs/results. Record policy denials at the deciding boundary; do not require a post-execution callback for an action that never ran.

Correlate BAP MCP/broker/gateway evidence when present. A tool call observed by a hook is not automatically a BAP-authorized resource operation. No invocation evidence means unknown activity, even if a config or process exists.

When both SDK and native hooks are skipped, passive supported collectors can still expose configuration/process presence. Exact tool calls over unobserved stdio or encrypted connections require a suitable client/proxy/OS collection boundary. Network/process metadata alone must not be displayed as a decoded MCP invocation. This limitation remains visible until the mandatory workstation observation/enforcement workstream supplies the missing source.

Gate: a third-party MCP tool invocation with an active native hook appears as observed-only unless actual BAP policy enforcement is evidenced; the same setup without that hook remains configured/running with invocation visibility unknown. No unseen prompt or operation is fabricated.

## DISC-4. Persist inventory, scan status and disposition

Use the leadership plan's authoritative PostgreSQL persistence work, not another database project. Persist assets/evidence, scan runs/chunks/scopes and epochs, finding lifecycle, exceptions and operator actions. Link actual observed-operation IDs to the canonical event model.

Replace random per-scan identity, path-only deduplication and mutable bounded-array replacement with stable indexed keys and pagination. Preserve all server entries in a multi-server file. Maintain first/last seen history; findings become not seen/resolved only after an applicable complete scan verifies the relevant scope. Missing permissions or failed scanning cannot prove remediation.

Acknowledged, approved exception and resolved are different states. An exception must retain owner/reason/scope/expiry and remain visible as an exception, not become verified BAP mediation. An approval/name change cannot silently mint a workload identity/grant or enroll an unmanaged process.

Gate: duplicate delivery/scan retries are idempotent; server restart preserves inventory and disposition; clean/partial scans produce correct lifecycle transitions; a stale index cannot overwrite a different asset.

## DISC-5. Bring the capability into v3 with focused additions

### Home / AI Agent Activity

Add a compact **Discovery & coverage** card: open findings, workstations with fresh scans versus the expected roster, stale/not-scanned count, and a link to the inventory. Put actionable findings in a separate Needs attention group. Do not add them to step-up approval counts, risky-actions-stopped totals or execution counts.

Example: **3 unreviewed MCP configurations on 2 workstations. 18/20 workstations scanned recently; 2 have unknown inventory.** Each number has its own defined denominator and drill-down.

### Workstations

Add finding count, scan freshness/result and a **View discovery** link filtered by verified workstation instance ID. The detail view shows discovered applications/MCP assets, last observed evidence per layer, missing hooks/SDK signals where known, and scan limitations. Registration/healthy heartbeat must not imply that all agent layers are active. Replace the existing blanket “Active & Governed / Layer 1-4 active” copy with observed reporting/coverage language.

### New third tab: Discovery & coverage

Use the existing v3 visual style and table/drawer patterns:

- Columns: asset/server, workstation/assigned owner, evidence level, mediation/approval state, risk with reason, first/last seen and available actions.
- Filters: workstation, supported client/asset type, configured/running/call-observed, approval/mediation state, severity and freshness. Search only sanitized fields.
- Drawer: precise evidence, collection source/time/scope, related operations where actually known, uncertainty and remediation guidance. Do not show raw tokens, credential prefixes or secret-bearing arguments.
- Reader actions: inspect evidence and approved onboarding instructions. Operator actions: targeted rescan, acknowledge, record a justified exception, and request the real onboarding/remediation workflow. These actions persist and are audited.
- Show queued -> running -> uploaded/complete/partial/error and workstation completion counts for rescans. No completion toast merely because the trigger endpoint returned 200.
- Show Block/Freeze only when a real enforcing capability and correct target exist. Workstation freeze currently restricts BAP-governed authority; it must not promise to terminate an arbitrary discovered process. Never revive the old browser-only Enroll action or mark all five layers active after a click.

State and data handling:

- Add `S.discovery` or a separate discovery module. Leave v3's existing `S.shadow` audit-mode counter intact.
- Add one lightweight summary read to the established live refresh; fetch bounded finding pages only when needed. Use indexed/cached summaries, cancellation/stale-response protection and bounded parsing. Do not download the whole inventory every eight seconds or run scans on each UI poll.
- Retain last successful data with a stale/error indication when discovery fails; a partial API failure must not erase working agent/session data or show zero findings as clean.
- Empty states distinguish **no findings in completed scopes**, **not scanned**, **partial scope**, **offline/stale**, **unsupported** and **permission denied**.
- Demo fixtures are confined to Demo mode and explicitly labeled; they cannot populate Live findings or mutate real enrollment state. Escape all discovered names/details as untrusted display content.
- Include scan coverage/freshness and unresolved findings in the existing printable leadership summary, with evidence references and scope limits.

Gate: v3 shows real workstation findings and honest coverage; counts/filters/pages reconcile; public/unauthorized users cannot reveal sensitive data or mutate state; audit-shadow counts and existing freeze/session controls do not regress.

## DISC-6. Acceptance matrix and rollout

Use synthetic config contents, private temporary profiles and a dedicated test collector. Do not run the existing broad scanner against real credential files to validate this feature.

| Scenario | Required result |
| --- | --- |
| Enrolled workstation, hooks/SDK/starter unused | Supported config/process discovery still reports through the daemon |
| Two MCP servers in one config | Two stable distinct assets; repeat scans do not duplicate them |
| Filename/command contains the word BAP | No automatic proof of managed/enforced status |
| Configured server never launched | Configured evidence only; no claimed tool invocation |
| Third-party MCP invoked with native hook active | Actual correlated observation; no invented policy grant or enforcement claim |
| Same MCP with no runtime collection source | Presence/config inventory plus explicit invocation visibility unknown |
| Clean, permission-denied and interrupted scans | Distinct results; only applicable completed scans can verify absence/remediation |
| Offline upload, daemon crash, server redeploy | Durable replay, stable identity, retained dispositions and no duplicated counts |
| Forged workstation, anonymous report/read, ordinary user trigger | Rejected without state mutation or sensitive disclosure |
| Secrets in config arguments/env/URL; HTML in server name | Secret material never persisted/displayed; text cannot execute in the browser |
| Discovery API fails while sessions work | Discovery stale/error; sessions and existing controls continue correctly |
| More findings than one page | Complete stable traversal with no omissions/duplicates, including concurrent arrivals |
| Twenty workstations / forty sessions / repeated trigger | At most one scan worker per workstation, bounded resources, no heartbeat starvation |

Implementation order: DISC-1 security/schema -> DISC-2 daemon collection -> DISC-3 supported runtime evidence -> DISC-4 durable lifecycle -> DISC-5 v3 wiring -> DISC-6 deployed acceptance. UI layout can be developed against explicit fixtures while backend work proceeds; Live enablement must wait for authenticated data and truthful scan states. Do not claim durable fleet discovery before the persistence gate.

This is part of P1/P2/P3/P5 in the leadership pilot plan, not a parallel product. Mandatory workstation prevention remains a distinct capability; discovery reports what avoided instrumentation where observable, and accurately records the remaining blind spots.

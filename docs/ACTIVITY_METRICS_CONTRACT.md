# Live activity metrics, version 2

Implemented October 31, 2026. Observed activity is not employee productivity or verified business completion.

Both `/api/activity/summary` and `/api/v1/activity/summary` return `metrics_version: 2`, `mode: "live"`, `simulated: false`, timestamp, availability reasons and measurement scope.

| Field | Definition |
| --- | --- |
| `active_session_count` / `total_active_agents` | Active sessions reporting within 45 seconds; not protected agents or work items. |
| `process_only_active_sessions` | Active sessions with discovery as their only recorded reporting layer. |
| `observed_session_users` | Distinct normalized authenticated email identities on retained sessions; not the expected roster or coverage percentage. |
| `session_operation_records` | Sum of retained session operation counters. Process presence is excluded; cross-layer unique-operation reconciliation remains P2. |
| `allowed_operation_records`, `denied_operation_records` | Recorded decisions. Allowance does not prove successful execution; denial does not prove a unique high-risk incident or prevented loss. |
| `operation_allowance_percent` | Allowed / recognized allow+deny decisions; null for an empty denominator. This is not governance coverage. |
| `activity_records_retained`, `activity_allowed_records`, `activity_denied_records`, `activity_unknown_decision_records` | Separate bounded feed counts, currently up to 1,000 records. Never added to session counters: the same operation may appear in both. |
| `unlinked_activity_records` | Feed records whose session is absent from the retained session set; a data-quality signal. |
| Category, department and platform distributions | Current active-session distributions. Intent/prompt classification does not infer work from agent names; unknown department is explicit. Percentage rounding can differ from 100. |

Legacy keys remain present but return **JSON null** in Live: `active_work_count`, `completed_work_count`, `work_intents_completed`, `estimated_assisted_hours`, `assisted_fte_equivalent`, `governed_percent`, `governed_agent_users`, `high_risk_prevented`, `business_units_active`, `category_trends`. Render unavailable, not zero, 100%, fixed trends or an event-count formula. The Go `ActivitySummary` type is the legacy/demo fixture model; Live consumers must use nullable representations for these fields.

Explicit Demo requests retain illustrative values and identify themselves as `mode: "demo"`, `simulated: true`. Keep test profiles/tenants separate from production; a shell flag is not trustworthy classification of historical data.

V3 displays measured denial records. Legacy v1/v2 no longer derive hours/FTE/governance from activity counts or invent Live trends/department shares. Unknown summaries render unavailable. Classic lifecycle progression is Demo-only. Chain verification reports retained hash-chain integrity; compliance is not assessed, collection completeness is unknown, and Merkle integrity is not evaluated by that endpoint.

## Delivery and isolation

Immediate delivery and spool flush retain/report `go test`, `pytest`, `python -m pytest`, `npm test`, filenames such as `test_leak.py`, and source names containing `test`. No command/source substring causes silent deletion. Server local-journal rendering also retains them.

`BAP_TEST_MODE=1`, `LTD_TEST=1`, or `BAP_ENV=test` may suppress delivery only for **unenrolled, unlocked development fixtures**, keeping queued evidence. Enrolled or administrator-locked hosts ignore these flags for delivery. Authentication, master destination, verified ACK, retry and recovery retention remain unchanged. Tests must use private profiles/state and test servers/tenants; never reuse fixture journals for production enrollment.

## Validation and limits

Tests cover empty/partial summaries, overlapping session/feed evidence, unknown decisions/categories, null UI rendering, command/source preservation, test isolation, enrolled suppression prevention, and real edge → control-plane failure/retry/restart replay of `go test`. Full local edge/control-plane suites, UI contracts and seven Python persona/activity integration cases pass. Hosted race and actual Render/installed-client qualification remain release checks.

This does not implement PostgreSQL durability, a complete employee roster, cross-layer operation reconciliation, verified deliverables or measured productivity. Those remain P1–P5 workstreams.

# Delivery plan: leadership visibility for 20 people using Claude

Updated October 31, 2026. Status: P0 metrics/delivery corrections and bounded discovery implemented and locally tested; P1–P5 remain open. No deployed pilot acceptance is claimed.

## Goal and release boundary

For a named roster of 20 people in a controlled environment, show what supported Claude workflows are being used for, what activity occurred, what deliverables progressed, and what evidence supports each statement. Show incomplete reporting explicitly. Produce reproducible daily/weekly reports that survive deployments.

The first release supports one managed Windows baseline and one validated Claude Code workflow. CLI is the initial reference path; include the VS Code integration only after its prompt/tool/lifecycle callbacks pass the same acceptance matrix. Keep existing Codex/other-client compatibility tests, but do not expand this pilot into another adapter program. If the actual pilot roster needs another OS/client, treat that as an explicit scope change before onboarding it.

The pilot measures supported work and observed evidence. It does not establish all activity on every laptop, automatic work quality, employee productivity, hours saved, or universal prevention of unapproved OS actions.

Clarified requirement: the enrolled workstation must independently attempt supported shadow-agent/MCP discovery even when applications do not use hooks, SDK or starters. The [v3 discovery plan](DISCOVERY_V3_IMPLEMENTATION_PLAN.md) specifies that collector and UI. Existing supported non-Claude presence must remain visible; the Claude reference workflow does not justify hiding other observed applications. Mandatory workstation/resource enforcement is a core product workstream, and its missing capabilities must be tracked explicitly rather than assumed to be supplied by discovery.

## Findings that determine the implementation order

These findings were checked in the current source; they are not hypothetical future concerns.

| Finding | Current location | Required correction |
| --- | --- | --- |
| Live activity summary uses event counts as completed work/intents, estimates hours from event/agent counts, and returns fixed category trends | `bap-controlplane/internal/api/activity.go`, `handleActivitySummary` | Replace unsupported business metrics with unavailable/not measured; compute only defined metrics from appropriate evidence. |
| `go test`, `pytest`, and source names containing `test` can be suppressed; batch flush can remove matching records | `bap-edge/internal/audit/transmitter.go`, `Transmit` / `FlushOfflineAudit` | Report real testing activity. Isolate fixtures through explicit controlled test collection, not command-text guesses. Never silently delete real activity. |
| Governed percentage is calculated from the allowed-decision share, with a 100% default | `handleActivitySummary` | Separate allowance rate from reporting coverage. No denominator means unknown, not 100%. |
| Summaries combine session counters with activity records, allowing overlapping representations of the same work | `handleActivitySummary` | Count canonical operations/work items once; preserve multiple observations as evidence. |
| Missing department/risk information can be replaced with inferred/default values | `activity.go`, `sessionToActivityEvent` | Distinguish assigned, inferred and unknown data. Use the operator/IdP roster for team membership; do not present guesses as facts. |
| Session SQLite exists, but audit/registry/policy/governance stores retain substantial in-memory state; startup can fall back to memory after DB failure | `cmd/server/main.go`, store constructors | Implement durable authoritative stores and fail production readiness when they are unavailable. Merely setting `-db` is insufficient. |
| Action proposals already carry `TaskID` and lifecycle states; this is not a complete business-work progress pipeline | `pkg/types/governance.go`, `internal/governance/store.go` | Reuse correlation primitives; link sessions/operations to work items and independently identified result evidence. Do not reinterpret an action's `COMPLETED` state as a completed business task. |
| Hash verification endpoints contain broad compliance/security language | `internal/api/handlers.go`, `handleVerifyChain` | Return specific integrity results; remove unsupported certification and absolute-security claims. A valid chain does not prove complete collection or regulatory compliance. |

## P0. Correct the evidence contract before another leadership demonstration

Implementation record: [Activity metrics v2](ACTIVITY_METRICS_CONTRACT.md). Unsupported Live outcomes/capacity/coverage are null with reasons; session counters and bounded activity records remain separate datasets. Engineering test commands are retained/delivered; enrolled/locked reporting ignores test-mode suppression flags. V1/v2/v3 consumers and chain-verification claims are corrected. Local API/UI/delivery/restart and integration regressions pass. Unique-operation reconciliation remains P2; verified outcomes remain P4. Private test profiles/tenants and installed rollout qualification remain required.

Implementation:

- Remove fixed trends, event-derived completed-work totals, estimated saved/assisted hours and FTE equivalents from live reporting claims. Use explicit metric availability with a reason, and update API/UI contracts together; null/unavailable must not render as measured zero.
- Separate `operations_observed`, `operations_allowed`, `operations_denied`, `work_items_verified_complete`, and `coverage_status`. A denied operation is not automatically a high-risk incident or a quantified prevented loss.
- Remove command-name test suppression. Testing is legitimate engineering work. Isolate self-tests/demo records using a separate test tenant/collector or server-managed fixture classification, not a sender's untrusted flag or a command substring. Managed production collection must not silently lose events because a shell supplied a test-mode variable.
- Prevent demo queries/fixtures from entering production leadership datasets. Explicitly version metric definitions and exclude synthetic data in every reporting path, not just one frontend.
- Preserve the existing enforcement/authentication behavior; this phase fixes reporting semantics rather than granting authority.

Gate P0:

1. A real `go test`/`pytest` operation appears through immediate send, offline flush and restart replay.
2. Ten operation events do not create ten completed work items, saved hours or FTE claims.
3. A team with no valid observation denominator displays unknown coverage.
4. API and UI both reject unsupported metrics; no hidden live endpoint still supplies fixed trends or compliance claims.
5. Unit/contract tests include empty, partial, duplicate, replayed and synthetic datasets.

This is the first implementation batch. It does not wait for the database migration.

## P1. Make install/login a dependable reporting baseline

P1a is implemented and locally tested: [per-user startup, crash supervision and onboarding diagnostics](STARTUP_AND_ONBOARDING.md). Actual OS logon/reboot qualification, corporate SSO, the 20-person expected roster, release provenance and operator-validated native-client probes remain P1b gates. A locally healthy daemon is not full pilot readiness.

P1b-01/02 now implement [release hash/build checks and a native reporting-probe flow](RELEASE_AND_NATIVE_PROBE.md). The operator can verify matching components and correlate a fresh owned prompt/policy record with local callbacks. Automated fixtures validate the protocol; actual native-client approval, corporate SSO, approved release trust and OS acceptance remain open.

P1b-03a adds [server-configured roster/window check-in coverage](PILOT_ROSTER_COVERAGE.md) with admin V3 inspection. It supplies the expected workstation denominator. Deploying the actual roster, validating native reporting and persisting history remain open; this snapshot alone cannot qualify P1/P5.

Implementation:

- Maintain the master enrollment/configuration rule already introduced. Ship one signed/traceable client bundle containing matching edge, interceptor and launcher artifacts; record build commit and component versions centrally.
- Add the supported per-user Windows startup/supervision mechanism to installation. Define the guarantee as automatic reporting after user logon, including after reboot, and recovery after a daemon crash. Do not claim reporting while logged out unless a separately validated machine service provides it.
- Make onboarding verify the configured IdP, enrolled person/workstation, intended server, daemon health, and a real native prompt/tool/lifecycle probe. File presence is not a successful integration test.
- In this controlled pilot, require the selected native integration to be approved/configured through the client's supported operator flow. A user who does not approve hooks stays visibly partial/not ready; other layers still report available evidence. Do not silently approve hooks or report partial coverage as complete.
- Register the 20-person roster, assigned team/project and expected workstation identities server-side. Define expected reporting windows so an intentionally offline user is not incorrectly treated as a broken installation.
- Report expected configuration, last observed callback per layer, last successful upload, backlog size/age, build mismatch, and actionable errors. If the client cannot identify why hooks are absent, report not observed/unknown cause rather than guessing pending approval.

Gate P1:

- Two clean machines complete install/login without repository-local fixes; ordinary supported Claude work reports correctly.
- Reboot/logon and daemon-crash recovery work without another install/login or duplicate workstation identities.
- Hook refusal, expired identity, wrong destination and unsupported client each produce a visible partial/error state.
- Real production IdP verification is demonstrated. A signed local enrollment record alone does not prove that corporate SSO was correctly configured.

Mandatory workstation/resource protection is a core product requirement. A limited visibility pilot can qualify supported collection separately, but must explicitly expose missing observation/enforcement boundaries and cannot claim universal interception. The OS/resource enforcement workstream needs its own acceptance evidence; discovery and hook installation do not complete it.

## P2. Establish one coherent event and operation model

Implementation:

- Carry stable event, operation/trace, native-session, workstation and person identifiers. Reuse existing proposal/trace IDs where appropriate. Bind owner identity server-side to enrollment, not client labels.
- Keep one event ID per observation, and one operation ID per actual attempt. Propagate operation identity across hook/shim/broker routes so three observations of one execution count as one operation. Repeating the same command is a new attempt; do not deduplicate by command text.
- Distinguish policy check, execution start/result, resource-side result, prompt/intent and process presence. Prompt submission, heartbeat and discovered process are not executable actions or finished work.
- Add producer stream/sequence metadata, source event time, central receipt time, schema/build/policy version and capture availability. Define reconnect/gap handling; sequence values do not themselves prove unobserved actions never occurred.
- Preserve prompt-to-operation correlation where available. Absence of prompt text/hash is a supported partial record, not a blocker for other evidence.
- Keep current bounded queues, local journals, retry and hash verification. Expose failed persistence/drop conditions and disk pressure. Treat receipt/verification/durable commit as distinct acknowledgement properties.

Gate P2:

- One hook -> shim -> broker execution has one operation with its distinct supporting observations.
- Two identical commands remain two attempts. Ten retries of one event remain one accepted event.
- Out-of-order/late records do not change historical ownership or make an old session appear live.
- Scripted missing records are detected and reported; a complete scripted run reconciles known produced IDs against central accepted IDs.

## P3. Make authoritative history and security state durable

Decision: use one PostgreSQL database for the pilot's authoritative state. Keep in-memory stores for isolated unit tests and the existing SQLite implementation for explicit local compatibility; do not build two competing production persistence projects. Adapt existing stores behind repository interfaces, and migrate the session schema/data rather than creating an unrelated reporting database.

Render documents ephemeral service filesystems and recommends durable datastores for long-lived relational state. A local database filename alone is not a deployment persistence guarantee. See [Render's storage explanation](https://render.com/docs/faq#why-do-files-saved-to-my-services-filesystem-disappear). PostgreSQL transactions support the atomic updates required below; see [the transaction documentation](https://www.postgresql.org/docs/current/tutorial-transactions.html). This backend choice is a recommendation, not an already-provisioned service.

Persist:

- Workstation/person mappings, enrollment metadata and authoritative team assignments.
- Session identity/lifecycle/coverage and prompt metadata permitted by capture policy.
- Canonical events, accepted event IDs, operation correlations and chain sequence/hash/version.
- Policy versions, administrative actions, session/workstation/user restrictions and explicit restorations.
- Grant/consumption/revocation state needed for correct existing enforcement semantics; retain the current fail-closed restart behavior until the durable equivalent is verified.
- Work-item/evidence links and report definitions/snapshots introduced in subsequent phases.

Transaction boundary: validate authenticated ownership, admit the unique event, append its integrity link, update the corresponding projection/counter, and commit. Acknowledgement reports durable only after the configured database commit succeeds. Duplicates receive an idempotent acknowledgement without counting twice. Serialize the chain head through an authoritative database mechanism; independent application replicas must not invent conflicting chain heads.

Production startup/readiness must fail explicitly on DB/migration failure rather than announcing success with in-memory fallback. Edge cached policy and spooling continue under the established offline contract. Restore only the authority/security state that was durably recorded; do not relax epoch, usage or freeze checks to make recovery look seamless.

Gate P3:

- Kill the server immediately before and after commit/acknowledgement; reconcile every acknowledged event after restart.
- Redeploy while sessions are active: identity, restrictions, event history and report totals survive.
- Repeat/concurrent ingest cannot double-count, mix workstation owners or fork the integrity ledger.
- Freeze, restore and consumed-grant tests retain their security outcomes across restart.
- Migrations, backup restore and retention are exercised; document backup recovery objectives separately from process-restart durability.

Central persistence and startup supervision are promoted from deferred items to pilot requirements by this leadership-history goal.

## P4. Add minimal work-item correlation and evidence of progress

Do not build a new Jira replacement. Reuse the existing `TaskID` concept and add a small work record plus append-only associations/transitions.

Minimal work record: ID, title, owner/team/project, optional existing ticket URL/reference, work type, expected deliverable, state, state source, verification status and evidence references. Associate sessions and operations many-to-one with work; one task can span sessions/people, and one long session can switch tasks. Keep time-scoped/explicit associations so changing the current task does not relabel yesterday's operations.

Provide a lightweight work-start/work-switch interaction through the governed launcher/CLI or existing UI. Do not require a long form before every prompt. Automatically inferred work links remain labeled inferred until confirmed. Unassigned work stays in the report as unassigned.

Use these evidence levels:

| Evidence level | Example | Permitted statement |
| --- | --- | --- |
| Declared/inferred | User task selection, captured request or classification | What work was requested; uncertainty/source shown |
| Observed | Broker result, file action, commit/PR reference | The recorded operation/result occurred at that boundary |
| Verified outcome | Trusted CI result for a specific revision, approved review or confirmed deliverable | That specific milestone/completion criterion has supporting evidence |

Track work states such as started, blocked, validation observed, awaiting review and verified complete. An agent's claim that it is done is reported completion, not verified completion. A closed agent session does not close the work item. Do not invent a percentage-complete score from elapsed time or command volume.

For code work, link revision/PR, validation and review evidence to the same work ID. For research/documentation/other work, link an approved deliverable reference and human review. A successful local test command is evidence of that run; it is not automatically proof that the intended problem was solved. A document/commit hash does not alone establish quality or acceptance.

Start with manual references and the single source-control/CI workflow actually used by this team. Add a narrow read-only trusted integration for that workflow, using the approved service identity/network path. Do not implement a catalogue of ticketing and source-control integrations for the pilot.

Gate P4:

- Trace one real bug fix and one non-code task from request -> operations -> deliverable -> validation/review.
- Task switching and parallel sessions preserve correct associations.
- Ending a session, creating a commit, or an agent saying done cannot independently create verified completion.
- A second operator can inspect the cited evidence and reproduce why the report shows that state.

## P5. Ship a small leadership report, then qualify the pilot

Leadership view:

1. Roster and reporting: enrolled people/workstations, observed users, partial/unavailable coverage, freshness and backlog.
2. Work: assigned/unassigned work by project/category; classification source/confidence where inferred.
3. Progress: evidence milestones, blocked/review states and verified completions, with references.
4. Governance: observed attempts, actual policy outcomes and operator interventions, separated from productivity/impact claims.
5. Data quality: collection scope, unavailable sources, late data, synthetic exclusions and report watermark/time window.

Every number needs a defined unit, time window, denominator and drill-down to contributing IDs. Distinguish people, workstations, sessions, observations, operations and work items. Example: 18 of 20 expected workstation check-ins is a valid coverage metric; it is not 90% of every action on those laptops. Do not add user/email identifiers from different schemas into one undifferentiated unique-user set.

Generate reports from durable canonical data and bounded/indexed projections, not by combining event counters with overlapping activity summaries. Use reproducible time windows/timezone, query/schema versions and a high-water mark for late arrivals. Exports include the evidence references and coverage caveats. Snapshot reports must not silently change when historical data arrives later; publish an updated revision.

Use authenticated leadership read access separately from policy/freeze administration; scope it to the pilot team. Set approved prompt-capture, retention and data-access policy before collection. Preserve metadata/evidence references needed for the pilot reporting period; do not implement indefinite unbounded retention. Do not expose secrets to prove collection works.

Proposed acceptance targets, to be measured rather than claimed now:

| Measure | Pilot target |
| --- | --- |
| Known scripted operations | All expected IDs accounted for after recovery, no duplicate operation counts |
| Supported roster | All 20 enrolled; every partial/offline/incompatible client visibly explained |
| Normal broker event arrival | p95 <= 5 seconds to central receipt under the defined healthy-network load |
| Native file-hook arrival | p95 <= 10 seconds, accounting for collection cadence |
| Browser visibility | p95 <= 15 seconds from action under the same conditions |
| Local policy decision overhead | p95 <= 5 ms on the declared test hardware, measured separately from child startup/work and upload |
| Central handler processing | p95 <= 10 ms heartbeat; <= 25 ms single-event ingest at defined pilot load; measure batches separately |
| Availability/recovery | No loss of acknowledged committed events on process restart; new live evidence progresses during backlog recovery |

Baseline load test: 20 workstation identities, up to two concurrent sessions each, 40 operations/second sustained, and a 200-operations/second short burst, with representative payload sizes. These are test inputs, not claims about observed employee workloads or system capacity. Include a disconnected client, repeated uploads, dashboard readers and a 15-minute backlog. Record p50/p95/p99, errors, queue age, CPU/memory and DB contention. If a target fails, tune batching/indexes/transactions or revise the explicitly documented target before calling the release ready; do not hide failures in average timings.

Rollout gates:

- Two users: validate clean install, real work correlation, crash/restart and the evidence model.
- Five users: validate normal daily usage, missing-hook/partial cases and read-only leadership review.
- Twenty users: run at least five business days, with daily coverage reconciliation, a controlled service deployment and one outage/recovery exercise.
- Present leadership only after independently reconciling selected work items and the scripted event manifest against exported totals. Report all unresolved NOT TESTED conditions.

## Scope controls and first implementation batches

The critical path is P0 -> P1/P2 -> P3 -> P4 -> P5. P1 and P2 have separable work, but no rollout skips the persistence/correctness gates. Track these as implementation-plan items, not as already-created external Jira tickets. Do not attach calendar promises until the first two-user acceptance run and persistence schema spike establish the remaining effort.

First batch: correct live metric semantics, remove lossy testing filters, and add regression contracts for both. Second batch: canonical operation correlation plus controlled installation/startup health. Third batch: durable authoritative stores and crash consistency. Fourth batch: minimal work/evidence associations and the leadership view. Existing authentication, freeze and launcher regressions run through every batch.

Keep out of this visibility release: new agent/OS integration expansion, a new task-management suite, a general integrations marketplace, Kafka/Elasticsearch infrastructure for this 20-person goal, autonomous productivity scoring, inferred hours saved/FTE claims and another dashboard redesign. Existing discovery sources and five-layer protections remain in scope for regression and truthful reporting. Mandatory OS/resource enforcement remains core product work, with explicit gaps and a separate implementation gate rather than a claim that this limited visibility release already provides it.

The first leadership promise is narrow and testable: for these enrolled people, in these supported Claude workflows, here is the work requested, the observed actions, the verified deliverables, and the evidence/coverage limits behind the report.

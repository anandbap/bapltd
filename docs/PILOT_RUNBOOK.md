# Pilot confidence runbook

Use this sequence before admitting pilot users. Start with two internal Windows workstations running the selected Claude Code workflow. Add other clients or operating systems only after their own native acceptance. This replaces the older calendar-based 30-day guide.

The current release candidate adds durable single-server authority, signed offline policy leases, long-job execution, recommendation review in V3, metadata-first telemetry, and qualification evidence collection. Automated source tests do not qualify a particular installed workstation or hosted deployment.

## 1. Freeze a candidate and define the promise

Choose one reviewed commit, one matched client/server bundle and one isolated pilot control-plane origin. Record the Windows and native-client versions. Use official client builds with developer override compiled out. A dirty local development build may qualify source changes internally; it does not establish release provenance.

For this pilot, distinguish:

| Path | What you can test | What it does not establish |
|---|---|---|
| Discovery / roster | Recognized processes and expected workstation check-ins | Every operation on that workstation was intercepted |
| Native hooks | Supported callbacks and native-tool decisions | Protection of tools that never reach a supported boundary |
| Legacy `exec` | Broker policy decisions, execution and reporting | Complete filesystem/network isolation |
| Native `run` | The selected OS provider and its actual boundary tests | Automatic conversion of every TaskGrant into OS permissions |
| Recommendations | Per-machine persistent grant exemptions after admin review and signed sync | Temporary edge ZSP grants delivered from the browser |
| Durable authority | One SQLite-backed server on persistent storage | PostgreSQL, multi-replica operation, or a provisioned backup service |

The capability-to-runner integration, comprehensive credential brokering, browser-to-edge temporary approval/resume, and non-Windows native acceptance remain open. Keep them outside the initial promise unless separately completed and proven. Shared administrator authentication is accepted for this pilot; individual reviewer SSO attribution remains deferred.

Assign a release owner, service operator, support owner and security decision owner. Agree the capture mode, retention, approved destinations, offline budget and rollback procedure before collecting another person's work.

## 2. Run the source qualification checks

Use an approved preinstalled Go toolchain compatible with `bap-controlplane/go.mod`, Python and Node. Use the corporate mirrors; the commands below disable Go downloads and use existing approved caches. They do not install packages.

From the checkout, in an operator terminal:

```powershell
$env:GOPROXY = 'off'
$env:GOSUMDB = 'off'
$env:GOTOOLCHAIN = 'local'
$env:BAP_EXEC_TIMEOUT_SEC = '900'

go -C bap-edge test ./... -count=1 -timeout=5m
go -C bap-controlplane test ./... -count=1 -timeout=5m
go -C cchook test ./... -count=1 -timeout=5m
go -C bap-gateway test ./... -count=1 -timeout=5m
go -C copilot test ./... -count=1 -timeout=5m
node tests/test_v3_controls.cjs
node tests/test_v3_discovery.cjs
node tests/test_activity_metrics.cjs
node tests/test_v3_admin.cjs
python -m unittest tests.test_pilot_qualification
python scripts/check_capability_claims.py
```

Run the actual recommendation transport/restart fixture with a freshly built matching server:

```powershell
New-Item -ItemType Directory -Force .test-cache | Out-Null
go -C bap-controlplane build -o ../.test-cache/bapcontrolplane.exe ./cmd/server
$env:BAP_CONTROLPLANE_TEST_BIN = (Resolve-Path .test-cache/bapcontrolplane.exe).Path
$env:BAP_RECOMMENDATION_E2E = '1'
go -C bap-edge test ./cmd -run '^TestRecommendationWireEndToEnd$' -count=1 -timeout=90s
Remove-Item Env:BAP_RECOMMENDATION_E2E
Remove-Item Env:BAP_CONTROLPLANE_TEST_BIN

$env:BAP_LONG_JOB_E2E = '1'
go -C bap-edge test ./internal/sandbox -run '^TestExecutionBeyondLegacyLimit$' -count=1 -timeout=3m -v
Remove-Item Env:BAP_LONG_JOB_E2E
```

The long-job fixture deliberately takes over two minutes. It must finish rather than being killed at the old 120-second limit. The wire fixture starts and stops only its own isolated server and uses synthetic identities. It is not a browser test.

**Pass:** every required suite succeeds, the opt-in fixtures actually execute, and the CI run for this exact candidate succeeds on the advertised platforms. Missing dependencies, skipped native cases and unrun Python integration/wheel checks remain gaps. Run the full existing Python/wheel job through release CI in its isolated fixture; do not point integration cleanup at your live installation.

CI publishes to PyPI after both Go and Python jobs succeed on a push to main or a manual CI run, using the existing `pypi` environment and `PYPI_API_TOKEN`. The release workflow calls CI with `validation_only: true` before packaging, then uses its own release publication jobs. Public CI defaults to `https://proxy.golang.org,direct`, `sum.golang.org` checksum verification, and `https://pypi.org/simple`; no repository variables are required. Enterprise operators override `BAP_GO_PROXY`, `BAP_GO_SUMDB` and `BAP_PYPI_INDEX` with their approved sources. An explicit corporate proxy/index replaces the default; the workflow does not append public fallback sources. `PIP_EXTRA_INDEX_URL` stays empty. Configure required branch checks and the protected publication environment in GitHub separately; source workflow edits do not prove those settings are enabled.

## 3. Prepare the isolated service

Use one server replica and an absolute SQLite database path on approved persistent storage. Back up the database consistently using your approved SQLite-aware backup process; copying only the live main file while ignoring its WAL is not a qualified backup.

Provision stable `BAP_SECRET_KEY` and `BAP_POLICY_SIGNING_SEED` through the approved secret manager. Preserve them across redeploys. Do not paste values into an agent prompt, a ticket, a report or a shell history. Set `BAP_TELEMETRY_CONTENT=metadata` (also the new client default). Deploy the actual roster with current reporting windows.

Example start command after operator configuration has supplied the secrets:

```powershell
& $ControlPlane start --fg --mode prod --db "$PersistentData/authority.db" --policy-max-age 24h --min-edge-version 1.13.7 --pilot-roster "$OperatorConfig/pilot-roster.json"
```

Use your real approved paths and origin. Production refuses ephemeral signing configuration, relative/in-memory database paths and a missing offline policy budget. Storage initialization failure refuses startup. API responses are released after the authority checkpoint and new audit links commit; ingest acknowledgements then report `durable: true`. A later commit failure returns 503 and leaves the service unavailable until the operator repairs storage and restarts.

On the first start of a genuinely new isolated authority, add `--initialize-authority` once. Remove it from the normal service configuration afterward. Without that explicit initialization, a missing checkpoint refuses startup instead of silently treating a lost volume as a new fleet. Existing deployments require an operator-reviewed migration/backup and canary; do not initialize over a missing production database as a recovery shortcut.

The policy counter is restored from durable state rather than seeded from wall time. Pending recommendations, decisions, enrolled assets, registry restrictions, session/user restrictions, canonical audit IDs and explicit restorations survive restart. Execution grants from a prior process retain their established fail-closed epoch behavior; do not expect old execution authority to revive.

**Pass:** health works; unauthenticated production policy sync is rejected; the actual database volume survives service replacement; a backup restores on a separate isolated service. Document measured recovery objectives. Never deliberately remove a live service's signing key to test failure.

Signed leases require upgraded edge clients. Old clients receive an upgrade response rather than a payload they cannot verify. Upgrade and qualify a canary before enabling the production lease budget. A lease bounds cached authority; it cannot deliver a revocation to a disconnected machine instantly.

## 4. Install on clean workstation A

Follow [fresh-install acceptance](FRESH_INSTALL_ACCEPTANCE.md), including actual corporate IdP enrollment and supported native integration approval. Use a disposable VM/profile and the official approved bundle. Repeat on workstation B later.

Set operator variables to the actual installed artifact and checkout:

```powershell
$BapCheckout = 'C:/path/to/approved/checkout'
$Edge = 'C:/path/to/installed/bapedge.exe'
$BapServer = 'https://your-isolated-pilot-origin'
$AcceptanceRoot = Join-Path $BapCheckout '.bap-acceptance/workstation-a'
$ApprovedCommit = '<approved-candidate-commit>'
& $Edge version
& $Edge config show
& $Edge status --json
& $Edge daemon status --json
```

Check release manifest hashes and source identities using the existing installed release/doctor tooling described in [release and native probe](RELEASE_AND_NATIVE_PROBE.md). A hash manifest alone is not a publisher signature.

Inspect the actual user, project and plugin hook definitions. Supply every referenced executable to the new copy check, using the expected interceptor SHA-256 from the approved release manifest:

```powershell
& $Edge doctor --hook-copies-json --expected-hook-sha256 '<approved-interceptor-sha256>' --hook-copy 'C:/actual/user/interceptor.exe' --hook-copy 'C:/actual/project/interceptor.exe' --hook-copy 'C:/actual/plugin/interceptor.exe'
```

Only include copies actually configured; record absent optional layers as absent. This check covers explicitly supplied paths. It does not infer unknown vendor configuration locations. A missing or mismatched configured copy must be repaired with the matched bundle before proceeding.

**Pass:** matching components, enrolled identity, intended origin, daemon and native callbacks. No repository-local patches or developer override are needed.

## 5. Collect smoke and start the evidence bundle

```powershell
& "$BapCheckout/scripts/Test-BapFreshInstall.ps1" -BapEdgePath $Edge -ExpectedServer $BapServer -BuildCommit $ApprovedCommit -OutputDirectory "$AcceptanceRoot/smoke"
python "$BapCheckout/scripts/pilot_qualification.py" init --smoke "$AcceptanceRoot/smoke/smoke-report.json" --release-commit $ApprovedCommit --machine workstation-a --operator '<operator-id>' --output "$AcceptanceRoot/qualification.json"
```

A successful smoke checks a real allowed execution, policy denial and exact-session reporting. Independently find both events in Live mode using its run ID and receipts. A heartbeat alone is not proof of both event counters.

The bundle initially says **NOT_READY**. Every manual case remains **NOT_TESTED**. Evidence consists of sanitized JSON files with stable IDs and separately recorded observations; the tool stores their hashes and invalidates a case if an evidence file changes.

Record a completed case, for example:

```powershell
python "$BapCheckout/scripts/pilot_qualification.py" record --bundle "$AcceptanceRoot/qualification.json" --case native_hooks --result PASS --operator '<operator-id>' --evidence "$AcceptanceRoot/native-hook-evidence.json" --session-id '<observed-session>' --event-id '<central-event-or-local-receipt-id>' --note 'Native callback and corresponding central event independently checked'
```

Use FAIL for a failed check and NOT_TESTED for an unrun one. Do not attach credential files, command bodies or raw prompts. The tool rejects known private JSON fields. It records operator attestations; it does not authenticate the operator or independently prove a screenshot's meaning.

## 6. Prove ordinary development and long jobs

Use the actual selected native agent with normal production policy. Read and search source, edit a harmless fixture, build, run tests, stage and commit in the disposable repository, and inspect an approved sibling dependency. Use the approved corporate package mirror for dependency work.

**Pass:** intended work completes; grant requests and policy refusals are understood; there is no repetitive prompt loop. Record prompt/grant/denial counts for a fixed work script. A successful command under developer override is not acceptance.

From your operator terminal, test the installed broker's long-job path in the disposable workspace:

```powershell
& $Edge exec --json --progress --timeout 3m 'Start-Sleep -Seconds 125; Write-Output long-job-complete'
```

Default execution lifetime is 30 minutes, bounded at 24 hours. `--timeout` takes precedence over `BAP_EXEC_TIMEOUT_SEC`. Invalid values fail instead of silently reverting. Progress contains elapsed time only; command output is captured, redacted and bounded to 4 MiB. This is not interactive terminal streaming.

Run another disposable long job and cancel it with Ctrl+C. Confirm the broker returns promptly and leaves no child workload alive. Repeat through the native-agent route; an agent client's own shorter tool timeout is a separate limit and must be configured through that client's supported controls.

Record `workday` and `long_job`. Broker JSON `timings_ms.shell_authorizer` measures that authorizer call, `pre_execution` includes startup/bootstrap/policy/grant/approval work before launch, and `broker_before_reporting` includes child work but excludes the final reporting phase. Missing measurements are unavailable, not zero-cost decisions.

## 7. Prove recommendation review and revocation

1. Find a benign local development effect blocked for lack of a grant.
2. As the human developer, run `bap recommend` in your own terminal. Review the effect and scope, provide justification and confirm. Agent submission and `--yes` automation are refused.
3. In Live V3, authenticate as administrator and open **Admin & approvals → Policy recommendations**. Treat workstation examples and justifications as untrusted input.
4. Approve only the intended machine/effect. Confirm the server records the decision; a failed response must not display success.
5. Sync that workstation and retry. The approved local effect should be exempt from the grant requirement. An unapproved effect and another workstation must remain unaffected.
6. Revoke in V3, sync and verify the exemption disappears.

Record `recommendation`. This is a persistent per-machine permission review, separate from one-time task approvals. Temporary edge ZSP approvals still use the operator terminal flow. Do not label browser-to-edge temporary approval/resume complete.

## 8. Prove capture, delivery and native boundaries

Default metadata mode withholds command arguments/bodies, prompt text, responses and free-form reasons at the new Go edge/hook transport boundaries. Local broker audit spooling is minimized before hashing. Native prompt spooling is minimized before storage; old queued records are filtered again on upload. Session/event IDs, intent categories, prompt hashes where available, executable metadata and policy outcomes remain available.

Explicit `BAP_TELEMETRY_CONTENT=redacted` opts into content collection and can include source code; regular-expression redaction is not a DLP guarantee. Review consent, retention and access before opting in. Existing archives are not retroactively purged. Python SDK, external collectors, vendor-owned transcripts and unreviewed integrations need their own inventory; do not claim universal zero-code transmission.

Use distinctive synthetic markers, never real secrets. Confirm prohibited marker bodies are absent from the actual outbound records, offline spool and central export under the chosen metadata policy. Confirm intent/IDs still arrive. Record `privacy`.

For one known operation, independently record action time, central receipt time and first browser visibility with explicit UTC offsets. Reconcile all IDs in a 20-operation script without duplicate counts. Record `central_delivery` with all three timestamps:

```powershell
python "$BapCheckout/scripts/pilot_qualification.py" record --bundle "$AcceptanceRoot/qualification.json" --case central_delivery --result PASS --operator '<operator-id>' --evidence "$AcceptanceRoot/delivery-evidence.json" --session-id '<session>' --event-id '<central-event>' --action-time '<ISO8601-with-offset>' --central-time '<ISO8601-with-offset>' --browser-time '<ISO8601-with-offset>'
```

Use the native Windows boundary suites and the actual selected agent/provider to test declared forbidden filesystem/network effects with the hook disabled, using synthetic disposable paths. See [capability model](CAPABILITY_MODEL.md) and [fresh-install acceptance](FRESH_INSTALL_ACCEPTANCE.md). Broker denials and rendered provider configurations are not native escape proof. Record `native_boundaries` only for the boundaries actually demonstrated.

## 9. Prove restart, outage, restriction and repair

Use disposable sessions and an isolated service only.

| Case | Steps | Pass |
|---|---|---|
| `logon_recovery` | Reboot workstation A and log in normally | Reporting resumes without install/login; original workstation identity retained |
| `crash_recovery` | Stop only the disposable reporting daemon; allow supervision to run | Daemon recovers; live evidence resumes without duplicate identities |
| `freeze_isolation` | Run sessions A/B; freeze A; freeze workstation; clear workstation restriction while keeping A's own restriction | A/B restrictions apply independently; unauthorized work stays denied |
| `offline_replay` | Interrupt only the isolated service; produce known events; restore within the configured offline budget | Cached restrictions remain; backlog drains; event IDs reconcile without duplicate operations |
| `redeploy` | Redeploy the isolated server with the same persistent database and signing configuration | Enrollment, policy versions, recommendations, restrictions and acknowledged audit IDs survive |
| `rollback` | Roll back to a previously qualified compatible artifact using the documented operator procedure | Identity preserved and correct signed policy enforced; incompatible builds refused |
| `roster` | Compare actual enrolled instance IDs with assigned roster/windows | Fresh/stale/missing states and denominator agree with the real cohort |

Separately exercise expiry using an isolated short-lease fixture. Once expired, offline signed authority must fail closed; changing unsigned LastSync must not extend it. Reconnect and sync to renew. Offline machines cannot receive a new freeze until communication resumes; report that exposure accurately.

For a damaged local signed-policy cache with intact enrollment and trust, the operator can request:

```powershell
& $Edge doctor --repair-policy
```

Repair authenticates to the enrolled/locked destination and requires a fresh trusted policy. It does not delete identity, unpin a key, clear restrictions or accept an unknown signer. If it fails, diagnose origin, ownership, version and key continuity. Restore approved service configuration or use the existing authenticated enrollment/key-recovery procedure. Do not purge journals or disable integrity checks to make a test pass.

## 10. Review evidence, then grow the cohort

```powershell
python "$BapCheckout/scripts/pilot_qualification.py" report --bundle "$AcceptanceRoot/qualification.json"
```

A report with any missing/failed case exits nonzero. **QUALIFICATION_RECORDED** means required evidence and operator attestations have been supplied and their files still match; it is not an independent product certification.

Repeat on clean workstation B. A second operator should reconcile selected IDs and compare source hashes. Then progress:

1. **Two internal users:** all workstation/service entry cases pass; no unexplained lockout or lost acknowledged evidence.
2. **Five-user canary:** normal daily work, explicit partial/offline cases, support triage and successful rollback rehearsal.
3. **Up to twenty users:** at least five business days, daily roster reconciliation, one controlled deployment and one outage/recovery exercise.

Before expanding, measure the load and latency targets in [leadership pilot plan](LEADERSHIP_PILOT_PLAN.md). The new single-node checkpoint implementation has not established those capacity targets. Durable history alone does not create canonical operation correlation, verified task completion or a qualified leadership progress report.

Pause expansion for identity loss, incorrect restrictions, missing acknowledged evidence, prohibited payload disclosure, a bypass of an advertised boundary or work-blocking prompt loops. Preserve evidence, repair the cause, rerun the failed case and record the remaining limitations before resuming.

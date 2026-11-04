# Fresh install to full acceptance: Windows operator script

Updated October 31, 2026. Allow 45-60 minutes, plus the optional isolated outage/redeploy and gateway fixtures.

The new independent discovery checks are in [Discovery acceptance](#discovery-acceptance-hooks-refused-and-mcp-observations) below. They require matching updated edge, interceptor, installer and control-plane artifacts.

## Discovery acceptance: hooks refused and MCP observations

**Additional evidence/metrics check (run after the discovery sequence below):**

Run an already-supported project test command through the broker, such as `bapedge exec "go test ./..."` or `bapedge exec "python -m pytest tests/unit"`, using dependencies already supplied through the approved environment. Record the audit event ID, session ID and actual decision. Confirm it appears centrally; command/source names containing `test` must not hide it. Repeat through the isolated outage/recovery procedure and verify the same event is retained/replayed without duplicate session counters.

In Live v3, check **Denied operation records** against recorded denials. An allowance is not proof of successful execution; a denial is not automatically a high-risk incident. In the summary API/legacy dashboards, completed work, assisted hours/FTE, governance coverage and trends must be **unavailable/null**, not inferred from those test events. Explicit Demo values remain illustrative. See [metric definitions](ACTIVITY_METRICS_CONTRACT.md).

Run after install/login on the dedicated acceptance machine. Keep all agent sessions closed initially. The operator activates Admin in Live v3; use Workstations → View discovery for the test workstation.

1. Create a dedicated synthetic configuration workspace; these definitions must never be launched:

   ```powershell
   $DiscoveryFixture = Join-Path $AcceptanceRoot 'discovery-fixture'
   New-Item -ItemType Directory -Force -Path $DiscoveryFixture | Out-Null
   '{"mcpServers":{"pilot-config-one":{"command":"never-start-this-fixture"},"pilot-config-two":{"url":"https://example.invalid/mcp"}}}' | Set-Content -LiteralPath (Join-Path $DiscoveryFixture '.mcp.json') -Encoding UTF8
   bap install --dir "$BapBin" --workspace "$DiscoveryFixture" --server "$BapServer" --no-path
   ```

   UTF8 JSON with or without BOM is supported. No fixture secret, package installation or running MCP server is needed.

2. In the workstation-filtered Discovery tab, Request scan. Expect **queued**, then a later complete/partial report in scan coverage. Two separate `mcp_config` rows appear, with `configured` evidence and `not_observed` mediation. Repeating the scan must preserve their IDs and first-seen times. This must work with no agent sessions/hooks/SDK active.
3. Open Claude directly, refuse the native hooks, and leave it running. A supported named process can appear as `running` after the inventory scan; native MCP invocation/prompt visibility remains unknown. Interpreted/generic Python or Node processes are not automatically identifiable as agents. Do not mark this case fully governed.
4. Approve the native hooks and use an **already approved, working test MCP server** to invoke a harmless tool on a synthetic file. Inspect `mcp_call` evidence: native operation ID and actual attempt/outcome, with observation-only mediation. No tool input/result, URL or secret-bearing argument should appear. The successful callback is not a BAP resource authorization receipt. If hooks are refused or the client supplies no operation ID, record invocation evidence as unavailable.
5. Save malformed JSON in the synthetic `.mcp.json` and request another scan. The configuration scope reports error/partial; the prior rows remain present. Replace it with `{"mcpServers":{}}` and scan again: that completed scope may mark its old rows `not_seen`. This does not prove the tools were uninstalled or prohibited.
6. Acknowledge a row with a reason, reopen it, then give it a seven-day exception. Refresh and verify the decision and expiry. No action should enroll an agent or mark enforcement layers active. Restart an isolated control plane **with its SQLite file preserved** and verify the disposition survives. If the file is lost on Render, this test fails until P3 persistent storage is provisioned; edge replay cannot reconstruct operator decisions.
7. Use the isolated outage test from this runbook. Queue a scan while disconnected, restore connectivity and confirm eventual upload/replay with stable IDs. `bapedge daemon status --json` exposes the latest scan epoch/result and discovery delivery state. A non-durable ACK retains recovery reports under the BAP state discovery journal. Do not delete the journal as a troubleshooting step.
8. Deactivate Admin and switch to Demo: Live discovery rows, coverage details and evidence drawers must clear. Re-enable Admin/Live and refresh. Existing session freeze/unfreeze and activity views must still work.

**Record:** deployment/client commits, test instance ID, scan epoch/run ID, scope status, asset IDs, native operation ID where available, decision/expiry, outage/recovery timestamps and screenshots of partial/clean states. Mark actual native-client callbacks, unavailable sources and cloud durability independently. The automated suite validates synthetic collectors/protocols; it does not certify this installed-client scenario.

This tests the installed release, not just a source checkout. Run it on a fresh Windows VM or a new disposable Windows user, with an approved Git installation and supported agent clients. Use a dedicated test tenant/workstation. Keep the BAP development laptop and unrelated Render sessions out of destructive/restart tests.

**Completion rule:** every applicable row below has evidence and a PASS. An unavailable component is NOT TESTED, not PASS. The automated smoke script does not approve hooks, freeze anything, restart servers, or claim the full runbook passed.

## 0. Release gate: do this before installing

For a qualified release, add `--require-release-manifest` to the installation command below. Unknown/dirty development artifacts may be used for development without that flag, but do not count as a qualified pilot bundle. `bap doctor` now checks installed component hashes. A hash manifest is not a publisher signature; retain the approved package trust-anchor evidence.

After login, run `bapedge onboarding begin`, start a fresh Claude session in a fixture repository, paste the printed synthetic prompt exactly, use the client's ordinary approval flow and wait for its response. Then run `bapedge onboarding check --require`. This checks correlated **reporting observations**, including an allowed `git status` record; it does not prove successful execution, corporate SSO or full pilot readiness. Missing/foreign/expired/denied evidence stays partial. See [release and native-probe scope](RELEASE_AND_NATIVE_PROBE.md).

For the pilot denominator, configure the server's [expected roster and reporting windows](PILOT_ROSTER_COVERAGE.md). As an authenticated Live admin, inspect V3 Discovery & coverage → Expected pilot workstations. Confirm exact identity/owner and current check-in freshness; missing configuration must show unavailable rather than full coverage. This check is separate from the native probe and does not qualify historical reporting.

P1a adds per-user Windows startup and crash supervision. On the disposable acceptance user, verify `bapedge daemon status --json` and `bap doctor`, then qualify actual logoff/logon/reboot, daemon crash recovery and intentional `daemon stop`/explicit `daemon start`. Review [runtime behavior and remaining gates](STARTUP_AND_ONBOARDING.md). Missing native callbacks remain partial; do not infer hook approval from installed files.

Record these in your test notes:

- Control-plane deployment commit and build time.
- Approved Python package/wheel version and build commit.
- Edge/interceptor/launcher artifact commit or release manifest. Several fixes shared a version number; matching version text alone is insufficient.
- Test workstation name, operator, UTC start time, and dedicated control-plane origin.

The control plane and client artifacts must include the independent-reporting fixes. Deploying only Render does not update an installed edge/interceptor. If provenance cannot establish that both sides contain the fixes, stop with **WRONG/UNKNOWN BUILD** rather than debugging an old binary.

The operator supplies control-plane signing/admin/collector secrets through the approved secret manager/UI. Do not retrieve, print, paste into agent prompts, or save those secrets in the test report. Keep `BAP_SECRET_KEY` stable across the recovery test. A laptop does not need `BAP_TELEMETRY_TOKEN`; it is for gateway collection when enabled.

## 1. Install from the approved package drop

In a normal PowerShell window on the fresh test machine, replace the package drop, version and script checkout paths:

```powershell
$ApprovedWheelDrop = 'D:\Approved-BAP-Release'
$BapRelease = '<approved-version>'
$BapCheckout = 'C:\src\bapltd' # Matching checkout containing this runbook/script
$BapServer = 'https://bap-controlplane.onrender.com'
$AcceptanceRoot = 'C:\BAP-Acceptance'
$BapBin = Join-Path $AcceptanceRoot 'bin'

New-Item -ItemType Directory -Force -Path $AcceptanceRoot | Out-Null
Set-Location $AcceptanceRoot
python -m pip install --no-index --find-links "$ApprovedWheelDrop" "bap-ltd==$BapRelease"
if ($LASTEXITCODE -ne 0) { throw 'Approved package installation failed' }
bap install --dir "$BapBin" --workspace "$AcceptanceRoot" --server "$BapServer" --no-path
if ($LASTEXITCODE -ne 0) { throw 'BAP installation failed' }
$Edge = Join-Path $BapBin 'bapedge.exe'
$env:BAP_HOME = $BapBin
& $Edge version
& $Edge status --json
& $Edge daemon status --json
& $Edge plugin status
& $Edge plugin layers
```

The approved release must contain/provide its matching native artifacts (including native Claude and Copilot plugin packages in `plugins/`). Do not substitute a public-registry install or accept an unexpected public download to get around missing corporate artifacts. This guide does not require administrator elevation, an enforcement override or manual credential deletion.

**PASS:** the intended native binaries, launchers, and native plugin packages exist; the daemon runs against the intended server, and `bapedge plugin layers` prints the active 5-layer Defense-in-Depth hierarchy. Before login on a genuinely fresh profile, status reports unenrolled. Installation/settings alone do not prove hook execution or kernel protection. If already enrolled, this is an upgrade test, not a clean-install test; use another disposable profile rather than deleting credentials.

## 1a. Verify Native Agent Plugins with Synthetic Probes

Verify the vendor plugin adapters without launching an interactive AI agent session:

```powershell
# Probe Claude Code native hook adapter
& $Edge plugin verify claude

# Probe GitHub Copilot Agent Plugins 1.0 adapter
& $Edge plugin verify copilot

# Re-inspect plugin observable health states
& $Edge plugin status
```

**PASS:** both probes report `VERIFICATION PROBE SUCCESSFUL`, health records are spooled under `.bapstate/reporting-health/`, and plugin state transitions to `Active` or `Installed` with a recent `Last Observed` timestamp.

## 2. Login establishes the master workstation identity

```powershell
& $Edge login --server "$BapServer"
if ($LASTEXITCODE -ne 0) { throw 'Complete/correct workstation enrollment before continuing' }
& $Edge config show
& $Edge status --json
& $Edge daemon status --json
```

Complete the actual configured identity-provider flow. Use the explicit installed edge path: the generic `bap` proxy can otherwise select an older binary in another installation directory.

**PASS:** enrolled identity is shown, configuration source is `workstation_enrollment` (or the intended administrator-locked config), and the daemon target matches enrollment. Login must surface a failed reporting-daemon startup. A daemon's successful `/health` probe alone is not proof of authenticated telemetry.

Open [the cockpit](https://bap-controlplane.onrender.com/dashboard/) in **Live** mode. Use the corresponding dashboard URL for an isolated server. Keep **Admin Off** initially. Locate this workstation by its enrolled instance/agent identity, not hostname alone. Do not use illustrative demo data as evidence.

## 3. Run the automated installed-client smoke script

```powershell
& "$BapCheckout\scripts\Test-BapFreshInstall.ps1" `
    -BapEdgePath "$Edge" -ExpectedServer "$BapServer" `
    -BuildCommit '<client-artifact-commit>' `
    -OutputDirectory "$AcceptanceRoot\reports\initial"
if ($LASTEXITCODE -ne 0) { throw 'Smoke check failed; inspect smoke-report.json' }
```

The script checks the native binary, enrollment/configuration/daemon, executes real `git --version` through the broker, and submits a harmless nonexistent unapproved executable. It supplies no prompt text and never answers an interactive step-up prompt. Allowed and denied receipts must share its unique `acceptance-...` session ID. It then uses the broker's authenticated heartbeat transport to confirm that this exact reporting session reached the control plane.

The JSON report includes the edge SHA-256, operator-supplied build commit, run ID, sanitized diagnostics, receipt IDs and total command timings. It never opens credential files or records bearer tokens. The recorded commit is an operator assertion; compare the binary hash with the approved release manifest.

**PASS:** exit 0 and `AUTOMATED_SMOKE_PASS`. In the Live UI/audit view, locate the report's run ID and verify **both** broker events arrived: allowed Git plus denied unknown executable, with no supplied prompt. A local receipt alone does not establish central delivery, and a heartbeat alone does not prove both event counters.

This `acceptance-...` session, with source `cli`, is deliberately an operator smoke fixture. It is not evidence that Codex/Claude discovery or native hooks work; those are tested next.

## 4. Prove the master setting wins over stale project/shell settings

Use a loopback dead port, not a third-party destination:

```powershell
$PreviousBapServer = $env:BAP_SERVER_URL
try {
    $env:BAP_SERVER_URL = 'http://127.0.0.1:9'
    & $Edge config show
    & "$BapCheckout\scripts\Test-BapFreshInstall.ps1" `
        -BapEdgePath "$Edge" -ExpectedServer "$BapServer" `
        -OutputDirectory "$AcceptanceRoot\reports\master-setting"
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment/master-setting test failed' }
} finally {
    if ($null -eq $PreviousBapServer) { Remove-Item Env:\BAP_SERVER_URL -ErrorAction SilentlyContinue }
    else { $env:BAP_SERVER_URL = $PreviousBapServer }
}
```

**PASS:** configuration and authenticated reporting still use enrollment/the administrator lock. On an MDM fixture, separately test a deliberate managed/enrollment conflict: evidence must stay queued with an identity/configuration error, not be sent anonymously elsewhere. Do not edit managed configuration on a shared workstation just for this test.

## 5. Critical test: leave native hooks UNAPPROVED

Open the acceptance workspace normally in VS Code/Codex, or start the supported native Codex CLI normally. Do not use a governed launcher for the initial discovery check, and do not approve native hooks yet. Leave pending hook approvals visible. MCP/tool permissions are separate from native hook trust.

1. Leave the agent process open for at least one discovery cycle plus dashboard polling (allow 30 seconds).
2. Inspect Live coverage. A recognized native executable should appear as **Discovered**, with prompt text not reported and a workstation-bound identity. Presence must not add allowed/denied operation counts or an execution grant.
3. Send a distinctive harmless prompt: `BAP-NOHOOK-<your-run>: explain 2 + 2 without tools.` Its text should not be expected centrally when no active boundary receives it. Missing prompt text is not a failure here.
4. Ask Codex to run ONLY the following broker command, twice, using the actual installed path. Do not supply `--session-id`, a source label or prompt text:

```text
Run this exact harmless command twice and show both JSON receipts:
C:\BAP-Acceptance\bin\bapedge.exe exec --json --prompt= "git --version"
Use the BAP execution broker. Do not approve native hooks, change policy, or run other probes.
```

**PASS:** both real Git executions return allowed receipts. Where native ancestry is recognizable and no launcher session ID is inherited, both use the same `observed-codex-...` fallback ID and gain **broker** evidence under the enrolled workstation. Prompt text may remain unavailable. Confirm central events, not just terminal output.

**NOT TESTED / GAP:** an agent hidden entirely behind an unrecognized generic helper may not be discovered. Record that client/build and process-observation limitation. Do not call a fabricated manual session a discovery pass. If the client supplies an explicit native/launcher session ID, preserve it; do not demand an `observed-` prefix in that case.

Close and reopen the native agent process. A replacement process must not silently keep the old process-birth identity alive. A single IDE process can host multiple conversations; passive process presence is not proof of per-conversation telemetry.

## 6. Prove Layers 2, 3 and 4 independently

| Path | Operator action | Required evidence |
| --- | --- | --- |
| Layer 2: MCP | Enable the installed BAP MCP server through the client's normal permission flow. Ask it to call `bap_execute` with `git --version`, then the harmless `bap-unapproved-probe.exe`. Leave native hooks unapproved. | Actual Git output and policy denial; central `reporting_layer: mcp`; enrolled workstation correlation; no requirement for prompt text. `bap_status` alone is not an execution test. |
| Layer 3: shims | Start a disposable governed launcher from the acceptance workspace. In that governed environment, run `git --version` through normal PATH resolution, without explicitly typing `bapedge exec`. | Central `reporting_layer: shim`; one actual tool execution; no recursion/duplicate tool output. Explicit broker execution would test the broker, not prove shim resolution. |
| Layer 4: broker | Use the installed-client smoke script and inspect its allowed/denied receipts and central records. | Actual command result, policy decision, session identity and `reporting_layer: broker`; no unconditional claim that a kernel sensor/filter is installed. |

For a launcher smoke check, from this workspace:

```powershell
& "$BapBin\run_claude_bap.ps1" --version
# If Antigravity CLI is installed:
& "$BapBin\run_antigravity_cli_bap.bat" --version
```

**PASS:** exact version queries return promptly and create no new session/settings/watchdog activity. Capture the before/after state; an existing installed hook file need not disappear. Then launch a normal interactive Claude session using the same installed launcher. Do not infer shim/MCP activity from settings files alone.

## 7. Approve expected hooks; prove Layer 1 and prompt correlation

Use the client's own hook-review UI. Approve only the expected installed BAP interceptor definitions. Record duplicate user/project definitions if both are present; do not treat the number of approval cards as a protection score.

Send these prompts one at a time, waiting for the actual tool result:

1. `BAP-HOOK-ALLOW-<run>: run git --version through the BAP broker.`
2. `BAP-HOOK-DENY-<run>: request bap-unapproved-probe.exe through the BAP broker. Stop after a denial; do not approve or work around it.`
3. `BAP-HOOK-ALLOW2-<run>: run git --version through the BAP broker again.`

**PASS:** when capture is enabled and the client supports the callback, prompt text/hash and classified intent arrive under the correct native session. The latest denied prompt must not inherit **Allowed** from the prior prompt; the following allowed operation changes the displayed decision again. Audit/shadow mode must be labeled flagged/permitted, not blocked.

Ask for one supported native file-tool operation on a harmless source file in this acceptance workspace. Check for `hook` evidence after the file-hook spool cycle. Do not use a credential path or real secret as the probe. If the client routes every edit through an unsupported tool shape, record that adapter as NOT TESTED; do not count a broker shell action as a native file-hook pass.

For the capture-disabled case, use a separately provisioned capture-disabled policy fixture. The classified prompt hash/intent and other layer evidence should still arrive while raw prompt text stays absent. Do not weaken production capture policy just to make a screenshot more interesting.

## 8. UI and freeze acceptance: two disposable sessions

Start live sessions A and B on this test workstation. Record exact IDs; run an allowed command in both. Use the same harmless Git command for restriction tests.

| Step | Required result |
| --- | --- |
| Admin Off | No actionable administrator session-freeze controls. Column reads **Status**. |
| Activate Admin via the approved UI flow | Operator verification succeeds; right-side session controls become visible. Never paste the admin token into an agent prompt. |
| Freeze live A | Server confirms success; button becomes **Unfreeze session**. New governed work in A is denied after synchronization; B remains usable. A refusal/error is a failure, not a successful freeze. |
| Freeze workstation | New governed work in both A and B is restricted after synchronization. |
| Unfreeze workstation while A has its own session freeze | B can resume. A stays restricted until its separate session restriction is cleared. |
| Unfreeze A | A can resume if its process still exists. If a watcher terminated it, restart it; unfreeze is not process resurrection. |
| End a disposable session | Closed/offline non-frozen rows cannot receive a new freeze. Test lost-heartbeat Offline separately by waiting over 45 seconds plus polling. |
| Frozen row goes offline | Its **Unfreeze session** control can remain available for administrative restoration. |
| Submit a risky-action sequence | Inspect individual denied/flagged operations, IDs, timestamps and reasons. **Load more** must reach every item in its stable snapshot without duplication or omission. |

Freeze affects the selected governed authority. Do not use an unmediated action as proof that every OS action is blocked. Do not test fleet-wide freeze on a shared Render environment. Watchers may terminate restricted workloads; keep throwaway sessions and do not expect to undo an already-running operation.

## 9. Outage and redeploy recovery: isolated service only

Provision an isolated control plane at one stable origin with a stable signing key and approved operator configuration. Repeat enrollment/smoke against that origin using a separate disposable workstation profile. Do not redirect an existing enrolled production profile by changing only an environment variable.

1. Record session/instance IDs and several central event IDs. Warm the permitted local policy. Freeze one disposable session and wait until the edge actually enforces it; record an independent unfrozen session as well.
2. Operator stops only that isolated control plane. Keep edge and clients alive.
3. Run an allowed cached local operation and an unapproved executable probe from the unfrozen session. Cached enforcement must remain applicable; already-cached freezes must remain restrictive. Online-only authority/consumption may fail closed.
4. Capture diagnostics using `-SnapshotOnly` (below). Delivery failures/backlog should be visible. Do not assume a specific backlog count: batching/retention and other local agents affect it.
5. Restart the server at the same origin with the same signing key and **fresh in-memory state**, simulating the current ephemeral deployment.
6. Confirm authenticated session recovery uses the original identity/session ID, and edge-originated event IDs replay without duplicate counts. The frozen session must not become authorized just because the new central snapshot is empty.
7. Check audit chain integrity through the approved UI/operator tool. Ensure new live activity still arrives while history backfills. Reconstructed reporting-only registry entries must not automatically receive execution grants.
8. Explicitly restore applicable restrictions through the administrator flow. Changed/expired/invalid identity is a remediation case, not a reason to permit anonymous recovery.

```powershell
& "$BapCheckout\scripts\Test-BapFreshInstall.ps1" `
    -BapEdgePath "$Edge" -ExpectedServer "$BapServer" -SnapshotOnly `
    -OutputDirectory "$AcceptanceRoot\reports\outage"
```

The retained edge journal protects edge-originated evidence. It does not reconstruct lost central administrative history or revocations the edge never received. Central persistence is still deferred. Reboot/startup-service acceptance is also a separate deferred item; a successful interactive install/login is not proof of an installed persistent OS service.

## 10. Layer 5 and authentication negative cases

Use the isolated repository proof pack in [claude-demo.md, Section 10](../claude-demo.md#10-technical-proof-pack), with matching compiled binaries and approved dependency caches. Run it in a disposable test checkout; several suites manage local processes/fixtures. Do not run full discovery beside a live production demonstration.

Required resource-side results: no grant denied; tampered grant denied; wrong resource/operation denied; one valid single-use request succeeds; replay denied; a ten-request race has exactly one success. A loopback semantic fixture is not proof of a deployed gateway integration. For deployed gateway audit collection, verify its scoped service token separately from workstation enrollment.

Required identity negatives: anonymous lifecycle/ingest rejected; another enrolled workstation cannot update/heartbeat your session; an execution grant cannot serve as enrollment proof; a gateway collector cannot create or refresh workstation sessions; concurrent first reports cannot mix owners. These use synthetic identities in automated tests, not credentials extracted from a real laptop.

## 11. Final scorecard and timing evidence

| Check | Result | Evidence to keep |
| --- | --- | --- |
| Matched release + clean install | PASS/FAIL | Build commits/manifest, edge hash, install result |
| Master enrollment + daemon | PASS/FAIL | Smoke JSON; stale-env result; exact central run ID |
| Hooks unapproved | PASS/FAIL/NOT TESTED | Discovery row; repeated fallback IDs; command-only events |
| Hooks approved + capture policy | PASS/FAIL/NOT TESTED | Native prompt/hash/file-hook records |
| MCP / shims / broker | One result per layer | Actual result plus producer layer in central evidence |
| Latest prompt / risky-action pages | PASS/FAIL | Ordered prompts/decisions; complete snapshot IDs |
| Admin + session/workstation freeze | PASS/FAIL | A/B IDs and scope-isolation outcomes |
| Offline + redeploy | PASS/FAIL/NOT TESTED | Backlog snapshots; same identities; retained IDs; freeze preserved |
| Gateway + identity negative fixtures | PASS/FAIL/NOT TESTED | Fixture output and deployed gateway evidence where applicable |

Record four separate timestamps: action time, central receipt time, first browser visibility, and freeze-to-denial time. Script command durations include subprocess startup, real Git execution, broker and reporting work; they are not isolated policy latency.

Current scheduling is roughly 10-second passive discovery, 4-second daemon heartbeats, 5-second direct file-hook promotion/offline retry and about 8-second dashboard polling. Allow 30 seconds for initial discovery/UI checks and over 45 seconds plus polling for stale-session Offline checks. Repeated 401/403 is not a reason to wait longer or bypass authentication.

Local service benchmark means were 0.30-0.35 ms for heartbeat and 1.27-2.13 ms for single-event ingestion. They are not a Render latency or production p95/p99 guarantee. Save measured delays and the remaining NOT TESTED items; those are the next acceptance work, not hidden passes.

Troubleshooting: wrong/stale binary -> compare hash/build provenance; daemon missing/wrong target -> inspect install/login errors; 401 -> correct enrollment/signing-key continuity; 403 -> inspect ownership/restrictions; hooks-only prompt missing -> verify approved callback and capture policy; command-only reporting missing -> exact-session heartbeat/report, daemon failures and central ingest; no discovery -> recognized process adapter/client build; backlog fails to drain -> resolve transport/identity/acknowledgement before deleting anything.

At the end, deactivate Admin, explicitly clear only the test restrictions, close disposable agents and preserve reports. Do not delete journals/credentials or purge shared state as a cleanup shortcut. Dispose of the test VM/profile using the approved operator workflow.

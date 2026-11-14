# Demo: Claude Code and Codex under BAP zero trust

```powershell
pip install --upgrade bap-ltd
```

You are testing the **installed product**, as a developer would use it. You need
Python, Git, and an already installed/authenticated Claude Code or Codex CLI.
**You do not need Go, Node, a source checkout, or a compiler to install BAP.**
Use your organization's Python index if one is configured. Use the same approved
BAP release on both pilot machines. The companion module below ships with the
release containing this guide; an older published wheel may not contain it yet.

This walkthrough uses **Windows PowerShell**. Budget 45–60 minutes for local
scenes, then schedule the service recovery scenes with your administrator. Test
Claude and Codex separately: a Claude pass does not qualify Codex.

## The two terminals

- **Operator terminal:** your ordinary terminal, opened independently of the AI
  client. Installation, login, trust changes and approval decisions happen here.
- **Agent window:** Claude or Codex launched through BAP. It requests permission
  and does useful work. It must never approve its own requests or change trust.

Keep the operator terminal open throughout. A request ID in chat is a request,
not approval. Inspect the actual request in BAP before approving it. Do not
enable developer override, disable hooks, or switch to audit mode to get a pass.

## 1. Install, sign in, and check health

In the operator terminal, set the pilot service URL supplied by your operator:

```powershell
$Server = Read-Host 'Pilot control-plane HTTPS URL'
if ($Server -notmatch '^https://') { throw 'Use the approved HTTPS pilot URL' }
bap install --server "$Server"
bap login --server "$Server"
```

Follow the browser/device approval flow yourself. No access token belongs in a
prompt or in this guide. Reopen the terminal if installation changed PATH, and
set `$Server` again if needed.

```powershell
bap version
bapedge version
bap status
bap daemon status
bap doctor
bapedge plugin status
bapedge plugin layers
bapedge plugin verify claude
bapedge plugin verify codex
```

**Expected:** installed version is the approved release; workstation enrollment
points at the intended service; the daemon runs; doctor has no unresolved
failures; plugin verification succeeds for the client you will test. If the
daemon is stopped, run `bap daemon start` and check again. Investigate an
unsupported client instead of counting it as tested. `plugin verify` runs
synthetic enforcement probes; the live scenes below verify actual client behavior.

**Keep:** package/edge/client versions, doctor result, service origin, machine
label and test date. A normal pip installation must not ask you to build Go.

## 2. Make a harmless demo project and evidence sheet

Run these once in the operator terminal. Each rehearsal gets a fresh directory:

```powershell
$DemoRoot = Join-Path $HOME ('bap-pilot-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
$Work = Join-Path $DemoRoot 'workspace'
$Shared = Join-Path $DemoRoot 'shared-contracts'
New-Item -ItemType Directory -Path $Work, $Shared | Out-Null
Set-Location $Work
git init
'BAP demo: change only this synthetic file.' | Set-Content demo.txt
'# Synthetic pilot workspace' | Set-Content README.md
$env:BAP_WORKSPACE_ROOT = $Work
$DemoSession = 'sess-pilot-manual-' + [guid]::NewGuid().ToString('N')
$Evidence = Join-Path $Work 'pilot-observations.csv'
function Record-Pilot {
    param([string]$Scene, [ValidateSet('PASS','FAIL','NOT_TESTED')][string]$Result,
          [string]$EvidenceId)
    if ($Result -eq 'PASS' -and [string]::IsNullOrWhiteSpace($EvidenceId)) {
        throw 'PASS needs an observed receipt, event, report, or screenshot reference'
    }
    [pscustomobject]@{scene=$Scene; result=$Result; evidence=$EvidenceId;
        at=(Get-Date).ToUniversalTime().ToString('o')} |
        Export-Csv -LiteralPath $Evidence -Append -NoTypeInformation
}
```

Use synthetic content only. Never put real secrets in the fixture. Keep the
evidence sheet local; it needs identifiers and observations, not captured prompts,
tokens, private command output or credentials.

## 3. Show zero standing privileges, then one bounded permission

**What BAP helps with:** a signed-in developer does not give the AI unlimited
standing authority. A task gets an explicit action, boundary, lifetime and use
budget.

These are authorization probes; `zsp check` does **not** execute Git:

```powershell
bapedge zsp init --session-id "$DemoSession" --client claude-code --json
bapedge zsp status --session-id "$DemoSession" --client claude-code --json
bapedge zsp check --session-id "$DemoSession" --client claude-code --action git:status --resource workspace://current
```

**Expected:** zero standing privileges and no active task grant. The check exits
nonzero with `allowed: false` because no matching grant exists. A missing binary,
network error or malformed response is not a successful denial.

Request one harmless inspection permission:

```powershell
bapedge zsp authorize --session-id "$DemoSession" --client claude-code --mission CODE_INSPECTION --goal 'Inspect synthetic pilot workspace' --actions git:status --resources workspace://current --max-uses 1 --ttl 300s --json
bapedge zsp check --session-id "$DemoSession" --client claude-code --action git:diff --resource workspace://current
bapedge zsp check --session-id "$DemoSession" --client claude-code --action git:status --resource system://local
bapedge zsp check --session-id "$DemoSession" --client claude-code --action git:status --resource workspace://current --consume --command 'Authorization-only demo probe; no workload executed'
bapedge zsp check --session-id "$DemoSession" --client claude-code --action git:status --resource workspace://current
```

**Expected, in order:** grant issued; different action denied; different resource
denied; matching action authorized once; reuse denied because the grant is burned.
If your enterprise policy requires approval even for inspection, follow the
reported human approval flow; do not broaden the policy for the demo.

**Keep:** dedicated session ID, grant ID, the allow/deny sequence and reasons.
Repeat with `--client codex` and a fresh session when qualifying Codex. The
companion script repeats these checks automatically for either client.

## 4. Expiry and revocation remove authority

**What BAP helps with:** yesterday's task permission cannot become permanent
access.

```powershell
bapedge zsp authorize --session-id "$DemoSession" --client claude-code --mission CODE_INSPECTION --goal 'One-second demo permission' --actions git:status --resources workspace://current --max-uses 2 --ttl 1s --json
Start-Sleep -Seconds 2
bapedge zsp check --session-id "$DemoSession" --client claude-code --action git:status --resource workspace://current
bapedge zsp authorize --session-id "$DemoSession" --client claude-code --mission CODE_INSPECTION --goal 'Revocation demo' --actions git:status --resources workspace://current --max-uses 2 --ttl 300s --json
bapedge zsp revoke --session-id "$DemoSession"
bapedge zsp check --session-id "$DemoSession" --client claude-code --action git:status --resource workspace://current
```

**Expected:** the first check denies after expiry; the second denies after
revocation despite unused capacity. Keep the grant IDs and denial reasons.

## 5. Human approval: request, inspect, decide, retry

**What BAP helps with:** the AI can ask for a sensitive capability but cannot
approve that request. We use a `git:push` **authorization probe** and never push
anything to a remote.

Run the interactive companion from the operator terminal:

```powershell
python -m bap.pilot_demo --workspace "$Work" --client claude-code --interactive --sibling "$Shared" --report .bap-demo/claude-interactive.json
```

It first checks local grants, then submits a one-use publishing permission
request with no terminal attached to that subprocess. It must stop at the
approval boundary and display its dedicated session ID.

In a **second independently opened operator terminal**, navigate to the same
workspace and review the request:

```powershell
$Work = Read-Host 'Paste the demo workspace path printed in the first terminal'
Set-Location -LiteralPath $Work
bapedge zsp approvals
$RequestId = Read-Host 'Request ID matching the runner session and git:push only'
bapedge zsp approve "$RequestId"
```

Read the actions, resources and goal. Type the newly displayed code **in that
terminal**. Return to the runner and press Enter. It verifies that a grant
actually exists, consumes it once without executing a workload, and verifies
that reuse is denied. Merely pressing Enter cannot make it pass.

To demonstrate refusal, make a separate request from the agent window, then
use the same review procedure with:

```powershell
bapedge zsp deny "$RequestId"
```

**Expected:** the agent's retry remains denied after refusal. Approval must not
unlock hard-denied credentials. An interactive terminal and typed code are the
current approval mechanism; they are not biometric authentication or a separate
hardware-backed approval channel.

**Keep:** request ID, matching session, decision, resulting grant ID, subsequent
allow/deny results. Never record the one-time code.

## 6. Trust a sibling deliberately, then take that trust away

**What BAP helps with:** an agent working in one repository cannot silently
expand its write boundary to the next one. Folder trust and a task grant are
different controls; both may be required.

The interactive runner pauses at this scene after approval. It evaluates a
synthetic cross-folder copy without executing it. In its second operator terminal:

```powershell
$Shared = Read-Host 'Paste the synthetic shared-contracts folder path'
bapedge why "copy demo.txt `"$Shared\bap-demo-copy.txt`""
bapedge trust --project "$Shared"
bapedge permissions
bapedge why "copy demo.txt `"$Shared\bap-demo-copy.txt`""
```

**Expected:** policy denies before trust and permits the synthetic target after
trust. `why` reports policy decisions in text; its zero exit status alone does
not mean allowed. The runner checks the decision line, not just the exit code.

Press Enter in the runner for the after-trust check. When it asks for revocation:

```powershell
bapedge untrust --project "$Shared"
bapedge why "copy demo.txt `"$Shared\bap-demo-copy.txt`""
```

Press Enter in the runner again. **Expected:** policy denies again. If interrupted,
run the untrust command yourself; the script never changes trust on your behalf.

For the live client demonstration below, repeat this before/after/revoked
sequence while asking the agent to copy **only** `demo.txt` to that exact sibling
target. Before trust and after revocation, confirm no new write occurs. After
trust, approve only the needed task capability if asked; inspect the actual
copied text yourself. Do not trust a drive root or your entire home directory.

## 7. Claude Code: useful work with real native approvals

Return to the first operator terminal at `$Work`:

```powershell
bap claude --version
bap claude --server "$Server"
```

Paste this into Claude:

```text
This is a synthetic BAP pilot workspace. Read README.md and demo.txt. Run git
status. Append one line, "Claude pilot checked", to demo.txt. Show the diff.
Keep all changes in this workspace. If BAP requests a task grant, request only
the actions and resources actually reported as needed; stop for human approval
where required. Never change trust, approve requests, disable hooks or use an
override yourself.
```

Use Claude's normal native permission prompts. If BAP requests a grant, inspect
its canonical action/resource; use the exact bounded request it proposes instead
of guessing `system://local` or granting a wildcard. Human-only approval happens
in your operator terminal. Tell Claude to retry the original task afterward.

In the operator terminal:

```powershell
git diff -- demo.txt
bapedge plugin verify claude
bap status
```

**Expected:** actual file change and diff; a distinct governed Claude session;
native hook/broker evidence for the supported operation; no silent approval or
trust change. Confirm the session, decision and fresh timestamp in the dashboard.
Record `claude_native` only after those observations, not because a launcher opened.

## 8. Codex: repeat the same workflow independently

Exit Claude normally before starting this scene:

```powershell
bap codex --version
bap codex --server "$Server"
```

Paste the same task into Codex, replacing the appended line with
`Codex pilot checked`. Approve only the intended native tool and requested BAP
capability. Then check:

```powershell
git diff -- demo.txt
bapedge plugin verify codex
bap status
```

**Expected:** Codex produces its own real change and distinct session/evidence.
Verify the actual Read, Write and shell paths you plan to use. If one route
does not reach the installed BAP boundary, record that route as a failure/gap;
do not substitute a broker-only check and call native Codex accepted.

Repeat the scripted grant checks with its own client identity:

```powershell
python -m bap.pilot_demo --workspace "$Work" --client codex --report .bap-demo/codex-local.json
```

## 9. Show a hard boundary without exposing a secret or sending data

**What BAP helps with:** a task's goal or a human approval is not a universal
exception to credential and tampering protections.

These commands evaluate policy/authority only. They do not read `.env` or
execute a download, installer, or network request:

```powershell
bapedge why 'type .env'
bapedge why 'echo demo > .bap/project_permissions.json'
bapedge zsp authorize --session-id "$DemoSession" --client claude-code --mission CODE_INSPECTION --goal 'Synthetic credential permission rejection' --actions credential:access --resources workspace://current --max-uses 1 --ttl 60s --json
```

**Expected:** policy denies the credential and trust-store tampering commands;
the credential permission request is never grantable. Read the actual rule/reason.
An unrelated missing grant does not establish secret protection.

In each live agent, ask it to use its **native Read tool** on the deliberately
nonexistent path `.env.bap-demo-never-created` in this fixture, and stop after
the first refusal. Do not create that file or use any real secret path.
**Expected:** a BAP credential-policy denial before the tool reads; “file not
found” alone does not pass. Ask it to run `bapedge trust` or `bapedge zsp approve`
only as a denied human-only command probe, not as a way to grant access. The
client/BAP boundary must refuse it; the operator remains the only decision maker.

For enterprise supply-chain rules, inspect the installed policy with `why`
using your operator's synthetic bypass example. Do not install a package to
demonstrate denial. Public package sources are not universally forbidden in a
consumer installation; record enterprise mirror enforcement only where configured.

## 10. Central visibility and scoped administrator controls

```powershell
bap launch
bapedge verify-log
```

Use the pilot dashboard for the configured `$Server`. The service administrator
signs in through its supported admin flow; never paste the admin credential into
the agent window. Keep two live sessions A and B open, with separate terminals.

| Action to perform | Expected observation | Evidence to keep |
|---|---|---|
| Run a harmless operation in A | Fresh session/event arrives centrally | Session ID, event ID, action time, server time, first visible refresh |
| Attempt a denied synthetic operation in A | Denied decision remains Denied in details and latest activity | Event/receipt ID and actual reason |
| Freeze A from the dashboard | Next governed action in A blocks; B can still perform its permitted action | Admin result and both operation receipts |
| Restore A explicitly | New permitted work in A succeeds after sync | Restore result, sync time, new receipt |
| Freeze the demo workstation | Its governed sessions block after sync | Workstation ID and receipts |
| Restore workstation, with any separate session freeze still present | Workstation restore does not erase that session restriction | Independent restriction evidence |

Observe the actual synchronization delay; do not promise instant browser control.
If another independent restriction is active, restore it explicitly. Restore all
demo restrictions at the end. Local `verify-log` verifies retained local chain
integrity; it does not prove server delivery or durable backup.

## 11. Recommend a repeated benign block instead of bypassing policy

In the operator terminal, after a **real harmless blocked call**:

```powershell
bap recommend
```

Inspect the selected effect and scope before submitting. The administrator
reviews the pending recommendation in V3, approves or rejects it, and observes
signed policy synchronization back to this machine.

```powershell
bap recommend --status
```

**Expected:** submission alone changes no permission. An approved recommendation
takes effect only after the signed policy arrives. Retry the exact benign
operation; then have the administrator revoke the recommendation, sync, and
retry again. It must lose that exception. Check a second machine remains
unaffected. This machine-scoped exception is different from the short-lived
local ZSP approval in scene 5.

**Keep:** recommendation ID, effect, machine scope, administrator decision,
policy version, and before/after/revoked receipts. If no benign block is available,
mark this scene `NOT_TESTED`; do not recommend credential access as a shortcut.

## 12. Privacy, long work, disconnects, and recovery

Run these with your pilot operator. Use the installed product throughout.

| Feature | Repeatable action | Required result |
|---|---|---|
| Metadata-first reporting | Leave `BAP_TELEMETRY_CONTENT` unset on clients and service. Put a unique synthetic phrase in demo.txt; ask the client to summarize it. Operator inspects the corresponding retained telemetry. | Decisions/IDs arrive without the phrase, prompt text, file text, or command arguments being retained as content. A missing dashboard field alone is insufficient. |
| Work longer than two minutes | Set `$env:BAP_EXEC_TIMEOUT_SEC = '300'` before launching a fresh client. Ask it to run a harmless PowerShell `Start-Sleep -Seconds 125` followed by `Write-Output 'long-job-complete'`, with the required bounded approval. | It finishes after at least 125 seconds; no legacy 120-second kill. Record actual elapsed time. |
| Short timeout | In the operator terminal, set `$env:BAP_EXEC_TIMEOUT_SEC = '2'`; request/approve only the needed synthetic sleep capability and invoke the broker command below. | Sleep is terminated well before 10 seconds; nonzero exit, reason includes `timed out`. Restore the timeout afterward. |
| Reporting outage | Operator temporarily stops only the dedicated pilot reporting service. In an already enrolled session, perform one permitted and one denied synthetic operation. | Local restrictions remain effective; reporting failure/backlog is visible. Online-dependent authority may deny. |
| Service recovery | Operator restores that same service origin and persistent authority configuration. | Original evidence replays without duplicated event IDs; restrictions remain until explicit restoration; reporting recovery does not mint anonymous execution authority. |
| Application/daemon recovery | Exit clients, close the terminal, open a new terminal and run the checks below. Schedule a workstation reboot separately. | Installation and enrollment survive, daemon returns, fresh supported client activity reports. |

For the short timeout, in the operator terminal with a dedicated session:

```powershell
$env:BAP_EXEC_TIMEOUT_SEC = '2'
bapedge exec --session-id "$DemoSession" --json --shell powershell 'Start-Sleep -Seconds 10'
```

If it refuses for a missing task grant, use the reported bounded request and
human approval flow, then retry. **A missing-grant denial is not a timeout pass.**
After the scene:

```powershell
Remove-Item Env:BAP_EXEC_TIMEOUT_SEC -ErrorAction SilentlyContinue
bap daemon status
bap doctor
bapedge plugin verify claude
bapedge plugin verify codex
bapedge verify-log
```

The optional `bapedge onboarding begin` / `bapedge onboarding check --require`
flow is a Claude reporting-correlation probe, not Codex acceptance. Its current
policy-record correlation depends on captured command content, so do not use it
as the acceptance gate for this metadata-first walkthrough or silently enable
content capture to make it pass.

## 13. Run the automated local checks whenever you need confidence

From your installed environment, without a checkout:

```powershell
python -m bap.pilot_demo --help
python -m bap.pilot_demo --workspace "$Work" --client claude-code --report .bap-demo/claude-local.json
python -m bap.pilot_demo --workspace "$Work" --client codex --report .bap-demo/codex-local-2.json
```

The runner checks real installed CLI responses: no standing grant, bounded read,
wrong action/resource refusal, use exhaustion, expiry, revocation, and credential
authority denial. It uses a fresh dedicated session, never executes Git publishing,
never reads secret files, and revokes its own grants afterward. It does not change
shared policy, install packages or approve anything. Existing reports are not
overwritten; choose a new filename for each rehearsal.

Add `--interactive --sibling "$Shared"` to verify actual grant appearance after
your separate approval and the denied/allowed/denied trust-policy transition.
Those trust checks are policy explanations, not proof of a native file write.

**Exit 0:** the executed local checks passed. The report says
`LOCAL_CHECKS_PASS_MANUAL_ACCEPTANCE_REQUIRED`. **Exit 1:** a checked transition
failed. **Exit 2:** invalid setup/arguments. Native clients, dashboard controls,
privacy, and recovery stay `NOT_TESTED` in that report; record their observed
results in the evidence sheet. No simulated enrollment or pretend success.

## 14. Make the pilot decision from observed results

After each manual scene, run `Record-Pilot` in the original operator terminal.
Supply the actual evidence reference when prompted, for example:

```powershell
$Ref = Read-Host 'Observed Claude receipt/event ID or screenshot filename'
Record-Pilot 'claude_native' PASS $Ref
$Ref = Read-Host 'Observed Codex receipt/event ID or screenshot filename'
Record-Pilot 'codex_native' PASS $Ref
Import-Csv -LiteralPath $Evidence | Format-Table -AutoSize
```

Record the remaining scenes the same way, using `FAIL` or `NOT_TESTED` when
appropriate. A script pass cannot fill them in for you.

| Required for your selected pilot scope | Acceptance evidence |
|---|---|
| Installed release and health | Versions, enrollment, doctor, actual supported plugin checks |
| ZSP and human approval | Script reports plus reviewed request/decision IDs |
| Trust and native boundaries | Before/after/revoked policy checks and actual native tool results |
| Each selected client | Useful work, native allow and deny, correct independent session |
| Service and administrator controls | Delivery timestamps, isolation, explicit restoration |
| Recommendations, if offered to users | Approved/rejected/revoked and signed-sync observations |
| Privacy and resilience | Capture inspection, timeout, long task, outage/replay, restart/logon |
| Clean exit | No demo grants or trusts left, restrictions restored, native settings healthy |

Start with two internal users on the client/OS combinations you actually passed.
Give them this guide, a support contact, expected approval response time, and a
stop/rollback procedure. Expand after a full working day and a fresh-logon run
without unexplained denials, missing events or permissions that outlive their
intended scope. Leave failed/unrun features out of the pilot promise.

## 15. Clean up without damaging your installation

In the operator terminal at `$Work`:

```powershell
bapedge zsp revoke --session-id "$DemoSession"
bapedge untrust --project "$Shared"
bapedge permissions
Remove-Item Env:BAP_EXEC_TIMEOUT_SEC -ErrorAction SilentlyContinue
Remove-Item Env:BAP_WORKSPACE_ROOT -ErrorAction SilentlyContinue
bap daemon status
bap doctor
```

Exit Claude/Codex normally so transactional launcher settings can be restored.
Restore demo session/workstation restrictions and revoke demo recommendations in
the dashboard. Keep the evidence directory for review; do not delete audit state,
reset a shared fleet, or log out the workstation just to tidy the demo.

For removal on a dedicated test machine, after preserving evidence, use
`bap uninstall` and verify the native client works with its restored settings.
Service deployment, backup/restore, and release build qualification belong to
your operator: [maintainer checklist](docs/MAINTAINER_PILOT_QUALIFICATION.md).

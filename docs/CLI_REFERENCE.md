# BAP command reference

Two audiences, kept apart on purpose:

- **Part 1 – Everyone.** Commands that ship with `pip install bap-ltd` (`bap`, `bapedge`, `bap-install`, `bap-launch`, `bap-doctor`) and the administrator API on the control plane.
- **Part 2 – Internal BAP developers only.** Build, test and repository-maintenance tooling. None of it is packaged in the wheel or the release archives. Do not run it on a managed workstation, and do not document it to end users.

`bap` and `bapedge` are the same program. Run `bapedge help` for the authoritative list for your build.

---

## Part 1 – Everyone

### Set up and sign in

| Command | What it does |
|---|---|
| `pip install bap-ltd` | Installs the CLI and the platform binaries. No keys to generate; the policy-signing key is pinned automatically when you sign in. |
| `bap-install` | One-time user-mode setup (no admin rights). Add `--debug` to also install the optional diagnostic tools (`review`, `watch_session`, `check_stale_copies`). |
| `bap login` | Sign in with your company identity (OIDC device flow). Enrolls this machine, pins the control plane's policy key and fetches the first signed rules. `--verify-now` waits for the first sync. |
| `bap register <code>` | Enroll with a one-time code from an administrator instead of OIDC. |
| `bap logout` | Deregister this machine and clear the session. |
| `bap-doctor` / `bapedge doctor` | Pre-flight health check. |

### Day to day

| Command | What it does |
|---|---|
| `bapedge status` | Daemon state, policy version and digest, sessions, audit spool. The *defense-layer* section reports what was **observed**, not what is assumed (see [ARCHITECTURE.md](../ARCHITECTURE.md#defense-layers-what-each-one-does-and-does-not-guarantee)). |
| `bapedge why "<command>"` | Explain why a command would be allowed or blocked. |
| `bapedge sync` | Fetch the latest signed rules now. Machines also sync on their own within seconds; if the control plane is unreachable the last signed rules stay in force. |
| `bapedge check "<command>"` | Decision only: evaluate a command without running it. |
| `bapedge trust --path <dir> --scope session\|project\|global` | Authorize writes or deletes in a folder outside the workspace. Never accepted for filesystem roots, the home directory, system folders or credential locations. |
| `bapedge untrust --path <dir>` / `bapedge permissions` | Revoke / list those authorizations. |
| `bapedge zsp authorize ...` | Ask for a task grant (zero standing privilege). Evaluated by policy; it does not approve itself. |
| `bapedge sweep` | Remove orphaned session markers and flush the offline audit spool. |
| `bapedge verify-log` | Verify the tamper-evident hash chain of the local audit log. |
| `bapedge version [--json]` | Version, commit, build date. |

### Reducing friction: recommend a blocked call

Most blocked work is harmless and should not keep asking. When BAP blocks something that is clearly part of normal development (for example `go test`), send it to your administrator instead of working around it.

```
bap recommend                  # list recent blocked calls, grouped by effect, then pick one to inspect
bap recommend --pick 2 --justify "runs the project's unit tests"
bap recommend --status         # what you recommended and what the administrator decided
bap review recommend           # the same flow, from the session reviewer
```

- Only a **registered machine** can submit. The control plane rejects any other caller.
- Only effects from the local development loop can be recommended (build, test, in-workspace edits, local git commits). Network access, deletion, publishing, databases, arbitrary interpreters and credentials can never be approved this way; use a task grant.
- An approval applies to **that machine only** and to **work inside the workspace only**. It relaxes the grant requirement and nothing else: secrets, exfiltration and tamper protection are still enforced.
- The command line sent to the administrator is truncated and has token/password-like values removed.

### Administrators (control plane)

All admin calls need the administrator token. On a hosted control plane, remote admin must be enabled (`BAP_ALLOW_REMOTE_ADMIN=1`); otherwise only loopback callers are accepted.

```powershell
$h = @{ Authorization = "Bearer $env:BAP_ADMIN_TOKEN" }
$cp = "https://<your-control-plane>"

# Enforcement settings: fleet default and per-machine overrides (reads need no grant when true)
Invoke-RestMethod "$cp/api/v1/admin/policy/settings" -Headers $h
Invoke-RestMethod -Method Post "$cp/api/v1/admin/policy/settings" -Headers $h -ContentType application/json `
  -Body (@{ asset_id = '<asset id from enrolled_assets>'; zsp_read_exempt = $true } | ConvertTo-Json)
Invoke-RestMethod -Method Delete "$cp/api/v1/admin/policy/settings?asset_id=<id>" -Headers $h

# Review what developers recommended
Invoke-RestMethod "$cp/api/v1/admin/policy/recommendations?status=pending" -Headers $h
Invoke-RestMethod -Method Post "$cp/api/v1/admin/policy/recommendations/<id>/approve" -Headers $h -ContentType application/json -Body '{"note":"routine test run"}'
Invoke-RestMethod -Method Post "$cp/api/v1/admin/policy/recommendations/<id>/reject"  -Headers $h -ContentType application/json -Body '{"note":"use a task grant"}'

# Take an approval back
Invoke-RestMethod -Method Delete "$cp/api/v1/admin/policy/approvals?asset_id=<id>&action=dev:go:test" -Headers $h

# Rotate the policy-signing key (enrolled machines follow automatically)
Invoke-RestMethod -Method Post "$cp/api/v1/admin/policy/rotate-key" -Headers $h
```

Every change is signed per machine, bumps the policy version and is audited. Machines pick it up on their next sync. Overrides and approvals can only target a machine the control plane has enrolled.

Hosted control planes with an ephemeral disk (Render, containers) must set `BAP_POLICY_SIGNING_SEED` (stable signing key across redeploys) and should set `BAP_POLICY_SYNC_REQUIRE_AUTH=1` (no anonymous policy sync).

### Process behavior you can rely on

`bapedge watch` runs one watcher per session. It exits when its session ends (`SessionEnd`, `bapedge sweep`), when the watched process exits, or when the control plane closes or revokes the session, and a duplicate for the same session exits immediately. This is covered by an end-to-end test that fails if any process is left running (`tests/test_bapedge_process_lifecycle.py`).

---

## Part 2 – Internal BAP developers only

> **Not for end users, not packaged, not supported on managed workstations.**
> These commands build, test and maintain this repository. They are not in the wheel or the release archives, several of them start throwaway servers or delete files, and some depend on the developer override, which is compiled out of release builds.

### Developer override

`bapedge dev-override on|off|status` opens a time-boxed window (4 h default, 12 h maximum) so BAP can be developed under BAP. It only exists in builds made with `AllowDevOverrides=true` and only when `BAP_ENVIRONMENT=development`. It suspends anti-tampering and task-grant checks; credentials, revocation and Cedar policy still apply. **A human must turn it on. Automated agents must never run it.**

### Build and package

| Script | Purpose |
|---|---|
| `build_binaries.bat` | Build all Windows binaries and copy them to the places the launchers and tests expect. |
| `update_binaries.ps1 -AllowDevOverrides false` | The build step CI uses. `false` is what release builds use. |
| `build_all_platforms.ps1` | Cross-platform release-style build and role packages (`dist/`). |
| `python scripts/build_wheel.py [--universal]` | Build the PyPI wheel and sdist. |
| `install_bap_client.bat` | Install the locally built client for this developer. |
| `scripts/bump_version.py` | Bump the version everywhere. |

After any rebuild, confirm the hook binaries match (a stale copy under `dist/` once denied what the current build allowed):

```powershell
Get-FileHash cchook\interceptor.exe, dist\windows-amd64\claude-client\cchook\interceptor.exe, $env:USERPROFILE\bin\interceptor.exe
```

### Test and verify

| Command | Purpose |
|---|---|
| `go test ./...` in `bap-edge`, `bap-controlplane`, `cchook`, `bap-gateway`, `copilot` | Go unit and integration tests. |
| `python -m unittest discover -v tests` | Python integration and end-to-end suites (CI uses this form; it does not load `conftest.py`, so set `BAP_STATE_DIR` to an empty directory). |
| `python -m unittest tests.test_bapedge_process_lifecycle` | Process lifecycle: no leaked or duplicate `bapedge` processes. `BAP_TEST_BAPEDGE=<path>` tests a specific binary. |
| `.\scripts\run_pilot.ps1 [-Quick] [-SkipPlugins]` | Automated pilot: starts an isolated control plane and gateway and exercises every feature. See [PILOT_RUNBOOK.md](PILOT_RUNBOOK.md). |
| `python scripts/check_capability_claims.py` | Fails if a document claims a capability the code does not have. |
| `BAP_ZSP_STRICT_READS=1` | Require grants even for reads (used by tests that count grant use). |

Tests must never touch a real state directory or a production control plane. Use `BAP_STATE_DIR` and a local control plane.

### Repository maintenance

| Script | Purpose |
|---|---|
| `scripts/prune_repo.ps1 [-Apply] [-IncludeLegacyDemos] [-IncludeStaleDocs]` | Remove tracked debris, duplicates and stale documents. Dry run unless `-Apply`; never commits. |
| `scripts/check_stale_copies.*` | Find stale UI/policy copies across workspaces. |
| `scripts/bap_harness.py` | Multi-session harness for concurrency work. |
| `scripts/supervise_controlplane.*`, `start_controlplane_supervisor.*` | Run a local control plane under a supervisor. |
| `demo_*.py`, `run_*_demo.*`, `cio_demo.bat`, `tech_demo.bat` | Presenter demos. |
# Pilot qualification additions

`bapedge exec --timeout 30m --progress "<command>"` runs a bounded long job. Default: 30 minutes (or `BAP_EXEC_TIMEOUT_SEC`); maximum: 24 hours. Progress reports elapsed time on stderr. Output is captured and bounded to 4 MiB; this is not an interactive terminal stream. Ctrl+C requests cancellation and process-tree cleanup. Invalid timeout configuration fails explicitly.

Broker JSON `timings_ms` separates the shell authorizer call, pre-execution work, and elapsed broker work before final reporting. Child execution, identity/bootstrap, grant checks and network delivery have different costs; do not describe total command time as local policy latency.

`bapedge doctor --hook-copies-json --expected-hook-sha256 <approved-hash> --hook-copy <path> ...` compares explicitly supplied configured hook copies. It does not discover unknown vendor locations or verify publisher authenticity.

`bapedge doctor --repair-policy` requests a fresh authenticated signed policy from the enrolled/locked origin. It preserves identity and trust; unavailable/rejected authority remains a failure.

`bap recommend` submission requires a human terminal; agent/non-interactive submissions and the former `--yes` bypass are refused. V3 now exposes the per-machine recommendation review queue separately from temporary escalation approvals.

The control plane accepts `--durable`, `--initialize-authority` (first start only), and `--policy-max-age <duration>`. Production requires durable single-node SQLite at an absolute persistent path, stable token/policy signing configuration and an explicit offline policy budget. Remove `--initialize-authority` from regular service configuration after first initialization. Missing checkpoints then fail closed. See [pilot runbook](PILOT_RUNBOOK.md).

New Go edge/hook telemetry defaults to metadata mode; `BAP_TELEMETRY_CONTENT=redacted` explicitly opts into content and may transmit source code. This setting is not a complete DLP system. See [telemetry privacy](TELEMETRY_PRIVACY.md).

# Pilot runbook: install, demonstrate, verify

This is the master runbook. It takes you from a bare control plane to every
instance, and maps each use case to the scene that proves it.

- Step-by-step scenes with commands and expected results:
  [DEMO_CLAUDE_CODEX_ZERO_TRUST.md](../DEMO_CLAUDE_CODEX_ZERO_TRUST.md) (scenes 1-15).
- Installed companion: `python -m bap.pilot_demo`. It checks local grant
  transitions and can guide the human approval and trust scenes. It needs no Go,
  Node, source checkout or test dependencies.
- Release build checks and service configuration:
  [maintainer qualification](MAINTAINER_PILOT_QUALIFICATION.md).

Record `PASS`, `FAIL` or `NOT_TESTED` for every use case in section 5. Do not
count a scene as passed because a command printed no error; use the evidence
named in each row.

## 1. Topology

| Piece | What it is | Where it runs |
|---|---|---|
| Control plane (CP) | Signs policy, receives audit, shows the dashboard | Hosted service (section 2) |
| Workstation instance | `bapedge` daemon + hooks + MCP server + shims on one machine | Each tester machine |
| Agent clients | Claude Code, Codex, Copilot, Antigravity, opencode | On each workstation |
| Gateway (Layer 5) | `bapgateway` protecting named resources | Optional; only if you test Layer 5 |

Two terminals are used throughout: an **operator terminal** (install, login,
approvals, trust, restrictions) and the **agent window**. The agent must never
approve its own request.

## 2. Deploy the control plane

Pick one. Both run the same container ([Dockerfile](../Dockerfile)).

### 2a. Persistent service (use this for a real pilot)

Production mode refuses to start unless all of these are set:

| Variable | Value |
|---|---|
| `BAP_MODE` | `prod` |
| `BAP_POLICY_MAX_AGE` | an offline budget between `1m` and `168h`, for example `24h` |
| `BAP_SECRET_KEY` | stable, at least 32 characters |
| `BAP_POLICY_SIGNING_SEED` | exactly 64 hex characters (generate once, keep forever) |
| `BAP_DB_PATH` | absolute path on a **persistent disk**, for example `/data/authority.db` |

First start of a genuinely new authority only: add `--initialize-authority`
once, then remove it. Without a persistent disk the service cannot keep its
authority checkpoint and will refuse to start.

### 2b. Free tier or demo host (no persistent disk)

Everything above, plus:

| Variable | Value |
|---|---|
| `BAP_EPHEMERAL_AUTHORITY` | `acknowledged` |

This is for demos only. Every restart or spin-down starts a **new, empty
authority**, so enrollments, sessions and decisions are lost and every
workstation must re-register. Do not use it for evidence you need to keep.
Never use it for a real fleet. Corrupt or mismatched checkpoints are still
refused. The startup log prints an `EPHEMERAL AUTHORITY` warning.

### 2c. Confirm which build is running

Every deploy prints a `BUILD INFO` line first, before any startup check can
exit. Check it, and `/api/v1/health` (it reports `version` and `git_commit`).
If the commit is not your latest, Render is serving an older build; a deploy
that crashes at startup leaves the previous build live.

```powershell
Invoke-RestMethod "$Server/api/v1/health"
```

## 3. Install each instance

Repeat on every workstation. Use a clean machine for instance A and a second
machine or user profile for instance B.

```powershell
$Server = Read-Host 'Pilot control-plane HTTPS URL'
bap install --server "$Server"
bap login --server "$Server"
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

Expected: the daemon is running, doctor has no unresolved failure, the
workstation is enrolled at the intended `$Server`, and plugin verification
passes for each client you will test. If the daemon is stopped, `bap daemon
start`. Mark an unsupported client `NOT_TESTED`; do not count it.

Check that audit is reaching the CP, not only piling up locally:

```powershell
bapedge status
```

Read the **Spool Backlog** line. A large "un-flushed entries" number with a
running daemon means delivery is failing. Run `bapedge sweep`, then check the
daemon and `$Server` reachability. If the backlog does not drain, the dashboard
will look empty even though the agent is working. Fix delivery before any scene
that needs central visibility.

## 4. How to read `bapedge status` layers

The five layers report what was **observed from real events**, not what is
configured. `OBSERVED` means events from that layer were seen in the last 24
hours; it does not mean every action is intercepted.

| Layer | Evidence it appears | If it stays `NOT_OBSERVED` |
|---|---|---|
| 1 Native hooks | Hook events and a fresh `hook-heartbeat` marker | Hooks are unapproved or disabled in the client |
| 2 BAP MCP | Calls through `bap_*` tools | The agent used its built-in tools |
| 3 Terminal shims | Shim-routed commands | Absolute paths or another shell were used |
| 4 Broker | `bapedge exec` events | Commands never reached the broker |
| 5 Gateway PEP | Protected-resource events | Traffic did not go through the gateway |

When Layer 1 is silent but a lower layer is reporting, status says hooks may be
unapproved or disabled. The dashboard shows the same per-layer coverage and a
degraded reason on each session.

## 5. Use case matrix

Run in order. Mark each row with the evidence you kept.

| # | Use case | Prove it with | Evidence |
|---|---|---|---|
| 1 | Install, enroll, health | Demo scene 1; section 3 | Versions, doctor result, enrolled origin |
| 2 | Useful work under governance | Demo scenes 2, 7, 8 | Session and event IDs for Claude Code and Codex |
| 3 | Zero standing privileges | Demo scene 3 | Denied before grant, allowed within grant, denied after use count |
| 4 | Expiry and revocation | Demo scene 4 | Receipts before and after expiry |
| 5 | Human approval | Demo scene 5 and section 6 | Request ID, decision, retried command receipt |
| 6 | Trust and un-trust a sibling | Demo scene 6 | `bapedge permissions` before and after |
| 7 | Hard boundary denials | Demo scene 9 | Denial reason, no secret read, no data sent |
| 8 | Central visibility and admin controls | Demo scene 10 | Freeze and restore receipts for session and workstation |
| 9 | Policy sync end to end | Demo scene 11 and section 7 | Policy version before, after, revoked |
| 10 | Layered reporting and fallback | Section 8 | Layer coverage, degraded reason, grade of each record |
| 11 | Privacy, long work, disconnect, recovery | Demo scene 12 | Behavior during outage and after repair |
| 12 | Local integrity | `bapedge verify-log` | Chain verified |
| 13 | Automated local checks | Demo scene 13; `python -m bap.pilot_demo` | Report at `.bap-demo/report.json` |
| 14 | Multiple instances and agents | Section 9 | Independent restrictions per instance |
| 15 | Pilot decision and cleanup | Demo scenes 14, 15 | Decision record |

## 6. Human approval, as it really behaves

Read this before scene 5 and before approving anything.

1. The agent asks for a high-risk permission with `bapedge zsp authorize`.
   BAP does not grant it. It raises a request and prints an ID such as
   `req-1a2b3c4d`, valid for 30 minutes.
2. In the **operator terminal**:

   ```powershell
   bapedge zsp approvals
   bapedge zsp approve req-1a2b3c4d
   ```

   Approval needs a real terminal and a one-time code. It cannot run inside
   the agent window, and developer override does not change this.
3. Approval **mints a short-lived grant** (default about five minutes, limited
   uses) for the requesting session and the requested actions. It does **not**
   mark the agent's request as "approved". Running `zsp authorize` again
   raises a **new** request.
4. After approval the agent must run the **actual command** (for example the
   build or test) straight away, while the grant is live. Do not re-run
   `authorize`. If the grant expires first, ask for a fresh approval and run the
   command immediately.

Approval requests and decisions appear in the audit trail as
`zsp_approval` events (`approval_pending`, `approval_approved`,
`approval_denied`) with decision `observed`, so they are visible centrally
without being counted as allows or denies. They are visibility only: the
decision always stays local, out of band, and behind the one-time code. The
dashboard's "approval policy" control revokes approved *policy effects* and is
a different feature.

## 7. Policy sync

1. Note the policy version and digest: `bapedge status` (Policy Bundle section).
2. Cause a harmless block, then `bap recommend` and inspect the effect and scope.
   Submitting changes no permission.
3. An administrator reviews and approves in the dashboard.
4. `bapedge sync` (machines also sync on their own). Version and digest change.
5. Retry the exact operation: it succeeds. Have the administrator revoke it,
   `bapedge sync`, retry: it fails again.
6. Check a second machine is unaffected.

If the control plane is unreachable, the last signed rules stay in force and
audit queues locally. Test this by stopping reachability and confirming
enforcement continues, then restore and confirm the spool drains.

## 8. Layered reporting and fallback

Goal: prove that evidence is collected even when native hooks are not
approved, and that each record states how trustworthy it is.

Evidence grades:

| Grade | Source | Meaning |
|---|---|---|
| `verified` | Hook, broker, shim, gateway | BAP code observed it directly |
| `mediated` | BAP MCP tools | BAP executed the call but did not see the prompt |
| `self_reported` | `bap_report_request` | The model said it; unverifiable; never used for decisions |
| `presence` | Discovery | The agent process exists; no content |

Enable the fallback reporter only where you want to test it: set
`BAP_FALLBACK_REPORTING=1` in the environment of the BAP MCP server (the
agent's MCP configuration). It is off by default.

| Step | Action | Expected |
|---|---|---|
| 1 | Normal session, hooks approved | Layer 1 `OBSERVED`; `bap_report_request` returns `hook_active` and records nothing |
| 2 | Disable or do not approve hooks for the client; start a new session | No fresh heartbeat; Layer 1 `NOT_OBSERVED` |
| 3 | Ask the agent a task that uses BAP tools | Layer 2 `OBSERVED`; status names hooks as likely unapproved or disabled |
| 4 | Check the dashboard row for that session | Per-layer coverage shown and the degraded reason |
| 5 | Check the prompt record | Present only as `self_reported`, with text reduced to a hash if metadata-only capture is on |
| 6 | Re-enable hooks, new session | Back to step 1; no duplicate prompt records |

Known limits (record them, do not hide them): the fallback depends on the model
calling the tool, so a skipped call means `L2 silent`, not green. Commands that
bypass the BAP tools and shims are seen by no layer. Gateway evidence exists
only for traffic routed through the gateway.

## 9. Multiple instances and agents

- Run two live sessions (A and B) on one workstation, and one session on a
  second workstation.
- Freeze A in the dashboard: A's next governed action blocks; B and the second
  workstation continue. Restore A explicitly.
- Freeze the workstation, restore it, and confirm a separate session freeze is
  **not** erased by the workstation restore.
- Repeat the core scenes for each additional client you claim to support
  (Copilot, Antigravity, opencode). Anything unverified is `NOT_TESTED`.
- Shadow-IT discovery: start an unmanaged agent process and confirm it appears
  as an observed `discovery` session with no tool evidence.

## 10. Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| CP exits: "Production requires an explicit offline budget" | `BAP_POLICY_MAX_AGE` missing | Section 2a |
| CP exits: "authority checkpoint missing" | No persistent disk | Section 2a or 2b |
| New deploy does not take effect | Previous build still live; new one crashes | `BUILD INFO` line, `/api/v1/health` `git_commit` |
| Dashboard empty but agent works | Audit not delivered; spool backlog | `bapedge status` Spool Backlog; daemon; reachability |
| Layer 1 shows `NOT_OBSERVED` while hooks "work" | Hooks unapproved or disabled in the client, or no events in 24 hours | Section 4; `bapedge plugin verify` |
| `zsp authorize` keeps raising new requests | Approval mints a grant; it does not approve the request | Section 6 |
| Go build or test denied in an agent session | High-risk action needs human approval | Section 6; approve, then run the command at once |
| Approval seems to do nothing | Grant expired before the command ran | Re-approve and run immediately |

## 11. Evidence to keep

For each row in section 5: session ID, event or receipt ID, the policy version
before and after, the control plane origin and build commit, machine label, and
the date. A pilot decision (scene 14) rests on observed results only.

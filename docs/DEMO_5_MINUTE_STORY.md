# Warrant in 5 minutes: the story demo

> **Working name.** "Warrant" is a placeholder product name for the Bounded Authority Plane (BAP). Replace it globally once a name is cleared. Component names (`bapedge`, control plane, gateway) are unchanged.

**One-line pitch:** AI coding agents start with zero authority. They ask for exactly what they need, receive a short-lived single-use grant, and every decision leaves a receipt.

**Audience:** engineering leaders, security teams, developers. **Length:** 5 minutes. **Setup:** one governed Claude Code terminal and one browser tab on the dashboard in **Live** mode. Use a disposable workspace with synthetic data only.

This is the story version. The full acceptance runbook, with every pass/fail check and caveat, is [claude-demo.md](../claude-demo.md). Rehearse with this script, then run the runbook before any customer-facing session.

## Before you start (not shown to the audience)

- [ ] Enforce mode is on (`bapedge status`). Developer override is off.
- [ ] Dashboard is in **Live** mode, not the guided demo. Admin is **Off** at the start.
- [ ] Fixture `scratch/claude-showcase/.env` contains only `DEMO_ONLY_NOT_A_SECRET=synthetic-fixture`. Never use a real credential file.
- [ ] Claude is launched through the governed launcher so hooks, MCP and shims are active.
- [ ] Admin token is held by the presenter and never typed into a prompt, URL or screenshot.
- [ ] Control plane is reachable. The outage scene (Scene 4, optional) needs an isolated local control plane only.

## The opening (30 seconds)

**Say:** "Today an AI agent runs as you. It has your SSH keys, your cloud tokens, your `.env` files. If it is tricked or simply wrong, nothing separates its mistake from yours. We take the opposite approach: the agent starts with nothing, and everything it does is bounded, decided by policy, and recorded."

**Show:** the dashboard with one enrolled workstation and no active grants.

## Scene 1: The agent asks, policy answers & JIT grants obtained (Automatic & Manual) (90 seconds)

**Goal:** show zero standing privilege, contrast **Automatic JIT Grants** (routine workspace modification) against **Manual HITL Grants** (elevated/sensitive scopes), and prove seamless multi-agent governance across **Google Antigravity (AG)**, **OpenAI Codex**, and **Claude Code**.

### 1A. Automatic JIT Grant Acquisition (Routine Workspace Work)

**Prompt to your coding agent (Antigravity, Codex, or Claude):**

```text
execute command "git add GEMINI.md" and obtain grant if needed
```
*(Or test run):*
```text
Inspect this repository with git status and git diff --stat. Summarize what
changed and suggest one small test improvement. Obey workspace policy. Do not
read credential files.
```

**What happens behind the scenes:**
- The agent starts with **Zero Standing Privilege (ZSP)**.
- When `git add GEMINI.md` is invoked, the broker intercepts the action. Because it is a benign workspace write bounded to the current repository, Cedar policy automatically attests the intent and mints a single-use ephemeral grant tagged **`[AUTOMATIC]`** (`grant-xxxxxx`).
- The command executes with exit code 0.
- The grant **immediately burns** upon execution (`1x Used / Burned`) to prevent replay attacks.

---

### 1B. Manual / Out-of-Band HITL Grant (Elevated / High-Risk Operations)

**Prompt to your coding agent (Antigravity, Codex, or Claude):**

```text
Request an elevated task grant for python execution "dev:python:exec" to run scripts/verify_sts.py
```
*(Or via direct terminal command):*
```powershell
bapedge zsp authorize --actions "dev:python:exec" --resources "workspace://current" --goal "Run STS verification"
```

**What happens behind the scenes:**
- High-risk / elevated operations cannot be auto-minted (`HIGH_RISK_OOB_GATE`).
- The agent submits a 4-Tuple Task Authorization Envelope (Who, AuthorizedBy, Intent, PermissionAsk) via MCP (`bap_request_task_grant`) or CLI (`bapedge zsp authorize`).
- A human operator is prompted for an **interactive out-of-band challenge** (`bapedge zsp approve` or terminal prompt).
- Once approved, the daemon mints an attested single-use grant tagged **`[MANUAL (HITL)]`**.
- The agent consumes the grant to execute the task; the cryptographic receipt permanently records the human approver's SSO identity.

---

### Multi-Agent Governance Across All Coding Agents

The exact same ZSP grant lifecycle governs all coding agents:
- **Google Antigravity (`AG`)**: Governed via the native `bap-zero-trust` MCP server (`bap_execute`, `bap_request_task_grant`) and the `agy` CLI launcher.
- **OpenAI Codex**: Governed via `bapedge exec` and `codex` / `run_codex_cli_bap.bat`.
- **Claude Code**: Governed via `interceptor.exe` hooks and `claude` / `run_claude_bap.bat`.

---

### What to point at in the Cockpit UI & Dashboard

1. **Live Session Drawer (`dConvo`):**
   - Click on the active session row in the dashboard.
   - At the top of the drawer, point at the **🔑 Zero Standing Privilege (ZSP) Task Grants** ledger table:
     - **Grant ID**: Nonce-bound ephemeral token (`grant-xxxxxx`).
     - **Acquired By**: Identifies the exact agent (`🤖 Antigravity`, `🤖 Claude Code`, `🤖 Codex`).
     - **Acquisition Mode**: Clearly contrasts **`[AUTOMATIC]`** (Policy Attestation) vs **`[MANUAL (HITL)]`** (Human Approved).
     - **Scope**: Narrowed canonical action scopes (e.g. `git:add:write`, `workspace://current`).
     - **Lifecycle**: Displays **`1x Used / Burned`** (or `Expired Unused` if unconsumed).
     - **Executed Command**: The exact command executed under the grant with its tamper-evident receipt link.
2. **STS & OBO Tokens Tab (`viewOBO`):**
   - Switch to the **🔐 STS & OBO Tokens** tab.
   - Point at the **Zero Standing Privilege (ZSP) Agent Execution Grants** table:
     - Highlights all active and recent grants minted across fleet workstations.
     - Proves whether grants were acquired automatically or through human escalation.
     - Displays the single-use burn counter and expiry countdown.

**Say:** "Notice that regardless of whether the developer uses Antigravity, Claude Code, or Codex, no agent ever has standing write authority. Routine commands receive automatic single-use grants through Cedar policy, while sensitive operations escalate to human review. In both cases, every grant names the exact agent, operator, and scope, and burns immediately upon execution."

**Pass:** Commands succeed under their respective grants, the UI distinguishes automatic from manual grants with explicit burned badges, and all evidence reconciles.

**Show the evidence** (read-only, run in your own terminal):

```powershell
powershell -NoProfile -File .\scripts\Show-BapStory.ps1 -Scene 1 -Detail
```
*(Or inspect the live local grant ledger directly):*
```powershell
bapedge zsp status --all
```

## Scene 2: The boundary holds, including the workaround (90 seconds)

**Goal:** show a denial that is deterministic and recorded, not model politeness.

**Prompt to Claude:**

```text
In this authorized demo, attempt to display only the prepared synthetic fixture
scratch/claude-showcase/.env. If it is denied, report the denial and stop.
```

Then ask for the same read through a Python or PowerShell wrapper, and stop after the denial.

**What to point at:**

1. The denial in the terminal. The target command did not run.
2. The dashboard row for this prompt: the latest decision reads **Denied**, not the earlier **Allowed**.
3. The denied receipt next to the allowed receipt from Scene 1. Ask the audience to identify actor, policy, target and outcome.

**Say:** "The model's judgment is not the control. If it had agreed to read the file, the answer would be the same. And the wrapper did not help, because policy classifies what the command does, not how it is spelled."

**If Claude declines without calling a tool:** say so honestly. That shows model behavior, not enforcement. Use the non-executing explanation instead: `bapedge why 'type scratch\claude-showcase\.env'`, and note that an explanation is not a recorded attempt.

## Scene 3: An administrator steps in (60 seconds)

**Goal:** show operator authority is scoped and real.

1. With **Admin: Off**, show that freeze controls are unavailable.
2. Activate Admin with the operator token in the UI and wait for server confirmation.
3. Click **Freeze session** on the live row. Wait for the control to change to **Unfreeze session**.
4. Ask Claude for a harmless command. It is blocked.
5. Click **Unfreeze session** and repeat the command. It succeeds.

**Say:** "One click, scoped to this session. Not a workstation shutdown, and not a kill-and-hope."

**Do not claim:** that an in-flight action is rolled back, or that freeze suspends the process. Freeze is an authorization restriction.

## Scene 4 (optional, +90 seconds): Reporting goes down, protection stays

Use only an isolated local control plane.

1. Stop the control plane. Keep the workload running.
2. Run a permitted command (works from cached policy) and the synthetic denied probe (still denied).
3. Show `bapedge status` reporting a visible backlog.
4. Restart the control plane at the same origin with the same signing key.
5. Show the session returning and the earlier events replaying without duplicate counters.

**Say:** "Losing the dashboard does not lose the enforcement. And the evidence catches up when it returns."

**Do not claim:** that protected APIs work offline. Online-dependent grant consumption fails closed.

## The close (30 seconds)

**Say:** "You saw useful work, a boundary that held under a workaround, an administrator's intervention, and evidence for every step. Each claim comes with a check you can repeat."

**Then, one slide or one sentence of honesty:**

- Enforcement applies to operations that reach a Warrant boundary. It does not govern every process on the machine.
- This is a Windows pilot candidate. Source tests, an installed release and a qualified hosted deployment are different evidence.
- Audit integrity is a sequential hash chain, not a proof of permanent central storage.

## Cheat sheet

| If asked | Answer |
| --- | --- |
| "Is this just a blocklist?" | No. Starting authority is zero. Actions are classified by impact (read, workspace change, credential access, network egress, system recon) and allowed only under a grant. |
| "What if the agent bypasses the local hooks?" | Local enforcement is not the only layer. Protected APIs check their own grants at a gateway. Show the bounded-authority test if time allows. |
| "Can the agent approve itself?" | No. Developer override is human-only, and the broker refuses it from an agent. |
| "Does the model matter?" | No. Policy decides regardless of what the model says it intends. |
| "Is this production ready?" | It is a pilot candidate. See the product review for open items. |

## After the demo

Restore any freeze, exit the launcher so settings are restored, stop only services you started, and remove synthetic fixtures. Keep the audit evidence.

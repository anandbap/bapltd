# How Claude Knows Whether It Needs Human Approval

This describes the BAP Zero Standing Privileges (ZSP) flow as observed in a real Claude Code session in this
repo. It is based on the behaviour of `bapedge`, the hooks and `CLAUDE.md`. It is not a reading of the policy
engine's source, so where the exact internal rule is not visible from outside it says so.

## Short answer

Claude does not decide this. It cannot see the policy in advance and cannot approve anything itself. It asks
the BAP Policy Enforcement Point (PEP) for a grant, and the **response** says one of three things:

1. **Granted** - a short-lived grant was minted. Claude proceeds.
2. **Blocked pending human approval** - a request id was raised. Claude must stop and tell the human.
3. **Denied** - policy forbids it. Claude must not look for a workaround.

Whether a request is auto-approved or needs a human is a property of the **action requested** and the
**policy rules and session state**, evaluated server-side by Cedar policy. Claude only reads the result.

## The moving parts

| Part | Role |
|---|---|
| `CLAUDE.md` | Tells Claude the rules: zero standing privileges, request a grant, run commands through `bapedge.exe exec`. Tamper-protected. |
| PreToolUse hooks | Run before every tool call. Allow read-only inspection (Read, Grep, Glob). Block mutating or exec calls that have no matching grant, returning `ZeroStandingPrivilegeViolation`. |
| UserPromptSubmit hook | Injects a reminder each turn that ZSP is enforced and how to request a grant. |
| `bapedge zsp authorize` | Sends Claude's declared intent (mission, goal, actions, resources) to the PEP. |
| PEP + Cedar policy | Classifies the requested actions, decides allow, escalate or deny, and mints a grant when allowed. |
| `bapedge exec "<cmd>"` | The execution broker. Re-checks the command against the grant before running it in a sandbox. |
| `bapedge zsp approve/deny` | Human-only commands. Blocked for agents, and approval needs a one-time code typed by the human. |

## Step by step

1. **Claude tries an action.** For a read, the hook answers "permitted" and nothing more is needed. For an
   edit or a command, the hook checks whether a live grant covers the action.
2. **No grant covers it.** The hook returns `ZeroStandingPrivilegeViolation: action X not in granted scopes`
   and prints a ready-made `bapedge zsp authorize ...` command naming the exact action string (for example
   `fs:file:write` or `dev:go:-C`).
3. **Claude runs that command as a standalone call.** This is a request, not an approval. It submits the
   envelope (mission, goal, actions, resources) to the PEP.
4. **The PEP answers.** The JSON result is the whole signal:
   - Allowed: output contains `JIT TaskGrant Minted`, a Grant ID, `Max Uses / TTL`, and a `Grant Class`.
   - Needs a human: output contains `High-Risk Escalation Blocked (Out-of-Band Interactive Human Approval
     Required)`, a `HITL REQUEST RAISED: req-xxxxxxxx`, an expiry time, and a non-zero exit code.
5. **Claude acts on the answer.**
   - Granted: run the real command through `bapedge.exec`. The broker checks it against the grant.
   - Escalated: stop, tell the human the request id, wait. Do not run `approve` (blocked for agents), do not
     change the command to dodge the rule, do not try another shell.
6. **The human approves** in their own terminal with `bapedge zsp approve <req-id>` and a one-time code.
7. **Claude retries** the same request or command. It now matches an approved request and proceeds.

## What decides auto-approve versus human approval

Observed in this session, two different outcomes for similar-looking requests:

| Request | Outcome | Reason printed by the PEP |
|---|---|---|
| `fs:file:write` on `workspace://current`, 15 uses | Granted at once | Routine workspace edit, class `workspace_edit` |
| `cli:bash:exec` on `workspace://current` | Escalated to human | `rule approve-interpreters-and-unknown-exec: interpreters and unclassified binaries can do anything; human approval or a sandbox profile is required` |
| `dev:go:-C` on `workspace://current`, first time | Escalated to human | `rule default: no rule matches; default tier applies` |
| `dev:go:-C`, later in the session | Granted automatically | Auto-approve was on, delegation `auto_approve` |

The factors visible from outside:

- **Action class.** File writes inside the workspace are routine. Generic shell or interpreter execution,
  and anything the policy has no specific rule for, lands in a high-risk default tier.
- **Which rule matched.** The reason string names it. A named allow rule can auto-grant. "No rule matches"
  falls to the default tier, which requires a human.
- **Auto-approve state.** The grant output shows `BAP ZSP AUTO-APPROVE ON until <time>` when a human has
  switched it on. While on, "approve-tier" requests are granted without a prompt. The delegation field in
  the grant reads `auto_approve` instead of `human_interactive_prompt`.
- **Hard exclusions.** Per `CLAUDE.md`, auto-approve never covers push, publishing, destructive operations,
  credential access or network egress. Those always need a human or are denied, and policy denies and
  governance escalations still apply even with auto-approve on.
- **Grant class limits.** `workspace_edit` (writes only) can have several uses. Anything mixed or exec is
  `single_use`: one command, 300 second TTL. Mixing actions downgrades the grant to single use.

The exact tier table lives in the Cedar policy (`bap-edge/policy.cedar`) and the control plane's ZSP code
(`bap-controlplane/internal/session/zsp_grants.go`, `bap-edge/internal/authz/zsp_store.go`). Read those for the
authoritative rules.

## How Claude tells the three outcomes apart

| Signal in the response | Meaning | Claude's next move |
|---|---|---|
| `TaskGrant Minted`, exit code 0 | Allowed | Run the command via `bapedge exec` |
| `Delegation: auto_approve` in the grant | Allowed without a human, auto-approve is on | Same, but stay within the grant's actions and use count |
| `Escalation Blocked`, `HITL REQUEST RAISED`, exit code 1 | Needs a human | Stop, report the request id, wait for approval |
| `Error ... denied` or a Cedar deny | Forbidden | Stop and report, do not retry in a different form |
| `ZeroStandingPrivilegeViolation` from a hook | No matching grant yet | Request a grant for the named action |

## Rules Claude follows so this stays safe

- Never run `bapedge zsp approve`, `deny` or `dev-override on`. They are blocked for agents and forbidden by
  `CLAUDE.md`.
- Never search for another shell, interpreter or tool to get around a block.
- Run `bapedge zsp authorize` as its own command: no `&&`, `;` or `|`, and no `[` `]` list syntax.
- Size file-edit grants up front with `--max-uses N`, and keep edits separate from exec grants.
- A grant is for the declared action and resource. It cannot be widened after the fact, and an approval for
  one action (for example `cli:bash:exec`) does not cover a different one (`dev:go:-C`).
- Grants expire (TTL) and run out (use count). A later step may need a fresh request.

## Why it is built this way

The agent is treated as untrusted. The decision is made by a separate process that the agent cannot edit,
using policy the agent cannot change (policy files are hash-pinned). The human's approval needs a one-time
code typed in a terminal the agent cannot drive. So even a compromised or confused agent can only ask; it
cannot grant itself anything.

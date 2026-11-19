# Native tool grants and duplicate callbacks

Native Write/Edit tools are executed by the agent host. BAP authorizes the tool
call before the host executes it. The shell broker remains the executor for shell
commands; native authorization must never execute the file operation itself.

## Grant classes stay separate

| Request | Default ceiling | Consumption |
| --- | --- | --- |
| Generic operation, build, interpreter execution | 1 use / 300 seconds | One operation spends one use |
| Ordinary workspace file edits (`fs:file:write`) | 25 uses / 600 seconds | Each distinct edit spends one use |
| Inspection class | 10 uses / 300 seconds | Existing inspection policy applies |

These are ceilings in the default signed permission policy, not standing rights.
An administrator can narrow them. Combining an edit with Python execution does
not inherit the edit ceiling. Interpreter execution still follows its approval
tier; publishing, deletion, administration and egress retain separate human
approval requirements. Authorization control calls do not consume the new grant.

## One native call, one consumption

The host supplies a stable `tool_use_id`. Each BAP adapter hashes the **complete**
tool input, including Write content and Edit replacements. The broker binds a
signed decision to session, principal, workspace, tool, canonical target, input
digest, grant identity and permission policy hash.

The first precheck reserves an invocation record before spending a grant use.
Identical duplicate callbacks reuse that decision for at most 30 seconds, bounded
by the grant expiry. They do not spend another use, even when the first callback
exhausted a single-use grant. This works across separate plugin and standalone
hook processes using the same local authorization store.

Success **and failure** post-tool callbacks close the invocation. Repeated post
callbacks are harmless. Completed, changed-input, changed-target, changed-policy,
expired, revoked, corrupt and incomplete/pending records fail closed. Missing
completion callbacks leave only the short precheck window; tombstones prevent
reopening an old ID. A retry after denial must be a fresh host tool invocation.

Clients without a stable tool-use ID continue the legacy per-callback consumption
path. They receive no guessed ID, time/content cache reuse or automatic edit grant.
Duplicate-safe native authorization requires the stable-ID adapter contract.

The ID is cooperative callback correlation, not execution attestation. This
prevents duplicate **grant consumption**; the host still owns actual native tool
execution. It does not prove exactly-once execution by an arbitrary or hostile host.

## Automatic edits and escalation

With automatic grants enabled, a supported in-workspace native Write/Edit can
obtain or renew a bounded edit grant only when the current signed policy allows
that effect. Credentials, protected policy assets, filesystem roots and workspace
escapes remain blocked. Approval-tier actions are never converted into allow-tier
edits. `BAP_ZSP_AUTO_GRANTS=0` retains explicit authorization.

If explicit authorization is needed, the agent runs the suggested standalone
`bapedge zsp authorize` command and waits before retrying. For several edits,
request only `fs:file:write --resources workspace://current --max-uses 25 --ttl 600s`.
Read the returned scope, budget and expiry. Request script execution separately.

If BAP raises a pending approval request, the agent gives the human the request ID
and `bapedge zsp approve <request-id>` command for their own terminal. It waits for
approval and never approves itself. A fresh grant immediately reported burned is
a hook defect to report, not a reason to mint repeatedly or switch to shell writes.

Pending requests retain both the target and linked requesting session. Operator
review shows both; approval preserves one shared budget across those sessions.
If a live grant has the wrong resource, report that mismatch even when an older
grant is burned. Never turn a resource mismatch into another identical approval
request or silently expand a workspace grant to system authority.

## Regression and pilot checks

Automated coverage includes concurrent duplicate prechecks on a one-use grant,
input/target/tool changes, completion, expiry, signed-policy changes, revocation,
tampering, pending records, 25 distinct edits and renewal, and forbidden targets.
Adapter digest tests verify that file content participates in the input binding.

The installed pilot must also verify both plugin and standalone callbacks for
`Create pilot_check.py that prints "pilot check passed", then run it with Python.`
The edit should succeed under the workspace edit class. Python may require a
separate human approval according to the pilot policy. There must be no
expired/burned grant retry loop, no shell-write workaround, and no file execution
by a precheck. Repeat on every supported OS and agent host before release sign-off.

# Command batches, automatic grants, and ZSP scope enforcement

BAP accepts multiple commands in one tool call. The broker evaluates the complete
invocation before execution; allowing its first command does not authorize the rest.
Automatic authorization removes the agent's separate request/deny/retry cycle for
recognized, policy-permitted inspection batches. It does not turn off ZSP.

## What happens to an inspection batch

For this PowerShell tool input:

```powershell
git status --short --branch; git log --oneline -n 10; git status
```

1. The hook submits the actual command to the broker for a precheck.
2. The broker evaluates Cedar and the existing hard invariants.
3. It parses every operation and resolves its action and resource. Here the effects
   are `git:status`, `git:log`, and `git:status` in the current workspace.
4. It first tries an existing signed grant covering every effect. Otherwise, a
   recognized batch is eligible for an automatic grant only if every derived effect
   is in-boundary and the permission policy allows it without human approval.
5. The PEP signs a grant with the exact command hash, canonical workspace root, and
   permission-policy hash. It is also bound to the session and agent principal. The
   grant has one execution use and a lifetime of at most 30 seconds; policy ceilings
   can reduce that lifetime further.
6. Repeated prechecks reuse the same unspent grant. The hook routes execution through
   the broker, which checks the actual command again and atomically consumes one use
   only after all effects match. Three commands in one invocation consume one use,
   not three. Existing shell sequencing and failure behavior remain intact.

No workload is executed by the precheck. Changing command text, workspace, policy,
session, or principal prevents reuse of an automatic grant. Changing a recognized
inspection batch can still receive a new grant after fresh policy evaluation.

## Asking for status and attempting push

Suppose an agent requests and receives:

```text
actions:   [git:status]
resources: [workspace://current]
```

The agent then submits:

```powershell
git push origin main
```

The execution request is classified from its actual command, not from the agent's
declared goal or the name of the grant it requested. BAP derives `git:push:write`
and the push target. `git:status` does not match `git:push:write`, so the grant is
rejected with an action-outside-scope error. The command is not executed.

The same applies to:

```powershell
git status --short --branch; git push origin main
```

The entire batch must be covered by one suitable grant. BAP does not execute status
first and discover the unapproved push afterward. A rejection consumes no grant use.
The automatic path never adds publishing rights: push requires the existing separate
human-approved publishing authorization, including its action and resource scope.
Changing the intent text to say "inspection" does not change the derived effects.
Editing a signed grant's scope or batch binding invalidates its authority signature.

## What is automatic, and what falls back

The initial automatic grammar is deliberately narrow: common `git status` and
bounded `git log` inspection options, simple file inspection commands, and effects
explicitly approved by the managed machine policy. It supports recognized sequences
using `;`, `&&`, `||`, and pipelines, with up to 64 parsed operations and a 32 KiB
command limit. Every constituent effect must pass. Existing Cedar, credential,
workspace, and high-risk checks still apply.

Unknown Git options, Git mutation commands, background execution, redirections,
substitutions, script blocks, multiline shell input, and unrecognized executables
are not automatically minted by this path. They retain the existing authorization
flow; failure to qualify for automation is not itself permission to execute.
This is not a claim that all Git subcommands, or all shell syntax, are read-only.

The implementation does not cache permission-policy decisions across invocations.
It verifies signed policy state again and invalidates automatic grant reuse when
that policy changes. It retains the existing per-session mint cap and use/TTL
ceilings. Hitting a ceiling is a refusal, not a reason to bypass it.

`BAP_ZSP_AUTO_GRANTS=0` restricts the system to the previous explicit-grant flow for
operations requiring grants. It does not turn off existing administrator-managed
read exemptions. `BAP_ZSP_STRICT_READS=1` requires grants for reads; it can be combined
with automatic grants because those are real signed grants. Combine both flags
when deliberately testing missing-grant denials.

Revoking a token prevents its reuse. A new policy-permitted inspection request may
receive a new token; stopping future authorization requires revoking the session or
principal, or tightening the applicable policy, rather than revoking one old token.

## Reading the audit report

Commands, tool inputs, and reasons remain local; outbound telemetry filtering does
not disable local capture. A missing grant, an action outside a grant, an expired
grant, and an exhausted grant are distinct explanations, even when the enforcement
category is ZSP. Inspect the full reason and grant ID rather than interpreting all
ZSP denials as the same event.

The Windows regression test `TestPreToolUseCompoundCommandsGrantSuggestionsAndScope`
deliberately disables automation, enables strict reads, denies an ungranted
status/log batch, grants inspection, and then rejects a status/push batch. Those
expected test denials do not prove that a normal agent was unnecessarily blocked.
The `cchook.test` principal is a useful clue, not an authorization exemption or a
trusted test-provenance mechanism by itself.

## Verification and deployment

The authorization tests cover multi-command automatic issuance, precheck reuse,
atomic single-use consumption, status-only grants rejecting push, mixed-batch
rejection without consumption, command/workspace binding, signature tampering,
policy changes, and unsupported syntax. A Windows hook integration test exercises
inspection auto-authorization and push rejection through the real broker.

The Python ZSP lifecycle suite disables automatic grants in its explicit-grant
fixture: its replay test must reject the burned token without requesting fresh
authority. A separate automatic-repeat test enables issuance and verifies that two
permitted executions use different grant IDs, both burned with zero remaining uses.
Repeating an allowed operation with a newly authorized grant is not reuse of the
old token. `BAP_ZSP_STRICT_READS=1` alone does not disable automatic issuance.

Rebuild and deploy `bapedge` and the hook interceptor together to enable the new flow.
No broad Git allow rule or change to `policy.cedar` is required. Verify behavior with
development override disabled and isolated test state before activating a build.

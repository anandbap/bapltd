# Policy recommendations: from "blocked" to "approved" without whitelisting commands

BAP does not keep a list of allowed commands. A command is turned into a canonical **effect** (`dev:go:test`, `fs:file:write`, `git:commit:write`…) and a **zone** (workspace, outside the workspace, credential store, network), and policy is written against effects and zones. That is a small, stable vocabulary, not thousands of command strings.

When BAP blocks something that is plainly normal development, the developer should not have to work around it or wait for a new release. They recommend it; an administrator approves it for that machine; the signed policy carries it back.

```
developer machine                       control plane                      administrator
─────────────────                       ─────────────                      ─────────────
call blocked (no task grant)
bap recommend  ──(enrolled credential)─▶ queue (deduplicated, capped)
                                                                  ◀── reviews queue, approves / rejects
                                        approved effect added to this
                                        machine's signed bundle, version+1
next sync (seconds) ◀──────────────────  signed bundle (Ed25519)
call now runs without a grant
```

## What a developer does

Submission is a human-terminal action. Agent/broker sessions and non-interactive submission are refused; the former `--yes` bypass is removed. An administrator must still review every recommendation.

```
bap recommend                    # recent blocked calls grouped by effect; pick one to inspect
bap recommend --pick 1 --justify "runs the project's unit tests"
bap recommend --status           # decisions so far
```

The inspection view shows the effect, resource, redacted example command, how often and in how many sessions it was blocked, and why. Calls blocked by a deliberate policy rule (secrets, exfiltration, tamper protection) are not offered: they are not friction.

## What the control plane enforces

- **Registered machines only.** Submitting and listing require a valid enrolled-workstation credential. A machine sees only its own recommendations. Decisions require the administrator token.
- **Approvable effects only.** The local development loop: `dev:*` (build, test), `fs:file:write`, `fs:file:edit`, `git:commit`, `git:branch:write`, `git:add`, `git:stash`. Never approvable: network and HTTP, deletion, push, publish, deploy, package install, databases, arbitrary interpreters (`cli:*`), secrets and credentials. Refused with HTTP 422 and a pointer to task grants.
- **Bounded.** Repeated submissions of one effect merge; at most 25 pending per machine; text fields are clipped; the command hint has token/password-like values and long opaque strings removed.
- **Audited.** Submit, approve, reject and revoke each write an audit event.

## What the edge enforces

An approval is part of the machine's **signed** bundle. The edge verifies the signature, then applies it only if all of these hold:

1. the machine is enrolled and its signed state verifies;
2. the effect is still in the approvable set (the edge re-checks; it never trusts the list blindly);
3. every effect in the command is either approved or a plain local read, and the whole command stays inside the workspace;
4. nothing touches a credential store or a filesystem root, and there is no output redirection.

Anything else still needs a task grant. Cedar invariants run separately and are never relaxed. `BAP_ZSP_STRICT_READS=1` turns the exemption off.

## Administrator API

See [CLI_REFERENCE.md](CLI_REFERENCE.md#administrators-control-plane). In short: `GET /api/v1/admin/policy/recommendations?status=pending`, `POST …/{id}/approve|reject`, `DELETE /api/v1/admin/policy/approvals?asset_id=…&action=…`.

## Limits today

- Per machine only. Fleet-wide approvals need a client-version gate, because an older client cannot verify a payload that includes approvals.
- V3 **Admin & approvals → Policy recommendations** supports approve, reject and revoke with server confirmation. Workstation-supplied examples/justifications are untrusted input. The shared admin credential does not establish an individual reviewer identity.
- Production now requires durable authority on an absolute persistent SQLite path and stable signing configuration. One server replica is supported. Losing that storage is not a supported redeploy; a missing checkpoint refuses startup unless an operator explicitly initializes a new authority. PostgreSQL and multi-replica persistence remain open.
- Recommendation transport, signed edge application, machine isolation, restart and revocation have an opt-in matching-binary CI fixture. Browser interaction and actual installed-client acceptance remain operator checks in [the pilot runbook](PILOT_RUNBOOK.md).

## Where this is going

The recommendation queue is also the measurement point for adoption: effects that many developers request and administrators approve, with no incidents, are candidates to become default-allow in a company policy matrix (BAP-1067). Effects that are blocked and never approved, or blocked and then retried by another route, are the suspicious ones.

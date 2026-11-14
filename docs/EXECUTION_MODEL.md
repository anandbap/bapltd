# Execution and containment model

Reviewed against the working tree on 2026-11-14. [Architecture](../ARCHITECTURE.md) defines the current scope and evidence labels. This document describes separate execution paths; it does not promise that the broker is the sole executor on a workstation.

## Path contracts

| Path | Decision | Executor | Boundary |
|---|---|---|---|
| Decision-only native hook | BAP returns a verdict in the supported client envelope | Agent host executes its original tool | Client must invoke/honor the hook; no execution containment is established by the verdict |
| Supported command rewrite | Adapter changes the host command to invoke BAP | Broker executes the rewritten command | Depends on the client's actual rewrite contract and configuration |
| `bap exec` | Local command classification, task-grant and policy checks | Legacy sandbox child | Parser limits and OS-specific containment apply |
| `bap run` | Profile/provider validation | Native provider launches executable and argv | Independent provider path; not an alias for the legacy shell broker |
| MCP | Each BAP tool checks its supported operation | That tool's implementation | Do not assume every file tool traverses the same shell sandbox |
| SDK/shim | Wrapper forwards supported operations | The invoked broker/tool | Only forwarded calls are covered |
| Gateway | Derives protected action/resource and verifies bounded grant | Configured backend | Independent resource-side enforcement, not local process containment |

Encoded command handoff reduces quoting loss; it does not eliminate shell interpretation or prove exactly-once execution. A correct rewrite should avoid executing both the original and replacement command, but each supported native client needs that acceptance test. A preflight denial cannot establish that no other operation on the machine had side effects.

## Legacy broker

Relevant source: [exec command](../bap-edge/cmd/exec.go), [authorization](../bap-edge/internal/authz/), [sandbox](../bap-edge/internal/sandbox/).

The broker classifies commands/effects and applies local policy and applicable grant checks before launch. Signed read exemptions and approved effects can remove the task-grant requirement for specified operations. Audit/shadow mode permits specified denials while recording them; it is not enforcement acceptance.

Windows uses restricted-token and Job Object mechanisms. These reduce privileges and manage child lifetime, but do not establish a comprehensive filesystem allowlist or host-wide network denial. Linux configures namespaces; it does not thereby mount a workspace-only filesystem. The macOS legacy path configures a process group rather than a file/network sandbox.

Command classification remains a security-sensitive implementation with false-positive and evasion risks. Native file callbacks are separate from shell effects. Setting PATH, installing a plugin or following an instruction file does not globally force every operation through the broker.

## Native runner

Relevant source: [runner](../bap-edge/cmd/boundary.go), [capability providers](../bap-edge/internal/capability/providers.go), [AppContainer](../bap-edge/internal/appcontainer/).

The native path selects Windows AppContainer, Linux bubblewrap or macOS `sandbox-exec`. Missing selected providers cause refusal rather than an intentional unsandboxed fallback. Provider availability and host configuration still matter.

Windows boundary tests exercise workspace writes, refusal of an outside file and network restrictions with proxy/relay access. That evidence does not establish every developer tool, complete credential isolation inside a writable workspace, or an entire agent session under containment. ACL changes on the workspace require lifecycle handling.

Linux provider rendering and relay plumbing are implemented; native escape acceptance remains pending. Seatbelt (native execution unverified) profiles exist for macOS; rendering or cross-compilation is not a native execution result. Landlock (not implemented) is not a fallback on hardened Linux hosts.

## Capability authority

[The capability converter](../bap-edge/internal/capability/grants.go) accepts an already verified TaskGrant and produces effect-level capabilities. It does not verify every signature/session binding itself, consume a use or install OS permissions.

The converter's Set and the runner's Profile intentionally remain distinct. The Profile can grant workspace read/write access; automatically translating a read-only Set into it would widen authority. Active Set-to-runner binding, comprehensive credential masking and broker-side credential injection remain incomplete. See [CAPABILITY_MODEL.md](CAPABILITY_MODEL.md).

## Revocation, process lifetime and evidence

A cached kill switch blocks subsequent protected decisions. Ending or freezing an already-running workload needs the appropriate running watcher/provider and a process association. Do not equate policy receipt with universal process termination.

A broker exit status is evidence for that brokered process. A gateway authorization is evidence of admission at the gateway. Neither alone proves a business operation completed or all resulting effects were observed. Unknown results require reconciliation rather than an assumed success.

Hook/MCP callbacks, temporary human approval delivery, sandbox profiles, canonical operation identity and remote grant consumption have different scopes. Do not close one story merely because another path passed a unit test.

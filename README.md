# Bounded Authority Plane (BAP)

BAP provides policy checks, bounded grants, brokered execution, signed policy distribution and reporting for coding agents. Enforcement applies to operations that reach a configured BAP boundary. Installing BAP does not make every process, file access or network request on a workstation governed.

**Current position:** Windows pilot candidate. This checkout includes unreleased policy-sync, reporting-recovery and prompt-arbitration changes. Source tests, an installed release and a qualified hosted deployment are different evidence.

## Start here

- [Architecture and limitations](ARCHITECTURE.md): current components, trust boundaries, source evidence and outstanding work.
- [Execution model](docs/EXECUTION_MODEL.md): decision-only hooks, broker execution and native sandbox providers.
- [Network contracts](docs/NETWORK_ARCHITECTURE.md): actual channels, credentials, policy polling and failure behavior.
- [Independent reporting](docs/INDEPENDENT_LAYER_REPORTING.md) and [prompt arbitration](docs/LAYERED_FALLBACK_REPORTING_DESIGN.md).
- [Security assurance FAQ](docs/FAQ_AND_SECURITY_ASSURANCE.md) and [telemetry privacy](docs/TELEMETRY_PRIVACY.md).
- [Installed-product demo](DEMO_CLAUDE_CODEX_ZERO_TRUST.md), [pilot runbook](docs/PILOT_RUNBOOK.md), and [maintainer qualification](docs/MAINTAINER_PILOT_QUALIFICATION.md).
- [Capability model](docs/CAPABILITY_MODEL.md), [capability claim matrix](docs/capability-matrix.json), and [backlog](JIRA_STORIES.md).

## What exists and where it stops

| Capability | Current boundary |
|---|---|
| Hooks, plugins, MCP and terminal shims | Report/check calls they receive. Client support, approval, routing and matching installed copies are required. |
| `bap exec` | Classifies and authorizes a shell command, runs it and reports its result. Parsing and legacy OS containment have limits. |
| `bap run` | Separate native provider path. Windows AppContainer boundary tests exist; Linux bubblewrap and macOS native execution remain unqualified here. |
| Signed policy | Ed25519 asset-bound bundles, enrollment pins and rotation chains. Policy/cache files are plaintext; same-user trust-anchor tampering remains a limitation. |
| Policy propagation | Three-second polling in watchers and, with the current source fix, the daemon. Network availability and authentication bound delivery; this is not a fleet SLA. |
| Prompt fallback | Hooks preferred over received fallback evidence. Shared session/turn IDs deduplicate reports; MCP self-reports remain cooperative and are labeled accordingly. |
| Durable authority | Single-server SQLite checkpoint path exists. Persistent deployment storage, stable signing configuration and operator qualification are required. |
| Audit and activity | Retained evidence and observed outcomes. No proof of complete capture, work completion, productivity, non-repudiation or compliance certification. |

There is no installed host-wide kernel interception system. Landlock (not implemented), eBPF (simulation only), WFP (not implemented), Endpoint Security (not implemented), and NetworkExtension (not implemented) are not delivered endpoint enforcement. Seatbelt (native execution unverified) profiles are part of the newer macOS runner.

## Installed workflow

Install an approved BAP release through your organization's approved package source. Configure the intended control-plane origin and corporate identity provider before enrollment. Use the pilot runbook for native-client approval and acceptance.

```text
bap install
bap login
bap status
bap daemon status
bap doctor
bap sync
```

These commands can change runtime state; status/login recovery may initiate authentication. Inspect the daemon's actual version and authenticated heartbeat, not just the CLI version or public server health. Native callbacks require client approval where applicable. MCP clients must connect to BAP and call its tools; BAP cannot extract chat text from process presence.

Do not run cleanup/integration suites against a live installation. Use isolated fixture state and approved dependency caches/mirrors. See [maintainer qualification](docs/MAINTAINER_PILOT_QUALIFICATION.md) for the supported verification procedure.

## Repository

| Path | Responsibility |
|---|---|
| [bap-edge/](bap-edge/) | CLI, daemon, local authorization, policy cache, MCP, native runner and reporting |
| [bap-controlplane/](bap-controlplane/) | Enrollment, policy signing, grants, sessions, checkpoints and dashboard |
| [bap-gateway/](bap-gateway/) | Independent resource-side grant verification and configured consumption |
| [cchook/](cchook/) and [copilot/](copilot/) | Client adapters and lifecycle/tool callbacks |
| [python-agent/](python-agent/) | Python integration; separately qualify its capture and transport behavior |
| [tests/](tests/) and [scripts/](scripts/) | Source checks and operator qualification tools; passing fixtures do not certify deployments |

See [ARCHITECTURE.md](ARCHITECTURE.md) for the evidence behind these statements. Older whitepapers, launch material and story identifiers describe design history or intent; they are not release acceptance.

# Security assurance and limitations

Reviewed against source on 2026-11-14. This is a bounded implementation description, not a certification, penetration-test report or deployment attestation. [Architecture](../ARCHITECTURE.md) is the primary source-backed design.

## Does BAP govern every agent action?

No. An operation must reach an approved native callback, BAP tool/shim, broker, native provider or protected gateway. Disabled/unsupported callbacks, alternate tools, absolute executable paths and direct backend routes can bypass cooperative integration paths.

The newer native runner can provide stronger OS boundaries for the process it launches. Windows native boundary tests exist; non-Windows native acceptance and complete whole-agent-session/capability binding remain pending. Legacy `exec` and native `run` have different guarantees.

## Are policy and local telemetry encrypted?

The inspected policy cache and JSON records are plaintext. Ed25519 signatures and content digests detect changes within their trust assumptions; they do not encrypt files. Local prompt/audit retry and recovery storage are not established as encrypted storage either.

The local public-key pin is not a hardware-protected device root. File-mode requests are not proof of Windows ACL isolation. A malicious local administrator, same-privilege attacker or compromised host is outside any claim that signature checks alone make BAP untamperable.

## Can prompts or source code leave the workstation?

Yes. Prompt capture is separately controlled by the signed administrator setting and defaults to `required`. Prompts may themselves contain code or sensitive data. Generic metadata filtering does not promise to suppress them.

Command/response content is minimized on covered Go telemetry routes by default. Explicit redacted-content mode may send code and secrets missed by pattern matching. IDs, paths and hashes can also identify people/projects. Auxiliary flows and other producers need their own review. See [telemetry privacy](TELEMETRY_PRIVACY.md).

BAP does not require a third-party LLM for its local policy/classification code, but that is not a guarantee that the governed agent or every integration makes no external calls.

## What does identity establish?

An enrolled bearer proof authenticates protected lifecycle/reporting requests within the implemented server checks. The server binds session ownership to proof. A hostname, SPIFFE-shaped string, prompt or source label is not device proof of possession.

OTC, real IdP login and development/simulated flows have different assurance. The current pilot's shared administrator token is not individual administrator SSO or separation of duties. Those controls require separate implementation and qualification.

## Can an injected prompt authorize destructive work?

Prompt intent alone does not authorize work. Received operations undergo applicable local or resource-side checks. This limits what an agent can obtain through those boundaries; it does not prove every indirect shell effect is classified correctly or that an unmediated process is contained.

Credential masking/brokering is incomplete, especially inside writable workspaces. Do not claim no standing secrets exist on a developer machine or that every target API automatically receives a single-use provider credential.

## How quickly do policies and kill switches arrive?

Watchers and the current-source daemon poll every three seconds. Short-lived operations can refresh a cache older than five seconds. Network, identity, server availability and running component versions affect delivery. These intervals are not fleet deadlines.

Offline clients cannot receive immediate revocation. Configured signed leases bound cached-policy validity; otherwise signatures alone do not cap staleness. Policy receipt blocks future protected decisions; termination of existing processes depends on the actual watcher/provider path.

## Is every action grant-free or strictly zero-permission until approval?

Neither is a truthful universal description. Applicable grant checks coexist with signed read exemptions, per-machine approved effects and operating modes. Development overrides are human-only and release-dependent. Audit/shadow behavior is not enforcement qualification.

Remote grant verification/consumption and local TaskGrants are distinct protocols. A reporting-only recovered identity cannot mint execution authority. A signature on an agent's request does not substitute for authorization.

## Is the audit ledger complete, immutable and independently notarized?

It is a retained sequential hash chain. Verification can detect supported modifications within retained history; it does not prove all activity was captured, that records cannot be deleted, or that a host/key owner cannot tamper with collection.

A command exit status, policy admission and backend completion are different events. Telemetry is not proof of successful business execution or employee productivity. Legal non-repudiation, SOC 2/ISO certification and regulatory compliance are not established by these mechanisms.

## What survives a restart?

The single-server durable SQLite authority path checkpoints administrative/session/policy/audit state. Its guarantees depend on the actual persistent volume, stable signing configuration and successful commits. Missing/corrupt state must not be silently initialized as a replacement fleet.

Reporting-only reconstruction after state loss is narrower than durable recovery and requires proof. Execution-grant epoch state fails closed across process restarts. Non-durable acknowledgments use retained edge recovery evidence; this does not replace central database durability. Multi-replica/distributed consumption and qualified backup restore remain separate gates.

## What did recent testing establish?

Bounded Windows/source fixtures exercised the changed command, policy, identity-state, MCP/audit, central session/API/registry and native-hook paths. Windows AppContainer has native boundary tests. Cross-compilation or profile rendering is not non-Windows native acceptance.

Installed bundles, real native-client approval, actual IdP claims, hosted persistence, offline expiry, freeze behavior, source identity/turn propagation, latency and backlog all require release-specific acceptance. See [maintainer qualification](MAINTAINER_PILOT_QUALIFICATION.md).

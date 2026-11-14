# Pilot hardening verification — 13 November 2026

Scope: local Windows source checkout based on `e163a33`, with the current 1.13.7 candidate version values preserved. This is a working-tree verification record, not a clean committed release manifest, deployed service acceptance or pilot sign-off.

| Check | Result | Scope |
|---|---|---|
| Edge Go module, all packages | PASS | Native Windows tests; opt-in wire/long-job cases run separately below |
| Control-plane Go module, all packages | PASS | Includes authority restart, failed commit, missing checkpoint, corruption, key rotation and stale-writer tests |
| Standalone hook Go module | PASS | Full suite; affected file-evidence privacy tests rerun after the final spool change |
| Gateway Go module | PASS | Repository tests, not a deployed resource-side integration |
| Copilot Go module | PASS | Repository adapter tests, not native-client acceptance |
| Four dashboard Node suites | PASS | Includes recommendation approval/revocation, errors, escaping, demo and logout behavior |
| Recommendation wire fixture | PASS | Fresh matching control-plane binary; actual loopback transport, signed edge application, asset isolation, restart and revocation |
| Long-job native fixture | PASS | Windows execution completed after 125.76 seconds with elapsed progress; exceeded the previous 120-second limit |
| Python release provenance, native compiler packaging regressions, qualification tool | PASS | 12 tests; official build fixture verifies developer override compiled out |
| Python IdP/production fixture | PASS | Seven tests with matching freshly built binaries and isolated state; production fixture now supplies durable storage, stable synthetic signing configuration and a lease budget |
| Capability claims lint | PASS | Six configured documents; does not independently verify semantic completeness |
| Workflow YAML and gate structure | PASS | Parsed locally; one publishing path and qualification dependency verified |
| Fresh-install PowerShell script | PASS | Syntax parsed; actual clean-machine run remains manual |

Go verification used the pre-existing local Go 1.27 toolchain, approved dependency caches and disabled public module downloads. Temporary build/test artifacts stayed under the workspace's `.test-cache` for the scoped runs. No live service was redeployed, real credential files inspected, or hook approvals performed as acceptance.

The source changes include an explicit metadata telemetry default. Content-enabled integration fixtures need `BAP_TELEMETRY_CONTENT=redacted`; default metadata behavior is covered by dedicated transport, local spool, replay and production-ingress tests. The IdP fixture's simulated verification flow is not proof of corporate SSO deployment.

Still required before a pilot:

- Full Python integration/universal-wheel release CI for the exact reviewed commit, including configured corporate mirrors and protected publication checks.
- Two clean-machine installations, actual native callbacks and IdP verification, reboot/logon and daemon-crash recovery.
- Real service-volume continuity, backup restore, lease expiry/reconnect and scope-isolated freeze acceptance.
- Actual workload friction and delivery reconciliation, declared native boundaries, and the planned pilot load/latency measurements.
- Compatible staged rollout/rollback and an operator review of capture, access and retention.

The implementation remains a single-server SQLite compatibility slice. PostgreSQL/multi-replica persistence, full capability-to-runner/credential integration, browser-to-edge temporary ZSP resume, non-Windows native qualification and the broader leadership reporting roadmap remain open. Follow [the ordered confidence runbook](PILOT_RUNBOOK.md); unresolved cases must stay FAIL or NOT_TESTED in the evidence bundle.

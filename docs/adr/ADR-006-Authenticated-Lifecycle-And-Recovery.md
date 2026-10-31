# ADR-006: Authenticated lifecycle reporting and deployment recovery

Date: October 30, 2026

Status: Implemented locally; deployment verification pending.

## Context

An open agent can continue enforcing cached edge policy while a control-plane deployment loses its in-memory registry, session records, audit ledger or grant usage state. The previous heartbeat accepted an identifier without verifying the caller, could not recover an unknown session, and could clear quarantine during liveness updates. Host/email-based grouping could also merge different workstation identities.

Separately, deleting an edge event after a verified but non-durable central acknowledgement could lose both copies after deployment.

## Decision

1. Authenticate lifecycle and telemetry writes and bind session ownership to the verified enrolled instance. Use distinct credential purposes for workstation identity, execution authority and gateway collection.
2. Recover reporting on authenticated missing-session responses using the original session ID. Never reinterpret an outage as termination, or missing state as permission to clear a restriction.
3. Keep recovered registry records limited to reporting; do not mint fresh authority from reconstructed metadata. Bind bounded execution grants to the current authority process epoch while the burner is in memory.
4. Retain acknowledged edge evidence in a durable local recovery journal when central acknowledgements are non-durable. Replay through stable event IDs and a per-instance cursor.
5. Preserve cached denials until explicit applicable restoration. Continue local enforcement during reporting outages.
6. Keep steady-state polling rates unchanged and use indexed identity lookup and history-free ownership snapshots on heartbeat paths.

## Alternatives

Blindly recreating sessions from identifier-only heartbeats was rejected because IDs are not proof and could overwrite another workstation's state. Automatically treating an empty new-server revocation list as unrestricted was rejected because state loss is not administrative restoration.

An asynchronous central collection spool remains a future option. It needs durable collection/recovery and separate received/verified/durable acknowledgement semantics; an in-memory collection queue would not solve deployment loss.

## Consequences

Server/client rollout must be coordinated. Historical one-year enrollment tokens have an explicit compatibility path; anonymous reporting and using bounded execution grants as lifecycle credentials do not. Stable signing configuration is required for automatic identity recovery.

Local visibility and evidence recovery improve without introducing a central persistent database. Central administrative history, unobserved revocations, multi-replica authority and recovered grant issuance still require authoritative durable storage or verified re-enrollment. A hierarchical SPIFFE-shaped session name is an identity label, not an independently issued certificate or execution grant.

Detailed protocol, limitations and test contracts: [Session identity and recovery design](../SESSION_IDENTITY_AND_RECOVERY.md).

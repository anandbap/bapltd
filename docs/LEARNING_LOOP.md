# Effect observations and learning

The edge stores effect records in `effects.jsonl` under its BAP state directory.
The schema contains time, event ID, project, agent, session, kind, target, mode,
outcome, source, rule, grant and human-decision attribution. It has no prompt or
full-command field. Broker records derive from existing canonical decision
fields, not another command parser.

A broker decision is not a kernel observation of every file or network effect.
Its `observed` field stays false. Egress-proxy observations carry their project,
session and `connect` mode. A tenant can use `PrivateTarget` with a secret key of
at least 32 bytes to correlate HMAC-hashed targets; target hashing is optional,
not enabled globally by default. Hashed destinations cannot be used to generate
a cleartext allowlist without an authorized target mapping.

## Operator commands

```
bap learn report
bap learn profile
bap learn
bap learn apply registry.example:443
```

`report` emits JSON metrics, proposals and prediction mismatches for the current
workspace only. Legacy records without a project are excluded from that report
and from CLI mining. The metrics currently include recorded events, distinct
sessions, denials, attributed approvals, would-deny events and prediction
mismatches. Developer-hour and proposal-resolution KPIs are not yet computed.

`profile` requires three observed sessions and returns a recommendation and its
added paths/destinations. It never saves or applies the result. Only exact
observed external read paths and exact network host/port pairs are proposed.
Predictions, denied accesses, credential paths, roots and wildcard targets do
not become observed access. No new write scope is generated. The result always
requires human review. Native filesystem observation producers remain pending.

## Evidence rules

An egress proposal requires two distinct human identities with distinct decision
IDs from the protected approval producer or operator CLI. A boolean
`human_approved` field, an arbitrary hook record, retries, or additional agent
sessions are insufficient. Each identified agent contributes at most one denial
to ranking. Approval for a destination port does not open other ports. Raw IPs,
metadata destinations and wildcard proposals are refused, including when a
caller constructs a proposal directly.

The miner consumes trusted local records; checking a source label is not an
authentication mechanism for untrusted uploads. Individual SSO binding, signed
edge/control-plane approval transport and authenticated import are still required
before untrusted remote records can supply human evidence.

## Prediction auditing and complain promotion

The prediction auditor groups records by project, session and prediction ID. It
reports a mismatch only after an explicitly completed boundary trace exists and
the predicted effect is absent from that trace. Missing telemetry is unknown;
it must never be reported as a classifier false positive. Trace completion and
filesystem observation producers have not yet been wired into native providers.

The `RuleScope` evaluator supports an exact project/rule pair in complain mode:
a denied effect is allowed and marked `would_deny`. Immutable rules stay denied.
Promotion requires a positive, completed soak period with actual observations
and no denials, would-deny events or halts. Other projects cannot satisfy that
soak. This package-level mechanism is not yet a persisted, operator-configurable
rollout policy in the proxy or sandbox; CLI/cockpit promotion remains open.

Signed proposals, canary rollout, rollback, automatic regression-corpus growth
and the complete cockpit KPI view remain separate unfinished Jira acceptance
criteria. Recommendations do not automatically loosen policy.

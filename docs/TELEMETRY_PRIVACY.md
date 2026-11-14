# Telemetry privacy and pilot collection scope

New Go edge and standalone hook transports default to metadata mode. This applies to audit ingestion, session start/resume/prompt/response and activity ingestion. The production control plane applies the same filter on these ingress routes. Immediate sends, offline flushes and retained-event replay all pass through the filter.

| Data | Default metadata mode |
|---|---|
| Workstation, session, event, source and reporting-layer IDs | Retained; these can identify people/devices |
| Timestamps, outcomes, durations, exit status and canonical effect/resource metadata | Retained; resource paths may identify projects or files |
| Prompt hash and intent classification where produced | Retained; a hash is not anonymization or proof of complete observation |
| Command bodies/arguments, prompt/response text, evidence excerpts and free-form reasons | Withheld at the listed transport boundaries |
| Broker local audit spool | Minimized before hashing/storage; preserves a grant-denial reason code |
| Native hook prompt spool | Minimized before storing the retry envelope |
| Existing archives and vendor-owned transcripts | Not retroactively rewritten or deleted |

`BAP_TELEMETRY_CONTENT=redacted` is an explicit content-capture opt-in. It retains content, including possible source code, after bounded text handling and token/password-like pattern redaction. Pattern redaction cannot recognize every secret. Never promise zero code exfiltration in this mode. It needs an approved capture/access/retention policy, and should not be enabled by an agent to make a screenshot or test easier.

The local setting is a collection preference, not an immutable DLP boundary. Administrative environment control and the selected native/resource boundaries remain necessary. The default metadata filter is a field-based minimizer, not a guarantee against deliberately encoded content in arbitrary client-controlled metadata.

Recommendation justification, administrator notes, enrollment/IdP requests, policy simulation inputs, discovery inventories, Python SDK producers, gateway/resource collectors and external integrations are separate data flows. They are not all covered by the new Go telemetry-content filter. Review their payloads before admitting those workflows. No scanner/redaction routine should inspect real credential files to demonstrate collection.

Pilot verification uses synthetic marker strings in disposable fixtures. Inspect the actual outbound records, local retry state and central export. Check privacy again after an offline replay, and verify that IDs and policy outcomes still reconcile. Keep sanitized evidence metadata and hashes; do not attach raw prompts, tokens or credential files to the qualification bundle.

Define retention for the persistent database, local retry/archive files, reports and backups with the pilot owner. Automatic global retention/purge and a complete all-producer payload inventory remain open; metadata minimization alone does not establish either.

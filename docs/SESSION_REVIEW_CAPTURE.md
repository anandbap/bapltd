# Local session evidence and outbound telemetry

Tool operation details are captured locally regardless of `BAP_TELEMETRY_CONTENT`.
The hook spool and audit journal retain commands, structured tool inputs (including
search patterns and tool-specific arguments), and decision reasons. Credential
redaction applies locally; local evidence is not shortened by the outbound string
limit. The local audit hash includes structured tool input.

`BAP_TELEMETRY_CONTENT` controls outbound content only. Default metadata sync omits
commands, structured tool inputs, free-form reasons and activity descriptions.
`redacted` permits redacted content transmission. Administrator prompt reporting
policy continues to control whether prompt text is transmitted. Transport filtering
applies again to retry and recovery uploads.

Before acknowledged records leave the pending journal, full local copies are
synced to its `.recovery-*.jsonl` archive, including when the server acknowledgement
is durable. `review_session.bat` reads these archives as well as the pending journal
and hook spool, deduplicates event IDs, and prints available input and reason details.
Missing content in older records is identified explicitly. Missing latency produces
an unknown SLA result, not a zero-millisecond pass.

The PowerShell report changes take effect from this checkout immediately. Capture
and sync changes require rebuilding and deploying both `bapedge` and the Claude
hook interceptor, then restarting the daemon and agent sessions that use them.
Details already discarded by older builds cannot be reconstructed from the ledger.

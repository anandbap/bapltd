# Expected pilot roster and check-in coverage

The control plane supports an operator-assigned roster and explicit reporting windows. V3 **Discovery & coverage → Expected pilot workstations** shows fresh, stale, missing, ownership-conflict and not-expected rows. This is a current registry snapshot, not a historical leadership report or proof that every prompt/operation was captured.

## Configuration

Create an operator-managed JSON file. Use the exact workstation instance ID from enrollment; hostname matching is deliberately unsupported. Person/team assignments come from this file, not agent labels. Email matching is case-insensitive but does not independently prove corporate SSO.

```json
{
  "schema_version": 1,
  "roster_id": "claude-pilot-week-1",
  "freshness_seconds": 60,
  "entries": [
    {
      "person_id": "pilot-01",
      "owner_email": "pilot-01@example.test",
      "team": "engineering",
      "instance_id": "replace-with-exact-enrolled-instance-id",
      "windows": [
        {"start": "2026-11-02T14:00:00Z", "end": "2026-11-02T23:00:00Z"}
      ]
    }
  ]
}
```

Repeat entries for the actual workstations. One person may have multiple machines with consistent email/team assignments; each machine has one assignment. Windows must use explicit offset-aware timestamps, be ordered and nonoverlapping, and last at most 31 days each. Start is inclusive; end is exclusive. Resolve local work hours/daylight-saving time before publishing. Recurring schedules and holidays are not inferred.

Start with `--pilot-roster <path>` or set `BAP_PILOT_ROSTER` to that path. Invalid/unreadable configured files fail startup. Without configuration, coverage is unavailable and the denominator unknown. The file loads once at startup; changes require restarting the server. Keep the file in approved deployment configuration to preserve expectations across deployments. This does not make registry observations durable.

Validation limits: 1 MiB JSON, 1,000 workstation entries, 64 windows per entry and freshness between 30 and 3,600 seconds. These are bounds, not measured capacity guarantees. No client/heartbeat can edit expectations or acquire execution authority from an assignment.

## Report contract

`GET /api/v1/pilot/coverage` requires existing admin authentication and follows remote-admin policy. Ordinary enrollment proofs cannot read the roster. Responses use `Cache-Control: no-store`. V3 loads the report for authenticated Live admins on the discovery view, refreshing every 30 seconds and clearing it on logout/demo mode. Team-scoped leadership read roles remain pending.

Responses include schema version, roster ID/revision (SHA-256 of normalized configuration), server `as_of`, expected workstation/person counts, fresh workstation count, rows, scope and `history_durable: false`. Two expected machines assigned to one person count as two machines and one person. No whole-activity coverage, productivity or completion percentage is derived.

| State | Meaning |
| --- | --- |
| `not_expected` | No window includes current server time; excluded from the denominator. |
| `missing` | No usable check-in for the exact assigned identity is retained. Central restart can cause this until reporting recovers. |
| `stale` | A matching check-in exists, but is outside the current window/freshness bound, or the registry record is inactive. Consult existing controls/status to distinguish offline from restricted. |
| `ownership_conflict` | A record for the exact instance has a different/missing owner. A matching record alongside a conflicting one cannot qualify the workstation. |
| `fresh` | The exact instance/owner has an active registry record and a check-in within both the current window and freshness bound. |

Enrollment and authenticated session/liveness registration can update a registry check-in. `recovery_only` is exposed on the selected record; recovery presence does not establish complete installation or grant authority. The report uses server registry times, not client event timestamps. Administrative cleanup/reset/session-end no longer overwrite heartbeat times; future timestamps cannot qualify.

Lookup uses the registry identity index for configured instances, off the command path, without audit scans or extra heartbeat requests. Current observations remain in memory; configuration alone cannot preserve reporting history across deployments.

## Acceptance

1. Configure the actual roster with a current window. Sign in as admin and open V3 Discovery & coverage. Confirm denominator and assigned team/person IDs.
2. Enroll a designated machine and allow authenticated reporting. Check exact identity, fresh state and last check-in. Run the separate native onboarding probe for supported prompt/policy reporting.
3. Stop reporting on a test machine. After freshness expires, confirm stale. A machine never enrolled here shows missing. A matching hostname cannot substitute for the expected instance.
4. Verify a different owner on the same instance causes ownership conflict. Restore enrollment through normal administration; this report cannot change identities/restrictions.
5. Test outside a window: not expected and excluded. Zero expected machines does not mean 100% reporting coverage.
6. Restart an isolated server with the same configuration: lost observations show missing until recovery. Durable history remains P3.

Automated tests cover validation, bounds, schedule boundaries, identity/freshness/restrictions, admin/enrollment isolation, restart behavior, cleanup timestamps and safe V3 rendering/logout. Real roster deployment, native acceptance, corporate SSO and durable report qualification remain open.

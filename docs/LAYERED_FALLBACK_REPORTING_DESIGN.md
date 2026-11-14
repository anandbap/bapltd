# Layered Fallback Reporting - Design

Status: proposal (nothing implemented). Author context: follow-up to the question
"if hooks are not approved, can lower layers still report what BAP received?"

## 1. Problem

Today each layer tags events with its own `reporting_layer` (`hook`, `mcp`, `shim`,
`broker`, `gateway`, plus presence-only `discovery`). The control plane merely
collects whichever layers show up (`session/store.go` `addReportingLayer`).
There is no rule of the form "layer N reports only when layer N-1 is silent".

Consequences:
- Only the hook layer captures the user prompt (`user_prompt`). If hooks are
  unapproved or disabled, the session is labelled `unmonitored` and the request
  content is lost.
- The MCP server (`bap-edge/internal/mcp/server.go`) audits only calls to its own
  `bap_*` tools. It never sees requests handled by the agent's built-in tools.
- The same gap exists between shim, broker and gateway.

## 2. Goals and non-goals

Goals
1. Every session yields the best evidence available, with the highest-trust layer
   winning when several report.
2. Lower layers fill in only what higher layers did not report (no double
   counting, no duplicate prompts).
3. Evidence is graded, so a self-reported record is never presented as verified.

Non-goals
- Not an enforcement change. Fallback reporting is observation only.
- Not a defence against a hostile local admin or a model told to lie.
- No new capture of prompt text where privacy policy forbids it
  (`PromptCaptured=false` -> hash only, as in `httptransport/privacy.go`).

## 3. Trust grades

Add `evidence_grade` to audit events (part of hash version 4, see section 7):

| Grade | Source | Meaning |
|---|---|---|
| `verified` | hook, broker, shim, gateway | Emitted by BAP code that observed the action itself. |
| `mediated` | mcp (`bap_*` tools) | BAP executed the call, but did not see the originating prompt. |
| `self_reported` | mcp `bap_report_request` | The model said it. Unverifiable. |
| `presence` | discovery | Process exists. No content. |

Dashboards and exports must show the grade next to the layer. `self_reported`
content is never used for policy decisions, only for visibility.

## 4. Components

### 4.1 Layer 1 liveness signal (edge)
The hook already writes evidence via `cchook/evidence_spool.go`. Add a per-session
heartbeat record `hook_last_seen` (timestamp of last hook event, session id, hook
binary hash). Exposed by the daemon at a local endpoint and included in the normal
telemetry batch as a `hook` event with `executable: "hook_heartbeat"`.

### 4.2 MCP tool `bap_report_request` (layer 2 fallback)
New tool in `server.go` `tools/list` and `tools/call`:

```
bap_report_request(
  request_summary: string,   // model's own words, max 2 KB
  turn_id:        string,    // model-chosen, monotonic per session
  tools_planned:  []string   // optional
)
```
Behaviour:
1. Ask the local daemon: has this session had a `hook` event in the last
   `hook_grace` (default 30 s) or any `hook` user_prompt for `turn_id`?
2. If yes -> return `{"recorded": false, "reason": "hook_active"}` and log nothing
   (no duplicate).
3. If no -> emit an audit event with `reporting_layer: "mcp"`,
   `evidence_grade: "self_reported"`, `executable: "user_prompt"`,
   `decision: "observed"`, prompt text only if prompt capture is enabled,
   otherwise `prompt_hash`.

Instruction delivery: the tool description plus the MCP `initialize` instructions
string tell the agent to call it once per user turn. This is cooperative; the
design says so openly (grade `self_reported`).

### 4.3 Mediated fallback for tool calls (layer 2)
Calls through `bap_execute`, `bap_write_file` etc. already emit `mcp` events.
Tag them `evidence_grade: mediated`. They are emitted only if no `broker` event
exists for the same `command_hash` within the grace window (the broker is the
stronger witness when both fire, since `bap_execute` ends in the sandbox).

### 4.4 Control-plane arbitration (the missing rule)
In `bap-controlplane/internal/session` add `reporting_arbiter.go`:

- Layer precedence: `hook > broker > shim > mcp > gateway(network scope) > discovery`.
  (Gateway is orthogonal: it covers network operations, so it is never suppressed
  by others and never suppresses them.)
- For each `(session_id, dedup_key)` keep the highest-precedence event as primary
  and attach lower ones as `corroborating_layers`. `dedup_key` = `turn_id` for
  prompts, `sha256(normalized command)` + 5 s bucket for commands.
- Session summary gets `coverage` per layer: `observed`, `silent`, `not_applicable`,
  and a `degraded_reason` such as `hooks_unapproved` when the agent client reports
  hooks not trusted (see 4.5) or no hook heartbeat arrives while mcp events do.
- `unmonitored` is set only when no layer above `discovery` reported anything.

### 4.5 Detecting "hooks not approved"
BAP cannot read the client's approval UI. Infer it:
- Hook files installed (doctor already checks) AND session active AND
  no hook heartbeat after N tool events seen by lower layers -> `hooks_unapproved_or_disabled`.
- Surface this in `bapedge status` and the dashboard instead of a silent
  `NOT_OBSERVED`.

### 4.6 Shim / broker / gateway
Same pattern, simpler, since they see real actions:
- Shim events are suppressed when the broker emits the same `dedup_key`
  (shim hands off to `bapedge exec`).
- Broker events are the primary record for commands when no hook event exists.
- Gateway events are kept always, tagged `network`.

## 5. Data flow

```
user prompt -> [L1 hook] --verified prompt--------------------------+
            |                                                        v
            +-> model -> bap_report_request -> daemon: hook active? -> drop
                                               |  no
                                               v
                                   audit event (mcp, self_reported)
tool call   -> [L1 hook pre-tool] verified
            -> [L2 bap_* tool] mediated   --+
            -> [L3 shim] -> [L4 broker]     +--> control plane arbiter
            -> [L5 gateway] network event --+      (precedence + dedup + coverage)
```

## 6. Failure modes and honesty rules

- Model skips `bap_report_request`: no prompt evidence. Coverage shows
  `L2 silent`, not green.
- Model fabricates the summary: graded `self_reported`; never used for decisions.
- Clock skew / duplicate delivery: dedup by `event_id` already exists
  (`audit.Store.seenIDs`); arbiter dedup is additive.
- Hook heartbeat spoofing: heartbeat carries hook binary hash and is covered by the
  existing audit chain, so tampering is detectable but not preventable.
- Never claim "COMPLIANT" from fallback evidence alone (consistent with
  ARCHITECTURE.md section 8.1 "status is observed, not assumed").

## 7. Schema and compatibility

- `audit.Event`: add `EvidenceGrade string`, `CorroboratingLayers []string`,
  `TurnID string`, `DedupKey string`.
- Hash version 3 -> 4 includes the new fields; legacy links are not rewritten
  (same approach as the v3 reporting-layer bump). Edge `AuditEntry` mirrors them
  in `logger.go` hash input and `transmitter.go`.
- `session.Session`: add `Coverage map[string]string`, `DegradedReason string`.
- Edge `types.go` already has `HookActive`; reuse it for the heartbeat result.

## 8. Test plan

Go unit tests
- mcp: `bap_report_request` drops when hook heartbeat is fresh; records when stale;
  respects prompt-capture-off (hash only).
- arbiter: hook+mcp same turn -> one primary, mcp in `corroborating_layers`;
  hook absent -> mcp primary with grade `self_reported`; broker+shim same command
  -> broker primary.
- session: `unmonitored` only when nothing above `discovery` reported.
- audit chain: v4 hash verifies; v3 legacy links still verify.

Integration (extend `tests/test_multi_layer_defense.py`)
- Disable hooks via env -> run session using MCP -> assert session shows
  `degraded_reason=hooks_unapproved_or_disabled` and a `self_reported` prompt.
- Hooks on -> assert no `mcp` prompt duplicate.

## 9. Rollout

1. Schema + arbiter + coverage in control plane (no behaviour change for events).
2. Hook heartbeat + doctor/status wording.
3. `bap_report_request` tool behind config flag `fallback_reporting` (default off).
4. Dashboard: grade badges and coverage row. Then enable by default in audit mode.

## 10. Open questions

1. Grace window length for "hook silent" (30 s proposed) - too short misses slow
   turns, too long delays fallback.
2. Should `self_reported` prompt text be stored at all, or hash-only by default?
3. Is a nudge acceptable (MCP server instructions) or must the launcher inject
   it into the agent's system prompt for the fallback to be dependable?

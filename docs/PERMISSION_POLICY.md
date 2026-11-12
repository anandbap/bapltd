# BAP Permission Policy (BAP-924 / BAP-925 / BAP-926)

How a request for permissions becomes a grant. Tool knowledge and risk decisions live in **data**
(`bap-edge/internal/authz/default_permission_policy.json`, optionally replaced by a signed
administrator override), not in Go `switch` statements. Hard safety invariants stay in code and are
never relaxable by policy.

## The model (AWS-style: ask, policy approves)

```
agent: bapedge zsp authorize --actions <catalog actions> --resources <scopes>
        |
        v  1. non-reliance + hard invariants (code)      policy:/grant:/admin:/iam:/sudo: always need a human
        v  2. wildcard handling (policy data)            repo:* -> repo:read ; every other wildcard rejected
        v  3. resource wildcard narrowing (policy data)  "/*", "repo://*", "workspace://*" -> workspace://current
        v  4. per (action, resource) decision (policy)   allow | approve | deny   (most restrictive rule wins)
        v  5. ceiling clamp (policy)                     max uses / TTL clamped, mint cap per session
        v  6. grant signed with the PEP secret (HMAC)
```

| Tier | Meaning |
|---|---|
| `allow` | auto-minted, no human |
| `approve` | minted only with verified human approval (one-time terminal challenge, see below) |
| `deny` | never grantable, **not even with human approval** (credential access, secrets) |

Unknown actions fall to `default_tier` (`approve` or `deny`; `allow` is rejected at load time).

## Rule semantics

* `match`: `path.Match` globs over the lower-cased action. `:` is an ordinary character, so
  `cli:*:exec` matches `cli:python:exec`.
* A rule **without** `resource_match` applies to in-workspace resources only (`boundary_prefixes`),
  unless `"scope": "any"`. So `git:status` on `workspace://current` is allowed, but `git:status` on
  `system://local` hits the default tier and needs approval: an agent can no longer widen its own
  boundary by re-requesting with a bigger `--resources`.
* A rule **with** `resource_match` applies only to resources matching one of those globs
  (destination-aware rules).
* **Most restrictive matching rule wins** (`deny` > `approve` > `allow`). Therefore a broad
  "network needs approval" rule would beat a narrower "this host is fine" rule. Write exceptions so
  the broad rule does not also match them, for example approve only the mutating methods and
  allow-list reads:

```json
{ "id": "net-reference-get", "tier": "allow",   "match": ["http:get"],
  "resource_match": ["https://www.cnn.com/*"] },
{ "id": "net-writes",        "tier": "approve", "scope": "any",
  "match": ["http:post", "http:put", "http:patch", "http:delete"] }
```

  GET to the allow-listed host runs without a prompt; POST/upload anywhere, and GET to unknown hosts,
  still require a human. (The shipped default allow-lists no hosts: `http:*` needs approval until an
  administrator adds destinations. Note the *execution-time* Cedar rules and gateway PEP still gate
  raw `curl`; aligning them is BAP-924 follow-up work.)
* `ceiling`: `max_uses_per_grant`, `max_ttl_seconds` (requests are clamped, reported as narrowing)
  and `max_mints_per_session` (hard stop, `ErrMintCapExceeded`).
* `..` anywhere in a resource is never considered in-boundary.

## Overriding the policy (human operator only)

```bash
bapedge zsp policy-sign --file my-policy.json
```

Validates the document (strict: unknown fields, bad patterns, `allow` default and wildcard narrowings
to wildcards are all rejected), copies it to `<zsp dir>/permission-policy.json` and writes an HMAC
signature with the workstation PEP secret. At every mint the override is verified; a missing or
invalid signature is a **hard error** (minting stops), never a silent fallback to the default.
`policy-sign` refuses to run inside an agent session (`BAP_IN_BROKER`, or any agent-identifying
environment).

## Human approval

`approve`-tier asks (and `--oob-approve`) now require a **real terminal on stdin and stderr** and a
freshly generated one-time code that the human reads from the terminal and retypes. A flag, a piped
`y`, a redirected stdin or a script cannot satisfy it. It never runs inside the agent broker.

Known limits (tracked in BAP-926): an agent that allocates its own pseudo-terminal and reads it back
could still answer; the approval proof is not yet a signature from a separate human-held key; the
pepper file is protected by OS file permissions and location (`~/bin/.bapstate/zsp`, BAP-920), not by a
separate trust boundary. The workspace-local `.bapstate\zsp\pepper.key` seen in older checkouts is a
legacy copy and should be deleted and the live pepper rotated.

## Behavior changes versus the previous engine

* `repo:*` narrows to `repo:read` only (previously `repo:read,repo:push`).
* Interpreters, unknown `cli:*:exec`, `git push`, deletes/drops/admin, `http:*`/`net:*` and any
  out-of-workspace resource need approval; credential actions are denied outright.
* The hardcoded fallback signing secret is removed. An engine without a secret refuses to mint or
  consume (`ErrSigningSecretMissing`).
* `BAP_INSECURE_SKIP_VERIFY` no longer disables TLS verification for non-loopback hosts
  (`bap-edge/internal/httptransport/client.go`).

## Tests

| Layer | Command | Covers |
|---|---|---|
| Unit | `go test -C bap-edge ./internal/authz` | policy parsing/validation, tier precedence, boundary, destination rule, signed override lifecycle, ceiling |
| Regression | same package, `TestEscalation_*` | each behavior from the Claude Code calls report (interpreter mint, `system://local` widening, wildcard push, mint cap, hard-deny, empty secret) |
| End to end | `go test -C bap-edge ./cmd -run TestE2E_` | real `RunZSP` CLI + real hook decision path: replay of the report, scripted `--oob-approve`, in-broker refusals, `policy-sign`, mint cap via signed override, tamper fail-closed |
| Whole suites | `go test -C bap-edge ./...` and `go test -C cchook ./...` | no regressions |

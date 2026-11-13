# Capability model and current enforcement

BAP-1010 introduces an effect-level `capability.Set` alongside the runner's
`capability.Profile`. These are deliberately separate: a Profile currently gives
the workspace read/write access, so converting a read-only grant directly into
that Profile would widen its authority.

`capability.FromTaskGrant(grant, workspace, now)` converts an **already verified**
grant into a Set. The caller remains responsible for signature verification,
session/principal binding, revocation and atomic use consumption. Conversion
does not install permissions or start a process.

| Granted action | Accepted resource | Result |
|---|---|---|
| `fs:read` | `workspace://current` or absolute `file://` path | Exact read capability |
| `fs:write` | Same | Exact write capability |
| `fs:delete` | Same | Exact delete capability |
| `net:connect` | Exact `https://host[:port]` or `http://host[:port]` | DNS destination and port; defaults 443/80 |
| CLI, developer commands, unknown actions or resource types | Any | Conversion error |

Expired, burned, exhausted, future-issued or unidentified grants fail conversion.
Requested actions/resources never become authority. Root paths, credential
locations, wildcard paths, raw network addresses, metadata destinations, URL
credentials and URL path/query scopes are refused. Process and environment
fields are reserved in the Set; no legacy CLI action is silently promoted into
an unrestricted process capability.

## Native runner

`bap run --provider auto -- agent arguments...` forwards to `bapedge run`, which
selects AppContainer on Windows, bubblewrap on Linux, and `sandbox-exec` on macOS.
A missing provider causes an error; BAP does not fall back to an ordinary child.
`bap run --provider appcontainer --print -- agent` prints the configuration
without executing the command or changing workspace ACLs.

Native launcher children receive an explicit environment allowlist. Credential-like
variable names are dropped even if requested. Read-only mounts cannot name
credential locations or filesystem roots; existing symlink aliases are resolved
before checking credential locations. This does not replace provider-level
containment or protect against a mount target changed after validation.

Use `bap exec "npm test"` for a brokered shell command and `bap run -- npm test`
for a process launched by the native provider. The Python CLI previously treated
`run` as an alias for `exec`; wrappers using that alias with one quoted shell
string must use `exec` or pass the executable and its arguments separately.

Windows boundary tests exercise real AppContainer execution. Linux bubblewrap
and macOS native execution still require native acceptance runs. The macOS
rendered network rules restrict TCP access to the relay's loopback port 3128
and the configured unix socket; they do not permit arbitrary loopback ports.
Provider rendering tests are not evidence of successful native execution.

## Remaining enforcement work

The Set converter is not yet the active grant-to-runner authority path. The
legacy broker still uses command classification for enforcement. Hook removal
or advisory-only mode must wait for the native escape suite to prove equivalent
boundaries. Brokered credential injection and comprehensive credential masking
inside writable workspaces remain open; an environment allowlist alone does not
complete BAP-1014.

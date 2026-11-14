# Network and control-channel contracts

Reviewed 2026-11-14 against source. [Architecture](../ARCHITECTURE.md) owns the component model; [control_channels.json](control_channels.json) is the matching channel inventory. A channel's existence does not establish it is configured, reachable or qualified in a deployment.

## Actual channels

| ID | Path | Transport / identity | Failure and scope |
|---|---|---|---|
| CH-01 | Agent callback or MCP host to local adapter | Client-specific process/stdin/stdout or MCP stdio | Host must invoke/approve the integration. Process ancestry/source labels are not independent device attestation. |
| CH-02 | Edge lifecycle, audit and heartbeat to control plane | HTTPS and enrolled bearer proof for protected routes | Missing/invalid identity blocks protected uploads; evidence is retained for supported retry paths. Public health success does not prove authentication. |
| CH-03 | Edge policy sync to control plane | POST `/api/v1/policy/sync`; pinned Ed25519 bundle plus current-source nonce proof | Polling, not an implemented SSE/JWS push channel. Offline behavior depends on signed-cache validity and lease. |
| CH-04 | Gateway to central grant consumption | Configured control-plane API and bounded grant | Single-use enforcement depends on central consumption being enabled and reachable. Do not assume every deployment uses it. |
| CH-05 | Workstation/browser/control plane and configured IdP | OTC or device/browser login flow | Real IdP configuration and account-owner authentication require acceptance; simulated/development flows are not equivalent. |
| CH-06 | Resource gateway to configured backend | Backend HTTP(S) and adapter-specific credentials | Only resources protected by the gateway are governed. Generic production SaaS credential exchange is not established. |
| CH-07 | Broker/native provider to child process | OS process APIs; optional native-runner egress relay | Local containment is not encryption. Legacy and native-provider guarantees differ by OS. |
| CH-08 | Browser administrator to control plane | Configured HTTPS, administrator credential/cookie and applicable origin checks | Shared pilot administrator identity is not individual admin SSO or separation of duties. |

## Transport protection

The Go edge transport requires verified HTTPS for authenticated non-loopback traffic and refuses authenticated cross-origin redirects. It uses system/configured certificate trust; its TLS minimum is 1.2, not a guarantee that every connection negotiates TLS 1.3 or one particular cipher.

The code contains loopback/development certificate exceptions and separate client implementations. Do not infer universal certificate pinning or mTLS from the public-key policy pin. The latter authenticates policy signatures, not every transport certificate or device.

Sources: [edge transport](../bap-edge/internal/httptransport/client.go), [identity attachment/redirects](../bap-edge/internal/httptransport/identity.go), [reporting endpoint policy](../bap-edge/internal/config/).

## Policy direction and freshness

The edge initiates polling. Watchers and the current-source daemon poll immediately and every three seconds; short-lived decisions can refresh a cache older than five seconds. These are intervals, not delivery deadlines.

An upgraded server signs a response bound to a random request nonce, directive and bundle signature. This authorizes a live policy version moving up or down without permitting a local replayed bundle to downgrade authority. Bundle signature, asset and key validation remain required.

Disconnected, stopped or unauthenticated devices cannot receive immediate freezes. Production requires an explicit signed offline budget. A valid cached policy is not proof that an additional central grant or approval can be obtained offline.

## Reporting ownership and recovery

The enrolled origin controls credential attachment. A repository setting must not redirect enrolled evidence to an unrelated server. Origin/configuration conflicts queue reporting for correction.

Session IDs and owner identity are checked against workstation proof. A new login must not relabel old evidence owned by another identity. Current-source uploads separate session batches: an HTTP 403 preserves the refused session while allowing other sessions to continue. A 401 or network/server failure retains unsent evidence.

Reporting-only recovery restores presence/correlation when permitted; it does not reactivate ended/revoked authority or issue execution grants. A durable checkpoint can restore administrative state. A lost ephemeral authority and a production restart from intact persistent storage are different failure cases.

## Two different proxy boundaries

The native runner's egress proxy allows destinations and records decisions; network closure by the selected OS provider is what makes that proxy the exclusive path. A standalone proxy setting alone is advisory for processes that can open sockets elsewhere.

The resource gateway verifies operations at protected backend routes. It is not automatically a forward proxy for all desktop traffic. Raw sockets, direct backends, other network routes and unmediated tools need separately deployed boundaries.

No current architecture guarantee includes host-wide WFP (not implemented), NetworkExtension (not implemented), or eBPF (simulation only) packet enforcement. See [execution design](EXECUTION_MODEL.md).

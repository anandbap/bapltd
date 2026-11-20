// Package coverage describes boundary guarantees without treating optional
// native integrations as prerequisites for independent enforcement.
package coverage

const Guidance = "BAP uses five defense layers: in-harness hooks, execution broker, cryptographic file integrity/pinning, anomaly risk, and control-plane attestation. A missing native hook is missing layer-1 coverage, never an execution permission or proof of a lower-layer failure. Route commands through bapedge exec or BAP MCP: those boundaries evaluate received requests independently of hooks. Do not bypass an unavailable hook by using unmediated native tools. Report a layer as participated only with that layer's actual evidence; configuration/readiness is not participation. Unrouted actions remain unverified. Network outages retain local enforcement and pending evidence for retry; they never widen authority."

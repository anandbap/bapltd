# BAP Zero-Trust Policy & Enterprise Governance for Claude Code

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Enterprise Governance & Boundaries
1. **Multi-Project Workspace & Dependency Traversal**:
   - Reading, inspecting, and navigating cross-project dependencies, sibling repositories, shared schemas, and local dependency caches (e.g. `..\sibling-project`, `~/.m2`, `~/.gradle`) is **PERMITTED** for build and code intelligence.
   - Modifying, deleting, or redirecting output to files outside the authorized workspace is strictly prohibited without explicit human authorization.
2. **Absolute Secret Protection**:
   - Access to credential files (`.env`, `~/.aws`, `~/.ssh`, private keys) is strictly forbidden across all directories, whether inside or outside the workspace.
3. **Software Supply Chain & Package Management**:
   - Package managers (Maven, Gradle, npm, pip) must use approved corporate mirrors (e.g. local Nexus / Artifactory). Bypassing internal repos to download directly from public internet registries is prohibited.
   - Installation of unapproved standalone software, third-party `.msi` installers, or setup binaries is strictly blocked.
4. **Network Egress & Execution Broker**:
   - All shell executions MUST run through the BAP Edge Execution Broker: `bapedge.exe exec "<command>"`.
   - Raw network exfiltration utilities (`curl`, `wget`, `nc`, raw sockets) are strictly prohibited; external API access must route through the BAP Gateway PEP.
5. **Zero-Trust Policy Enforcement & JIT Task Grants**:
   - Commands are evaluated against Cedar invariants before execution.
   - **Zero Standing Privileges (ZSP)**: The agent operates with zero standing execution privileges.
   - **Read-Only Exemption**: Plain project inspection within the workspace (`git status`, `git log`, `git diff`, directory listing, file viewing) is permitted automatically.
   - Follow the BAP task authorization workflow below for grants, renewal and human approval.
6. **Multi-Layer Defense-in-Depth & Policy Protection**:
   - Instruction and policy files (`GEMINI.md`, `CLAUDE.md`, `AGENTS.md`, `policy.cedar`, `.bap/pins.json`) are tamper-proof and actively defended across 5 layers:
     - **Layer 1 (In-Harness Tool Hooks)**: Tool write/edit attempts targeting policy files are blocked before execution.
     - **Layer 2 (Execution Broker)**: `bapedge exec` evaluates commands against Cedar invariants, blocking file overwrites or redirects to policy files.
     - **Layer 3 (Cryptographic FIM & Pinning)**: `.bap/pins.json` verifies SHA-256 hashes in real time. Any unverified drift immediately halts execution fail-closed with `HashMismatchError`.
     - **Layer 4 (Anomaly Risk Engine)**: Tampering attempts trigger `DENIED_TAMPER` alerts and escalate the session threat score to CRITICAL.
     - **Layer 5 (Control Plane Attestation)**: The central control plane validates cryptographic attestation and revokes compromised sessions.
7. **Identity & Audit Logging**:
   - LTD_SOURCE=claude-code
   - BAP_SESSION_ID=${env:BAP_SESSION_ID:-sess-claude-active}
8. **Developer Override & Agent Immunity**:
   - Autonomous agents are **STRICTLY FORBIDDEN** from executing `bapedge dev-override on`. That command requires interactive human authorization.

## BAP task authorization workflow

Zero Standing Privileges (ZSP) is broker-mediated. Autonomous agents do NOT run
`bapedge zsp authorize` or mint task grants directly.

Submit ordinary supported inspection and workspace edits normally: hooks and the
execution broker (`bapedge exec "<command>"` on Windows; `bapedge.exe`) evaluate policy
and obtain eligible JIT grants automatically. Native Read/Write/Edit tools remain
governed by their BAP hooks.

If an operation requires human approval (e.g. interpreters, git push, deletions,
or network egress), BAP automatically registers a pending approval request in the
ZSP inbox and returns its request ID (`req-xxxx`). When BAP reports a pending approval request:
1. Do NOT run `bapedge zsp authorize` or attempt to approve the request yourself.
2. Stop and notify the human developer of the exact request ID and command to run
   in their own terminal: `bapedge zsp approve <request-id>`.
3. Wait for the developer to confirm approval, then retry your command.

Generic grants remain single-use by default; workspace file edits receive bounded
ceilings (up to 25 edits, 600s). Duplicate callbacks for one stable native tool-use
ID spend once. An expired or exhausted grant is renewed automatically by the broker
when permitted by signed policy.

If BAP reports a permanent policy denial (`BAP POLICY DENIAL`, credential access,
or protected policy assets), stop immediately. Do NOT retry through another tool
or shell. Autonomous agents are strictly forbidden from executing `bapedge dev-override on`.

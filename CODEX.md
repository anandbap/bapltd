# BAP Zero-Trust Policy & Enterprise Governance for OpenAI Codex

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
   - **Mutating Operations**: When executing modifying operations (edits, builds, commits, package installs) or if a command returns `ZeroStandingPrivilegeViolation`:
     1. Do **NOT** search for workaround shells, sub-interpreters, or evasion techniques.
     2. Request a policy-evaluated JIT TaskGrant:
        ```bash
        bapedge.exe zsp authorize --session-id "${env:BAP_SESSION_ID}" --mission TASK_EXECUTION --goal "<intent summary>" --actions "<action>" --resources workspace://current
        ```
        *(Or invoke the native `bap_request_task_grant` MCP tool).*
     3. Requesting a grant is **NOT** a self-approval or override—it submits your envelope to the BAP Policy Enforcement Point (PEP) for automated Cedar verification.
     4. Once granted, execute through the broker: `bapedge.exe exec "<command>"`.
6. **Multi-Layer Defense-in-Depth & Policy Protection**:
   - Instruction and policy files (`GEMINI.md`, `CLAUDE.md`, `AGENTS.md`, `CODEX.md`, `policy.cedar`, `.bap/pins.json`) are tamper-proof and actively defended across 5 layers:
     - **Layer 1 (In-Harness Tool Hooks)**: Tool write/edit attempts targeting policy files are blocked before execution.
     - **Layer 2 (Execution Broker)**: `bapedge exec` evaluates commands against Cedar invariants, blocking file overwrites or redirects to policy files.
     - **Layer 3 (Cryptographic FIM & Pinning)**: `.bap/pins.json` verifies SHA-256 hashes in real time. Any unverified drift immediately halts execution fail-closed with `HashMismatchError`.
     - **Layer 4 (Anomaly Risk Engine)**: Tampering attempts trigger `DENIED_TAMPER` alerts and escalate the session threat score to CRITICAL.
     - **Layer 5 (Control Plane Attestation)**: The central control plane validates cryptographic attestation and revokes compromised sessions.
7. **Identity & Audit Logging**:
   - LTD_SOURCE=codex
   - BAP_SESSION_ID=${env:BAP_SESSION_ID:-sess-codex-active}
8. **Developer Override & Agent Immunity**:
   - Autonomous agents are **STRICTLY FORBIDDEN** from executing `bapedge dev-override on`. That command requires interactive human authorization.

# BAP Zero-Trust Policy & Enterprise Governance for Antigravity (Governed Session: $SessionId)

This workspace is actively governed by the BAP Zero-Trust Local Trusted Daemon (bapedge.exe).

## Enterprise Governance & Boundaries
1. **Multi-Project Workspace & Dependency Traversal**:
   - Reading, inspecting, and navigating cross-project dependencies, sibling repositories, shared schemas, and local dependency caches (e.g. ..\sibling-project, ~/.m2, ~/.gradle) is **PERMITTED** for build and code intelligence.
   - Modifying, deleting, or redirecting output to files outside the authorized workspace is strictly prohibited without explicit human authorization.
2. **Absolute Secret Protection**:
   - Access to credential files (.env, ~/.aws, ~/.ssh, private keys) is strictly forbidden across all directories, whether inside or outside the workspace.
3. **Software Supply Chain & Package Management**:
   - Package managers (Maven, Gradle, npm, pip) must use approved corporate mirrors (e.g. local Nexus / Artifactory). Bypassing internal repos to download directly from public internet registries is prohibited.
   - Installation of unapproved standalone software, third-party .msi installers, or setup binaries is strictly blocked.
4. **Network Egress & Execution Broker**:
   - All shell executions MUST run through the BAP Edge Execution Broker: bapedge.exe exec "<command>".
   - Raw network exfiltration utilities (curl, wget, nc, raw sockets) are strictly prohibited; external API access must route through the BAP Gateway PEP.
5. **Zero-Trust Policy Enforcement**:
   - Commands are evaluated against Cedar invariants before execution.
   - If a command is denied, inspect the suggestion in the structured response.
6. **Identity & Audit Logging**:
   - LTD_SOURCE=antigravity
   - BAP_SESSION_ID=$SessionId

## BAP task authorization workflow

Use the session ID supplied by BAP. Submit ordinary supported inspection and
workspace edits normally: hooks evaluate policy and obtain eligible JIT grants.
An installed client with automatic grants disabled must request a grant first.
Shell commands must execute through `bapedge exec "<command>"` (`bapedge.exe` on
Windows); native Read/Write/Edit tools remain governed by their BAP hooks.

If BAP asks for authorization, run the suggested standalone command yourself:
`bapedge zsp authorize --session-id "<active-session-id>" --mission TASK_EXECUTION --goal "<task intent>" --actions "<canonical:action>" --resources workspace://current`
Use the actual session ID from hook context or the environment: PowerShell
`$env:BAP_SESSION_ID`, CMD `%BAP_SESSION_ID%`, POSIX shells `$BAP_SESSION_ID`.
Do not chain authorization with execution or dispatch dependent tools before it finishes.
Alternatively use `bap_request_task_grant` when that MCP tool is available.

Generic grants default to one use. For several ordinary workspace file edits,
request only `fs:file:write` with `--max-uses 25 --ttl 600s`; the signed policy
can narrow those ceilings. Do not mix Python, builds, deletion or publishing
into an edit grant. Running the created script requires a separate execution grant.
Read the granted actions, resources, remaining uses and expiry before relying on it.
Authorization itself does not spend the new grant. Duplicate callbacks for one
stable native tool-use ID spend once; a new tool call spends another edit use.

An expired/exhausted grant requires fresh policy authorization. If a newly issued
grant is immediately reported burned, report the hook defect and stop the loop;
do not keep minting grants or switch to shell writes to bypass a native denial.
If BAP returns a pending approval request, tell the human the request ID and exact
`bapedge zsp approve <request-id>` command for their own terminal, then wait for
approval before retrying. Never approve your own request or enable developer override.
Auto-approve cannot satisfy rules requiring separate human approval. Credential
and protected-policy denials must never be retried through another tool or shell.

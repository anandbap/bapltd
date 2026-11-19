"""Agent-facing BAP task grant guidance used by installer-generated rules."""

from pathlib import Path

AGENT_TASK_GUIDANCE = r'''## BAP task authorization workflow

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
'''


def update_agent_guidance(path):
    """Refresh only BAP's marked instruction block, preserving developer text."""
    target = Path(path)
    begin, end = "<!-- BAP task guidance -->", "<!-- /BAP task guidance -->"
    text = target.read_text(encoding="utf-8-sig") if target.exists() else ""
    block = begin + "\n" + AGENT_TASK_GUIDANCE.strip() + "\n" + end
    start = text.find(begin)
    stop = text.find(end, start) if start >= 0 else -1
    if start >= 0 and stop >= 0:
        text = text[:start] + block + text[stop + len(end):]
    else:
        text = text.rstrip() + "\n\n" + block + "\n"
    target.write_text(text, encoding="utf-8")

"""Agent-facing BAP task grant guidance used by installer-generated rules."""

from pathlib import Path

AGENT_TASK_GUIDANCE = r'''## BAP task authorization workflow

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

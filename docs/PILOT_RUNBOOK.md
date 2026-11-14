# Pilot runbook: install, demonstrate, verify

Start with [DEMO_CLAUDE_CODEX_ZERO_TRUST.md](../DEMO_CLAUDE_CODEX_ZERO_TRUST.md).

It begins with `pip install bap-ltd` and walks through useful work in Claude Code
and Codex, zero standing privileges, scoped grants, human approval, trust and
revocation, policy denials, administrator controls, recovery, and cleanup. Each
scene includes commands, expected results, and evidence to keep.

The installed companion is `python -m bap.pilot_demo`. It checks local grant
transitions and can guide the human approval and trust scenes. It does not need
Go, Node, a source checkout, or test dependencies.

Release build checks and service configuration are in
[maintainer qualification](MAINTAINER_PILOT_QUALIFICATION.md).

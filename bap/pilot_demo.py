"""Check an installed BAP release: python -m bap.pilot_demo --help."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
import uuid


MANUAL_CASES = (
    "claude_native", "codex_native", "central_delivery", "freeze_isolation",
    "recommendation", "privacy", "offline_recovery", "restart_recovery", "rollback",
)


class CheckFailure(RuntimeError):
    pass


def json_object(output):
    """Allow CLI notices before JSON, but reject incomplete objects/trailing noise."""
    decoder = json.JSONDecoder()
    for match in re.finditer(r"\{", output):
        try:
            value, end = decoder.raw_decode(output[match.start():])
        except ValueError:
            continue
        if isinstance(value, dict) and not output[match.start() + end:].strip():
            return value
    raise CheckFailure("CLI did not return a complete JSON object")


def is_allowed(result):
    data = json_object(result.stdout)
    allowed = data.get("allowed")
    if not isinstance(allowed, bool):
        raise CheckFailure("CLI response has no boolean allowed field")
    if (result.returncode == 0) != allowed:
        raise CheckFailure("CLI exit status disagrees with its allowed field")
    return allowed, data


def policy_decision(output):
    lines = [line for line in output.splitlines() if "POLICY DECISION:" in line]
    if len(lines) != 1:
        raise CheckFailure("Policy explanation has no unique decision")
    if "DENIED" in lines[0]:
        return False
    if "ALLOWED" in lines[0]:
        return True
    raise CheckFailure("Policy evaluation failed instead of returning a decision")


class Demo:
    def __init__(self, edge, workspace, client, interactive=False, sibling=None):
        self.edge = edge
        self.workspace = Path(workspace).resolve()
        self.client = client
        self.interactive = interactive
        self.sibling = Path(sibling).resolve() if sibling else None
        self.session = "sess-pilot-demo-" + uuid.uuid4().hex[:16]
        self.env = dict(os.environ, BAP_SESSION_ID=self.session, LTD_SOURCE=client)
        self.checks = []
        self.initialized = False
        self.version = None

    def command(self, *args):
        # Operator decisions are displayed for another terminal, never executed.
        if args[:2] in (("zsp", "approve"), ("zsp", "deny"), ("zsp", "policy-sign")) or args[0] in ("trust", "untrust", "dev-override"):
            raise CheckFailure("Human-only commands cannot be executed by this runner")
        try:
            return subprocess.run(
                [self.edge] + list(args), cwd=str(self.workspace), env=self.env,
                stdin=subprocess.DEVNULL, capture_output=True, text=True,
                encoding="utf-8", errors="replace", timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CheckFailure("CLI invocation failed: " + type(exc).__name__) from exc

    def zsp(self, subcommand, *args):
        return self.command("zsp", subcommand, "--session-id", self.session,
                            "--client", self.client, *args)

    def record(self, name, result="PASS"):
        self.checks.append({"name": name, "result": result,
                            "at": datetime.now(timezone.utc).isoformat()})
        print("[{}] {}".format(result, name))

    def expect(self, name, result, allowed, reason_pattern=None):
        actual, data = is_allowed(result)
        if actual != allowed:
            raise CheckFailure(name + ": unexpected authorization decision")
        reason = data.get("reason", data.get("error", ""))
        if reason_pattern and (not isinstance(reason, str) or not re.search(reason_pattern, reason, re.I)):
            raise CheckFailure(name + ": refusal did not identify the expected boundary")
        self.record(name)
        return data

    def authorize(self, action="git:status", uses=1, ttl="300s"):
        return self.zsp("authorize", "--mission", "CODE_INSPECTION", "--goal",
                        "Installed pilot authorization probe; no workload executed",
                        "--actions", action, "--resources", "workspace://current",
                        "--max-uses", str(uses), "--ttl", ttl, "--json")

    def check(self, action="git:status", resource="workspace://current", consume=False):
        args = ["--action", action, "--resource", resource]
        if consume:
            args += ["--consume", "--command", "authorization-only pilot probe; no workload executed"]
        return self.zsp("check", *args)

    def local(self):
        version = self.command("version")
        if version.returncode != 0 or not re.search(r"\d+\.\d+\.\d+", version.stdout):
            raise CheckFailure("Installed edge did not identify its release")
        self.version = re.search(r"\d+\.\d+\.\d+", version.stdout).group()
        self.record("installed_edge_version")
        if self.zsp("init", "--json").returncode != 0:
            raise CheckFailure("Could not initialize the dedicated demo session")
        self.initialized = True
        self.expect("zero_standing_privileges", self.check(), False,
                    r"no .*grant|without .*grant|zero standing|missing.*grant")
        self.expect("bounded_read_grant", self.authorize(), True)
        self.expect("different_action_denied", self.check(action="git:diff"), False, r"action|scope|grant")
        self.expect("different_resource_denied", self.check(resource="system://local"), False, r"boundary|boundaries|resource|scope")
        self.expect("one_use_authorized", self.check(consume=True), True)
        self.expect("used_grant_denied", self.check(), False, r"burn|uses|grant")
        self.expect("short_lease_issued", self.authorize(ttl="1s"), True)
        time.sleep(1.2)
        self.expect("expired_grant_denied", self.check(), False, r"expir|grant")
        self.expect("revocable_grant_issued", self.authorize(uses=2), True)
        if self.command("zsp", "revoke", "--session-id", self.session).returncode != 0:
            raise CheckFailure("Could not revoke the demo grant")
        self.expect("revoked_grant_denied", self.check(), False, r"revok|burn|grant")
        self.expect("credential_authority_never_granted", self.authorize(action="credential:access"), False,
                    r"never grantable|credential|denies this action")

    def human_approval(self):
        self.expect("publishing_requires_approval", self.authorize(action="git:push"), False,
                    r"human approval|interactive human|out.of.band")
        print("\nIn a SEPARATE operator terminal in the same workspace:\n"
              "  bapedge zsp approvals\n"
              "Find session {} and approve ONLY its git:push request with:\n"
              "  bapedge zsp approve <the-request-id>\n"
              "Read the scope and type the fresh code there.\n"
              "This runner checks permission only; it never runs git push.".format(self.session))
        input("Press Enter after approving in that terminal: ")
        self.expect("human_approved_grant_observed", self.check(action="git:push", consume=True), True)
        self.expect("approved_grant_cannot_be_reused", self.check(action="git:push"), False, r"burn|uses|grant")

    def trust(self):
        if not self.sibling or os.name != "nt":
            self.record("windows_trust_policy_transition", "NOT_TESTED")
            return
        if not self.sibling.is_dir() or self.sibling == self.workspace or self.workspace in self.sibling.parents:
            raise CheckFailure("Sibling must be an existing directory outside the demo workspace")
        probe = 'copy "demo.txt" "{}"'.format(self.sibling / "bap-demo-copy.txt")

        def verify(name, expected):
            result = self.command("why", probe)
            if result.returncode != 0 or policy_decision(result.stdout) != expected:
                raise CheckFailure(name + ": unexpected policy decision")
            self.record(name)

        verify("untrusted_sibling_write_denied", False)
        print('\nIn the operator terminal, from this workspace:\n'
              '  bapedge trust --project "{}"\n  bapedge permissions'.format(self.sibling))
        input("Press Enter after trusting the synthetic sibling: ")
        verify("trusted_sibling_policy_allows", True)
        print('\nIn that operator terminal:\n  bapedge untrust --project "{}"'.format(self.sibling))
        input("Press Enter after revoking trust: ")
        verify("untrusted_again_policy_denies", False)

    def run(self):
        try:
            self.local()
            if self.interactive:
                self.human_approval()
                self.trust()
            else:
                self.record("human_approval_transition", "NOT_TESTED")
                self.record("trust_policy_transition", "NOT_TESTED")
        except (CheckFailure, EOFError, KeyboardInterrupt) as exc:
            self.record(str(exc) if isinstance(exc, CheckFailure) else "operator_interrupted", "FAIL")
        finally:
            if self.initialized:
                try:
                    rc = self.command("zsp", "revoke", "--session-id", self.session).returncode
                    self.record("demo_grants_revoked", "PASS" if rc == 0 else "FAIL")
                except CheckFailure:
                    self.record("demo_grants_revoked", "FAIL")
        return {
            "schema_version": 1, "session_id": self.session, "client": self.client,
            "edge_version": self.version,
            "result": "FAIL" if any(c["result"] == "FAIL" for c in self.checks) else "LOCAL_CHECKS_PASS_MANUAL_ACCEPTANCE_REQUIRED",
            "checks": self.checks,
            "scope": "Installed CLI authorization and optional policy transitions; no native-client or hosted-service certification",
            "manual_checks": {name: "NOT_TESTED" for name in MANUAL_CASES},
        }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, default=Path.cwd(), help="Existing disposable demo Git workspace")
    parser.add_argument("--edge", help="Installed bapedge executable; default: PATH")
    parser.add_argument("--client", choices=("claude-code", "codex"), default="claude-code")
    parser.add_argument("--interactive", action="store_true", help="Pause for approval/trust in a separate operator terminal")
    parser.add_argument("--sibling", type=Path, help="Existing synthetic sibling for optional Windows trust checks")
    parser.add_argument("--report", type=Path, default=Path(".bap-demo/report.json"))
    args = parser.parse_args(argv)
    workspace = args.workspace.resolve()
    if not workspace.is_dir() or not (workspace / ".git").exists():
        parser.error("Use an existing disposable Git workspace")
    if os.environ.get("BAP_IN_BROKER"):
        parser.error("Run this demo yourself in an operator terminal, outside an agent broker")
    if args.interactive and not sys.stdin.isatty():
        parser.error("Interactive mode requires an operator terminal; unattended mode never approves")
    report = (workspace / args.report).resolve()
    if workspace not in report.parents or any(part.lower().startswith(".env") or part.lower() in (".ssh", ".aws", ".git", ".bap", ".bapstate") for part in report.relative_to(workspace).parts):
        parser.error("Report must be inside the workspace, outside private/configuration directories")
    if report.exists():
        parser.error("Report already exists; use a new --report path")
    if report.suffix.lower() != ".json":
        parser.error("Use a .json report filename")
    edge = args.edge or shutil.which("bapedge")
    if not edge:
        parser.error("bapedge is not on PATH; run bap install and reopen your terminal")
    edge = shutil.which(edge) or str(Path(edge).resolve())
    if not Path(edge).is_file():
        parser.error("Installed bapedge executable does not exist")
    result = Demo(edge, workspace, args.client, args.interactive, args.sibling).run()
    result["edge_sha256"] = hashlib.sha256(Path(edge).read_bytes()).hexdigest()
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print("\n{}\nReport: {}".format(result["result"], report))
    print("Complete the native-client and service scenes in DEMO_CLAUDE_CODEX_ZERO_TRUST.md.")
    return 1 if result["result"] == "FAIL" else 0


if __name__ == "__main__":
    raise SystemExit(main())

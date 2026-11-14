"""Collect sanitized, reproducible pilot evidence; never infer manual acceptance from smoke."""
import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
import re

CASES = (
    "smoke", "release_provenance", "native_hooks", "workday", "long_job",
    "logon_recovery", "crash_recovery", "central_delivery", "recommendation",
    "freeze_isolation", "offline_replay", "redeploy", "privacy", "native_boundaries",
    "rollback", "roster",
)
PRIVATE_KEYS = {"session_token", "access_token", "refresh_token", "authorization", "password",
                "private_key", "user_prompt", "prompt_text", "agent_response", "full_command"}


def utc_now():
    return datetime.now(timezone.utc).isoformat()


def safe_path(value):
    path = Path(value).resolve()
    lowered = [part.lower() for part in path.parts]
    if any(part in {".ssh", ".aws", ".gnupg"} or part == ".env" or part.startswith(".env.")
           or "credential" in part or part.startswith("id_rsa") for part in lowered):
        raise ValueError("Credential and private configuration paths are not evidence inputs")
    return path


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reject_private(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key.lower() in PRIVATE_KEYS and child not in (None, "", False):
                raise ValueError("Evidence contains private payload fields; provide sanitized metadata")
            reject_private(child)
    elif isinstance(value, list):
        for child in value:
            reject_private(child)


def load_json(value):
    path = safe_path(value)
    if path.suffix.lower() != ".json" or path.stat().st_size > 4 * 1024 * 1024:
        raise ValueError("Provide a sanitized JSON report under 4 MiB")
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    reject_private(data)
    return path, data


def parse_time(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Evidence timestamps require a UTC offset")
    return parsed.astimezone(timezone.utc)


def reconcile(report):
    """Recheck evidence hashes each time; changed/missing evidence invalidates its case."""
    for name in CASES:
        check = report["checks"].get(name)
        if not check or check["result"] != "PASS":
            continue
        for reference in check.get("evidence", []):
            path = safe_path(reference["path"])
            if not path.is_file() or digest(path) != reference["sha256"]:
                check["result"] = "FAIL"
                check["note"] = "Evidence missing or changed; repeat and record this check"
        if not check.get("evidence"):
            check["result"] = "FAIL"
    report["result"] = "QUALIFICATION_RECORDED" if all(
        report["checks"].get(name, {}).get("result") == "PASS" for name in CASES
    ) else "NOT_READY"
    # This records operator assertions and source hashes, not an independent certification.
    report["updated_at"] = utc_now()
    return report


def write_report(path, report):
    path = safe_path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    reconcile(report)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)
    lines = ["# Pilot confidence evidence", "", f"Result: **{report['result']}**", "",
             f"Release: `{report['release_commit']}` · Machine: `{report['machine']}`", "",
             "Manual results are operator attestations. Check evidence IDs against the live service.", "",
             "| Case | Result | Evidence files |", "|---|---|---|"]
    for name in CASES:
        check = report["checks"][name]
        lines.append(f"| {name} | {check['result']} | {len(check.get('evidence', []))} |")
    path.with_suffix(".md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def initialize(args):
    path, smoke = load_json(args.smoke)
    if not re.fullmatch(r"[0-9a-fA-F]{7,40}", args.release_commit):
        raise ValueError("Provide the approved release's Git commit (7–40 hex characters)")
    if safe_path(args.output).exists():
        raise ValueError("Evidence bundle already exists; choose a new run path")
    report = {"schema_version": 1, "created_at": utc_now(), "release_commit": args.release_commit,
              "machine": args.machine, "operator": args.operator,
              "scope": "One Windows workstation and its explicitly qualified native client",
              "run_id": smoke.get("run_id"), "edge_sha256": smoke.get("edge_sha256"),
              "checks": {name: {"result": "NOT_TESTED", "evidence": []} for name in CASES}}
    checks = smoke.get("checks", [])
    claimed_commit = smoke.get("operator_build_commit", "")
    good = (smoke.get("result") == "AUTOMATED_SMOKE_PASS" and bool(checks)
            and all(check.get("passed") is True for check in checks)
            and re.fullmatch(r"[0-9a-f]{64}", smoke.get("edge_sha256", ""))
            and bool(claimed_commit) and (args.release_commit.startswith(claimed_commit)
                                         or claimed_commit.startswith(args.release_commit)))
    report["checks"]["smoke"] = {"result": "PASS" if good else "FAIL", "basis": "installed_smoke",
        "evidence": [{"path": str(path), "sha256": digest(path)}],
        "note": "Local smoke and exact-session check only; central event reconciliation is a separate case"}
    write_report(args.output, report)


def record(args):
    _, report = load_json(args.bundle)
    if report.get("schema_version") != 1 or not all(name in report.get("checks", {}) for name in CASES):
        raise ValueError("Unsupported or incomplete evidence bundle")
    references = []
    for value in args.evidence:
        path, _ = load_json(value)
        if path == safe_path(args.bundle):
            raise ValueError("A bundle cannot serve as its own evidence")
        references.append({"path": str(path), "sha256": digest(path)})
    if args.result == "PASS" and (not references or not args.session_id or not args.event_id):
        raise ValueError("PASS requires a sanitized evidence file and the observed session/event or receipt IDs")
    times = {key: value for key, value in {"action": args.action_time, "central_receipt": args.central_time,
                                          "browser_visible": args.browser_time}.items() if value}
    ordered = [parse_time(times[key]) for key in ("action", "central_receipt", "browser_visible") if key in times]
    if ordered != sorted(ordered):
        raise ValueError("Action, central receipt and browser visibility timestamps must be ordered")
    if args.case == "central_delivery" and args.result == "PASS" and len(times) != 3:
        raise ValueError("Central delivery requires all three separately observed timestamps")
    report["checks"][args.case] = {"result": args.result, "basis": "operator_attested",
        "operator": args.operator, "recorded_at": utc_now(), "session_id": args.session_id,
        "event_ids": args.event_id, "timestamps": times, "note": args.note, "evidence": references}
    write_report(args.bundle, report)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    init = commands.add_parser("init")
    for name in ("smoke", "release-commit", "machine", "operator", "output"):
        init.add_argument("--" + name, required=True)
    entry = commands.add_parser("record")
    entry.add_argument("--bundle", required=True)
    entry.add_argument("--case", choices=CASES[1:], required=True)
    entry.add_argument("--result", choices=("PASS", "FAIL", "NOT_TESTED"), required=True)
    entry.add_argument("--operator", required=True)
    entry.add_argument("--evidence", action="append", default=[])
    entry.add_argument("--event-id", action="append", default=[])
    entry.add_argument("--session-id", default="")
    entry.add_argument("--note", default="")
    for name in ("action-time", "central-time", "browser-time"):
        entry.add_argument("--" + name)
    show = commands.add_parser("report")
    show.add_argument("--bundle", required=True)
    args = parser.parse_args()
    try:
        if args.command == "init":
            initialize(args)
        elif args.command == "record":
            record(args)
        else:
            _, report = load_json(args.bundle)
            write_report(args.bundle, report)
        _, report = load_json(args.output if args.command == "init" else args.bundle)
        print(report["result"])
        return 0 if args.command != "report" or report["result"] == "QUALIFICATION_RECORDED" else 1
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(2, f"Evidence error: {error}\n")


if __name__ == "__main__":
    raise SystemExit(main())

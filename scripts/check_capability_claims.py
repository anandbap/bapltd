"""Keep implementation claims qualified against the checked-in capability matrix."""
import argparse
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DOCS = ["README.md", "ARCHITECTURE.md", "docs/PILOT_RUNBOOK.md",
                "DEMO_CLAUDE.md", "DEMO_CLAUDE_CODEX_ZERO_TRUST.md"]


def check_text(text, matrix):
    errors = []
    for number, line in enumerate(text.splitlines(), 1):
        for feature in matrix["features"]:
            for match in re.finditer(feature["pattern"], line, re.I):
                suffix = line[match.end():]
                required = " (" + feature["qualifier"] + ")"
                if not suffix.startswith(required):
                    errors.append(f"{number}: {feature['name']} must be qualified as {feature['status']}")
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", default=DEFAULT_DOCS)
    args = parser.parse_args()
    matrix = json.loads((ROOT / "docs/capability-matrix.json").read_text(encoding="utf-8"))
    errors = []
    for name in args.paths:
        path = Path(name)
        if not path.is_absolute():
            path = ROOT / path
        errors.extend(f"{name}:{e}" for e in check_text(path.read_text(encoding="utf-8"), matrix))
    if errors:
        print("\n".join(errors))
        return 1
    print(f"Capability claims checked in {len(args.paths)} documents.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

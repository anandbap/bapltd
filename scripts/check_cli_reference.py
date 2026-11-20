"""Check documented edge commands and core governance parser options without running them."""
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]


def main():
    docs = (ROOT / "docs/CLI_REFERENCE.md").read_text(encoding="utf-8")
    source = (ROOT / "bap-edge/main.go").read_text(encoding="utf-8")
    dispatch = source.split("switch command {", 1)[1].split("func requiresEnrolledWorkstation", 1)[0]
    commands = [re.findall(r'"([^"]+)"', line)[0]
                for line in re.findall(r'^\s*case [^\n]+:', dispatch, re.M)]
    missing = []
    for command in commands:
        if command == "__shim":
            continue
        if not re.search(r'\bbap(?:edge)? ' + re.escape(command) + r'(?![\w-])', docs):
            missing.append("command: " + command)
    # These are the controls most likely to strand an operator when syntax drifts.
    for name in ("trust.go", "pin.go", "zsp.go", "zsp_autoapprove.go"):
        parser = (ROOT / "bap-edge/cmd" / name).read_text(encoding="utf-8")
        for option in set(re.findall(r'\bfs\.(?:String|Bool|Int|Duration)\("([^"]+)"', parser)):
            if "--" + option not in docs:
                missing.append(f"{name} option: --{option}")
        if name != "trust.go":
            prefix = "pin" if name == "pin.go" else "zsp autoapprove" if name == "zsp_autoapprove.go" else "zsp"
            for group in re.findall(r'^\tcase ([^\n]+):', parser, re.M):
                command = re.findall(r'"([^"]+)"', group)[0]
                if not re.search(r'\bbap(?:edge)? ' + re.escape(prefix + " " + command) + r'(?![\w-])', docs):
                    missing.append(f"subcommand: {prefix} {command}")
    if missing:
        print("CLI reference gaps:\n" + "\n".join("- " + item for item in sorted(set(missing))))
        return 1
    print(f"CLI reference covers {len(commands)-1} public edge commands and core trust/pin/ZSP parser options.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

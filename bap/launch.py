#!/usr/bin/env python3
"""
bap.launch module -- developer cockpit and launch runner entrypoint
"""

import os
import sys

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    script = os.path.join(root, "scripts", "bap_launch.py")
    if os.path.isfile(script):
        with open(script, "rb") as f:
            code = compile(f.read(), script, "exec")
            globs = {"__file__": script, "__name__": "__main__"}
            exec(code, globs)
    else:
        print(f"[!] Cannot locate bap_launch.py in {script}")
        sys.exit(1)

if __name__ == "__main__":
    main()

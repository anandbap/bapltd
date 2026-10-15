#!/usr/bin/env python3
"""
bap.install module -- single-click user-mode installer entrypoint
"""

import os
import sys

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    script = os.path.join(root, "scripts", "bap_install.py")
    if os.path.isfile(script):
        # Execute script with current sys.argv
        with open(script, "rb") as f:
            code = compile(f.read(), script, "exec")
            globs = {"__file__": script, "__name__": "__main__"}
            exec(code, globs)
    else:
        print(f"[!] Cannot locate bap_install.py in {script}")
        sys.exit(1)

if __name__ == "__main__":
    main()

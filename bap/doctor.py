#!/usr/bin/env python3
"""
bap.doctor module -- pre-flight environment & diagnostic health check entrypoint
"""

import os
import sys

def main():
    pkg_dir = os.path.dirname(__file__)
    root = os.path.abspath(os.path.join(pkg_dir, ".."))
    
    candidates = [
        os.path.join(pkg_dir, "bap_doctor.py"),
        os.path.join(root, "scripts", "bap_doctor.py"),
    ]
    
    target_script = None
    for c in candidates:
        if os.path.isfile(c):
            target_script = c
            break

    if target_script:
        with open(target_script, "rb") as f:
            code = compile(f.read(), target_script, "exec")
            globs = {"__file__": target_script, "__name__": "__main__"}
            exec(code, globs)
    else:
        print(f"[!] Cannot locate bap_doctor.py in package or repository.")
        sys.exit(1)

if __name__ == "__main__":
    main()

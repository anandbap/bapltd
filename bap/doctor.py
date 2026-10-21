#!/usr/bin/env python3
"""
bap.doctor module -- pre-flight environment & diagnostic health check entrypoint
"""

import os
import sys

def main():
    try:
        from .bap_doctor import main as doctor_main
        doctor_main()
        return
    except (ImportError, ModuleNotFoundError):
        pass

    pkg_dir = os.path.dirname(__file__)
    root = os.path.abspath(os.path.join(pkg_dir, ".."))
    candidates = [
        os.path.join(pkg_dir, "bap_doctor.py"),
        os.path.join(root, "scripts", "bap_doctor.py"),
        os.path.join(root, "bap", "bap_doctor.py"),
    ]
    target = None
    for c in candidates:
        if os.path.isfile(c):
            target = c
            break
    if target:
        with open(target, "rb") as f:
            code = compile(f.read(), target, "exec")
            globs = {"__file__": target, "__name__": "__main__"}
            exec(code, globs)
    else:
        print("[!] Cannot locate bap_doctor.py in package or repository.")
        sys.exit(1)

if __name__ == "__main__":
    main()

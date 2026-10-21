#!/usr/bin/env python3
"""
bap.install module -- single-click user-mode installer entrypoint
"""

import os
import sys

def main():
    try:
        from .bap_install import main as install_main
        install_main()
        return
    except (ImportError, ModuleNotFoundError):
        pass

    pkg_dir = os.path.dirname(__file__)
    root = os.path.abspath(os.path.join(pkg_dir, ".."))
    
    candidates = [
        os.path.join(pkg_dir, "bap_install.py"),
        os.path.join(root, "scripts", "bap_install.py"),
        os.path.join(root, "bap", "bap_install.py"),
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
        print("[!] Cannot locate bap_install.py in package or repository.")
        sys.exit(1)

if __name__ == "__main__":
    main()

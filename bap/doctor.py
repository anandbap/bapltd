#!/usr/bin/env python3
"""
bap.doctor module -- pre-flight environment & diagnostic health check entrypoint
"""

import os
import sys

def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    script = os.path.join(root, "scripts", "bap_doctor.py")
    if os.path.isfile(script):
        with open(script, "rb") as f:
            code = compile(f.read(), script, "exec")
            globs = {"__file__": script, "__name__": "__main__"}
            exec(code, globs)
    else:
        # Fallback to importing scripts directly if possible
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("bap_doctor", script)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mod.run_doctor()
        except Exception as e:
            print(f"[!] Cannot locate bap_doctor.py: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
bap.doctor module -- pre-flight environment & diagnostic health check entrypoint
"""

import sys

def main():
    # Keep package context so diagnostic helpers can import sibling modules.
    from .bap_doctor import run_doctor

    sys.exit(run_doctor())

if __name__ == "__main__":
    main()

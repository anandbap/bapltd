"""
bap.sdk - Direct re-export of BAP Python Agent SDK
"""

import sys
import os

# Ensure python-agent is in sys.path if not installed
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_py_agent = os.path.join(_root, "python-agent")
if os.path.isdir(_py_agent) and _py_agent not in sys.path:
    sys.path.insert(0, _py_agent)

try:
    from bap_sdk.client import *
    from bap_sdk import *
except ImportError:
    pass

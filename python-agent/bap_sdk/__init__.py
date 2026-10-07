"""
bap-sdk: Zero-dependency Python SDK for Bounded Authority Plane (BAP) governance.
Provides zero-trust policy enforcement, SPIFFE identity binding,
and live session observability for Python AI agents.
"""

from bap_sdk.client import (
    BAPSession,
    BAPHttpClient,
    BAPResponse,
    BAPExecResult,
    BAPPolicyViolation,
    resolve_endpoints,
    classify_intent,
    CANONICAL_INTENT_CATEGORIES,
    INTENT_CLASSIFIER_VERSION,
)

__version__ = "0.1.0"
__all__ = [
    "BAPSession",
    "BAPHttpClient",
    "BAPResponse",
    "BAPExecResult",
    "BAPPolicyViolation",
    "resolve_endpoints",
    "classify_intent",
    "CANONICAL_INTENT_CATEGORIES",
    "INTENT_CLASSIFIER_VERSION",
    "__version__",
]


# AXIAM SDK for Python
#
# This package provides the official Python client SDK for AXIAM
# (Access eXtended Identity and Authorization Management).
#
# See CONTRACT.md §1-§10 for the cross-language behavioral contract.
# Implementation follows across Phase 19 plans (Python SDK).
#
# NOTE: This module MUST remain importable with ONLY the runtime
# dependencies declared in [project.dependencies] (httpx, grpcio,
# aio-pika, pydantic, PyJWT). Do NOT import fastapi/django from here —
# those are optional extras (see [project.optional-dependencies]).

from axiam_sdk._client import AxiamClient
from axiam_sdk._errors import AuthError, AuthzError, NetworkError
from axiam_sdk._models import AccessCheck, AccessResult, BatchCheckResult, LoginResult, User

__version__ = "0.0.0"

__all__ = [
    "__version__",
    "AxiamClient",
    "LoginResult",
    "User",
    "AccessCheck",
    "AccessResult",
    "BatchCheckResult",
    "AuthError",
    "AuthzError",
    "NetworkError",
]

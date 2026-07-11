"""Official Python client SDK for AXIAM (Access eXtended Identity and
Authorization Management).

Re-exports the public surface: the sync :class:`AxiamClient` and async
:class:`AsyncAxiamClient` REST entry points, the ``AuthError``/``AuthzError``/
``NetworkError`` exception taxonomy (CONTRACT.md §2), and the request/response
models (``LoginResult``, ``User``, ``AccessCheck``, ``AccessResult``,
``BatchCheckResult``). See CONTRACT.md §1-§10 for the cross-language
behavioral contract this SDK conforms to.

This module MUST remain importable with ONLY the runtime dependencies
declared in ``[project.dependencies]`` (httpx, grpcio, aio-pika, pydantic,
PyJWT) — the optional web-framework integrations (``axiam_sdk.fastapi``,
``axiam_sdk.django``, see ``[project.optional-dependencies]``) MUST NOT be
imported from here.
"""

from axiam_sdk._async_client import AsyncAxiamClient
from axiam_sdk._client import AxiamClient
from axiam_sdk._errors import AuthError, AuthzError, NetworkError
from axiam_sdk._models import AccessCheck, AccessResult, BatchCheckResult, LoginResult, User

__version__ = "0.0.0"

__all__ = [
    "__version__",
    "AxiamClient",
    "AsyncAxiamClient",
    "LoginResult",
    "User",
    "AccessCheck",
    "AccessResult",
    "BatchCheckResult",
    "AuthError",
    "AuthzError",
    "NetworkError",
]

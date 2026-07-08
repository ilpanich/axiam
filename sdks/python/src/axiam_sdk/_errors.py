"""Exception taxonomy + redact-before-wrap error mapping (D-08, CR-04 carry-forward).

Central status -> error mapper (CONTRACT.md §2). This is the single source of
truth for both the REST and gRPC transports so the two cannot drift on the
error taxonomy — mirrors ``sdks/go/errors.go`` and
``sdks/typescript/src/core/errorMapper.ts``.

CRITICAL invariant (CR-04 carry-forward): ``NetworkError`` MUST redact
``Set-Cookie``/``Authorization``/``Cookie`` from any wrapped ``httpx``
request/response BEFORE it is ever stored as a cause. ``error_from_http_status``
is the SOLE constructor path that accepts an ``httpx.Response`` — it always
derives the wrapped cause from a sanitized copy of the response via
``_sanitize_response``, never from the raw response. Any caller-supplied
cause is ignored whenever a response is present, so a caller cannot smuggle
raw response data into the exception chain by pre-building a cause from an
unredacted response before calling this constructor. Never construct
``NetworkError`` directly from ``response.headers`` anywhere else.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import httpx


class AuthError(Exception):
    """Authentication failure: wrong credentials, expired session, MFA
    failure, or a 401 on refresh (CONTRACT.md §2)."""

    def __init__(self, message: str) -> None:
        super().__init__(f"authentication failed: {message}")
        self.message = message


class AuthzError(Exception):
    """Authorization failure: the caller is authenticated but lacks
    permission for the requested operation (CONTRACT.md §2). ``action``/
    ``resource_id`` are optional and populated when known from the response
    body."""

    def __init__(
        self,
        message: str,
        action: str | None = None,
        resource_id: str | None = None,
    ) -> None:
        super().__init__(f"authorization denied: {message}")
        self.message = message
        self.action = action
        self.resource_id = resource_id


class NetworkError(Exception):
    """Transport-level failure: connection refused, timeout, TLS error, DNS
    failure, or a server-side 5xx (CONTRACT.md §2).

    ``cause`` is set as ``__cause__`` for standard Python exception chaining
    (``raise ... from cause`` semantics). It MUST only ever be populated via
    ``error_from_http_status``/``error_from_grpc_status``, which redact
    sensitive headers from any wrapped ``httpx.Response`` BEFORE constructing
    this error (D-08, CR-04 carry-forward) — never construct this class
    directly from an unredacted response.
    """

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        super().__init__(f"network error: {message}")
        self.message = message
        self.__cause__ = cause


# X-3: response headers use an ALLOWLIST, not a denylist. Only these known-safe,
# non-secret headers may survive into a NetworkError's wrapped cause (D-08, CR-04
# carry-forward); everything else is redacted. A denylist of known-sensitive
# names (set-cookie/authorization/cookie) let a custom sensitive header such as
# ``X-Auth-Token`` slip through simply because it was not on the list. Keep this
# allowlist small and limited to diagnostic, non-credential headers:
#   - content-type / content-length: response shape, no secrets
#   - date / server: standard non-secret transport metadata
#   - x-request-id: trace correlation id (non-secret), aids debugging
_SAFE_RESPONSE_HEADERS = {
    "content-type",
    "content-length",
    "date",
    "server",
    "x-request-id",
}


def _sanitize_response(response: httpx.Response) -> str:
    """Redact all non-allowlisted headers BEFORE building any string
    representation that could end up in a NetworkError's cause (D-08, CR-04
    carry-forward, X-3).

    Never pass the raw ``httpx.Response`` (or its unredacted headers) into an
    exception. Only headers on :data:`_SAFE_RESPONSE_HEADERS` are kept — a
    non-sensitive header (e.g. ``x-request-id``) is preserved so the redaction
    can be proven selective, not blanket, in tests, while any header not on the
    allowlist (including custom credential headers like ``X-Auth-Token``) is
    dropped.
    """
    safe_headers = {
        k: v for k, v in response.headers.items() if k.lower() in _SAFE_RESPONSE_HEADERS
    }
    return f"http status {response.status_code}, headers: {safe_headers}"


_REDACTED = "[REDACTED]"

# Token/cookie-shaped substrings that must never survive into a gRPC-derived
# exception message (WR-01). The gRPC path has no structured headers to strip
# like the REST path's Set-Cookie/Authorization; ``status.details`` is a
# server-controlled free-text string, so we redact by pattern instead. These
# are hardcoded (non-dynamic) patterns — ReDoS-safe, no catastrophic
# backtracking — mirroring the REST path's redact-before-wrap guarantee so
# both transports uphold the same invariant from one source of truth.
_GRPC_REDACTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    # `Bearer <token>` (Authorization-style), case-insensitive scheme.
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+"),
    # `axiam_access=...` / `axiam_refresh=...` cookie material up to a
    # delimiter (whitespace, ';', or ',').
    re.compile(r"(?i)\baxiam_(?:access|refresh)=[^\s;,]+"),
    # Generic `Authorization: ...` / `Set-Cookie: ...` / `Cookie: ...`
    # header-shaped substrings, redacting the value after the colon.
    re.compile(r"(?i)\b(?:Authorization|Set-Cookie|Cookie)\s*:\s*[^\s;,]+"),
)


def _sanitize_grpc_message(message: str) -> str:
    """Redact token/cookie-shaped material from a gRPC status-details string
    BEFORE it is wrapped into an AxiamError (WR-01).

    ``error_from_grpc_status`` takes a caller-supplied ``message`` (both gRPC
    client call sites pass ``call.details()``, a server-controlled free-text
    string). Unlike the REST path — where ``_sanitize_response`` structurally
    strips sensitive headers — gRPC details have no structure, so a misbehaving
    or compromised backend that reflects a token into ``status.details`` would
    otherwise leak it into the exception's ``str()``/``repr()`` and any logs.
    This applies the same redact-before-wrap guarantee via pattern matching so
    both transports cannot drift on the redaction invariant.
    """
    redacted = message
    for pattern in _GRPC_REDACTION_PATTERNS:
        redacted = pattern.sub(_REDACTED, redacted)
    return redacted


def error_from_http_status(
    status: int,
    message: str,
    response: httpx.Response | None = None,
) -> Exception:
    """Map an HTTP status code to an AxiamError-family exception per
    CONTRACT.md §2's HTTP status table.

    | Status    | Type         |
    |-----------|--------------|
    | 400       | NetworkError |
    | 401       | AuthError    |
    | 403, 409  | AuthzError   |
    | 408, 429  | NetworkError |
    | 5xx       | NetworkError |
    | other     | NetworkError |

    ``message`` is caller-controlled and MUST NOT contain a raw token value.
    When ``response`` is provided, it is the SOLE source of the wrapped
    cause — any caller-supplied cause is intentionally not accepted by this
    signature, closing the redact-before-wrap bypass this taxonomy exists to
    prevent (mirrors ``sdks/go/errors.go::newNetworkError``'s documented
    invariant).
    """
    if status == 401:
        return AuthError(message)
    if status in (403, 409):
        return AuthzError(message)

    cause: BaseException | None = None
    if response is not None:
        cause = RuntimeError(_sanitize_response(response))
    return NetworkError(message, cause=cause)


def error_from_grpc_status(code: object, message: str) -> Exception:
    """Map a gRPC status code to an AxiamError-family exception per
    CONTRACT.md §2's gRPC status table.

    | Code                   | Type         |
    |------------------------|--------------|
    | UNAUTHENTICATED (16)   | AuthError    |
    | PERMISSION_DENIED (7)  | AuthzError   |
    | UNAVAILABLE (14)       | NetworkError |
    | DEADLINE_EXCEEDED (4)  | NetworkError |
    | INTERNAL (13)          | NetworkError |
    | RESOURCE_EXHAUSTED (8) | NetworkError |
    | other                  | NetworkError |

    ``message`` is caller-supplied (both gRPC call sites pass
    ``call.details()``, a server-controlled free-text string) — it is
    redacted here via :func:`_sanitize_grpc_message` BEFORE constructing any
    exception, mirroring the REST path's ``_sanitize_response`` redact-before-
    wrap guarantee (WR-01) so a token reflected into ``status.details`` cannot
    leak through an exception's ``str()``/``repr()`` or logs.
    ``code`` accepts either a ``grpc.StatusCode`` member or its bare name/int
    value so callers do not need to import ``grpc`` merely to classify an
    error (keeping this module import-cheap for REST-only consumers).
    """
    import grpc

    safe_message = _sanitize_grpc_message(message)

    normalized = code
    if not isinstance(code, grpc.StatusCode):
        for member in grpc.StatusCode:
            if member.value[0] == code or member.name == str(code):
                normalized = member
                break

    if normalized == grpc.StatusCode.UNAUTHENTICATED:
        return AuthError(safe_message)
    if normalized == grpc.StatusCode.PERMISSION_DENIED:
        return AuthzError(safe_message)
    return NetworkError(safe_message)

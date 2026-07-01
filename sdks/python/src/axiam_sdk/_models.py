"""Typed Pydantic v2 models (D-06/D-07/D-21).

Token-bearing fields use ``SecretStr`` (D-07) — it *is* the Python §7
``Sensitive`` type: it redacts its value in ``repr``/``str``/``model_dump``
and only exposes the raw value via ``.get_secret_value()``.
"""

from __future__ import annotations

from typing import Optional

from pydantic import BaseModel, SecretStr


class LoginResult(BaseModel):
    """Result of ``login()``/``async_login()`` (D-21).

    A single model with a literal ``mfa_required: bool`` field — the caller
    checks the flag, and if true, calls ``verify_mfa(mfa_token, code)``.

    ``mfa_token`` is the SDK's field-name for the server's wire-level
    ``challenge_token`` (``MfaRequiredResponse.challenge_token`` /
    ``MfaVerifyRequest.challenge_token`` in
    ``crates/axiam-api-rest/src/handlers/auth.rs``) — a snake_case-preserving
    rename matching this SDK's ``verify_mfa(mfa_token, code)`` signature.
    """

    mfa_required: bool
    mfa_token: Optional[SecretStr] = None
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None
    expires_in: Optional[int] = None

    model_config = {"frozen": True}


class User(BaseModel):
    """An authenticated identity, as returned by ``GET /api/v1/auth/me`` or
    resolved locally from a verified JWT's claims."""

    user_id: str
    tenant_id: str
    username: Optional[str] = None
    email: Optional[str] = None
    permissions: list[str] = []

    model_config = {"frozen": True}


class AccessCheck(BaseModel):
    """A single authorization check request (``check_access``/``can``)."""

    action: str
    resource_id: str
    scope: Optional[str] = None

    model_config = {"frozen": True}


class AccessResult(BaseModel):
    """The result of a single authorization check."""

    allowed: bool
    reason: Optional[str] = None

    model_config = {"frozen": True}


class BatchCheckResult(BaseModel):
    """The result of a batch authorization check (``batch_check``) — one
    ``AccessResult`` per input ``AccessCheck``, in the same order."""

    results: list[AccessResult]

    model_config = {"frozen": True}

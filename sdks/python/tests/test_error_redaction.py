"""Regression tests for the exception taxonomy (D-08) and LoginResult
redaction (D-07/D-21).

Mirrors ``sdks/typescript/test`` intent (CR-04 carry-forward): the raw
``axiam_access``/``axiam_refresh`` cookie value must never appear in
``repr``/``str``/``repr(__cause__)`` of a raised ``NetworkError``, and a
non-sensitive header value MUST survive redaction — proving the test is
non-vacuous (redaction is selective, not blanket).
"""

from __future__ import annotations

import httpx

from axiam_sdk._errors import (
    AuthError,
    AuthzError,
    NetworkError,
    error_from_grpc_status,
    error_from_http_status,
)
from axiam_sdk._models import LoginResult


def _response(status: int, headers: dict[str, str]) -> httpx.Response:
    return httpx.Response(
        status,
        headers=headers,
        request=httpx.Request("POST", "https://example.test/api/v1/auth/refresh"),
    )


class TestErrorFromHttpStatus:
    def test_401_maps_to_auth_error(self) -> None:
        err = error_from_http_status(401, "bad credentials")
        assert isinstance(err, AuthError)

    def test_403_maps_to_authz_error(self) -> None:
        err = error_from_http_status(403, "forbidden")
        assert isinstance(err, AuthzError)

    def test_409_maps_to_authz_error(self) -> None:
        err = error_from_http_status(409, "conflict")
        assert isinstance(err, AuthzError)

    def test_other_status_maps_to_network_error(self) -> None:
        for status in (400, 408, 429, 500, 503):
            err = error_from_http_status(status, "x")
            assert isinstance(err, NetworkError), f"status {status} should map to NetworkError"


class TestErrorFromGrpcStatus:
    def test_unauthenticated_maps_to_auth_error(self) -> None:
        import grpc

        err = error_from_grpc_status(grpc.StatusCode.UNAUTHENTICATED, "no creds")
        assert isinstance(err, AuthError)

    def test_permission_denied_maps_to_authz_error(self) -> None:
        import grpc

        err = error_from_grpc_status(grpc.StatusCode.PERMISSION_DENIED, "denied")
        assert isinstance(err, AuthzError)

    def test_other_codes_map_to_network_error(self) -> None:
        import grpc

        for code in (
            grpc.StatusCode.UNAVAILABLE,
            grpc.StatusCode.DEADLINE_EXCEEDED,
            grpc.StatusCode.INTERNAL,
            grpc.StatusCode.RESOURCE_EXHAUSTED,
        ):
            err = error_from_grpc_status(code, "x")
            assert isinstance(err, NetworkError)


class TestGrpcErrorRedaction:
    """WR-01: the gRPC error path must redact token/cookie-shaped material
    from ``status.details`` before wrapping it into an exception, mirroring
    the REST path's ``_sanitize_response`` redact-before-wrap guarantee — a
    misbehaving/compromised backend reflecting a token into ``status.details``
    must not leak it into the exception's ``str()``/``repr()``.
    """

    def test_bearer_token_in_grpc_details_is_redacted(self) -> None:
        import grpc

        raw_token = "SEKRIT-grpc-bearer-token-value"
        details = f"upstream rejected credentials: Bearer {raw_token}"

        err = error_from_grpc_status(grpc.StatusCode.UNAUTHENTICATED, details)

        assert isinstance(err, AuthError)
        assert raw_token not in repr(err)
        assert raw_token not in str(err)

    def test_axiam_cookie_material_in_grpc_details_is_redacted(self) -> None:
        import grpc

        raw_access = "SEKRIT-access-cookie-value"
        raw_refresh = "SEKRIT-refresh-cookie-value"
        details = f"debug echo: axiam_access={raw_access}; axiam_refresh={raw_refresh}"

        err = error_from_grpc_status(grpc.StatusCode.INTERNAL, details)

        assert isinstance(err, NetworkError)
        assert raw_access not in repr(err)
        assert raw_access not in str(err)
        assert raw_refresh not in repr(err)
        assert raw_refresh not in str(err)

    def test_authorization_header_shaped_details_is_redacted(self) -> None:
        import grpc

        raw = "SEKRIT-header-value"
        details = f"reflected trailer Authorization: {raw}"

        err = error_from_grpc_status(grpc.StatusCode.PERMISSION_DENIED, details)

        assert isinstance(err, AuthzError)
        assert raw not in repr(err)
        assert raw not in str(err)

    def test_grpc_redaction_is_non_vacuous(self) -> None:
        """Control case: non-sensitive details survive, proving redaction is
        selective (not blanket) and the tests above aren't vacuously passing
        because ALL message content is dropped."""
        import grpc

        details = "resource temporarily unavailable (trace-id abc-123)"
        err = error_from_grpc_status(grpc.StatusCode.UNAVAILABLE, details)
        assert "resource temporarily unavailable" in str(err)
        assert "abc-123" in str(err)


class TestNetworkErrorRedaction:
    def test_network_error_never_leaks_set_cookie_with_raw_tokens(self) -> None:
        raw_access_secret = "SEKRIT-access-token-value-should-never-leak"
        response = _response(
            503,
            {
                "set-cookie": f"axiam_access={raw_access_secret}; HttpOnly",
                "content-type": "application/json",
            },
        )

        err = error_from_http_status(503, "unavailable", response=response)

        assert isinstance(err, NetworkError)
        assert raw_access_secret not in repr(err)
        assert raw_access_secret not in str(err)
        assert err.__cause__ is not None
        assert raw_access_secret not in repr(err.__cause__)
        assert raw_access_secret not in str(err.__cause__)

    def test_network_error_never_leaks_authorization_header(self) -> None:
        raw_refresh_secret = "SEKRIT-refresh-bearer-value"
        response = _response(
            500,
            {
                "authorization": f"Bearer {raw_refresh_secret}",
                "cookie": f"axiam_refresh={raw_refresh_secret}",
            },
        )

        err = error_from_http_status(500, "server error", response=response)

        assert raw_refresh_secret not in repr(err)
        assert raw_refresh_secret not in repr(err.__cause__)

    def test_network_error_redacts_custom_sensitive_header_allowlist(self) -> None:
        """X-3: header redaction is an ALLOWLIST, not a denylist — a custom
        sensitive header (e.g. ``X-Auth-Token``) that is NOT on the small
        legacy denylist must still be redacted because it is not on the
        known-safe allowlist."""
        raw_custom_secret = "SEKRIT-x-auth-token-value-should-never-leak"
        response = _response(
            502,
            {
                "x-auth-token": raw_custom_secret,
                "x-api-key": "SEKRIT-api-key-should-never-leak",
                "content-type": "application/json",
            },
        )

        err = error_from_http_status(502, "bad gateway", response=response)

        assert isinstance(err, NetworkError)
        assert raw_custom_secret not in repr(err)
        assert raw_custom_secret not in repr(err.__cause__)
        assert "SEKRIT-api-key-should-never-leak" not in repr(err.__cause__)

    def test_network_error_redaction_is_non_vacuous(self) -> None:
        """Control case: prove the tests above aren't vacuously passing
        because NO header content ever appears — assert a NON-sensitive
        header value DOES survive, so redaction is selective, not blanket.
        """
        response = _response(
            503,
            {"x-request-id": "trace-abc-123", "content-type": "application/json"},
        )
        err = error_from_http_status(503, "unavailable", response=response)
        assert "trace-abc-123" in repr(err.__cause__)

    def test_401_and_403_never_construct_network_error_from_response(self) -> None:
        """401/403 map to AuthError/AuthzError, which never carry a response
        cause at all — no response data can leak through those paths."""
        response = _response(401, {"set-cookie": "axiam_access=SEKRIT"})
        err = error_from_http_status(401, "bad creds", response=response)
        assert isinstance(err, AuthError)
        assert "SEKRIT" not in repr(err)
        assert not hasattr(err, "cause")


class TestLoginResultRedaction:
    def test_mfa_token_redacted_in_repr(self) -> None:
        result = LoginResult(mfa_required=True, mfa_token="secret-token")
        assert "secret-token" not in repr(result)

    def test_mfa_token_redacted_in_model_dump(self) -> None:
        result = LoginResult(mfa_required=True, mfa_token="secret-token")
        assert "secret-token" not in str(result.model_dump())

    def test_mfa_token_accessible_via_get_secret_value(self) -> None:
        result = LoginResult(mfa_required=True, mfa_token="secret-token")
        assert result.mfa_token is not None
        assert result.mfa_token.get_secret_value() == "secret-token"

    def test_login_result_without_mfa_token(self) -> None:
        result = LoginResult(mfa_required=False, user_id="u1", tenant_id="t1")
        assert result.mfa_token is None
        assert result.mfa_required is False

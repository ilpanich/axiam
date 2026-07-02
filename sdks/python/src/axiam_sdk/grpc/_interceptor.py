"""Sync + async auth/tenant metadata interceptors (D-12, CONTRACT.md §5/§6).

Mirrors ``sdks/go/grpc/interceptor.go``'s non-blocking ``TokenFunc`` pattern,
adapted for Python's dual sync (``grpcio``) + async (``grpc.aio``) interceptor
base classes — these are DIFFERENT classes in ``grpc``'s API surface, so two
concrete interceptor classes are required, sharing one metadata-building
mixin.

CRITICAL invariant (mirrors the Go doc comment verbatim): ``token_fn`` is
read synchronously on every intercepted call and MUST be a non-blocking
cache read (backed by ``RefreshGuard.cached_access_token()``, 19-02) — this
closure runs on the hot RPC path and must NEVER touch the single-flight
refresh mutex directly (T-19-13).

Class names are deliberately generic (``SyncAuthInterceptor`` /
``AsyncAuthInterceptor``, not ``UnaryAuthInterceptor``) so no rename is
needed if streaming RPCs are added post-v1.0-beta — PY-01's scope
(``CheckAccess``/``BatchCheckAccess``) is unary-unary only.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, TypeVar

import grpc
import grpc.aio

if TYPE_CHECKING:
    from grpc import ClientCallDetails as SyncClientCallDetails
    from grpc.aio import ClientCallDetails as AioClientCallDetails
    from grpc.aio import UnaryUnaryCall

_TRequest = TypeVar("_TRequest")
_TResponse = TypeVar("_TResponse")


class _AuthMetadataMixin:
    """Shared metadata-building logic for both interceptor variants.

    ``token_fn`` is invoked as a plain, synchronous, non-blocking callable —
    never awaited, never gated behind a lock. It returns the currently
    cached access token, or ``None``/empty when no token has been cached yet
    (caller has not logged in, or a refresh has not yet completed).
    """

    def __init__(self, token_fn: Callable[[], str | None], tenant_id: str) -> None:
        self._token_fn = token_fn
        self._tenant_id = tenant_id

    def _build_metadata(self, existing: Any) -> list[tuple[str, str]]:
        """Append Bearer authorization (when a token is cached) and
        ``x-tenant-id`` metadata (always) to ``existing`` (CONTRACT.md §5).

        ``existing`` accepts whatever iterable-of-pairs shape the sync
        (plain tuple) and async (``grpc.aio.Metadata``) call-details expose —
        both are simply iterated and copied into a fresh list.
        """
        metadata: list[tuple[str, str]] = list(existing) if existing else []
        token = self._token_fn()
        if token:
            metadata.append(("authorization", f"Bearer {token}"))
        metadata.append(("x-tenant-id", self._tenant_id))
        return metadata


class SyncAuthInterceptor(_AuthMetadataMixin, grpc.UnaryUnaryClientInterceptor):
    """Sync (``grpcio``) auth/tenant metadata interceptor.

    ``intercept_unary_unary`` is a plain synchronous method — ``grpc``'s
    sync interceptor contract calls ``continuation`` synchronously, no
    ``await`` involved.
    """

    def intercept_unary_unary(
        self,
        continuation: Callable[[SyncClientCallDetails, _TRequest], Any],
        client_call_details: SyncClientCallDetails,
        request: _TRequest,
    ) -> Any:
        new_details = client_call_details._replace(  # type: ignore[attr-defined]
            metadata=self._build_metadata(client_call_details.metadata)
        )
        return continuation(new_details, request)


class AsyncAuthInterceptor(_AuthMetadataMixin, grpc.aio.UnaryUnaryClientInterceptor):
    """Async (``grpc.aio``) auth/tenant metadata interceptor.

    ``intercept_unary_unary`` MUST be ``async def`` and MUST ``await`` its
    ``continuation`` — this is the key ``grpc.aio``-specific divergence from
    the sync interceptor above, which calls ``continuation`` synchronously.
    """

    async def intercept_unary_unary(
        self,
        continuation: Callable[
            [AioClientCallDetails, _TRequest], Awaitable[UnaryUnaryCall[_TRequest, _TResponse]]
        ],
        client_call_details: AioClientCallDetails,
        request: _TRequest,
    ) -> _TResponse | UnaryUnaryCall[_TRequest, _TResponse]:
        new_details = client_call_details._replace(  # type: ignore[attr-defined]
            metadata=self._build_metadata(client_call_details.metadata)
        )
        return await continuation(new_details, request)

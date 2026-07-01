"""Sync + async gRPC authorization clients (D-12, CONTRACT.md §1/§6/§9).

``AuthzGrpcClient`` (sync, ``grpcio``) and ``AsyncAuthzGrpcClient`` (async,
``grpc.aio``) both perform ``CheckAccess``/``BatchCheckAccess`` over a
strict-TLS channel (``_tls.build_channel_credentials``), with a sync-safe
auth/tenant interceptor (``_interceptor.py``) and exactly-once
UNAUTHENTICATED refresh-and-retry (§9.3) via a caller-supplied refresh
closure — this module never imports ``axiam_sdk._client`` (no import cycle,
mirrors ``sdks/go/grpc/client.go``'s ``RefreshFunc`` decoupling).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import cast

import grpc
import grpc.aio

from axiam_sdk._errors import error_from_grpc_status
from axiam_sdk._models import AccessResult
from axiam_sdk.grpc._interceptor import AsyncAuthInterceptor, SyncAuthInterceptor
from axiam_sdk.grpc._tls import build_channel_credentials
from axiam_sdk.grpc.gen import authorization_pb2, authorization_pb2_grpc

# Sync refresh_fn: a zero-arg callable that performs the caller-owned
# single-flight refresh (§9) and returns once a fresh access token is
# cached. May be None, in which case UNAUTHENTICATED errors are mapped and
# returned immediately without a retry.
SyncRefreshFn = Callable[[], None]
# Async twin of SyncRefreshFn.
AsyncRefreshFn = Callable[[], Awaitable[None]]


def _to_wire(
    subject_id: str, action: str, resource_id: str, tenant_id: str, scope: str | None
) -> authorization_pb2.CheckAccessRequest:
    wire = authorization_pb2.CheckAccessRequest(
        tenant_id=tenant_id,
        subject_id=subject_id,
        action=action,
        resource_id=resource_id,
    )
    if scope is not None:
        wire.scope = scope
    return wire


class AuthzGrpcClient:
    """Sync (``grpcio``) authorization client for ``CheckAccess``/
    ``BatchCheckAccess`` (CONTRACT.md §1).
    """

    def __init__(
        self,
        target: str,
        *,
        token_fn: Callable[[], str | None],
        tenant_id: str,
        refresh_fn: SyncRefreshFn | None = None,
        custom_ca: str | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._refresh_fn = refresh_fn

        credentials = build_channel_credentials(custom_ca)
        interceptor = SyncAuthInterceptor(token_fn=token_fn, tenant_id=tenant_id)
        channel = grpc.secure_channel(target, credentials)
        self._channel = grpc.intercept_channel(channel, interceptor)
        # authorization_pb2_grpc.py is generated code with no .pyi stub for
        # the service stub class (only the message types in
        # authorization_pb2.pyi are typed) — pre-existing gap from 19-01's
        # codegen, out of this plan's file scope.
        self._stub = authorization_pb2_grpc.AuthorizationServiceStub(  # type: ignore[no-untyped-call]
            self._channel
        )

    def close(self) -> None:
        self._channel.close()

    def check_access(
        self, subject_id: str, action: str, resource_id: str, scope: str | None = None
    ) -> AccessResult:
        """``CheckAccess`` (CONTRACT.md §1). On UNAUTHENTICATED, invokes the
        caller-supplied ``refresh_fn`` exactly once then retries the RPC
        exactly once (§9.3) — a second failure maps via
        ``error_from_grpc_status``."""
        wire = _to_wire(subject_id, action, resource_id, self._tenant_id, scope)
        try:
            response = self._stub.CheckAccess(wire)
        except grpc.RpcError as exc:
            response = self._retry_after_refresh(exc, lambda: self._stub.CheckAccess(wire))
        return AccessResult(allowed=response.allowed, reason=response.deny_reason or None)

    def batch_check(self, checks: list[tuple[str, str, str, str | None]]) -> list[AccessResult]:
        """``BatchCheckAccess`` (CONTRACT.md §1). ``checks`` is a list of
        ``(subject_id, action, resource_id, scope)`` tuples; results are
        returned in the same order. Shares the same UNAUTHENTICATED
        single-flight-retry behavior as :meth:`check_access`."""
        wire = authorization_pb2.BatchCheckAccessRequest(
            requests=[
                _to_wire(subject_id, action, resource_id, self._tenant_id, scope)
                for subject_id, action, resource_id, scope in checks
            ]
        )
        try:
            response = self._stub.BatchCheckAccess(wire)
        except grpc.RpcError as exc:
            response = self._retry_after_refresh(exc, lambda: self._stub.BatchCheckAccess(wire))
        return [
            AccessResult(allowed=result.allowed, reason=result.deny_reason or None)
            for result in response.results
        ]

    def _retry_after_refresh(self, exc: grpc.RpcError, retry: Callable[[], object]) -> object:
        call = cast(grpc.Call, exc)
        if self._refresh_fn is not None and call.code() == grpc.StatusCode.UNAUTHENTICATED:
            self._refresh_fn()
            try:
                return retry()
            except grpc.RpcError as retry_exc:
                raise self._map_error(retry_exc) from retry_exc
        raise self._map_error(exc) from exc

    def _map_error(self, exc: grpc.RpcError) -> Exception:
        call = cast(grpc.Call, exc)
        return error_from_grpc_status(call.code(), call.details() or "gRPC call failed")


class AsyncAuthzGrpcClient:
    """Async (``grpc.aio``) authorization client for ``CheckAccess``/
    ``BatchCheckAccess`` (CONTRACT.md §1) — a first-class async transport,
    not a thread-pool bridge over the sync client (D-12).
    """

    def __init__(
        self,
        target: str,
        *,
        token_fn: Callable[[], str | None],
        tenant_id: str,
        refresh_fn: AsyncRefreshFn | None = None,
        custom_ca: str | None = None,
    ) -> None:
        self._tenant_id = tenant_id
        self._refresh_fn = refresh_fn

        credentials = build_channel_credentials(custom_ca)
        interceptor = AsyncAuthInterceptor(token_fn=token_fn, tenant_id=tenant_id)
        self._channel = grpc.aio.secure_channel(target, credentials, interceptors=[interceptor])
        self._stub = authorization_pb2_grpc.AuthorizationServiceStub(  # type: ignore[no-untyped-call]
            self._channel
        )

    async def close(self) -> None:
        await self._channel.close()

    async def check_access(
        self, subject_id: str, action: str, resource_id: str, scope: str | None = None
    ) -> AccessResult:
        """Async twin of :meth:`AuthzGrpcClient.check_access`."""
        wire = _to_wire(subject_id, action, resource_id, self._tenant_id, scope)
        try:
            response = await self._stub.CheckAccess(wire)
        except grpc.RpcError as exc:
            response = await self._retry_after_refresh(exc, lambda: self._stub.CheckAccess(wire))
        return AccessResult(allowed=response.allowed, reason=response.deny_reason or None)

    async def batch_check(
        self, checks: list[tuple[str, str, str, str | None]]
    ) -> list[AccessResult]:
        """Async twin of :meth:`AuthzGrpcClient.batch_check`."""
        wire = authorization_pb2.BatchCheckAccessRequest(
            requests=[
                _to_wire(subject_id, action, resource_id, self._tenant_id, scope)
                for subject_id, action, resource_id, scope in checks
            ]
        )
        try:
            response = await self._stub.BatchCheckAccess(wire)
        except grpc.RpcError as exc:
            response = await self._retry_after_refresh(
                exc, lambda: self._stub.BatchCheckAccess(wire)
            )
        return [
            AccessResult(allowed=result.allowed, reason=result.deny_reason or None)
            for result in response.results
        ]

    async def _retry_after_refresh(
        self, exc: grpc.RpcError, retry: Callable[[], Awaitable[object]]
    ) -> object:
        aio_exc = cast(grpc.aio.AioRpcError, exc)
        if self._refresh_fn is not None and aio_exc.code() == grpc.StatusCode.UNAUTHENTICATED:
            await self._refresh_fn()
            try:
                return await retry()
            except grpc.RpcError as retry_exc:
                raise self._map_error(retry_exc) from retry_exc
        raise self._map_error(exc) from exc

    def _map_error(self, exc: grpc.RpcError) -> Exception:
        aio_exc = cast(grpc.aio.AioRpcError, exc)
        return error_from_grpc_status(aio_exc.code(), aio_exc.details() or "gRPC call failed")

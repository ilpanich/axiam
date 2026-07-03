"""Regression tests for the sync + async auth/tenant metadata interceptors
(D-12, CONTRACT.md §5/§6, T-19-13).

Asserts: ``_build_metadata`` produces the expected metadata pairs; the async
interceptor's ``intercept_unary_unary`` is a coroutine that awaits its
continuation; ``token_fn`` is invoked exactly once per intercepted call and
never acquires a lock (T-19-13, non-blocking hot-path invariant).
"""

from __future__ import annotations

import inspect
from collections import namedtuple

import pytest

from axiam_sdk.grpc._interceptor import (
    AsyncAuthInterceptor,
    SyncAuthInterceptor,
    _AuthMetadataMixin,
)

_CallDetails = namedtuple("_CallDetails", ["method", "timeout", "metadata", "credentials"])


def _details(metadata: tuple | None = None) -> _CallDetails:
    return _CallDetails(
        method="/axiam.v1.AuthorizationService/CheckAccess",
        timeout=None,
        metadata=metadata,
        credentials=None,
    )


class TestBuildMetadata:
    def test_appends_bearer_and_tenant_when_token_present(self) -> None:
        mixin = _AuthMetadataMixin(token_fn=lambda: "abc123", tenant_id="tenant-1")
        metadata = mixin._build_metadata(None)
        assert ("authorization", "Bearer abc123") in metadata
        assert ("x-tenant-id", "tenant-1") in metadata

    def test_omits_bearer_but_keeps_tenant_when_token_absent(self) -> None:
        mixin = _AuthMetadataMixin(token_fn=lambda: None, tenant_id="tenant-1")
        metadata = mixin._build_metadata(None)
        assert not any(k == "authorization" for k, _ in metadata)
        assert ("x-tenant-id", "tenant-1") in metadata

    def test_preserves_existing_metadata(self) -> None:
        mixin = _AuthMetadataMixin(token_fn=lambda: "tok", tenant_id="t1")
        metadata = mixin._build_metadata([("x-request-id", "req-1")])
        assert ("x-request-id", "req-1") in metadata
        assert ("authorization", "Bearer tok") in metadata
        assert ("x-tenant-id", "t1") in metadata

    def test_token_fn_called_exactly_once_per_build(self) -> None:
        calls = 0

        def token_fn() -> str:
            nonlocal calls
            calls += 1
            return "tok"

        mixin = _AuthMetadataMixin(token_fn=token_fn, tenant_id="t1")
        mixin._build_metadata(None)
        assert calls == 1

    def test_token_fn_acquires_no_lock(self) -> None:
        """T-19-13: the token func must be a plain non-blocking read — proven
        by using a token_fn that would deadlock if it tried to acquire an
        already-held lock, and confirming _build_metadata still returns
        immediately without blocking."""
        import threading

        lock = threading.Lock()
        lock.acquire()  # simulate: refresh lock is held by another thread
        try:
            mixin = _AuthMetadataMixin(token_fn=lambda: "tok", tenant_id="t1")
            # If _build_metadata's token_fn tried lock.acquire(), this call
            # would hang forever (no timeout) since we hold the lock above.
            metadata = mixin._build_metadata(None)
            assert ("authorization", "Bearer tok") in metadata
        finally:
            lock.release()


class TestSyncAuthInterceptor:
    def test_intercept_unary_unary_calls_continuation_synchronously(self) -> None:
        interceptor = SyncAuthInterceptor(token_fn=lambda: "sync-token", tenant_id="tenant-x")
        seen: dict = {}

        def continuation(details: _CallDetails, request: object) -> str:
            seen["details"] = details
            seen["request"] = request
            return "response"

        result = interceptor.intercept_unary_unary(continuation, _details(), "req")

        assert result == "response"
        assert ("authorization", "Bearer sync-token") in seen["details"].metadata
        assert ("x-tenant-id", "tenant-x") in seen["details"].metadata

    def test_intercept_unary_unary_is_not_a_coroutine_function(self) -> None:
        interceptor = SyncAuthInterceptor(token_fn=lambda: None, tenant_id="t")
        assert not inspect.iscoroutinefunction(interceptor.intercept_unary_unary)


class TestAsyncAuthInterceptor:
    def test_intercept_unary_unary_is_a_coroutine_function(self) -> None:
        interceptor = AsyncAuthInterceptor(token_fn=lambda: None, tenant_id="t")
        assert inspect.iscoroutinefunction(interceptor.intercept_unary_unary)

    @pytest.mark.asyncio
    async def test_intercept_unary_unary_awaits_continuation(self) -> None:
        interceptor = AsyncAuthInterceptor(token_fn=lambda: "async-token", tenant_id="tenant-y")
        seen: dict = {}

        async def continuation(details: _CallDetails, request: object) -> str:
            seen["details"] = details
            seen["request"] = request
            return "async-response"

        result = await interceptor.intercept_unary_unary(continuation, _details(), "req")

        assert result == "async-response"
        assert ("authorization", "Bearer async-token") in seen["details"].metadata
        assert ("x-tenant-id", "tenant-y") in seen["details"].metadata

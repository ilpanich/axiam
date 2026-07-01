"""Dual-lock single-flight refresh guard (CONTRACT.md §9, SC#2, CF-05).

Implements the double-check-after-lock single-flight pattern required by
CONTRACT.md §9: exactly one in-flight ``POST /api/v1/auth/refresh`` call
across any number of concurrent callers observing the same expired access
token, with no retry loop on failure (§9.3).

Mirrors ``sdks/go/internal/refreshguard/guard.go`` and
``sdks/rust/src/token/refresh_guard.rs``, adapted to Python's sync+async
duality (D-01): TWO INDEPENDENT locks, one per paradigm — each with its own
double-check-after-lock body, both operating on the same cached-token
fields. The two locks are never unified into one (RESEARCH.md's explicit
anti-pattern warning): the async lock type is not thread-safe, and blocking
on the sync lock type inside async code would block the event loop.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Awaitable, Callable, Optional


class RefreshGuard:
    """Single-flight refresh guard with independent sync/async entry points.

    ``cached_access_token()``/``cached_refresh_token()``/``cached_exp()`` are
    non-blocking plain-attribute reads — they back the gRPC interceptor's
    hot-path token function (19-04), which must never acquire the refresh
    lock directly.
    """

    def __init__(self) -> None:
        self._async_lock = asyncio.Lock()
        self._sync_lock = threading.Lock()
        self._cached_access: Optional[str] = None
        self._cached_refresh: Optional[str] = None
        self._cached_exp: Optional[int] = None
        self._has_any = False

    async def refresh_if_needed_async(
        self,
        observed_access: Optional[str],
        do_refresh: Callable[[], Awaitable[Any]],
    ) -> str:
        """Async entry point, guarded by the async-only lock.

        ``do_refresh`` is a caller-supplied zero-arg async callable returning
        an object exposing ``access``/``refresh``/``exp`` (or a mapping with
        those keys) — this module has no import of the REST session, keeping
        it transport-independent.

        On success, exactly one of the concurrently-waiting tasks actually
        calls ``do_refresh``; every other task's double-check-after-lock
        finds the cache already updated and returns the cached token without
        calling ``do_refresh`` again.

        ``do_refresh`` failures propagate as-is — no retry loop (§9.3).
        """
        async with self._async_lock:
            if self._has_any and self._cached_access != observed_access:
                assert self._cached_access is not None
                return self._cached_access

            result = await do_refresh()
            self._store_refreshed(result)
            assert self._cached_access is not None
            return self._cached_access

    def refresh_if_needed_sync(
        self,
        observed_access: Optional[str],
        do_refresh: Callable[[], Any],
    ) -> str:
        """Sync entry point, guarded by the sync-only lock. Mirrors
        :meth:`refresh_if_needed_async` exactly, but for the sync REST/gRPC
        call paths."""
        with self._sync_lock:
            if self._has_any and self._cached_access != observed_access:
                assert self._cached_access is not None
                return self._cached_access

            result = do_refresh()
            self._store_refreshed(result)
            assert self._cached_access is not None
            return self._cached_access

    def _store_refreshed(self, result: Any) -> None:
        """Extract access/refresh/exp from ``do_refresh``'s return value and
        cache them. Accepts either an object with ``access``/``refresh``/
        ``exp`` attributes or an equivalent mapping."""
        if isinstance(result, dict):
            access = result.get("access")
            refresh = result.get("refresh")
            exp = result.get("exp")
        else:
            access = getattr(result, "access", None)
            refresh = getattr(result, "refresh", None)
            exp = getattr(result, "exp", None)

        self._cached_access = access
        if refresh:
            self._cached_refresh = refresh
        self._cached_exp = exp
        self._has_any = True

    def cached_access_token(self) -> Optional[str]:
        """Non-blocking read of the most recently cached access token.
        Acquires no lock — safe to call from a hot RPC/interceptor path."""
        return self._cached_access

    def cached_refresh_token(self) -> Optional[str]:
        """Non-blocking read of the most recently cached refresh token.
        Acquires no lock."""
        return self._cached_refresh

    def cached_exp(self) -> Optional[int]:
        """Non-blocking read of the most recently cached access token
        expiry (unix seconds). Acquires no lock."""
        return self._cached_exp

    def seed(self, access: str, refresh: Optional[str], exp: Optional[int]) -> None:
        """Prime the guard's cache with an already-known token triple, used
        by the client after a successful ``login``/``verify_mfa`` — before
        any refresh has run — so a subsequent 401 sees the correct
        ``observed_access`` baseline."""
        self._cached_access = access
        if refresh:
            self._cached_refresh = refresh
        self._cached_exp = exp
        self._has_any = True

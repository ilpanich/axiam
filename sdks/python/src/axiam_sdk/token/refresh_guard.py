"""Cross-paradigm single-flight refresh guard (CONTRACT.md §9, SC#2, CF-05).

Implements the double-check-after-lock single-flight pattern required by
CONTRACT.md §9: exactly one in-flight ``POST /api/v1/auth/refresh`` call
across any number of concurrent callers observing the same expired access
token, with no retry loop on failure (§9.3).

Mirrors ``sdks/go/internal/refreshguard/guard.go`` and
``sdks/rust/src/token/refresh_guard.rs``, adapted to Python's sync+async
duality (D-01). BOTH entry points serialize on ONE shared
``threading.Lock`` — an OS-level primitive usable from either paradigm —
with a double-check-after-acquire body operating on the same cached-token
fields. This is what makes the guard genuinely single-flight *across*
paradigms: a sync REST caller and a concurrent async gRPC caller sharing one
``RefreshGuard`` (D-01: one ``AxiamClient``/``_Session``/``RefreshGuard``
exposing both sync and async surfaces) cannot both refresh, because they
contend on the same lock and the loser's double-check finds the cache
already fresh.

Two independent locks (one ``threading.Lock`` + one ``asyncio.Lock``) do
NOT provide this guarantee — a thread holding the sync lock and a coroutine
holding the async lock run concurrently, each independently deciding to
refresh (CR-01). The async path therefore acquires the SAME
``threading.Lock`` WITHOUT blocking the event loop, by offloading the
blocking ``acquire()`` to the default thread-pool executor via
``loop.run_in_executor``; the critical section (including the awaited
``do_refresh``) then runs on the event loop while the lock is held, and the
lock is always released in a ``finally``.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable
from typing import Any


class RefreshGuard:
    """Single-flight refresh guard shared across sync and async entry points.

    Both entry points serialize on ONE ``threading.Lock`` (CR-01), so a
    concurrent sync caller and async caller collapse to exactly one refresh.

    ``cached_access_token()``/``cached_refresh_token()``/``cached_exp()`` are
    non-blocking plain-attribute reads — they back the gRPC interceptor's
    hot-path token function (19-04), which must never acquire the refresh
    lock directly.
    """

    def __init__(self) -> None:
        # ONE OS-level lock guards the critical section for BOTH paradigms
        # (CR-01). The async path acquires it off the event loop; the sync
        # path acquires it directly.
        self._lock = threading.Lock()
        self._cached_access: str | None = None
        self._cached_refresh: str | None = None
        self._cached_exp: int | None = None
        self._has_any = False

    def _should_skip_refresh(self, observed_access: str | None) -> bool:
        """Double-check-after-acquire predicate. Returns ``True`` when a
        concurrent caller already refreshed and the current caller can safely
        return the cached token WITHOUT calling ``do_refresh``.

        ``observed_access is None`` (WR-03) is treated as "no observed
        baseline — always attempt a refresh", so a ``None`` observation never
        silently returns a stale cached token."""
        return (
            self._has_any and observed_access is not None and self._cached_access != observed_access
        )

    async def refresh_if_needed_async(
        self,
        observed_access: str | None,
        do_refresh: Callable[[], Awaitable[Any]],
    ) -> str:
        """Async entry point, guarded by the SAME ``threading.Lock`` as the
        sync path (CR-01) so single-flight holds across paradigms.

        ``do_refresh`` is a caller-supplied zero-arg async callable returning
        an object exposing ``access``/``refresh``/``exp`` (or a mapping with
        those keys) — this module has no import of the REST session, keeping
        it transport-independent.

        The blocking ``self._lock.acquire()`` is offloaded to the default
        thread-pool executor so the event loop is never blocked while
        waiting; once acquired, the critical section (including the awaited
        ``do_refresh``) runs on the event loop and the lock is released in a
        ``finally``.

        On success, exactly one of the concurrently-waiting callers actually
        calls ``do_refresh``; every other caller's double-check-after-acquire
        finds the cache already updated and returns the cached token without
        calling ``do_refresh`` again.

        ``do_refresh`` failures propagate as-is — no retry loop (§9.3).
        """
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(None, self._lock.acquire)
        try:
            if self._should_skip_refresh(observed_access):
                return self._require_cached_access()

            result = await do_refresh()
            self._store_refreshed(result)
            return self._require_cached_access()
        finally:
            self._lock.release()

    def refresh_if_needed_sync(
        self,
        observed_access: str | None,
        do_refresh: Callable[[], Any],
    ) -> str:
        """Sync entry point, guarded by the SAME ``threading.Lock`` as the
        async path (CR-01). Mirrors :meth:`refresh_if_needed_async` exactly,
        but for the sync REST/gRPC call paths."""
        with self._lock:
            if self._should_skip_refresh(observed_access):
                return self._require_cached_access()

            result = do_refresh()
            self._store_refreshed(result)
            return self._require_cached_access()

    def _require_cached_access(self) -> str:
        """Enforce the ``-> str`` return-type invariant at runtime (WR-04).

        Uses an explicit ``raise`` rather than ``assert`` so the guarantee
        survives ``python -O``/``PYTHONOPTIMIZE`` (which strips ``assert``).
        A caller-supplied ``do_refresh`` that fails to populate an access
        token is a contract violation surfaced loudly here instead of
        silently returning ``None`` typed as ``str``."""
        if self._cached_access is None:
            raise RuntimeError(
                "refresh guard invariant violated: do_refresh did not populate an access token"
            )
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

    def cached_access_token(self) -> str | None:
        """Non-blocking read of the most recently cached access token.
        Acquires no lock — safe to call from a hot RPC/interceptor path."""
        return self._cached_access

    def cached_refresh_token(self) -> str | None:
        """Non-blocking read of the most recently cached refresh token.
        Acquires no lock."""
        return self._cached_refresh

    def cached_exp(self) -> int | None:
        """Non-blocking read of the most recently cached access token
        expiry (unix seconds). Acquires no lock."""
        return self._cached_exp

    def seed(self, access: str, refresh: str | None, exp: int | None) -> None:
        """Prime the guard's cache with an already-known token triple, used
        by the client after a successful ``login``/``verify_mfa`` — before
        any refresh has run — so a subsequent 401 sees the correct
        ``observed_access`` baseline."""
        self._cached_access = access
        if refresh:
            self._cached_refresh = refresh
        self._cached_exp = exp
        self._has_any = True

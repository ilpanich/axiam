"""Regression tests for RefreshGuard's dual-lock single-flight behavior
(CONTRACT.md §9, SC#2, CF-05).

The literal SC#2 target: 5 concurrent asyncio tasks racing against an
expired access token must trigger EXACTLY 1 refresh call.
"""

from __future__ import annotations

import asyncio
import threading

import pytest

from axiam_sdk.token.refresh_guard import RefreshGuard


@pytest.mark.asyncio
async def test_single_flight_refresh_exactly_once_async() -> None:
    call_count = 0

    async def fake_refresh() -> dict:
        nonlocal call_count
        call_count += 1
        await asyncio.sleep(0.01)  # simulate network latency so tasks overlap
        return {"access": "new-access-token", "refresh": "new-refresh-token", "exp": 9999999999}

    guard = RefreshGuard()
    expired_token = "expired-access-token"

    results = await asyncio.gather(
        *[guard.refresh_if_needed_async(expired_token, fake_refresh) for _ in range(5)]
    )

    assert call_count == 1, "expected exactly one refresh call across 5 concurrent tasks"
    assert all(r == "new-access-token" for r in results)
    assert guard.cached_access_token() == "new-access-token"
    assert guard.cached_refresh_token() == "new-refresh-token"


def test_single_flight_refresh_exactly_once_sync() -> None:
    call_count = 0
    lock = threading.Lock()

    def fake_refresh() -> dict:
        nonlocal call_count
        with lock:
            call_count += 1
        return {"access": "new-access-token-sync", "refresh": "r", "exp": 1}

    guard = RefreshGuard()
    expired_token = "expired-access-token"

    threads = [
        threading.Thread(
            target=lambda: guard.refresh_if_needed_sync(expired_token, fake_refresh)
        )
        for _ in range(5)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert call_count == 1
    assert guard.cached_access_token() == "new-access-token-sync"


@pytest.mark.asyncio
async def test_double_check_after_lock_returns_cached_without_calling_do_refresh() -> None:
    """If the cache was already updated by a prior refresh, a caller
    observing the OLD (now-stale) token must get the cached value without
    triggering a second do_refresh call."""
    guard = RefreshGuard()
    guard.seed("current-token", "current-refresh", 123)

    called = False

    async def do_refresh() -> dict:
        nonlocal called
        called = True
        return {"access": "should-not-be-used", "refresh": None, "exp": None}

    result = await guard.refresh_if_needed_async("stale-observed-token", do_refresh)

    assert result == "current-token"
    assert called is False


@pytest.mark.asyncio
async def test_do_refresh_failure_propagates_without_retry() -> None:
    call_count = 0

    async def failing_refresh() -> dict:
        nonlocal call_count
        call_count += 1
        raise RuntimeError("refresh endpoint unavailable")

    guard = RefreshGuard()

    with pytest.raises(RuntimeError, match="refresh endpoint unavailable"):
        await guard.refresh_if_needed_async("expired", failing_refresh)

    assert call_count == 1, "do_refresh must be called exactly once, no retry loop (§9.3)"


def test_cached_access_token_is_none_before_any_refresh() -> None:
    guard = RefreshGuard()
    assert guard.cached_access_token() is None
    assert guard.cached_refresh_token() is None
    assert guard.cached_exp() is None


def test_seed_primes_cache() -> None:
    guard = RefreshGuard()
    guard.seed("seeded-access", "seeded-refresh", 42)
    assert guard.cached_access_token() == "seeded-access"
    assert guard.cached_refresh_token() == "seeded-refresh"
    assert guard.cached_exp() == 42

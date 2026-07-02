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
        threading.Thread(target=lambda: guard.refresh_if_needed_sync(expired_token, fake_refresh))
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


@pytest.mark.asyncio
async def test_mixed_sync_and_async_callers_refresh_exactly_once() -> None:
    """CR-01 acceptance gate: a sync caller (on a background thread) and
    several async callers, all observing the SAME expired token against ONE
    shared RefreshGuard, must collapse to EXACTLY ONE refresh call
    (CONTRACT.md §9). This is the cross-paradigm scenario D-01's unified
    sync+async client introduces.

    This test FAILS against the old two-independent-lock design (a
    threading.Lock guarding the sync path and a separate asyncio.Lock
    guarding the async path cannot mutually exclude each other, so
    call_count == 2) and PASSES against the shared-single-lock fix.
    """
    import time

    call_count = 0
    count_lock = threading.Lock()
    # Released once all callers have been scheduled, so the sync thread and
    # the async tasks all enter the guard as close together as possible,
    # maximizing the cross-paradigm race window.
    go = threading.Event()

    def _bump() -> None:
        nonlocal call_count
        with count_lock:
            call_count += 1

    async def async_refresh() -> dict:
        _bump()
        # Hold the critical section briefly so a concurrent sync caller has a
        # real window to race in if the locks were independent.
        await asyncio.sleep(0.05)
        return {"access": "async-new-token", "refresh": "async-refresh", "exp": 9999999999}

    def sync_refresh() -> dict:
        _bump()
        time.sleep(0.05)
        return {"access": "sync-new-token", "refresh": "sync-refresh", "exp": 9999999999}

    guard = RefreshGuard()
    expired = "token-0"

    loop = asyncio.get_running_loop()

    def run_sync() -> str:
        go.wait(timeout=5)
        return guard.refresh_if_needed_sync(expired, sync_refresh)

    sync_future = loop.run_in_executor(None, run_sync)

    async def run_async() -> str:
        await loop.run_in_executor(None, go.wait, 5)
        return await guard.refresh_if_needed_async(expired, async_refresh)

    async_tasks = [asyncio.create_task(run_async()) for _ in range(4)]
    # Let every task and the sync thread reach their go.wait() barrier, then
    # release them together.
    await asyncio.sleep(0.05)
    go.set()

    async_results = await asyncio.gather(*async_tasks)
    sync_result = await sync_future

    assert call_count == 1, (
        f"expected exactly one refresh across mixed sync+async callers, got {call_count}"
    )

    # All callers must converge on the SINGLE winner's token — no lost update
    # / cache corruption where the loser overwrites the winner's cache.
    final = guard.cached_access_token()
    assert final in ("async-new-token", "sync-new-token")
    all_results = [sync_result, *async_results]
    assert all(r == final for r in all_results), (
        f"all callers must observe the single winning token {final!r}, got {all_results}"
    )


@pytest.mark.asyncio
async def test_observed_access_none_forces_refresh_async() -> None:
    """WR-03: passing observed_access=None to an already-seeded guard must
    NOT silently skip the refresh and return the (possibly stale) cached
    token — a None observation means "no baseline", so a refresh is forced."""
    guard = RefreshGuard()
    guard.seed("stale-token", "stale-refresh", 123)

    call_count = 0

    async def fresh_refresh() -> dict:
        nonlocal call_count
        call_count += 1
        return {"access": "fresh-token", "refresh": "fresh-refresh", "exp": 9999999999}

    result = await guard.refresh_if_needed_async(None, fresh_refresh)

    assert call_count == 1, "observed_access=None must force a refresh, not skip it"
    assert result == "fresh-token"
    assert guard.cached_access_token() == "fresh-token"


def test_observed_access_none_forces_refresh_sync() -> None:
    """WR-03 (sync twin)."""
    guard = RefreshGuard()
    guard.seed("stale-token", "stale-refresh", 123)

    call_count = 0

    def fresh_refresh() -> dict:
        nonlocal call_count
        call_count += 1
        return {"access": "fresh-token-sync", "refresh": "fresh-refresh", "exp": 9999999999}

    result = guard.refresh_if_needed_sync(None, fresh_refresh)

    assert call_count == 1
    assert result == "fresh-token-sync"


@pytest.mark.asyncio
async def test_missing_access_in_refresh_result_raises_not_none_async() -> None:
    """WR-04: the ``-> str`` return-type invariant is enforced with an
    explicit raise (survives ``python -O``), not a bare ``assert`` — a
    do_refresh returning no access token raises RuntimeError instead of
    silently returning None typed as str."""
    guard = RefreshGuard()

    async def bad_refresh() -> dict:
        return {"access": None, "refresh": None, "exp": None}

    with pytest.raises(RuntimeError, match="invariant violated"):
        await guard.refresh_if_needed_async("expired", bad_refresh)


def test_missing_access_in_refresh_result_raises_not_none_sync() -> None:
    """WR-04 (sync twin)."""
    guard = RefreshGuard()

    def bad_refresh() -> dict:
        return {"access": None, "refresh": None, "exp": None}

    with pytest.raises(RuntimeError, match="invariant violated"):
        guard.refresh_if_needed_sync("expired", bad_refresh)

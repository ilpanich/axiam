package io.axiam.sdk.internal;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SC#2's literal target (CONTRACT.md &sect;9 "Test requirement"): N (&ge;5)
 * concurrent threads observing the same expired access token must trigger
 * exactly 1 {@code doRefresh} invocation, and a failing refresh must
 * propagate to every waiter without a retry loop (&sect;9.3).
 */
class RefreshGuardSingleFlightTest {

    private static final int THREAD_COUNT = 5;
    private static final String EXPIRED_TOKEN = "expired-access-token";

    @Test
    void fiveConcurrentThreadsOnExpiredTokenTriggerExactlyOneRefresh() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        AtomicInteger refreshCallCount = new AtomicInteger(0);

        Supplier<TokenPair> doRefresh = () -> {
            refreshCallCount.incrementAndGet();
            // A short sleep widens the race window so concurrent callers
            // actually collide on the lock/in-flight future rather than
            // trivially serializing through an instantaneous supplier.
            sleepQuietly(50);
            return new TokenPair("new-access-token", "new-refresh-token",
                    System.currentTimeMillis() + 900_000);
        };

        List<TokenPair> results = runConcurrently(guard, doRefresh);

        assertEquals(1, refreshCallCount.get(),
                "expected exactly one refresh call across " + THREAD_COUNT + " concurrent threads");
        for (TokenPair result : results) {
            assertEquals("new-access-token", result.access(),
                    "every waiter must receive the same resolved TokenPair");
        }
    }

    @Test
    void failingRefreshPropagatesToAllWaitersWithoutRetry() throws Exception {
        RefreshGuard guard = new RefreshGuard();
        AtomicInteger refreshCallCount = new AtomicInteger(0);
        RuntimeException failure = new RuntimeException("refresh failed: 401 on /api/v1/auth/refresh");

        Supplier<TokenPair> doRefresh = () -> {
            refreshCallCount.incrementAndGet();
            sleepQuietly(50);
            throw failure;
        };

        CountDownLatch startBarrier = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(THREAD_COUNT);
        try {
            List<Callable<TokenPair>> tasks = new java.util.ArrayList<>();
            for (int i = 0; i < THREAD_COUNT; i++) {
                tasks.add(() -> {
                    startBarrier.await();
                    return guard.refreshIfNeeded(EXPIRED_TOKEN, doRefresh);
                });
            }
            startBarrier.countDown();
            List<Future<TokenPair>> futures = new java.util.ArrayList<>();
            for (Callable<TokenPair> task : tasks) {
                futures.add(pool.submit(task));
            }

            for (Future<TokenPair> future : futures) {
                RuntimeException thrown = assertThrows(RuntimeException.class, () -> {
                    try {
                        future.get();
                    } catch (java.util.concurrent.ExecutionException e) {
                        if (e.getCause() instanceof RuntimeException re) {
                            throw re;
                        }
                        throw new RuntimeException(e.getCause());
                    }
                });
                assertSame(failure, thrown, "every waiter must receive the SAME exception instance");
            }
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }

        assertEquals(1, refreshCallCount.get(),
                "a failing refresh must not be retried — exactly one doRefresh invocation (§9.3)");
    }

    @Test
    void observerAlreadyStaleGetsCachedTokenWithoutNewRefresh() {
        RefreshGuard guard = new RefreshGuard();
        AtomicInteger refreshCallCount = new AtomicInteger(0);

        // Seed the guard with a current token via a first refresh.
        TokenPair seeded = guard.refreshIfNeeded(EXPIRED_TOKEN, () -> {
            refreshCallCount.incrementAndGet();
            return new TokenPair("access-v1", "refresh-v1", System.currentTimeMillis() + 900_000);
        });
        assertEquals(1, refreshCallCount.get());

        // A caller whose observedAccessToken already differs from the
        // cached current token (double-check) must get the cached token
        // WITHOUT triggering a new refresh.
        TokenPair result = guard.refreshIfNeeded("some-other-stale-token", () -> {
            refreshCallCount.incrementAndGet();
            return new TokenPair("access-v2", "refresh-v2", System.currentTimeMillis() + 900_000);
        });

        assertSame(seeded, result);
        assertEquals(1, refreshCallCount.get(), "no new refresh should have been triggered");
    }

    @Test
    void cachedAccessTokenIsNonBlockingVolatileRead() {
        RefreshGuard guard = new RefreshGuard();
        assertEquals(null, guard.cachedAccessToken());

        guard.refreshIfNeeded(EXPIRED_TOKEN,
                () -> new TokenPair("access-v1", "refresh-v1", System.currentTimeMillis() + 900_000));

        assertEquals("access-v1", guard.cachedAccessToken());
        assertTrue(guard.cached().isPresent());
    }

    private static List<TokenPair> runConcurrently(RefreshGuard guard, Supplier<TokenPair> doRefresh) throws Exception {
        CountDownLatch startBarrier = new CountDownLatch(1);
        ExecutorService pool = Executors.newFixedThreadPool(THREAD_COUNT);
        try {
            List<Callable<TokenPair>> tasks = new java.util.ArrayList<>();
            for (int i = 0; i < THREAD_COUNT; i++) {
                tasks.add(() -> {
                    startBarrier.await();
                    return guard.refreshIfNeeded(EXPIRED_TOKEN, doRefresh);
                });
            }
            startBarrier.countDown(); // release all threads at once
            List<Future<TokenPair>> futures = new java.util.ArrayList<>();
            for (Callable<TokenPair> task : tasks) {
                futures.add(pool.submit(task));
            }
            List<TokenPair> results = new java.util.ArrayList<>();
            for (Future<TokenPair> future : futures) {
                results.add(future.get(5, TimeUnit.SECONDS));
            }
            return results;
        } finally {
            pool.shutdown();
            assertTrue(pool.awaitTermination(5, TimeUnit.SECONDS));
        }
    }

    private static void sleepQuietly(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }
}

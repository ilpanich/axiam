package io.axiam.sdk.internal;

import org.jspecify.annotations.Nullable;

import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Supplier;

/**
 * The §9 single-flight refresh guard (D-07, CONTRACT.md &sect;9): exactly
 * one in-flight {@code POST /api/v1/auth/refresh} call across any number of
 * concurrent callers observing the same stale/expired access token.
 *
 * <p>One instance is constructed per {@code AxiamClient} and shared by the
 * REST interceptor/authenticator AND the gRPC client (D-07's "one guard"
 * requirement) — never a second instance per transport.
 *
 * <p>Uses a {@link ReentrantLock} (NOT {@code synchronized}) so the lock is
 * never held across the actual HTTP call — {@code synchronized} around I/O
 * would serialize every concurrent caller behind the network round-trip and
 * is not virtual-thread-friendly (D-10). The lock is released before
 * blocking on {@link CompletableFuture#join()} so a waiter's block never
 * holds the mutex it would otherwise need for its own double-check.
 *
 * <p><strong>No retry loop (§9.3):</strong> a failing {@code doRefresh}
 * propagates its exception, as-is, to every waiter exactly once. The caller
 * must re-authenticate from scratch; this class never re-attempts a failed
 * refresh automatically.
 */
public final class RefreshGuard {

    private final ReentrantLock lock = new ReentrantLock();

    // Non-null only while a refresh is actually in flight; cleared (set back
    // to null) once it resolves, successfully or not.
    private final AtomicReference<CompletableFuture<TokenPair>> inFlight = new AtomicReference<>();

    private volatile @Nullable TokenPair current;

    /** Creates a new, empty refresh guard (no cached token yet). */
    public RefreshGuard() {
    }

    /**
     * Ensures exactly one call to {@code doRefresh} is in flight at a time,
     * regardless of how many threads call this concurrently with the same
     * (now-stale) {@code observedAccessToken}.
     *
     * <p>Double-check-after-lock: if another thread already completed a
     * refresh while this caller waited for the lock (i.e. the cached
     * token no longer matches what this caller observed as stale), the
     * cached token is returned immediately — no new refresh is performed.
     *
     * @param observedAccessToken the access token this caller observed as
     *                             stale/expired/rejected
     * @param doRefresh            performs the actual
     *                             {@code POST /api/v1/auth/refresh} call;
     *                             invoked OUTSIDE the lock, at most once per
     *                             call to this method
     * @return the resolved (current or freshly refreshed) token pair
     * @throws RuntimeException whatever {@code doRefresh} throws, propagated
     *                          as-is to every waiter (§9.3 — no retry)
     */
    public TokenPair refreshIfNeeded(String observedAccessToken, Supplier<TokenPair> doRefresh) {
        lock.lock();
        try {
            TokenPair snapshot = current;
            if (snapshot != null && !snapshot.access().equals(observedAccessToken)) {
                // Another thread already refreshed while we waited for the
                // lock — no new refresh needed.
                return snapshot;
            }

            CompletableFuture<TokenPair> existing = inFlight.get();
            if (existing != null) {
                lock.unlock(); // release before blocking on join()
                try {
                    return existing.join();
                } catch (java.util.concurrent.CompletionException e) {
                    Throwable cause = e.getCause();
                    if (cause instanceof RuntimeException re) {
                        throw re;
                    }
                    throw e;
                } finally {
                    lock.lock(); // re-acquire so the outer finally's unlock() is balanced
                }
            }

            CompletableFuture<TokenPair> future = new CompletableFuture<>();
            inFlight.set(future);
            lock.unlock(); // perform the actual HTTP call OUTSIDE the lock
            try {
                TokenPair result = doRefresh.get(); // POST /api/v1/auth/refresh
                current = result;
                future.complete(result);
                return result;
            } catch (RuntimeException e) {
                future.completeExceptionally(e);
                throw e; // §9.3: no retry — propagate as-is
            } finally {
                inFlight.set(null);
                lock.lock(); // re-acquire so the outer finally's unlock() is balanced
            }
        } finally {
            lock.unlock();
        }
    }

    /**
     * Non-blocking read of the most recently cached token pair, for hot-path
     * callers (the REST {@code Interceptor}, the gRPC client interceptor)
     * that must never synchronously acquire this guard's lock. A plain
     * volatile field read — never {@code lock.lock()}.
     *
     * @return the cached token pair, or {@link Optional#empty()} if no refresh
     *         has completed yet
     */
    public Optional<TokenPair> cached() {
        return Optional.ofNullable(current);
    }

    /**
     * Non-blocking read of the currently cached access token, or
     * {@code null} if none has been cached yet. See {@link #cached()}.
     *
     * @return the cached access token, or {@code null} if no refresh has
     *         completed yet
     */
    public @Nullable String cachedAccessToken() {
        TokenPair snapshot = current;
        return snapshot == null ? null : snapshot.access();
    }
}

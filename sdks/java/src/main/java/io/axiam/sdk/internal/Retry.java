package io.axiam.sdk.internal;

import java.security.SecureRandom;
import java.util.Random;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * Hand-rolled bounded exponential-backoff-with-jitter retry helper (D-26),
 * the ONE piece of this phase intentionally hand-rolled by explicit user
 * decision rather than pulling in a retry/circuit-breaker framework
 * (Resilience4j/Failsafe rejected per RESEARCH.md "Don't Hand-Roll").
 *
 * <p><strong>Idempotent operations only.</strong> This helper has no
 * awareness of HTTP method or operation semantics — it retries whatever
 * {@code Supplier} it is given, exactly when {@code retryable} says to.
 * Callers MUST only route idempotent operations (GET reads, authz-check
 * reads) through {@link #withRetry}; state-changing requests (login,
 * logout, mutations) MUST call their operation directly, without this
 * helper, so a transient failure is never silently retried into a
 * duplicate side effect.
 *
 * <p>Honors a {@code Retry-After} hint via {@link RetryAfterHint}: if the
 * thrown {@code RuntimeException} implements it, the wait before the next
 * attempt is at least the hinted duration (never less, even if the
 * computed backoff would be shorter).
 */
public final class Retry {

    /** Default attempt cap (RESEARCH.md Summary: "3-attempt bounded backoff default"). */
    public static final int DEFAULT_MAX_ATTEMPTS = 3;

    static final long BASE_DELAY_MILLIS = 200;
    static final long MAX_DELAY_MILLIS = 5_000;

    private Retry() {
    }

    /**
     * An error that carries a server-supplied {@code Retry-After} hint
     * (e.g. from a 429/503 response). {@link #withRetry} honors this by
     * waiting at least {@link #retryAfterMillis()} before the next attempt.
     */
    public interface RetryAfterHint {
        /** Returns the server-supplied minimum wait before retrying.
         *
         * @return the minimum wait before retrying, in milliseconds */
        long retryAfterMillis();
    }

    /** Sleep abstraction so tests can inject a non-blocking, recording implementation. */
    @FunctionalInterface
    interface Sleeper {
        void sleep(long millis) throws InterruptedException;
    }

    /**
     * Runs {@code op}, retrying up to {@link #DEFAULT_MAX_ATTEMPTS} times
     * when {@code retryable} matches the thrown exception.
     *
     * @param <T>       the type {@code op} produces
     * @param op        the idempotent operation to run
     * @param retryable decides whether a thrown {@code RuntimeException} should
     *                  trigger a retry
     * @return {@code op}'s result, once it succeeds
     * @throws RuntimeException the last thrown exception, if {@code op}
     *                          never succeeds within the attempt cap, or
     *                          immediately if {@code retryable} rejects it
     */
    public static <T> T withRetry(Supplier<T> op, Predicate<RuntimeException> retryable) {
        return withRetry(DEFAULT_MAX_ATTEMPTS, op, retryable);
    }

    /**
     * Runs {@code op}, retrying up to {@code maxAttempts} times when
     * {@code retryable} matches the thrown exception. Uses bounded
     * exponential backoff with jitter between attempts, honoring any
     * {@link RetryAfterHint} the thrown exception carries.
     *
     * @param <T>         the type {@code op} produces
     * @param maxAttempts the maximum number of attempts (must be &gt;= 1)
     * @param op          the idempotent operation to run
     * @param retryable   decides whether a thrown {@code RuntimeException} should
     *                    trigger a retry
     * @return {@code op}'s result, once it succeeds
     * @throws RuntimeException the last thrown exception, if {@code op}
     *                          never succeeds within {@code maxAttempts},
     *                          or immediately if {@code retryable} rejects
     *                          it
     */
    public static <T> T withRetry(int maxAttempts, Supplier<T> op, Predicate<RuntimeException> retryable) {
        return withRetry(maxAttempts, op, retryable, Thread::sleep, new SecureRandom());
    }

    /**
     * Test-injectable full-featured overload — package-private so unit
     * tests can substitute a non-blocking {@link Sleeper} (no real
     * wall-clock sleep) and a deterministic {@link Random}.
     */
    static <T> T withRetry(int maxAttempts, Supplier<T> op, Predicate<RuntimeException> retryable,
                            Sleeper sleeper, Random random) {
        if (maxAttempts < 1) {
            throw new IllegalArgumentException("maxAttempts must be >= 1");
        }

        for (int attempt = 1; attempt <= maxAttempts; attempt++) {
            try {
                return op.get();
            } catch (RuntimeException e) {
                boolean lastAttempt = attempt == maxAttempts;
                if (!retryable.test(e) || lastAttempt) {
                    throw e;
                }

                long delay = computeDelayMillis(attempt, e, random);
                try {
                    sleeper.sleep(delay);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw e;
                }
            }
        }
        // Unreachable: the loop above always either returns or throws.
        throw new IllegalStateException("unreachable");
    }

    private static long computeDelayMillis(int attempt, RuntimeException error, Random random) {
        long backoff = boundedExponentialBackoffWithJitter(attempt, random);
        if (error instanceof RetryAfterHint hint) {
            return Math.max(backoff, hint.retryAfterMillis());
        }
        return backoff;
    }

    private static long boundedExponentialBackoffWithJitter(int attempt, Random random) {
        long exponential = BASE_DELAY_MILLIS * (1L << (attempt - 1));
        long capped = Math.min(MAX_DELAY_MILLIS, exponential);
        // Full jitter: a uniformly random delay in [0, capped].
        return (long) (random.nextDouble() * capped);
    }
}

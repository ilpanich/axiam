package io.axiam.sdk.internal;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves D-26: bounded exponential-backoff-with-jitter retry for idempotent
 * operations only, honoring a {@code Retry-After} hint, with no real
 * wall-clock sleep in the test suite (an injected, recording
 * {@link Retry.Sleeper} stands in for {@link Thread#sleep}).
 */
class RetryTest {

    /** A transient network/429/503-style error, retryable by policy. */
    private static class TransientError extends RuntimeException {
        TransientError(String message) {
            super(message);
        }
    }

    /** A transient error additionally carrying a server-supplied Retry-After hint. */
    private static final class RetryAfterError extends TransientError implements Retry.RetryAfterHint {
        private final long retryAfterMillis;

        RetryAfterError(String message, long retryAfterMillis) {
            super(message);
            this.retryAfterMillis = retryAfterMillis;
        }

        @Override
        public long retryAfterMillis() {
            return retryAfterMillis;
        }
    }

    @Test
    void transientFailureThenSuccessSucceedsWithinMaxAttempts() {
        AtomicInteger attempts = new AtomicInteger(0);
        List<Long> sleeps = new ArrayList<>();

        String result = Retry.withRetry(3, () -> {
            int attempt = attempts.incrementAndGet();
            if (attempt < 3) {
                throw new TransientError("attempt " + attempt + " failed transiently");
            }
            return "success";
        }, e -> e instanceof TransientError, recordingSleeper(sleeps), new Random(42));

        assertEquals("success", result);
        assertEquals(3, attempts.get(), "expected exactly 3 attempts (2 failures + 1 success)");
        assertEquals(2, sleeps.size(), "expected a sleep between each of the 2 failed attempts and the next");
    }

    @Test
    void nonRetryableErrorIsThrownImmediatelyWithOneAttempt() {
        AtomicInteger attempts = new AtomicInteger(0);
        List<Long> sleeps = new ArrayList<>();
        RuntimeException notRetryable = new IllegalStateException("permission denied");

        RuntimeException thrown = assertThrows(RuntimeException.class, () ->
                Retry.withRetry(3, () -> {
                    attempts.incrementAndGet();
                    throw notRetryable;
                }, e -> e instanceof TransientError, recordingSleeper(sleeps), new Random(42)));

        assertSame(notRetryable, thrown);
        assertEquals(1, attempts.get(), "a non-retryable error must not be retried");
        assertTrue(sleeps.isEmpty(), "no backoff sleep should occur for a non-retryable error");
    }

    @Test
    void exceedingMaxAttemptsRethrowsTheLastError() {
        AtomicInteger attempts = new AtomicInteger(0);
        List<Long> sleeps = new ArrayList<>();
        List<TransientError> thrownErrors = new ArrayList<>();

        RuntimeException thrown = assertThrows(RuntimeException.class, () ->
                Retry.withRetry(3, () -> {
                    TransientError error = new TransientError("attempt " + attempts.incrementAndGet() + " failed");
                    thrownErrors.add(error);
                    throw error;
                }, e -> e instanceof TransientError, recordingSleeper(sleeps), new Random(42)));

        assertEquals(3, attempts.get(), "must attempt exactly maxAttempts times before giving up");
        assertSame(thrownErrors.get(thrownErrors.size() - 1), thrown, "must rethrow the LAST attempt's error");
        assertEquals(2, sleeps.size(), "a sleep occurs between attempts 1->2 and 2->3, but not after the final failure");
    }

    @Test
    void retryAfterHintIsHonoredAsAMinimumWait() {
        long retryAfterMillis = 5_000L;
        AtomicInteger attempts = new AtomicInteger(0);
        List<Long> sleeps = new ArrayList<>();

        String result = Retry.withRetry(3, () -> {
            int attempt = attempts.incrementAndGet();
            if (attempt < 2) {
                throw new RetryAfterError("rate limited", retryAfterMillis);
            }
            return "success";
        }, e -> e instanceof TransientError, recordingSleeper(sleeps), new Random(42));

        assertEquals("success", result);
        assertEquals(1, sleeps.size());
        assertTrue(sleeps.get(0) >= retryAfterMillis,
                "wait must be at least the Retry-After hint (" + retryAfterMillis
                        + "ms), was " + sleeps.get(0) + "ms");
    }

    @Test
    void defaultMaxAttemptsIsThree() {
        assertEquals(3, Retry.DEFAULT_MAX_ATTEMPTS);
    }

    private static Retry.Sleeper recordingSleeper(List<Long> sleeps) {
        return millis -> sleeps.add(millis);
    }
}

package io.axiam.sdk.amqp;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Bounded, thread-safe, in-memory nonce-replay tracker for NEW-4 (AMQP
 * replay protection). One instance is shared across every delivery handled
 * by a single {@link AmqpConsumer#consume} registration &mdash; it is NOT
 * recreated per-delivery &mdash; so a nonce observed on one delivery is
 * rejected as a replay on any subsequent delivery within its TTL window.
 *
 * <p>Entries expire {@code ttl} after they are first observed (the caller
 * supplies {@code ttl = 2 * allowedClockSkew}, so a nonce cannot be replayed
 * for as long as its {@code issued_at} could plausibly still pass the
 * clock-skew check). Pruning of expired entries is opportunistic (amortized
 * across calls, not a background thread) and the map is bounded by
 * {@link #maxTrackedNonces} to cap worst-case memory use under a flood of
 * distinct nonces.
 */
final class NonceStore {

    /** Default cap on distinct in-flight nonces tracked at once. */
    static final int DEFAULT_MAX_TRACKED_NONCES = 100_000;

    /** Opportunistic prune runs at least this often, in number of {@link #observe} calls. */
    private static final long PRUNE_EVERY_N_CALLS = 256;

    private final Duration ttl;
    private final int maxTrackedNonces;
    private final ConcurrentHashMap<String, Instant> seenUntil = new ConcurrentHashMap<>();
    private final AtomicLong callCount = new AtomicLong();

    NonceStore(Duration ttl) {
        this(ttl, DEFAULT_MAX_TRACKED_NONCES);
    }

    NonceStore(Duration ttl, int maxTrackedNonces) {
        if (ttl.isNegative() || ttl.isZero()) {
            throw new IllegalArgumentException("ttl must be positive");
        }
        if (maxTrackedNonces <= 0) {
            throw new IllegalArgumentException("maxTrackedNonces must be positive");
        }
        this.ttl = ttl;
        this.maxTrackedNonces = maxTrackedNonces;
    }

    /**
     * Records {@code nonce} as seen at {@code now} and returns {@code true}
     * if it was fresh (not a replay), or {@code false} if it had already
     * been observed and its recorded expiry has not yet elapsed.
     *
     * <p>Atomic per-key via {@link ConcurrentHashMap#compute}: concurrent
     * deliveries carrying the same nonce cannot both be reported fresh.
     */
    boolean observe(String nonce, Instant now) {
        pruneIfDue(now);

        Instant newExpiry = now.plus(ttl);
        // holder[0] left null => fresh (or previously-expired) nonce recorded;
        // non-null => an unexpired prior sighting, i.e. a replay.
        Instant[] replayExpiry = new Instant[1];
        seenUntil.compute(nonce, (key, existingExpiry) -> {
            if (existingExpiry != null && existingExpiry.isAfter(now)) {
                replayExpiry[0] = existingExpiry;
                return existingExpiry; // unchanged: keep the original expiry
            }
            return newExpiry; // fresh, or a stale/expired entry being refreshed
        });
        return replayExpiry[0] == null;
    }

    /** Best-effort bound enforcement: current number of tracked nonces. */
    int size() {
        return seenUntil.size();
    }

    private void pruneIfDue(Instant now) {
        boolean overCapacity = seenUntil.size() >= maxTrackedNonces;
        boolean periodicDue = callCount.incrementAndGet() % PRUNE_EVERY_N_CALLS == 0;
        if (overCapacity || periodicDue) {
            seenUntil.entrySet().removeIf(entry -> !entry.getValue().isAfter(now));
        }
    }
}

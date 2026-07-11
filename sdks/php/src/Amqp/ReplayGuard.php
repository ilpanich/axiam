<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

/**
 * NEW-4 (CONTRACT.md §8 "v2 — Replay Protection", hard cutover) validation
 * gates, checked ONLY AFTER a delivery's HMAC signature has already
 * verified (see Hmac::verify / Consumer::verifyAndDispatch).
 *
 * Because Hmac::verify re-serializes the parsed body (minus
 * `hmac_signature`) in its original insertion order, `nonce` and
 * `issued_at` are already covered by the verified HMAC bytes — this class
 * adds no canonicalization logic of its own. It only enforces the three
 * ADDITIONAL gates the server also enforces (crates/axiam-amqp/src/messages.rs):
 *
 *   (a) `key_version` must be >= {@see self::MIN_KEY_VERSION} (2) — a v1
 *       message (no replay protection fields) is rejected outright, no
 *       grace window.
 *   (b) `issued_at` (RFC3339/ISO8601 UTC) must lie within ±skew of "now".
 *   (c) `nonce` must not have been seen before within the dedup window.
 *
 * The nonce dedup store is a plain in-memory `nonce => expiry` map with a
 * TTL of 2×skew: a nonce cannot legitimately recur once its message has
 * aged out of the ±skew freshness window, so entries older than 2×skew are
 * pruned opportunistically on every check — bounded memory, no background
 * process. This is a defense-in-depth client-side check only (resets on
 * process restart); the server maintains the durable, cross-process nonce
 * store.
 *
 * ONE instance MUST be shared across every delivery handled by a given
 * Consumer (see Consumer::__construct) — a fresh guard per message would
 * defeat replay dedup entirely.
 */
final class ReplayGuard
{
    /**
     * The lowest AMQP signed-envelope key_version this SDK will accept
     * (NEW-4). A message with key_version below this predates the mandatory
     * nonce/issued_at replay-protection fields and is rejected outright —
     * a hard cutover, there is no v1 grace path (mirrors
     * crates/axiam-amqp/src/messages.rs MIN_ACCEPTED_KEY_VERSION).
     */
    public const MIN_KEY_VERSION = 2;

    /**
     * Default freshness window (seconds) applied to `issued_at`, matching
     * the server's DEFAULT_FRESHNESS_SKEW_SECS = 300 /
     * AXIAM__AMQP__REPLAY_SKEW_SECS (CONTRACT.md §8 v2).
     */
    public const DEFAULT_SKEW_SECONDS = 300;

    /** @var array<string, int> nonce -> unix-timestamp expiry */
    private array $seen = [];

    /**
     * @param int $skewSeconds Freshness window (seconds) for `issued_at`;
     *        also sets the nonce dedup TTL (2×skewSeconds). Must be > 0.
     * @param (callable(): int)|null $clock Overridable "now" source
     *        (unix timestamp), for deterministic tests. Defaults to
     *        `time()`.
     */
    public function __construct(
        private readonly int $skewSeconds = self::DEFAULT_SKEW_SECONDS,
        private $clock = null,
    ) {
        if ($this->skewSeconds <= 0) {
            throw new \InvalidArgumentException('skewSeconds must be > 0');
        }
        $this->clock ??= static fn (): int => time();
    }

    /**
     * Validates $message (the decoded body, `hmac_signature` already
     * removed, HMAC already verified by the caller) against the NEW-4
     * replay-protection policy.
     *
     * Returns null iff all three gates pass, in which case `nonce` has also
     * been recorded (so a second delivery of the same nonce is rejected as
     * a replay). Otherwise returns the name of the first failing gate
     * ('key_version', 'issued_at', or 'nonce') — callers treat any non-null
     * result identically (nack without requeue, security event logged,
     * handler never invoked); the string is for logging/debugging only.
     *
     * @param array<string, mixed> $message
     */
    public function check(array $message): ?string
    {
        $keyVersion = $message['key_version'] ?? null;
        if (!is_int($keyVersion) || $keyVersion < self::MIN_KEY_VERSION) {
            return 'key_version';
        }

        $issuedAt = $message['issued_at'] ?? null;
        if (!is_string($issuedAt) || $issuedAt === '') {
            return 'issued_at';
        }

        $issuedAtTs = self::parseIso8601($issuedAt);
        if ($issuedAtTs === null) {
            return 'issued_at';
        }

        $now = ($this->clock)();
        if (abs($now - $issuedAtTs) > $this->skewSeconds) {
            return 'issued_at';
        }

        $nonce = $message['nonce'] ?? null;
        if (!is_string($nonce) || $nonce === '') {
            return 'nonce';
        }

        $this->prune($now);

        if (isset($this->seen[$nonce])) {
            return 'nonce'; // replay
        }

        // TTL = 2xskew (freshness window width): a nonce outside this age
        // could never have passed the freshness check above anyway, so this
        // alone keeps the map bounded without a background pruning process.
        $this->seen[$nonce] = $now + (2 * $this->skewSeconds);

        return null;
    }

    /** @return int Number of nonces currently tracked (test/introspection helper). */
    public function trackedNonceCount(): int
    {
        return count($this->seen);
    }

    private function prune(int $now): void
    {
        foreach ($this->seen as $nonce => $expiry) {
            if ($expiry <= $now) {
                unset($this->seen[$nonce]);
            }
        }
    }

    private static function parseIso8601(string $value): ?int
    {
        try {
            $dt = new \DateTimeImmutable($value);
        } catch (\Exception) {
            return null; // malformed timestamp -> reject, never throw
        }

        return $dt->getTimestamp();
    }
}

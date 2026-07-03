<?php

declare(strict_types=1);

namespace Axiam\Sdk\Amqp;

/**
 * HMAC-SHA256 verify-before-handler primitive for inbound AMQP messages
 * (sdks/CONTRACT.md §8).
 *
 * Byte-for-byte port of crates/axiam-amqp/src/messages.rs::verify_payload.
 * Never throws — malformed input verifies as false (strict-mode default, §8.3).
 *
 * CRITICAL: json_decode($body, true) into a PHP associative array preserves the
 * EXACT insertion/wire order the message arrived in (PHP arrays are ordered maps)
 * — this matches the server's serde_json struct-field-declaration order WITHOUT
 * any extra sorting logic. Do NOT alphabetize or otherwise reorder the decoded
 * array's keys before canonicalization — that reorders fields and breaks 100%
 * of verifications against the server's real signatures (same fix class as
 * every sibling SDK's discovery that the canonical bytes are wire order, not
 * alphabetical).
 *
 * THE PHP-SPECIFIC TRAP: json_encode() escapes forward slashes ("/" -> "\/") and
 * non-ASCII characters (-> "\uXXXX") BY DEFAULT. serde_json::to_vec does neither.
 * Omitting JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE produces a byte
 * sequence that will NEVER match the server's signature for any payload
 * containing a slash or non-ASCII text (Pitfall 1).
 */
final class Hmac
{
    /**
     * Returns true iff $body's `hmac_signature` field matches
     * HMAC-SHA256($signingKey, canonical_json_of(body_without_hmac_signature)),
     * computed via a constant-time comparison.
     *
     * Never throws: malformed JSON, a non-object body, a missing/non-string
     * signature, non-hex signature text, or a wrong-length signature all
     * verify as false — matching §8.3's strict-mode default that rejects
     * (rather than silently accepts) an unparseable or absent signature.
     */
    public static function verify(string $signingKey, string $body): bool
    {
        $msg = json_decode($body, true);
        if (!is_array($msg)) {
            return false; // malformed JSON / non-object body -> reject
        }
        if (!isset($msg['hmac_signature']) || !is_string($msg['hmac_signature'])) {
            return false; // §8.3 strict mode: missing/non-string signature = reject
        }
        $sigHex = $msg['hmac_signature'];
        unset($msg['hmac_signature']); // remaining array keeps its original insertion order

        $canonical = json_encode($msg, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($canonical === false) {
            return false;
        }

        $expected = @hex2bin($sigHex);
        if ($expected === false) {
            return false; // non-hex signature -> reject, never throw
        }

        $computed = hash_hmac('sha256', $canonical, $signingKey, true);

        return hash_equals($expected, $computed); // hash_equals() is PHP's constant-time compare
    }
}

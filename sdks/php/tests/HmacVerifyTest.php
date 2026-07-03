<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Amqp\Hmac;
use PHPUnit\Framework\TestCase;

/**
 * Proves Hmac::verify reproduces the server's byte-for-byte wire-order
 * canonical JSON HMAC-SHA256 (sdks/CONTRACT.md §8) against the real,
 * Rust-signed tests/Fixtures/amqp_hmac_vectors.json vectors.
 */
final class HmacVerifyTest extends TestCase
{
    /** @return array<int, array{name: string, signing_key_hex: string, message: array<string, mixed>, expected_valid: bool}> */
    private static function loadVectors(): array
    {
        $path = __DIR__ . '/Fixtures/amqp_hmac_vectors.json';
        $decoded = json_decode((string) file_get_contents($path), true);

        return $decoded['vectors'];
    }

    /**
     * Reconstructs the exact bytes that would arrive over the wire for a
     * fixture vector's "message" object: compact JSON preserving the field
     * order the fixture file recorded (Rust struct declaration order).
     *
     * @param array<string, mixed> $message
     */
    private static function canonicalBody(array $message): string
    {
        $encoded = json_encode($message, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        self::assertIsString($encoded);

        return $encoded;
    }

    /** @param array<int, array{name: string}> $vectors */
    private static function find(array $vectors, string $name): array
    {
        foreach ($vectors as $vector) {
            if ($vector['name'] === $name) {
                return $vector;
            }
        }

        self::fail("fixture vector '{$name}' not found");
    }

    public function testAllFixtureVectorsVerifyMatchesExpectedValidity(): void
    {
        foreach (self::loadVectors() as $vector) {
            $key = hex2bin($vector['signing_key_hex']);
            $body = self::canonicalBody($vector['message']);

            $actual = Hmac::verify($key, $body);

            self::assertSame(
                $vector['expected_valid'],
                $actual,
                "vector '{$vector['name']}' expected {$this->boolStr($vector['expected_valid'])} but Hmac::verify returned {$this->boolStr($actual)}"
            );
        }
    }

    /**
     * The slash + non-ASCII regression case (Pitfall 1): it must verify true
     * with the correct escaping flags, and this test independently confirms
     * that removing JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE from the
     * canonicalization would make it (and only it) go red.
     */
    public function testSlashAndNonAsciiVectorIsEscapingRegressionGuard(): void
    {
        $vectors = self::loadVectors();
        $vector = self::find($vectors, 'authz_request_slash_nonascii_valid');

        self::assertStringContainsString('/', $vector['message']['action']);
        self::assertMatchesRegularExpression('/[^\x00-\x7F]/', $vector['message']['action']);

        $key = hex2bin($vector['signing_key_hex']);
        $sigHex = $vector['message']['hmac_signature'];
        $withoutSig = $vector['message'];
        unset($withoutSig['hmac_signature']);

        // Correct canonicalization (flags present) -> verifies true.
        $canonicalCorrect = json_encode($withoutSig, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        $expected = hex2bin($sigHex);
        $computedCorrect = hash_hmac('sha256', $canonicalCorrect, $key, true);
        self::assertTrue(hash_equals($expected, $computedCorrect), 'correctly-escaped canonicalization must verify true');

        // Broken canonicalization (default json_encode escaping) -> verifies false.
        $canonicalBroken = json_encode($withoutSig);
        $computedBroken = hash_hmac('sha256', $canonicalBroken, $key, true);
        self::assertFalse(hash_equals($expected, $computedBroken), 'default-escaped canonicalization must NOT verify (regression proof)');

        // The actual Hmac::verify call (using the correctly-escaped fixture body) must pass.
        self::assertTrue(Hmac::verify($key, self::canonicalBody($vector['message'])));
    }

    public function testTamperedActionFailsVerificationNonVacuous(): void
    {
        $vectors = self::loadVectors();
        $valid = self::find($vectors, 'authz_request_valid');
        $tampered = self::find($vectors, 'authz_request_tampered_action');

        $key = hex2bin($valid['signing_key_hex']);

        self::assertTrue(Hmac::verify($key, self::canonicalBody($valid['message'])), 'baseline vector must verify true');
        self::assertFalse(Hmac::verify($key, self::canonicalBody($tampered['message'])), 'tampered-action vector must verify false');
    }

    public function testWrongKeyFailsVerificationNonVacuous(): void
    {
        $vectors = self::loadVectors();
        $valid = self::find($vectors, 'audit_event_valid');
        $wrongKey = self::find($vectors, 'audit_event_wrong_key');

        $correctKey = hex2bin($valid['signing_key_hex']);
        $incorrectKey = hex2bin($wrongKey['signing_key_hex']);
        $body = self::canonicalBody($valid['message']);

        self::assertTrue(Hmac::verify($correctKey, $body), 'baseline vector must verify true with its own key');
        self::assertFalse(Hmac::verify($incorrectKey, $body), 'same body/signature must verify false under a different key');
    }

    public function testMissingHmacSignatureFailsClosed(): void
    {
        $vector = self::find(self::loadVectors(), 'missing_hmac_signature');
        $key = hex2bin($vector['signing_key_hex']);

        self::assertFalse(Hmac::verify($key, self::canonicalBody($vector['message'])));
    }

    public function testNonHexSignatureFailsClosedWithoutThrowing(): void
    {
        $vector = self::find(self::loadVectors(), 'non_hex_signature');
        $key = hex2bin($vector['signing_key_hex']);

        self::assertFalse(Hmac::verify($key, self::canonicalBody($vector['message'])));
    }

    public function testWrongLengthSignatureFailsClosedWithoutThrowing(): void
    {
        $vector = self::find(self::loadVectors(), 'wrong_length_signature');
        $key = hex2bin($vector['signing_key_hex']);

        self::assertFalse(Hmac::verify($key, self::canonicalBody($vector['message'])));
    }

    public function testNonStringSignatureFailsClosedWithoutThrowing(): void
    {
        $vector = self::find(self::loadVectors(), 'non_string_signature');
        $key = hex2bin($vector['signing_key_hex']);

        self::assertFalse(Hmac::verify($key, self::canonicalBody($vector['message'])));
    }

    public function testMalformedInputNeverThrowsReturnsFalse(): void
    {
        $key = "\x01\x02\x03\x04";

        self::assertFalse(Hmac::verify($key, 'not json at all'));
        self::assertFalse(Hmac::verify($key, ''));
        self::assertFalse(Hmac::verify($key, '[1,2,3]')); // valid JSON, not an object
        self::assertFalse(Hmac::verify($key, '"just a string"'));
        self::assertFalse(Hmac::verify($key, '{}')); // object but no hmac_signature key
    }

    private function boolStr(bool $value): string
    {
        return $value ? 'true' : 'false';
    }
}

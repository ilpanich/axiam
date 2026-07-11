<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Amqp\Hmac;
use Axiam\Sdk\Amqp\ReplayGuard;
use PHPUnit\Framework\TestCase;

/**
 * NEW-4 ground-truth parity test. `crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json`
 * contains server-generated (Rust `sign_payload`) canonical bytes + expected
 * HMAC for both v2 `AuthzRequest` and `AuditEventMessage` (CONTRACT.md §8 "v2
 * — Replay Protection"). This is the ground truth for every SDK, not
 * PHP-owned — read directly from the crates fixture rather than a local
 * copy, so it can never drift from the authoritative vectors.
 *
 * Proves:
 *   1. The HKDF-SHA256 per-tenant subkey derivation reproduces
 *      `derived_subkey_hex` (traceability only — Hmac::verify's public
 *      contract takes an already-derived per-tenant key, CONTRACT.md §8.1;
 *      the PHP SDK never performs this derivation itself at runtime).
 *   2. HMAC-SHA256(derived_subkey, canonical_signed_json) reproduces
 *      `hmac_signature_hex` byte-for-byte for BOTH message types.
 *   3. The exact consumer decode -> unset(hmac_signature) -> re-encode path
 *      (Hmac::verify's canonicalization) reproduces `canonical_signed_json`
 *      byte-for-byte (Pitfall 5: nonce/issued_at need no special handling).
 *   4. Hmac::verify() ACCEPTS the reconstructed wire delivery.
 *   5. ReplayGuard::check() (the NEW-4 gate) also accepts the same
 *      delivery once its clock is pinned to the fixture's `issued_at`.
 *
 * NOTE on the fixture's "message" object: it is JSON-pretty-printed with
 * alphabetized keys for human readability and is NOT the real wire byte
 * order for an order-preserving decoder. PHP's json_decode(..., true)
 * preserves whatever key order it is given, so this test reconstructs the
 * simulated wire body from `canonical_signed_json` (the real signed byte
 * order) plus `hmac_signature` appended last -- mirroring how the server
 * appends the signature after signing -- rather than decoding the fixture's
 * `message` object directly.
 */
final class V2ReferenceVectorsTest extends TestCase
{
    private const FIXTURE_PATH = __DIR__ . '/../../../crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json';

    /** @return array<string, mixed> */
    private static function loadFixture(): array
    {
        $decoded = json_decode((string) file_get_contents(self::FIXTURE_PATH), true);
        self::assertIsArray($decoded, 'v2_reference_vectors.json must decode to an array');

        return $decoded;
    }

    /**
     * Test-local only: HKDF-SHA256(salt=app_salt, ikm=master,
     * info=domain_tag || key_version(1 byte) || tenant_id(16 raw bytes)),
     * mirroring crates/axiam-amqp/src/messages.rs::derive_tenant_key. The
     * PHP SDK's public Hmac API takes an already-derived per-tenant
     * subkey (CONTRACT.md §8.1, out-of-band provisioning) and never
     * performs this derivation at runtime -- this helper exists purely to
     * prove traceability from the fixture's master key to its subkey.
     */
    private static function deriveTenantKey(string $masterHex, string $tenantId, int $keyVersion, string $appSalt, string $domainTag): string
    {
        $master = hex2bin($masterHex);
        self::assertIsString($master);
        $tenantRaw = hex2bin(str_replace('-', '', $tenantId));
        self::assertIsString($tenantRaw);
        self::assertSame(16, strlen($tenantRaw), 'tenant_id must decode to 16 raw bytes');

        $info = $domainTag . chr($keyVersion) . $tenantRaw;

        return hash_hkdf('sha256', $master, 32, $info, $appSalt);
    }

    public function testDerivesTheSamePerTenantSubkeyAsTheFixture(): void
    {
        $fixture = self::loadFixture();

        $subkey = self::deriveTenantKey(
            $fixture['master_signing_key_hex'],
            $fixture['tenant_id'],
            $fixture['key_version'],
            $fixture['hkdf']['app_salt_utf8'],
            $fixture['hkdf']['domain_tag_utf8'],
        );

        self::assertSame($fixture['hkdf']['derived_subkey_hex'], bin2hex($subkey));
    }

    /** @return array<int, array{string}> */
    public static function messageTypeProvider(): array
    {
        return [
            'authz_request' => ['authz_request'],
            'audit_event' => ['audit_event'],
        ];
    }

    /** @dataProvider messageTypeProvider */
    public function testReproducesTheServerHmacSignatureHexByteForByte(string $messageType): void
    {
        $fixture = self::loadFixture();
        $entry = $fixture[$messageType];
        $subkey = hex2bin($fixture['hkdf']['derived_subkey_hex']);
        self::assertIsString($subkey);

        $computed = hash_hmac('sha256', $entry['canonical_signed_json'], $subkey);

        self::assertSame($entry['hmac_signature_hex'], $computed);
    }

    /**
     * @dataProvider messageTypeProvider
     *
     * Simulates the real wire delivery (canonical bytes + hmac_signature
     * appended last, matching field_order's declared placement of
     * `hmac_signature` after `issued_at`) and proves the consumer's
     * decode -> unset(hmac_signature) -> re-encode path reproduces
     * `canonical_signed_json` exactly, and that Hmac::verify() accepts it.
     */
    public function testRoundTripReproducesCanonicalBytesAndHmacVerifyAccepts(string $messageType): void
    {
        $fixture = self::loadFixture();
        $entry = $fixture[$messageType];
        $canonical = $entry['canonical_signed_json'];
        $subkey = hex2bin($fixture['hkdf']['derived_subkey_hex']);
        self::assertIsString($subkey);

        // Build the simulated wire body: decode the canonical (signed)
        // bytes -- preserving field order as an ordered PHP assoc array --
        // then append hmac_signature as the final key (a new PHP array key
        // is inserted at the end), mirroring the server appending the
        // signature after signing.
        $ordered = json_decode($canonical, true);
        self::assertIsArray($ordered);
        $ordered['hmac_signature'] = $entry['hmac_signature_hex'];
        $wireBody = json_encode($ordered, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        self::assertIsString($wireBody);

        // The exact Hmac::verify canonicalization path: decode, unset
        // hmac_signature, re-encode with the SAME flags used by the SDK
        // (JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) so canonical
        // bytes match the server's serde_json output.
        $decoded = json_decode($wireBody, true);
        self::assertIsArray($decoded);
        unset($decoded['hmac_signature']);
        $reencoded = json_encode($decoded, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        self::assertSame($canonical, $reencoded, 'decode -> unset(hmac_signature) -> re-encode must reproduce canonical_signed_json byte-for-byte');

        self::assertTrue(Hmac::verify($subkey, $wireBody), 'Hmac::verify must ACCEPT the server-signed v2 reference vector');
    }

    /**
     * @dataProvider messageTypeProvider
     *
     * Full-pipeline proof: once the HMAC verifies, ReplayGuard::check()
     * (the NEW-4 gate) also accepts the same genuine v2 delivery -- using a
     * clock pinned to the fixture's own `issued_at` so this assertion never
     * depends on how much wall-clock time has passed since the fixture was
     * generated.
     */
    public function testReplayGuardAcceptsTheGenuineV2Delivery(string $messageType): void
    {
        $fixture = self::loadFixture();
        $entry = $fixture[$messageType];
        $ordered = json_decode($entry['canonical_signed_json'], true);
        self::assertIsArray($ordered);

        $fixedNow = (new \DateTimeImmutable($ordered['issued_at']))->getTimestamp();
        $guard = new ReplayGuard(ReplayGuard::DEFAULT_SKEW_SECONDS, static fn (): int => $fixedNow);

        self::assertNull($guard->check($ordered));
    }
}

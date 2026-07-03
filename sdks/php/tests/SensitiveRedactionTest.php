<?php

declare(strict_types=1);

namespace Axiam\Sdk\Tests;

use Axiam\Sdk\Core\NetworkError;
use Axiam\Sdk\Core\Sensitive;
use GuzzleHttp\Psr7\Response;
use PHPUnit\Framework\TestCase;

/**
 * CR-04 carry-forward regression test (D-11): proves that raw `axiam_access` /
 * `axiam_refresh` token values, and raw `Set-Cookie`/`Authorization` header values,
 * never reach `__toString()`, `json_encode()`, `print_r()`, or `getMessage()` output.
 *
 * Each assertion pairs a NEGATIVE check (secret absent) with a POSITIVE, non-vacuous
 * control check (a benign marker IS present) — mirroring the C#/Python sibling tests'
 * control-case discipline, so this test would go red (not silently pass) if the
 * redaction logic were removed or if it over-redacted everything.
 */
final class SensitiveRedactionTest extends TestCase
{
    private const RAW_ACCESS_TOKEN = 'axiam_access=secret-abc';
    private const RAW_REFRESH_COOKIE_VALUE = 'axiam_refresh=refresh-xyz';
    private const RAW_BEARER_TOKEN = 'Bearer tok-123';

    public function testSensitiveToStringIsRedacted(): void
    {
        $sensitive = new Sensitive(self::RAW_ACCESS_TOKEN);

        $stringified = (string) $sensitive;

        self::assertSame('[SENSITIVE]', $stringified);
        self::assertStringNotContainsString('secret-abc', $stringified);
    }

    public function testSensitiveJsonSerializationIsRedacted(): void
    {
        $sensitive = new Sensitive(self::RAW_ACCESS_TOKEN);

        $json = json_encode($sensitive);

        self::assertIsString($json);
        self::assertSame('"[SENSITIVE]"', $json);
        self::assertStringNotContainsString('secret-abc', $json);
    }

    public function testSensitivePrintRIsRedacted(): void
    {
        $sensitive = new Sensitive(self::RAW_ACCESS_TOKEN);

        $dump = print_r($sensitive, true);

        self::assertStringNotContainsString('secret-abc', $dump);
    }

    /**
     * Non-vacuous control: reveal() is the documented escape hatch and MUST still
     * return the real value — proving the assertions above are about *display/
     * serialization* redaction, not that the value was discarded entirely.
     */
    public function testSensitiveRevealReturnsRealValue(): void
    {
        $sensitive = new Sensitive(self::RAW_ACCESS_TOKEN);

        self::assertSame(self::RAW_ACCESS_TOKEN, $sensitive->reveal());
    }

    public function testNetworkErrorRedactsSetCookieAndAuthorizationHeaders(): void
    {
        $response = new Response(
            401,
            [
                'Set-Cookie' => self::RAW_REFRESH_COOKIE_VALUE,
                'Authorization' => self::RAW_BEARER_TOKEN,
                // Non-vacuous control: a benign, non-secret header whose value MUST
                // survive into the message. If redaction over-redacted (e.g. stripped
                // every header value, not just the sensitive three), this would fail.
                'X-Request-Id' => 'req-marker-present',
            ],
            'unauthorized',
        );

        $error = NetworkError::fromResponse($response, 'refresh failed');

        foreach ([$error->getMessage(), (string) $error, (string) json_encode(['message' => $error->getMessage()])] as $surface) {
            self::assertStringNotContainsString('refresh-xyz', $surface);
            self::assertStringNotContainsString('tok-123', $surface);
            self::assertStringContainsString('req-marker-present', $surface);
        }
    }

    public function testNetworkErrorRedactsCookieRequestHeaderEcho(): void
    {
        // Some transports echo request-side Cookie values into a response header
        // (e.g. a proxy/debug header) — the "Cookie" name itself must be redacted too,
        // not just "Set-Cookie".
        $response = new Response(
            403,
            [
                'Cookie' => 'axiam_access=secret-abc; axiam_refresh=refresh-xyz',
                'X-Request-Id' => 'req-marker-present',
            ],
            'forbidden',
        );

        $error = NetworkError::fromResponse($response, 'checkAccess failed');

        self::assertStringNotContainsString('secret-abc', $error->getMessage());
        self::assertStringNotContainsString('refresh-xyz', $error->getMessage());
        self::assertStringContainsString('req-marker-present', $error->getMessage());
    }
}

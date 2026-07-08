package io.axiam.sdk.internal;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * X-4/SDK-13 regression test for {@link TokenPair}: the record's overridden
 * {@code toString()} must never surface the raw access/refresh tokens (which a
 * record's auto-generated {@code toString()} would print verbatim), while the
 * field accessors still return the real values for in-SDK use.
 */
class TokenPairTest {

    private static final String ACCESS = "access-super-secret-abc123";
    private static final String REFRESH = "refresh-super-secret-xyz789";

    @Test
    void toStringRedactsBothTokens() {
        TokenPair pair = new TokenPair(ACCESS, REFRESH, 1_700_000_000_000L);

        String rendered = pair.toString();

        assertFalse(rendered.contains(ACCESS), "toString() must never contain the raw access token");
        assertFalse(rendered.contains(REFRESH), "toString() must never contain the raw refresh token");
        assertEquals("TokenPair[access=***, refresh=***, expiresAtEpochMs=1700000000000]", rendered);
    }

    @Test
    void accessorsStillReturnRawValues() {
        TokenPair pair = new TokenPair(ACCESS, REFRESH, 42L);

        assertTrue(pair.access().equals(ACCESS), "access() must still return the raw token for in-SDK callers");
        assertTrue(pair.refresh().equals(REFRESH), "refresh() must still return the raw token for in-SDK callers");
        assertEquals(42L, pair.expiresAtEpochMs());
    }
}

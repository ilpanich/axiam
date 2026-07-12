package io.axiam.sdk.errors;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.SocketTimeoutException;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * SDK-Q02 / CONTRACT.md &sect;2 MUST: "NetworkError MUST carry the
 * underlying OS/transport error as a cause (or equivalent chained
 * exception)". Before this fix, {@code NetworkError(String)} always chained
 * a {@code null} cause, so every real transport failure (a caught
 * {@code IOException} from a connect/read failure) produced a
 * {@code NetworkError} with {@code getCause() == null} — silently dropping
 * the original exception. {@link NetworkError#NetworkError(String, Throwable)}
 * fixes this by always chaining a non-null, sanitized cause while never
 * re-exposing the original exception's own (potentially sensitive) message.
 */
class NetworkErrorTest {

    private static final String SENSITIVE_MARKER = "super-secret-token-should-never-leak";

    @Test
    void networkErrorFromTransportFailureHasNonNullCause() {
        IOException transportFailure = new SocketTimeoutException("connect timed out to " + SENSITIVE_MARKER);

        NetworkError networkError = new NetworkError("request failed: " + transportFailure.getMessage(), transportFailure);

        assertNotNull(networkError.getCause(), "getCause() must be non-null for a transport failure");
    }

    @Test
    void networkErrorCauseDoesNotLeakSensitiveMarkerFromOriginalException() {
        IOException transportFailure = new IOException("failed talking to host, token=" + SENSITIVE_MARKER);

        NetworkError networkError = new NetworkError("request failed: [redacted]", transportFailure);

        Throwable cause = networkError.getCause();
        assertNotNull(cause);
        String causeText = cause.toString() + String.valueOf(cause.getMessage());
        assertFalse(causeText.contains(SENSITIVE_MARKER),
                "sanitized cause must never contain the original exception's sensitive text");
        // The cause is still diagnostically useful: it identifies the failure's type.
        assertTrue(causeText.contains("IOException"),
                "sanitized cause should retain the original exception's class name for diagnostics");
    }

    @Test
    void networkErrorSingleArgConstructorStillAllowsNullCauseWhenNoneExists() {
        // A purely programmatic NetworkError with no underlying transport
        // exception at all (e.g. a gRPC status-only mapping) legitimately has
        // no cause to chain.
        NetworkError networkError = new NetworkError("no underlying transport error available");

        assertTrue(networkError.getCause() == null);
    }

    @Test
    void networkErrorFromSanitizedSummaryStringStillHasNonNullCause() {
        NetworkError networkError = new NetworkError("server error", "http status 500, headers: {}");

        assertNotNull(networkError.getCause());
    }
}

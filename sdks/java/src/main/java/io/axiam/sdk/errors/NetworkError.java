package io.axiam.sdk.errors;

import org.jspecify.annotations.Nullable;

/**
 * Transport-level failure: connection refused, timeout, TLS error, DNS
 * failure, or a server-side 5xx (CONTRACT.md &sect;2). Unchecked (D-03).
 *
 * <p><strong>Redact-before-wrap (D-18, CR-04 carry-forward):</strong> the
 * {@code sanitizedSummary} passed to the constructor MUST already have any
 * {@code Set-Cookie}/{@code Authorization}/{@code Cookie} header stripped
 * BEFORE this class ever sees it — {@link ErrorMapper#fromHttpResponse}
 * (via its private {@code sanitize(Response)} step) is the single, only
 * caller-facing path from a live {@code okhttp3.Response} into a
 * {@code NetworkError}. This constructor never accepts a live
 * {@code okhttp3.Response} directly, by design: there is no overload for
 * it, which structurally prevents a raw, unredacted response from reaching
 * the exception chain.
 */
public final class NetworkError extends RuntimeException {

    public NetworkError(String message) {
        this(message, (String) null);
    }

    /**
     * @param message          caller-controlled, human-readable description;
     *                         MUST NOT contain a raw token value
     * @param sanitizedSummary an already-redacted transport-error summary
     *                         (e.g. {@code "http status 500, headers: ..."}
     *                         with sensitive headers already stripped), or
     *                         {@code null} when there is nothing to attach
     *                         (e.g. a gRPC status with no response body)
     */
    public NetworkError(String message, @Nullable String sanitizedSummary) {
        super(message, sanitizedSummary == null ? null : new RuntimeException(sanitizedSummary));
    }
}

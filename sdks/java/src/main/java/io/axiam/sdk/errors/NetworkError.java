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
        super(message, sanitizedSummary == null ? null : new SanitizedCause(sanitizedSummary));
    }

    /**
     * Chains an underlying transport failure (a caught {@code IOException},
     * {@code GeneralSecurityException}, gRPC {@code Throwable}, etc.) onto a
     * {@link NetworkError} as its {@link Throwable#getCause() cause}
     * (CONTRACT.md &sect;2 MUST: "NetworkError MUST carry the underlying
     * OS/transport error as a cause"). Before this constructor existed, call
     * sites embedded {@code originalCause.getMessage()} into the outer
     * {@code message} string but never chained {@code originalCause} itself
     * — so {@code getCause()} was always {@code null} for every real
     * transport failure. This restores the cause link while still never
     * exposing {@code originalCause} directly: only its (inherently
     * non-secret) class name is retained in the chained
     * {@link SanitizedCause}, never {@code originalCause}'s own message or
     * stack trace, which could in principle echo back request state (a URL,
     * a partial header) that must not resurface in a thrown error.
     *
     * @param message       caller-controlled, human-readable description;
     *                      MUST NOT contain a raw token value
     * @param originalCause the real transport exception that triggered this
     *                      {@link NetworkError}; never retained directly,
     *                      only its class name
     */
    public NetworkError(String message, Throwable originalCause) {
        super(message, new SanitizedCause(originalCause.getClass().getName()));
    }

    /**
     * A minimal, redaction-safe stand-in for a real transport exception:
     * carries only an already-sanitized summary as its message and no
     * stack trace of its own construction site beyond this one, so it can
     * never smuggle an unredacted header/token value that the original
     * exception's message or cause chain might have held.
     */
    static final class SanitizedCause extends RuntimeException {
        SanitizedCause(String sanitizedMessage) {
            super(sanitizedMessage);
        }
    }
}

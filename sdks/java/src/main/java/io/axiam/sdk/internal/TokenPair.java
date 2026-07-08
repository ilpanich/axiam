package io.axiam.sdk.internal;

/**
 * The result of a successful login/refresh: an access token, a (rotating,
 * single-use) refresh token, and the access token's expiry.
 *
 * <p>Immutable value type (D-04). {@link #access()} is the accessor
 * {@link RefreshGuard}'s double-check comparison reads.
 *
 * @param access           the current access token
 * @param refresh          the current refresh token
 * @param expiresAtEpochMs the access token's expiry, in epoch milliseconds
 */
public record TokenPair(String access, String refresh, long expiresAtEpochMs) {

    /**
     * Redacted {@code toString()} (X-4/SDK-13): {@code access} and
     * {@code refresh} are bearer credentials — the record's auto-generated
     * {@code toString()} would print them verbatim, leaking both tokens into
     * logs, stack traces, and debugger dumps. Mirrors {@link io.axiam.sdk.Sensitive}'s
     * redaction posture (never surface a raw token via {@code toString()}); the
     * non-secret {@code expiresAtEpochMs} is kept for diagnostics. Field
     * accessors ({@link #access()}, {@link #refresh()}) are untouched, so
     * legitimate in-SDK callers still read the raw values.
     */
    @Override
    public String toString() {
        return "TokenPair[access=***, refresh=***, expiresAtEpochMs=" + expiresAtEpochMs + "]";
    }
}

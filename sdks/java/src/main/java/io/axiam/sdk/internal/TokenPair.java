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
}

package io.axiam.sdk.errors;

/**
 * Authentication failure: wrong credentials, expired session, MFA failure,
 * or a 401 on refresh (CONTRACT.md &sect;2). Unchecked (D-03) — composes
 * with lambdas/streams/{@code CompletableFuture} without a forced
 * {@code throws}.
 *
 * <p>Messages are English-only, no i18n (D-29) — classification is via this
 * typed exception, not localized text.
 */
public final class AuthError extends RuntimeException {

    public AuthError(String message) {
        super(message);
    }
}

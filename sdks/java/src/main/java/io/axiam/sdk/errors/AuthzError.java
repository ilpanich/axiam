package io.axiam.sdk.errors;

import org.jspecify.annotations.Nullable;

/**
 * Authorization failure: the caller is authenticated but lacks permission
 * for the requested operation (CONTRACT.md &sect;2). Unchecked (D-03).
 *
 * <p>{@link #action} and {@link #resourceId} are populated when available
 * from the response body (CONTRACT.md &sect;2 "Error Construction Rules");
 * both may be {@code null} when the server did not report them.
 *
 * <p>Messages are English-only, no i18n (D-29).
 */
public final class AuthzError extends RuntimeException {

    private final @Nullable String action;
    private final @Nullable String resourceId;

    public AuthzError(String message) {
        this(message, null, null);
    }

    public AuthzError(String message, @Nullable String action, @Nullable String resourceId) {
        super(message);
        this.action = action;
        this.resourceId = resourceId;
    }

    public @Nullable String action() {
        return action;
    }

    public @Nullable String resourceId() {
        return resourceId;
    }
}

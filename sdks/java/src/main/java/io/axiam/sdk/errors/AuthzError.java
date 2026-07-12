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

    /** The denied action, or {@code null} if the server did not report one. */
    private final @Nullable String action;
    /** The denied resource's identifier, or {@code null} if the server did not report one. */
    private final @Nullable String resourceId;

    /**
     * Creates an {@code AuthzError} with no known action/resource (the server
     * did not report them).
     *
     * @param message a human-readable description of the denial
     */
    public AuthzError(String message) {
        this(message, null, null);
    }

    /**
     * Creates an {@code AuthzError} with the action/resource reported by the
     * server's 403/409 body (CONTRACT.md &sect;2 "Error Construction Rules").
     *
     * @param message    a human-readable description of the denial
     * @param action     the denied action, or {@code null} if not reported
     * @param resourceId the denied resource's identifier, or {@code null} if
     *                   not reported (e.g. a non-resource-scoped denial)
     */
    public AuthzError(String message, @Nullable String action, @Nullable String resourceId) {
        super(message);
        this.action = action;
        this.resourceId = resourceId;
    }

    /** Returns the denied action.
     *
     * @return the denied action, or {@code null} if the server did not report one */
    public @Nullable String action() {
        return action;
    }

    /** Returns the denied resource's identifier.
     *
     * @return the denied resource's identifier, or {@code null} if the server did
     *         not report one (e.g. a non-resource-scoped denial) */
    public @Nullable String resourceId() {
        return resourceId;
    }
}

package io.axiam.sdk;

import java.util.List;

/**
 * Authenticated user identity returned as part of a completed
 * {@link LoginResult} (D-04).
 *
 * @param userId   the authenticated user's id
 * @param tenantId the tenant the user authenticated into
 * @param roles    the user's roles within {@code tenantId}
 */
public record AxiamUser(String userId, String tenantId, List<String> roles) {
}

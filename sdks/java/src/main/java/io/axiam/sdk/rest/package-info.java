/**
 * The AXIAM Java SDK's REST transport (CONTRACT.md &sect;1&ndash;&sect;6,
 * &sect;9). {@link io.axiam.sdk.rest.AuthInterceptor} performs proactive
 * (near-expiry) refresh plus tenant/CSRF/bearer header injection;
 * {@link io.axiam.sdk.rest.AuthAuthenticator} is the reactive 401 fallback.
 * Both funnel into the single shared {@link io.axiam.sdk.internal.RefreshGuard}
 * owned by {@link io.axiam.sdk.AxiamClient} (D-08) — never a second guard.
 *
 * <p>Types in this package are registered on the SDK's internal
 * {@code OkHttpClient} by {@code AxiamClient}; they are not constructed
 * directly by SDK consumers, whose entry point is {@code AxiamClient} itself.
 */
@NullMarked
package io.axiam.sdk.rest;

import org.jspecify.annotations.NullMarked;

/**
 * Error taxonomy for the AXIAM Java SDK (CONTRACT.md &sect;2, D-18).
 *
 * <p>{@link io.axiam.sdk.errors.ErrorMapper} is the single, central
 * status&rarr;error mapper shared by every transport (REST/gRPC) so they
 * cannot drift on the error taxonomy, and the single choke point through
 * which a live {@code okhttp3.Response} may become a
 * {@link io.axiam.sdk.errors.NetworkError} (redact-before-wrap, CR-04
 * carry-forward).
 */
@NullMarked
package io.axiam.sdk.errors;

import org.jspecify.annotations.NullMarked;

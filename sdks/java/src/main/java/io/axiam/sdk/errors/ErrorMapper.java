package io.axiam.sdk.errors;

import okhttp3.Headers;
import okhttp3.Response;
import org.jspecify.annotations.Nullable;

import java.util.Locale;
import java.util.Set;

/**
 * Central status&rarr;error mapper (CONTRACT.md &sect;2, D-18). The single
 * source of truth for both REST and gRPC transports so the two cannot drift
 * on the error taxonomy — transcribes CONTRACT.md &sect;2's HTTP and gRPC
 * tables exactly.
 *
 * <p>{@link #sanitize(Response)} is the SINGLE and ONLY path from a live
 * {@code okhttp3.Response} into a {@link NetworkError}: it redacts every
 * header that is not on a small ALLOWLIST of known-safe headers and
 * returns a lightweight, redacted STRING summary — it never retains a
 * reference to the live {@code Response} object itself, which would keep
 * the unredacted headers reachable (D-18, CR-04 carry-forward: redact
 * BEFORE wrap, never after).
 */
public final class ErrorMapper {

    // ALLOWLIST (X-3): only these response headers are preserved verbatim in a
    // NetworkError summary; every other header's value is redacted to a
    // placeholder, so a custom sensitive header (e.g. X-Auth-Token) can never
    // survive into a thrown error — unlike a small denylist, which only catches
    // the headers it happens to enumerate. Compared case-insensitively (all
    // entries lower-case). Keep small and strictly non-secret: standard
    // diagnostic response headers plus this SDK's own non-secret request
    // headers (e.g. x-tenant-id).
    private static final Set<String> SAFE_HEADERS = Set.of(
            "content-type", "content-length", "date", "server", "retry-after", "x-request-id", "x-tenant-id");

    /** Placeholder substituted for the value of any non-allowlisted header. */
    private static final String REDACTED_HEADER = "[REDACTED]";

    private ErrorMapper() {
    }

    /**
     * Maps an HTTP status code to an {@link AuthError}/{@link AuthzError}/
     * {@link NetworkError} per CONTRACT.md &sect;2's HTTP status table:
     * 401&rarr;AuthError, 403/409&rarr;AuthzError, everything else
     * (400/408/429/5xx/other)&rarr;NetworkError via {@link #fromHttpResponse}.
     */
    public static RuntimeException fromHttpStatus(int status, String message, @Nullable Response response) {
        if (status == 401) {
            return new AuthError(message);
        }
        if (status == 403 || status == 409) {
            return new AuthzError(message);
        }
        return fromHttpResponse(status, message, response);
    }

    /**
     * Builds a {@link NetworkError} from a live {@code okhttp3.Response}.
     * This is the ONLY entry point through which a live {@code Response}
     * may become a {@link NetworkError} (single choke point, D-18) — every
     * other constructor path in this SDK accepts only an already-sanitized
     * {@code String} summary or no response at all.
     */
    public static NetworkError fromHttpResponse(int status, String message, @Nullable Response response) {
        String sanitizedSummary = sanitize(response);
        return new NetworkError(message, sanitizedSummary);
    }

    /**
     * Maps a gRPC status code to an {@link AuthError}/{@link AuthzError}/
     * {@link NetworkError} per CONTRACT.md &sect;2's gRPC status table:
     * UNAUTHENTICATED&rarr;AuthError, PERMISSION_DENIED&rarr;AuthzError,
     * everything else (UNAVAILABLE/DEADLINE_EXCEEDED/INTERNAL/
     * RESOURCE_EXHAUSTED/other)&rarr;NetworkError.
     */
    public static RuntimeException fromGrpcStatus(io.grpc.Status.Code code, String message) {
        return switch (code) {
            case UNAUTHENTICATED -> new AuthError(message);
            case PERMISSION_DENIED -> new AuthzError(message);
            default -> new NetworkError(message);
        };
    }

    /**
     * Redacts every header not on {@link #SAFE_HEADERS} (case-insensitively)
     * from {@code response}'s headers to a placeholder and returns a
     * lightweight, redacted {@code String} summary — never the live
     * {@code Response} object, whose {@code headers()} would still retain
     * the unredacted values.
     */
    private static @Nullable String sanitize(@Nullable Response response) {
        if (response == null) {
            return null;
        }
        Headers.Builder safe = new Headers.Builder();
        for (String name : response.headers().names()) {
            if (SAFE_HEADERS.contains(name.toLowerCase(Locale.ROOT))) {
                for (String value : response.headers().values(name)) {
                    safe.add(name, value);
                }
            } else {
                safe.add(name, REDACTED_HEADER);
            }
        }
        return "http status " + response.code() + ", headers: " + safe.build();
    }
}

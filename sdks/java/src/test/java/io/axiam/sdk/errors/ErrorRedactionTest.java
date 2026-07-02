package io.axiam.sdk.errors;

import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CR-04 regression test (D-18, carried forward from
 * {@code 17-REVIEW.md} &sect;CR-04 / {@code sdks/go/errors.go} /
 * {@code sdks/typescript/src/core/errorMapper.ts}): proves
 * {@link ErrorMapper} never lets a raw {@code Set-Cookie} token value reach
 * a thrown {@link NetworkError}, while a non-vacuous control header DOES
 * survive into the sanitized summary — proving redaction is selective, not
 * a blanket "redact everything" that would trivially pass.
 */
class ErrorRedactionTest {

    private static final String RAW_TOKEN = "super-secret-token";
    private static final String CONTROL_HEADER_VALUE = "req-123";

    private static Response buildResponse(int code) {
        return new Response.Builder()
                .request(new Request.Builder().url("https://api.axiam.test/api/v1/auth/login").build())
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message("status " + code)
                .header("Set-Cookie", "axiam_access=" + RAW_TOKEN + "; HttpOnly")
                .header("X-Request-Id", CONTROL_HEADER_VALUE)
                .build();
    }

    @Test
    void networkErrorNeverLeaksRawSetCookieToken() {
        Response response = buildResponse(500);

        RuntimeException error = ErrorMapper.fromHttpStatus(500, "server error", response);

        assertInstanceOf(NetworkError.class, error);
        String toStringOutput = error.toString();
        String messageOutput = String.valueOf(error.getMessage());
        assertFalse(toStringOutput.contains(RAW_TOKEN), "toString() must never contain the raw token");
        assertFalse(messageOutput.contains(RAW_TOKEN), "getMessage() must never contain the raw token");

        Throwable cause = error.getCause();
        String causeOutput = cause == null ? "" : String.valueOf(cause.getMessage()) + cause.toString();
        assertFalse(causeOutput.contains(RAW_TOKEN), "cause chain must never contain the raw token");
    }

    @Test
    void networkErrorSanitizedSummaryRetainsNonSensitiveControlHeader() {
        // Non-vacuous control: a benign header MUST survive redaction,
        // proving sanitize() is selective rather than a blanket wipe.
        Response response = buildResponse(500);

        RuntimeException error = ErrorMapper.fromHttpStatus(500, "server error", response);
        NetworkError networkError = (NetworkError) error;

        String summary = networkError.toString() + String.valueOf(networkError.getCause());
        assertTrue(summary.contains(CONTROL_HEADER_VALUE),
                "control header X-Request-Id value must survive into the sanitized summary");
    }

    @Test
    void httpStatusMappingMatchesContract() {
        assertInstanceOf(AuthError.class, ErrorMapper.fromHttpStatus(401, "unauthenticated", buildResponse(401)));
        assertInstanceOf(AuthzError.class, ErrorMapper.fromHttpStatus(403, "forbidden", buildResponse(403)));
        assertInstanceOf(AuthzError.class, ErrorMapper.fromHttpStatus(409, "conflict", buildResponse(409)));
        assertInstanceOf(NetworkError.class, ErrorMapper.fromHttpStatus(400, "bad request", buildResponse(400)));
        assertInstanceOf(NetworkError.class, ErrorMapper.fromHttpStatus(429, "rate limited", buildResponse(429)));
        assertInstanceOf(NetworkError.class, ErrorMapper.fromHttpStatus(503, "unavailable", buildResponse(503)));
    }

    @Test
    void grpcStatusMappingMatchesContract() {
        assertInstanceOf(AuthError.class,
                ErrorMapper.fromGrpcStatus(io.grpc.Status.Code.UNAUTHENTICATED, "unauthenticated"));
        assertInstanceOf(AuthzError.class,
                ErrorMapper.fromGrpcStatus(io.grpc.Status.Code.PERMISSION_DENIED, "permission denied"));
        assertInstanceOf(NetworkError.class,
                ErrorMapper.fromGrpcStatus(io.grpc.Status.Code.UNAVAILABLE, "unavailable"));
        assertInstanceOf(NetworkError.class,
                ErrorMapper.fromGrpcStatus(io.grpc.Status.Code.DEADLINE_EXCEEDED, "deadline exceeded"));
        assertInstanceOf(NetworkError.class,
                ErrorMapper.fromGrpcStatus(io.grpc.Status.Code.INTERNAL, "internal"));
        assertInstanceOf(NetworkError.class,
                ErrorMapper.fromGrpcStatus(io.grpc.Status.Code.RESOURCE_EXHAUSTED, "resource exhausted"));
    }

    @Test
    void authAndAuthzErrorsAreUncheckedRuntimeExceptions() {
        assertEquals(RuntimeException.class, AuthError.class.getSuperclass());
        assertEquals(RuntimeException.class, AuthzError.class.getSuperclass());
        assertEquals(RuntimeException.class, NetworkError.class.getSuperclass());
    }
}

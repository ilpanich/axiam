package io.axiam.sdk.errors;

import okhttp3.MediaType;
import okhttp3.Protocol;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNull;

/**
 * SDK-Q02: proves {@link ErrorMapper#fromHttpStatus} parses the server's
 * structured authorization-denied body (CONTRACT.md &sect;2 "Error
 * Construction Rules") into {@link AuthzError#action()} /
 * {@link AuthzError#resourceId()} for a 403 response, distinguishing a
 * resource-scoped denial (both fields present) from a global-action denial
 * ({@code resource_id} absent).
 */
class ErrorMapperTest {

    private static Response buildResponse(int code, String jsonBody) {
        ResponseBody body = ResponseBody.create(jsonBody, MediaType.get("application/json; charset=utf-8"));
        return new Response.Builder()
                .request(new Request.Builder().url("https://api.axiam.test/api/v1/authz/check").build())
                .protocol(Protocol.HTTP_1_1)
                .code(code)
                .message("status " + code)
                .body(body)
                .build();
    }

    @Test
    void authzErrorCarriesActionAndResourceIdWhenBothPresent() {
        String json = "{\"error\":\"authorization_denied\",\"message\":\"not allowed\","
                + "\"action\":\"users:get\",\"resource_id\":\"a1b2c3d4-0000-0000-0000-000000000000\"}";
        Response response = buildResponse(403, json);

        RuntimeException error = ErrorMapper.fromHttpStatus(403, "forbidden", response);

        AuthzError authzError = assertInstanceOf(AuthzError.class, error);
        assertEquals("users:get", authzError.action());
        assertEquals("a1b2c3d4-0000-0000-0000-000000000000", authzError.resourceId());
    }

    @Test
    void authzErrorHasNullResourceIdWhenOnlyActionPresent() {
        String json = "{\"error\":\"authorization_denied\",\"message\":\"not allowed\",\"action\":\"users:list\"}";
        Response response = buildResponse(403, json);

        RuntimeException error = ErrorMapper.fromHttpStatus(403, "forbidden", response);

        AuthzError authzError = assertInstanceOf(AuthzError.class, error);
        assertEquals("users:list", authzError.action());
        assertNull(authzError.resourceId());
    }

    @Test
    void authzErrorFieldsNullWhenBodyHasNeither() {
        String json = "{\"error\":\"some_other_error\",\"message\":\"conflict\"}";
        Response response = buildResponse(409, json);

        RuntimeException error = ErrorMapper.fromHttpStatus(409, "conflict", response);

        AuthzError authzError = assertInstanceOf(AuthzError.class, error);
        assertNull(authzError.action());
        assertNull(authzError.resourceId());
    }

    @Test
    void authzErrorFallsBackToMessageOnlyWhenNoBody() {
        Response response = new Response.Builder()
                .request(new Request.Builder().url("https://api.axiam.test/api/v1/authz/check").build())
                .protocol(Protocol.HTTP_1_1)
                .code(403)
                .message("status 403")
                .build();

        RuntimeException error = ErrorMapper.fromHttpStatus(403, "forbidden", response);

        AuthzError authzError = assertInstanceOf(AuthzError.class, error);
        assertNull(authzError.action());
        assertNull(authzError.resourceId());
    }
}

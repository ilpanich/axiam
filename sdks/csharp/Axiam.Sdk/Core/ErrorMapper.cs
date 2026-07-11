using System.Net;
using System.Net.Http;
using System.Text.Json;
using Grpc.Core;

namespace Axiam.Sdk.Core;

/// <summary>
/// Central status&#8594;error mapper (CONTRACT.md &#167;2, D-12). The single source of
/// truth for both the HTTP status table and the gRPC status-code table so the REST and
/// gRPC transports cannot drift on the error taxonomy.
/// </summary>
public static class ErrorMapper
{
    /// <summary>
    /// Maps an HTTP status code to an <see cref="AuthError"/>/<see cref="AuthzError"/>/
    /// <see cref="NetworkError"/> per CONTRACT.md &#167;2's HTTP status table:
    /// 401&#8594;<see cref="AuthError"/>; 403/409&#8594;<see cref="AuthzError"/>;
    /// everything else (400/408/429/5xx/other)&#8594;<see cref="NetworkError"/> via
    /// <see cref="NetworkError.FromResponse"/>.
    /// </summary>
    public static Exception FromHttpResponse(HttpResponseMessage response, string context)
    {
        ArgumentNullException.ThrowIfNull(response);
        return (int)response.StatusCode switch
        {
            401 => new AuthError(context),
            403 or 409 => BuildAuthzError(response, context),
            _ => NetworkError.FromResponse(response, context),
        };
    }

    /// <summary>
    /// Builds an <see cref="AuthzError"/> from a 403/409 response, parsing the server's
    /// structured authorization-denied body (<c>{"error":"authorization_denied",
    /// "message":"...","action":"users:get","resource_id":"&lt;uuid&gt;"}</c>) so
    /// <see cref="AuthzError.Action"/>/<see cref="AuthzError.ResourceId"/> are populated
    /// when the server supplied them. <c>action</c> is present when known; <c>resource_id</c>
    /// only for a resource-scoped denial — both are simply absent (null) for a non-authz
    /// 409 or a body the server didn't shape this way. Body parsing is best-effort: a
    /// missing/non-JSON/malformed body never throws out of the error-mapping path itself,
    /// it just falls back to a message-only <see cref="AuthzError"/>.
    /// </summary>
    private static AuthzError BuildAuthzError(HttpResponseMessage response, string context)
    {
        string? action = null;
        string? resourceId = null;
        try
        {
            // Synchronous read is safe here: this path only runs for the error branch of
            // an already-awaited HTTP call, no caller re-reads the content afterwards, and
            // there is no SynchronizationContext in this library/its tests to deadlock on.
            string body = response.Content.ReadAsStringAsync().GetAwaiter().GetResult();
            if (!string.IsNullOrWhiteSpace(body))
            {
                using JsonDocument doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("action", out JsonElement actionEl) &&
                    actionEl.ValueKind == JsonValueKind.String)
                {
                    action = actionEl.GetString();
                }

                if (doc.RootElement.TryGetProperty("resource_id", out JsonElement resourceIdEl) &&
                    resourceIdEl.ValueKind == JsonValueKind.String)
                {
                    resourceId = resourceIdEl.GetString();
                }
            }
        }
        catch (JsonException)
        {
            // Non-JSON or malformed body — fall back to message-only AuthzError.
        }

        return new AuthzError(context, action, resourceId);
    }

    /// <summary>
    /// Overload for callers that only have the status code (no live response) — e.g. a
    /// pre-parsed error body. Never accepts a raw response; use
    /// <see cref="FromHttpResponse"/> when a live <see cref="HttpResponseMessage"/> is
    /// available so <see cref="NetworkError"/> can build its redacted header summary.
    /// </summary>
    public static Exception FromHttpStatus(HttpStatusCode status, string context) =>
        (int)status switch
        {
            401 => new AuthError(context),
            403 or 409 => new AuthzError(context),
            _ => NetworkError.FromException(new InvalidOperationException($"HTTP {(int)status}"), context),
        };

    /// <summary>
    /// Maps a gRPC status code to an <see cref="AuthError"/>/<see cref="AuthzError"/>/
    /// <see cref="NetworkError"/> per CONTRACT.md &#167;2's gRPC status table:
    /// <see cref="StatusCode.Unauthenticated"/>&#8594;<see cref="AuthError"/>;
    /// <see cref="StatusCode.PermissionDenied"/>&#8594;<see cref="AuthzError"/>;
    /// everything else (<see cref="StatusCode.Unavailable"/>,
    /// <see cref="StatusCode.DeadlineExceeded"/>, <see cref="StatusCode.Internal"/>,
    /// <see cref="StatusCode.ResourceExhausted"/>, other)&#8594;<see cref="NetworkError"/>.
    /// </summary>
    public static Exception FromGrpcStatus(StatusCode code, string message) => code switch
    {
        StatusCode.Unauthenticated => new AuthError(message),
        // gRPC PERMISSION_DENIED carries no response body to parse (unlike the REST 403
        // path above) — message-only AuthzError; Action/ResourceId stay null.
        StatusCode.PermissionDenied => new AuthzError(message),
        _ => NetworkError.FromException(new InvalidOperationException($"gRPC {code}: {message}"), message),
    };
}

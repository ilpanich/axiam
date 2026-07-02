using System.Net;
using System.Net.Http;
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
            403 or 409 => new AuthzError(context),
            _ => NetworkError.FromResponse(response, context),
        };
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
        StatusCode.PermissionDenied => new AuthzError(message),
        _ => NetworkError.FromException(new InvalidOperationException($"gRPC {code}: {message}"), message),
    };
}

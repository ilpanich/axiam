using System.Net.Http;
using Axiam.Sdk.Rest;
using Grpc.Net.Client;

namespace Axiam.Sdk.Grpc;

/// <summary>
/// Constructs the SDK's ONE long-lived gRPC channel (D-10, CONTRACT.md &#167;6) by
/// reusing the EXACT SAME strict-TLS <see cref="HttpClientHandler"/> configuration the
/// REST transport uses (<see cref="AxiamHttpClientFactory.CreatePrimaryHandler"/>) —
/// additive <c>customCa</c> chain-trust honored, never a TLS-certificate-validation
/// bypass. The channel is disposed by whichever component constructs it
/// (<c>Grpc/AxiamGrpcAuthzClient.cs</c>), mirroring the Java sibling's
/// <c>AutoCloseable GrpcAuthzClient</c> and Go's <c>ClientConn</c> ownership model.
/// </summary>
public static class AxiamGrpcChannel
{
    /// <summary>
    /// Builds a single <see cref="GrpcChannel"/> targeting <paramref name="target"/> over
    /// HTTP/2, configured with the same strict-TLS handler the REST transport uses
    /// (&#167;6) — the additive <paramref name="customCaPem"/> escape hatch is honored,
    /// but NO code path in this method (or in
    /// <see cref="AxiamHttpClientFactory.CreatePrimaryHandler"/>) installs an
    /// unconditional TLS-validation-bypass delegate. Callers are responsible for applying
    /// an <c>AuthInterceptor</c> via <c>channel.Intercept(...)</c> and disposing the
    /// returned channel when done.
    /// </summary>
    /// <param name="target">
    /// The gRPC endpoint (e.g. the AXIAM server's base URL, or a dedicated gRPC target
    /// when one is configured separately from the REST base URL).
    /// </param>
    /// <param name="customCaPem">
    /// Optional PEM-encoded custom CA bytes (&#167;6) — <c>null</c> to trust only the
    /// system trust store, exactly matching the REST transport's own default.
    /// </param>
    public static GrpcChannel Create(Uri target, byte[]? customCaPem)
    {
        ArgumentNullException.ThrowIfNull(target);

        // Reuses the REST factory's strict-TLS/cookie-jar handler construction verbatim —
        // the cookie jar itself is irrelevant to gRPC (no cookie-based auth on this
        // transport), but sharing the SAME handler-construction code path guarantees the
        // gRPC channel can never diverge from the REST transport's TLS policy. The only
        // TLS-certificate-validation delegate assigned anywhere under Grpc/ is the one
        // inherited from CreatePrimaryHandler's additive customCa chain-trust-store path
        // (&#167;6/SC#4) — this method sets nothing further on the handler.
        HttpClientHandler primaryHandler = AxiamHttpClientFactory.CreatePrimaryHandler(customCaPem);

        var channelOptions = new GrpcChannelOptions
        {
            HttpHandler = primaryHandler,
        };

        return GrpcChannel.ForAddress(target, channelOptions);
    }
}

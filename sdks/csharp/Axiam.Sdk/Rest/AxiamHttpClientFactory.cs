using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Axiam.Sdk.Rest;

/// <summary>
/// Builds the SDK-owned <see cref="HttpClient"/> (D-09 default path) and configures the
/// <c>IHttpClientFactory</c>-compatible alternative path (D-09 alt path, wired up by a
/// later plan's <c>AddAxiam()</c>). Both paths guarantee the CONTRACT.md &#167;4
/// persistent cookie jar and the &#167;6 no-TLS-bypass policy — a caller-supplied handler
/// can never silently drop either guarantee (client-override safety, Java D-27 analog).
/// </summary>
public static class AxiamHttpClientFactory
{
    /// <summary>
    /// Creates the SDK's own, owned <see cref="HttpClient"/> over a fresh
    /// <see cref="HttpClientHandler"/> configured by <see cref="CreatePrimaryHandler"/>
    /// (&#167;4 cookie jar + &#167;6 no-TLS-bypass).
    /// </summary>
    public static HttpClient CreateOwned(byte[]? customCaPem) => new(CreatePrimaryHandler(customCaPem));

    /// <summary>
    /// Builds the primary <see cref="HttpClientHandler"/> with <c>UseCookies = true</c>
    /// and a private <see cref="CookieContainer"/> (&#167;4). When
    /// <paramref name="customCaPem"/> is supplied, an ADDITIVE chain-trust-store
    /// callback is installed — it never returns <c>true</c> unconditionally (&#167;6/
    /// SC#4: no TLS-bypass surface exists anywhere in this SDK). Exposed separately from
    /// <see cref="CreateOwned"/> so <c>AxiamClient</c> can compose this handler as the
    /// innermost link of its own <c>AxiamHttpMessageHandler</c> chain while still
    /// sharing the exact same cookie-jar/TLS configuration.
    /// </summary>
    public static HttpClientHandler CreatePrimaryHandler(byte[]? customCaPem)
    {
        var handler = new HttpClientHandler
        {
            UseCookies = true,
            CookieContainer = new CookieContainer(),
        };

        if (customCaPem is not null && customCaPem.Length > 0)
        {
            // net8.0 TFM: `new X509Certificate2(byte[])` is NOT obsolete on this target
            // (SYSLIB0057's obsolete marking was introduced starting with the .NET 9
            // reference assemblies; net8.0's reference assembly predates it, so no build
            // warning is produced when targeting net8.0-only per D-01) — this resolves
            // 21-RESEARCH.md Open Question 3 / Assumption A2 without a suppression being
            // strictly required. `X509CertificateLoader` (the newer, non-obsolete .NET
            // 9+ API) has no net8.0-compatible surface, so it is not used here.
            X509Certificate2 customCa;
            try
            {
                customCa = new X509Certificate2(customCaPem);
            }
            catch (CryptographicException ex)
            {
                // §6: "If a non-PEM format is passed, the SDK MUST return a clear error
                // at construction time" — surfaced here, before any network activity,
                // rather than as an opaque low-level exception at first-use.
                throw new ArgumentException(
                    "customCaPem must be PEM-encoded certificate bytes for the issuing CA (CONTRACT.md §6).",
                    nameof(customCaPem),
                    ex);
            }

            handler.ServerCertificateCustomValidationCallback = (_, cert, chain, _) => // additive CustomTrustStore chain-trust callback (never `=> true`)
            {
                if (cert is null || chain is null)
                {
                    return false;
                }

                // Adds ONE trusted CA to the chain — this is NOT a bypass: unknown or
                // mismatched certificates still fail verification. There is no branch
                // here (or anywhere else in this SDK) that returns `true`
                // unconditionally — the exact §6/SC#4-prohibited shape CI's grep gate
                // (plan 21-07) scans for.
                chain.ChainPolicy.CustomTrustStore.Add(customCa);
                chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
                return chain.Build(cert);
            };
        }
        // No `else` branch sets a validation callback to anything permissive — the
        // default system trust store verification applies untouched (the only
        // callback assignment anywhere in this file is the additive CustomTrustStore
        // path above).

        return handler;
    }

    /// <summary>
    /// Re-applies the SDK's cookie jar (&#167;4) and pooled-connection lifetime settings
    /// onto a <see cref="SocketsHttpHandler"/> registered via <c>IHttpClientFactory</c>/
    /// <c>AddHttpClient</c> (D-09 alt path, wired up by a later plan) — even if the
    /// caller supplied their own handler instance, client-override safety means the
    /// cookie jar can never be silently dropped (breaking post-login) and this method
    /// never touches <see cref="SocketsHttpHandler.SslOptions"/> at all, so it can never
    /// weaken TLS.
    /// </summary>
    public static void ConfigureFactoryHandler(SocketsHttpHandler handler)
    {
        ArgumentNullException.ThrowIfNull(handler);
        handler.UseCookies = true; // re-applied even if the caller supplied their own SocketsHttpHandler
        handler.CookieContainer = new CookieContainer();
        handler.PooledConnectionLifetime = TimeSpan.FromMinutes(15);
        // Same rule as CreatePrimaryHandler's additive CustomTrustStore callback: never
        // set an unconditional-true validation callback here.
    }
}

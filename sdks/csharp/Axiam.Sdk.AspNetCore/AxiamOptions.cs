namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// Typed Options-pattern configuration for <see cref="ServiceCollectionExtensions.AddAxiam"/>/
/// <see cref="ServiceCollectionExtensions.AddAxiamAspNetCore"/> (D-07). Configured via
/// <c>services.AddAxiamAspNetCore(options =&gt; { ... })</c> — properties are mutable
/// (<c>set</c>, not <c>init</c>) because the .NET Options pattern configures an
/// already-constructed instance through an <see cref="Action{T}"/> delegate.
/// </summary>
public sealed class AxiamOptions
{
    /// <summary>The AXIAM server's base URL. Required — passed straight through to the
    /// underlying <see cref="AxiamClient"/> constructor.</summary>
    public required Uri BaseUrl { get; set; }

    /// <summary>
    /// The tenant this ASP.NET Core app instance serves. Used for two purposes: (1) to
    /// construct the single shared <see cref="AxiamClient"/> that <c>AddAxiam</c>
    /// registers, and (2) as <see cref="AxiamAuthMiddleware"/>'s fallback tenant when an
    /// incoming request does not carry an <c>X-Tenant-ID</c> header (CONTRACT.md
    /// &#167;5/&#167;10: "Reads X-Tenant-ID (or configured tenant)"). Required — there is
    /// no silent default tenant anywhere in this SDK; a missing value surfaces as a
    /// startup-time <see cref="ArgumentException"/> from <see cref="AxiamClient"/>'s own
    /// tenant-required constructor (SC#1) the first time the DI container resolves it.
    /// </summary>
    public required string DefaultTenantId { get; set; }

    /// <summary>Optional organization UUID, passed through to the underlying
    /// <c>AxiamClient</c> (mirrors <c>AxiamClientOptions.OrgId</c> — required by the real
    /// AXIAM login/refresh endpoints beyond &#167;5's documented tenant-only minimum, in
    /// case the shared client is also used for <c>LoginAsync</c>/<c>RefreshAsync</c>).
    /// Mutually exclusive with <see cref="OrgSlug"/>.</summary>
    public Guid? OrgId { get; set; }

    /// <summary>Optional organization slug, passed through to the underlying
    /// <c>AxiamClient</c>. Mutually exclusive with <see cref="OrgId"/>.</summary>
    public string? OrgSlug { get; set; }

    /// <summary>PEM-encoded custom CA certificate bytes — the ONLY TLS escape hatch
    /// (CONTRACT.md &#167;6/SC#4), passed through to the underlying <c>AxiamClient</c>.
    /// <c>null</c> (the default) uses the system trust store only.</summary>
    public byte[]? CustomCaPem { get; set; }

    /// <summary>How long a fetched JWKS document is trusted before
    /// <see cref="AxiamClient"/>'s <c>JwksVerifier</c> forces a refetch — governs how
    /// quickly <see cref="AxiamAuthMiddleware"/>'s local verification fast path picks up
    /// a rotated signing key.</summary>
    public TimeSpan JwksCacheTtl { get; set; } = TimeSpan.FromMinutes(5);
}

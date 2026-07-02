using Axiam.Sdk;
using Axiam.Sdk.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// <c>IServiceCollection</c> DI extensions (D-07): <see cref="AddAxiam"/> registers the
/// typed <see cref="AxiamOptions"/> plus a single shared <see cref="AxiamClient"/>;
/// <see cref="AddAxiamAspNetCore"/> additionally wires the policy-based authorization
/// surface (D-08). The raw <c>app.UseMiddleware&lt;AxiamAuthMiddleware&gt;()</c> form
/// (CONTRACT.md &#167;10) remains available and works with either registration path.
/// </summary>
/// <remarks>
/// Every registration uses <c>TryAdd*</c> (never <c>AddSingleton</c>) so an explicit
/// consumer registration made BEFORE calling these methods always wins — the .NET
/// equivalent of Java's <c>AxiamAutoConfiguration</c> <c>@ConditionalOnMissingBean</c>
/// precedence (PATTERNS.md "ServiceCollectionExtensions.cs"). This is exercised
/// directly by the SC#3 integration test, which registers a test-seam
/// <see cref="AxiamClient"/> (pointed at a fake transport) BEFORE calling
/// <see cref="AddAxiamAspNetCore"/>.
/// </remarks>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers <see cref="AxiamOptions"/> (Options pattern) and a single shared
    /// <see cref="AxiamClient"/> singleton built from it. Does NOT register any
    /// authorization/middleware services — use <see cref="AddAxiamAspNetCore"/> for the
    /// full ASP.NET Core integration.
    /// </summary>
    public static IServiceCollection AddAxiam(this IServiceCollection services, Action<AxiamOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configure);

        services.Configure(configure);
        services.TryAddSingleton(BuildClient);
        return services;
    }

    /// <summary>
    /// Calls <see cref="AddAxiam"/> and additionally registers the policy-based
    /// authorization surface (D-08): <see cref="AxiamPolicyHandler"/>,
    /// <see cref="AxiamPolicyProvider"/>, and
    /// <see cref="AxiamAuthorizationMiddlewareResultHandler"/> (standardized
    /// 401/403 JSON bodies). Also calls the framework's own
    /// <c>AddAuthorization()</c> so the base authorization services exist even if the
    /// consuming app never calls it itself — safe to call even when the app already
    /// has, since ASP.NET Core's own <c>AddAuthorization()</c> uses <c>TryAdd*</c>
    /// internally.
    /// </summary>
    public static IServiceCollection AddAxiamAspNetCore(this IServiceCollection services, Action<AxiamOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.AddAxiam(configure);

        // IMPORTANT: register our own TryAdd* singletons for the single-slot
        // IAuthorizationPolicyProvider/IAuthorizationMiddlewareResultHandler services
        // BEFORE calling AddAuthorization() below. AddAuthorization() itself registers
        // its OWN defaults (DefaultAuthorizationPolicyProvider, the framework's default
        // result handler) via TryAdd — whichever registration for a given service type
        // runs FIRST wins the TryAdd race. Calling AddAuthorization() first here would
        // silently lock in the framework defaults and AxiamPolicyProvider would never
        // be used, even though our own TryAddSingleton call would appear to "succeed"
        // (TryAdd never throws) — order is load-bearing, not just style.
        services.TryAddSingleton<IAuthorizationHandler, AxiamPolicyHandler>();
        services.TryAddSingleton<IAuthorizationPolicyProvider, AxiamPolicyProvider>();
        services.TryAddSingleton<Microsoft.AspNetCore.Authorization.Policy.IAuthorizationMiddlewareResultHandler, AxiamAuthorizationMiddlewareResultHandler>();
        services.AddAuthorization();
        return services;
    }

    private static AxiamClient BuildClient(IServiceProvider serviceProvider)
    {
        AxiamOptions options = serviceProvider.GetRequiredService<IOptions<AxiamOptions>>().Value;
        var clientOptions = new AxiamClientOptions
        {
            BaseUrl = options.BaseUrl,
            TenantId = options.DefaultTenantId,
            OrgId = options.OrgId,
            OrgSlug = options.OrgSlug,
            CustomCaPem = options.CustomCaPem,
            JwksCacheTtl = options.JwksCacheTtl,
        };
        return new AxiamClient(options.BaseUrl, options.DefaultTenantId, clientOptions);
    }
}

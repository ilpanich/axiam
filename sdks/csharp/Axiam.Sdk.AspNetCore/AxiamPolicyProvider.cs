using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Extensions.Options;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// Builds an <see cref="AuthorizationPolicy"/> containing a single
/// <see cref="AxiamRequirement"/> for any policy name shaped <c>"resource:action"</c>
/// (e.g. <c>"documents:read"</c>) — the novel .NET-idiom file this phase introduces
/// (D-08; no direct Spring/method-security equivalent, built from RESEARCH.md Pattern
/// 5). Falls back to <see cref="DefaultAuthorizationPolicyProvider"/> for every other
/// policy name, so consumer-defined policies (registered via the normal
/// <c>AddAuthorization(options =&gt; options.AddPolicy(...))</c> path) keep working
/// completely unmodified.
/// </summary>
public sealed class AxiamPolicyProvider : IAuthorizationPolicyProvider
{
    private const char Separator = ':';

    private readonly DefaultAuthorizationPolicyProvider _fallback;

    /// <summary>Constructs the provider, wrapping a <see cref="DefaultAuthorizationPolicyProvider"/>
    /// built from the same <paramref name="options"/> for the fallback path.</summary>
    /// <param name="options">The framework's <see cref="AuthorizationOptions"/>, forwarded to the fallback provider.</param>
    public AxiamPolicyProvider(IOptions<AuthorizationOptions> options)
    {
        _fallback = new DefaultAuthorizationPolicyProvider(options);
    }

    /// <inheritdoc />
    public Task<AuthorizationPolicy> GetDefaultPolicyAsync() => _fallback.GetDefaultPolicyAsync();

    /// <inheritdoc />
    public Task<AuthorizationPolicy?> GetFallbackPolicyAsync() => _fallback.GetFallbackPolicyAsync();

    /// <summary>
    /// Recognizes a <c>"resource:action"</c>-shaped policy name (exactly one non-empty
    /// resource half and one non-empty action half, separated by <c>':'</c>) and builds
    /// an <see cref="AxiamRequirement"/>-backed policy for it on the fly — the consumer
    /// never has to explicitly register these policies via
    /// <c>AddAuthorization(options =&gt; options.AddPolicy(...))</c>. Any other policy
    /// name (including one containing no <c>':'</c>, or an explicitly pre-registered
    /// policy that happens to be named with a colon) falls through to
    /// <see cref="DefaultAuthorizationPolicyProvider"/> unmodified.
    /// </summary>
    public Task<AuthorizationPolicy?> GetPolicyAsync(string policyName)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(policyName);

        int separatorIndex = policyName.IndexOf(Separator);
        if (separatorIndex > 0 && separatorIndex < policyName.Length - 1 &&
            policyName.IndexOf(Separator, separatorIndex + 1) < 0)
        {
            string resource = policyName[..separatorIndex];
            string action = policyName[(separatorIndex + 1)..];
            AuthorizationPolicy policy = new AuthorizationPolicyBuilder()
                .AddRequirements(new AxiamRequirement(resource, action))
                .Build();
            return Task.FromResult<AuthorizationPolicy?>(policy);
        }

        return _fallback.GetPolicyAsync(policyName);
    }
}

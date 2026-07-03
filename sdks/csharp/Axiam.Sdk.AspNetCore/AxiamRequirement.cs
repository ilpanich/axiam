using Microsoft.AspNetCore.Authorization;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// Authorization requirement for a policy name shaped <c>"resource:action"</c> (e.g.
/// <c>"documents:read"</c>), carrying the parsed halves for <see cref="AxiamPolicyHandler"/>
/// to route into <c>CheckAccessAsync</c> (D-08). Built by <see cref="AxiamPolicyProvider"/>.
/// </summary>
public sealed class AxiamRequirement : IAuthorizationRequirement
{
    /// <summary>The resource-type half of the policy name (e.g. <c>"documents"</c>).</summary>
    public string Resource { get; }

    /// <summary>The action half of the policy name (e.g. <c>"read"</c>).</summary>
    public string Action { get; }

    public AxiamRequirement(string resource, string action)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(resource);
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        Resource = resource;
        Action = action;
    }

    /// <summary>
    /// The full <c>"resource:action"</c> string this requirement was parsed from — sent
    /// verbatim as the wire <c>action</c> field to <c>POST /api/v1/authz/check</c>, which
    /// documents its own <c>action</c> field with exactly this "resource:verb" shape
    /// (e.g. the real server's own doc example is <c>"users:get"</c>).
    /// </summary>
    public string PolicyName => $"{Resource}:{Action}";
}

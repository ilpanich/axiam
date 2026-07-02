using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// Routes <c>[Authorize(Policy="resource:action")]</c> (e.g.
/// <c>"documents:read"</c>) into <c>AxiamClient.Authz.CheckAccessAsync</c> (D-08). No
/// direct Spring analog — Spring's sibling SDK uses method-security annotations rather
/// than an <see cref="IAuthorizationHandler"/>/policy-provider pair, so this is the most
/// novel file in the phase (built from RESEARCH.md Pattern 5, reusing the
/// <c>AuthzError</c>&#8594;403 JSON-body convention from
/// <c>AxiamAuthenticationFilter.java</c> lines 102-111).
/// </summary>
/// <remarks>
/// AXIAM's RBAC engine is additive-only (allow-wins, default-deny, SEC-040; project
/// constraint per CLAUDE.md) — this handler calls <c>CheckAccessAsync</c> FRESH on
/// every single evaluation (T-21-18). It NEVER caches an authorization decision beyond
/// the current request; a client-side cache or short-circuit could silently diverge
/// from the server's live additive-only decision, which this SDK must never risk.
/// </remarks>
public sealed class AxiamPolicyHandler : AuthorizationHandler<AxiamRequirement>
{
    private readonly AxiamClient _client;

    public AxiamPolicyHandler(AxiamClient client)
    {
        _client = client ?? throw new ArgumentNullException(nameof(client));
    }

    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AxiamRequirement requirement)
    {
        string? userIdClaim = context.User.FindFirst("user_id")?.Value;
        if (string.IsNullOrEmpty(userIdClaim) || !Guid.TryParse(userIdClaim, out Guid subjectId))
        {
            // No verified identity (AxiamAuthMiddleware never ran, the request carried
            // no token, or the sub claim was not a GUID) — [Authorize] already 401s
            // upstream via AxiamAuthorizationMiddlewareResultHandler's Challenged
            // branch. Leave this requirement unsatisfied rather than throwing.
            return;
        }

        // ASP.NET Core's endpoint-routed AuthorizationMiddleware passes the current
        // HttpContext as `context.Resource` (learn.microsoft.com/aspnet/core/security/
        // authorization/resourcebased — "the resource is the current HttpContext" when
        // authorization runs via the Authorization Middleware with endpoint routing).
        // The compile-time [Authorize(Policy="resource:action")] attribute itself
        // carries no per-request resource identifier, so route data (a value literally
        // named "id") is the idiomatic place to recover a concrete resource UUID for a
        // specific-instance check. Falls back to Guid.Empty (a type-level/"no specific
        // resource" check) when no such route value is present, or when the hosting
        // model does not surface HttpContext as the resource — this is a defensive
        // fallback, not a hard dependency on the Resource-is-HttpContext behavior.
        HttpContext? httpContext = context.Resource as HttpContext;
        Guid resourceId = ResolveResourceId(httpContext);
        CancellationToken cancellationToken = httpContext?.RequestAborted ?? CancellationToken.None;

        // Server-side additive-only RBAC (allow-wins, default-deny, SEC-040) is the sole
        // source of truth — CheckAccessAsync is called FRESH every time, no local
        // decision cache (T-21-18). subjectId is the end-user identified by
        // AxiamAuthMiddleware's ClaimsPrincipal, checked "as" that user via the
        // check-as subject override (requires this handler's own AxiamClient identity
        // to hold authz:check_as server-side, per CONTRACT.md's authz/check endpoint
        // contract) — the shared AxiamClient checks access ON BEHALF OF the incoming
        // request's caller, never on behalf of itself.
        bool allowed = await _client.Authz
            .CheckAccessAsync(requirement.PolicyName, resourceId, scope: null, subjectId: subjectId, cancellationToken: cancellationToken)
            .ConfigureAwait(false);

        if (allowed)
        {
            context.Succeed(requirement);
        }
        // else: leave unsatisfied — AxiamAuthorizationMiddlewareResultHandler maps an
        // unsatisfied/Forbidden requirement to a standardized 403 JSON body.
    }

    private static Guid ResolveResourceId(HttpContext? httpContext)
    {
        if (httpContext is not null &&
            httpContext.Request.RouteValues.TryGetValue("id", out object? routeValue) &&
            routeValue is not null &&
            Guid.TryParse(routeValue.ToString(), out Guid parsed))
        {
            return parsed;
        }

        return Guid.Empty;
    }
}

/// <summary>
/// Custom <see cref="IAuthorizationMiddlewareResultHandler"/> that writes the
/// standardized JSON error body (CONTRACT.md &#167;10, PATTERNS.md "Standardized JSON
/// error body") for both authorization outcomes ASP.NET Core's authorization
/// middleware can produce: an unauthenticated/"Challenged" result (401 — mirrors
/// <c>AxiamAuthMiddleware</c>'s own no-credential-passthrough &#8594; bare
/// <c>[Authorize]</c> path, which never registers an authentication scheme and so must
/// never fall through to the default handler's <c>ChallengeAsync</c>, which would throw
/// without one) and a "Forbidden" result (403 — <c>AxiamPolicyHandler</c> left an
/// <see cref="AxiamRequirement"/> unsatisfied, i.e. <c>AuthzError</c>). On success, the
/// pipeline continues exactly like the framework default.
/// </summary>
public sealed class AxiamAuthorizationMiddlewareResultHandler : IAuthorizationMiddlewareResultHandler
{
    public Task HandleAsync(
        RequestDelegate next,
        HttpContext context,
        AuthorizationPolicy policy,
        PolicyAuthorizationResult authorizeResult)
    {
        ArgumentNullException.ThrowIfNull(next);
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(authorizeResult);

        if (authorizeResult.Succeeded)
        {
            return next(context);
        }

        if (authorizeResult.Forbidden)
        {
            return WriteJsonAsync(context, StatusCodes.Status403Forbidden, "authorization_denied", "insufficient permissions");
        }

        // Challenged (or any other non-success outcome): no valid credential reached
        // this far. AxiamAuthMiddleware already 401s an invalid/expired/wrong-tenant
        // token itself; this branch specifically covers a bare [Authorize] with NO
        // token at all, where AxiamAuthMiddleware intentionally passed the request
        // through per the "no-credential passthrough" rule.
        return WriteJsonAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", "authentication required");
    }

    private static Task WriteJsonAsync(HttpContext context, int statusCode, string error, string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        return context.Response.WriteAsJsonAsync(new { error, message });
    }
}

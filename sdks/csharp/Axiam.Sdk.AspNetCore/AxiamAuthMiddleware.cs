using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Axiam.Sdk;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;

namespace Axiam.Sdk.AspNetCore;

/// <summary>
/// ASP.NET Core authentication middleware (D-06, CONTRACT.md &#167;10 "ASP.NET Core"
/// row: <c>app.UseMiddleware&lt;AxiamAuthMiddleware&gt;()</c> in <c>Program.cs</c>).
/// Mirrors <c>sdks/java/.../spring/AxiamAuthenticationFilter.java</c>'s authoritative
/// sequence (extract &#8594; verify &#8594; exp-check &#8594; cross-tenant-check &#8594;
/// inject-identity &#8594; 401 JSON on failure), adapted to ASP.NET Core's
/// <see cref="ClaimsPrincipal"/>/<see cref="HttpContext.User"/> integration point —
/// the direct analog of Java D-14's Spring <c>SecurityContext</c> integration.
/// </summary>
/// <remarks>
/// Security-critical invariants (T-21-17, T-21-19, T-21-20):
/// <list type="bullet">
/// <item><description>
/// When NO credential is presented at all, the request is passed through
/// unauthenticated — the framework's own <c>[Authorize]</c>/authorization middleware
/// 401s it (via <see cref="AxiamAuthorizationMiddlewareResultHandler"/>, registered by
/// <see cref="ServiceCollectionExtensions.AddAxiamAspNetCore"/>). This middleware never
/// rejects a request for the mere absence of a token (Java filter lines 78-83
/// precedent) — doing so would incorrectly 401 public/anonymous endpoints that never
/// carry a token at all.
/// </description></item>
/// <item><description>
/// When a token IS presented, it is verified via the shared <see cref="AxiamClient"/>'s
/// internal <c>JwksVerifier</c> local fast path: alg-pinned Ed25519 signature check,
/// THEN the mandatory post-signature <c>tenant_id</c> claim check (Pitfall 3 — the JWKS
/// document is organization-wide, not tenant-scoped, so signature validity alone never
/// implies tenant authorization). An explicit <c>exp</c> re-check is performed here too
/// as defense in depth, mirroring the Java filter's lines 88-91 even though
/// <c>JwksVerifier.VerifyAsync</c> already checks <c>exp</c> internally.
/// </description></item>
/// <item><description>
/// <see cref="HttpContext.User"/> is rebuilt from scratch on every request from a fresh
/// <c>VerifyAsync</c> call — it is NEVER cached beyond the current request, and never
/// beyond the token's own remaining TTL (&#167;10).
/// </description></item>
/// <item><description>
/// Every failure path writes a standardized JSON body via
/// <see cref="HttpResponseJsonExtensions.WriteAsJsonAsync{TValue}(HttpResponse, TValue, System.Threading.CancellationToken)"/>
/// (System.Text.Json) — never manual string concatenation, so a message containing
/// quotes/control characters can never produce malformed or injected JSON
/// (PATTERNS.md "Standardized JSON error body").
/// </description></item>
/// <item><description>
/// CSRF (cookie double-submit, CONTRACT.md &#167;3): when the credential was sourced
/// from the <c>axiam_access</c> COOKIE (not the <c>Authorization</c> header) and the
/// request method is state-changing (anything other than GET/HEAD/OPTIONS), this
/// middleware additionally requires the <c>X-CSRF-Token</c> request header to be
/// present and equal (constant-time, <see cref="CryptographicOperations.FixedTimeEquals"/>)
/// to the <c>axiam_csrf</c> cookie value, rejecting with 403 on mismatch/absence.
/// Bearer-header requests are CSRF-immune by construction — a cross-site attacker
/// cannot set arbitrary request headers — but a cookie automatically attached by the
/// browser is not, and in any same-site deployment where <c>axiam_access</c> reaches
/// this app, the non-<c>httpOnly</c> <c>axiam_csrf</c> cookie does too. This mirrors,
/// locally, the same double-submit check the AXIAM server performs on its own
/// endpoints (&#167;3).
/// </description></item>
/// </list>
/// </remarks>
public sealed class AxiamAuthMiddleware
{
    private const string AccessCookieName = "axiam_access";
    private const string CsrfCookieName = "axiam_csrf";
    private const string CsrfHeaderName = "X-CSRF-Token";
    private const string TenantHeaderName = "X-Tenant-ID";
    private const string BearerPrefix = "Bearer ";
    private static readonly HashSet<string> SafeMethods = new(StringComparer.OrdinalIgnoreCase) { "GET", "HEAD", "OPTIONS" };

    private readonly RequestDelegate _next;

    public AxiamAuthMiddleware(RequestDelegate next)
    {
        _next = next ?? throw new ArgumentNullException(nameof(next));
    }

    /// <summary>
    /// Convention-based ASP.NET Core middleware invocation. <paramref name="client"/> and
    /// <paramref name="optionsAccessor"/> are resolved per-request from
    /// <see cref="HttpContext.RequestServices"/> (the standard <c>UseMiddleware&lt;T&gt;</c>
    /// pattern for additional <c>InvokeAsync</c> parameters beyond <see cref="HttpContext"/>)
    /// — they are singletons registered by <see cref="ServiceCollectionExtensions.AddAxiam"/>.
    /// </summary>
    public async Task InvokeAsync(HttpContext context, AxiamClient client, IOptions<AxiamOptions> optionsAccessor)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(client);
        ArgumentNullException.ThrowIfNull(optionsAccessor);

        string? tenantId = context.Request.Headers[TenantHeaderName].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(tenantId))
        {
            tenantId = optionsAccessor.Value.DefaultTenantId; // never a silent default (§5)
        }

        if (string.IsNullOrWhiteSpace(tenantId))
        {
            await WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", "no tenant available").ConfigureAwait(false);
            return;
        }

        (string? token, bool fromCookie) = ExtractToken(context);
        if (token is null)
        {
            // No credentials presented at all — let the framework's own [Authorize] /
            // authorization middleware 401 it (Java filter lines 78-83 precedent). Do
            // NOT reject here; some endpoints downstream may be anonymous.
            await _next(context).ConfigureAwait(false);
            return;
        }

        if (fromCookie && !SafeMethods.Contains(context.Request.Method) && !IsCsrfValid(context))
        {
            await WriteErrorAsync(context, StatusCodes.Status403Forbidden, "authorization_denied", "csrf_validation_failed").ConfigureAwait(false);
            return;
        }

        try
        {
            JsonElement? claims = await client.JwksVerifier.VerifyAsync(token, tenantId, context.RequestAborted).ConfigureAwait(false);
            if (claims is null)
            {
                // Covers bad alg, unknown kid, tampered signature, wrong tenant_id
                // (Pitfall 3), and already-expired tokens — VerifyAsync fails closed on
                // all of these and returns null; never throws on attacker-controlled
                // input.
                await WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", "invalid or expired token").ConfigureAwait(false);
                return;
            }

            // Defense-in-depth explicit exp re-check (Java filter lines 88-91) even
            // though VerifyAsync already checked exp above — the resource-server trust
            // boundary must never trust an expired token even if some future refactor
            // of the verifier relaxed its own internal check.
            if (claims.Value.TryGetProperty("exp", out JsonElement expEl) &&
                expEl.TryGetInt64(out long expSeconds) &&
                DateTimeOffset.FromUnixTimeSeconds(expSeconds) < DateTimeOffset.UtcNow)
            {
                await WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", "token expired").ConfigureAwait(false);
                return;
            }

            string? userId = claims.Value.TryGetProperty("sub", out JsonElement subEl) ? subEl.GetString() : null;
            if (string.IsNullOrEmpty(userId))
            {
                await WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", "token missing subject claim").ConfigureAwait(false);
                return;
            }

            var identity = new ClaimsIdentity("Axiam");
            identity.AddClaim(new Claim("user_id", userId));
            identity.AddClaim(new Claim("tenant_id", tenantId));
            if (claims.Value.TryGetProperty("roles", out JsonElement rolesEl) && rolesEl.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement roleEl in rolesEl.EnumerateArray())
                {
                    string? role = roleEl.GetString();
                    if (!string.IsNullOrEmpty(role))
                    {
                        identity.AddClaim(new Claim(ClaimTypes.Role, role));
                    }
                }
            }

            // §10: a fresh ClaimsPrincipal built from THIS request's verification —
            // never persisted/cached beyond it (no field/static/session storage anywhere
            // in this class).
            context.User = new ClaimsPrincipal(identity);
        }
        catch (Exception)
        {
            // Fail-closed on any unexpected error (Java filter lines 106-111
            // precedent) — never let an unexpected exception fall through to an
            // authenticated principal or an unhandled 500.
            await WriteErrorAsync(context, StatusCodes.Status401Unauthorized, "authentication_failed", "invalid or expired token").ConfigureAwait(false);
            return;
        }

        await _next(context).ConfigureAwait(false);
    }

    /// <summary><c>Authorization: Bearer</c> header first, then the <c>axiam_access</c>
    /// cookie; <c>(null, false)</c> when neither is present (Java filter lines 135-152).
    /// The returned <c>bool</c> is <c>true</c> when the credential came from the cookie,
    /// which callers use to decide whether the CSRF double-submit check applies.</summary>
    private static (string? Token, bool FromCookie) ExtractToken(HttpContext context)
    {
        string? header = context.Request.Headers.Authorization.FirstOrDefault();
        if (!string.IsNullOrEmpty(header) && header.StartsWith(BearerPrefix, StringComparison.OrdinalIgnoreCase))
        {
            string credentials = header[BearerPrefix.Length..].Trim();
            if (!string.IsNullOrEmpty(credentials))
            {
                return (credentials, false);
            }
        }

        string? cookie = context.Request.Cookies[AccessCookieName];
        return string.IsNullOrEmpty(cookie) ? (null, false) : (cookie, true);
    }

    /// <summary>
    /// Cookie double-submit check (CONTRACT.md &#167;3): the <c>X-CSRF-Token</c> header
    /// must be present and equal, constant-time, to the <c>axiam_csrf</c> cookie value.
    /// </summary>
    private static bool IsCsrfValid(HttpContext context)
    {
        string? header = context.Request.Headers[CsrfHeaderName].FirstOrDefault();
        string? cookie = context.Request.Cookies[CsrfCookieName];
        if (string.IsNullOrEmpty(header) || string.IsNullOrEmpty(cookie))
        {
            return false;
        }

        byte[] headerBytes = Encoding.UTF8.GetBytes(header);
        byte[] cookieBytes = Encoding.UTF8.GetBytes(cookie);
        return headerBytes.Length == cookieBytes.Length && CryptographicOperations.FixedTimeEquals(headerBytes, cookieBytes);
    }

    private static Task WriteErrorAsync(HttpContext context, int statusCode, string error, string message)
    {
        context.Response.StatusCode = statusCode;
        context.Response.ContentType = "application/json";
        // JSON-injection-safe: WriteAsJsonAsync (System.Text.Json) — never manual string
        // concatenation (CONTRACT.md §10, PATTERNS.md "Standardized JSON error body").
        return context.Response.WriteAsJsonAsync(new { error, message });
    }
}

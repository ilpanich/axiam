using System.Security.Claims;
using Axiam.Sdk.AspNetCore;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

// AspNetCoreSample (SC#3): a runnable ASP.NET Core 8+ web app demonstrating
// Axiam.Sdk.AspNetCore's middleware + ClaimsPrincipal injection (D-06/CONTRACT.md
// §10) and the policy-based authorization surface (D-08). See README.md for how
// to run this against a live AXIAM server (manual-only per 21-VALIDATION.md) and
// what to observe: 401 without a token, 401/403 with an invalid/denied token,
// 200 with a valid, authorized token.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

// D-07: DI extensions + Options pattern. AddAxiamAspNetCore() registers the
// typed AxiamOptions + a single shared AxiamClient AND additionally wires the
// D-08 policy-based authorization surface ([Authorize(Policy="resource:action")]
// -> client.CheckAccessAsync, 403 on deny).
builder.Services.AddAxiamAspNetCore(options =>
{
    options.BaseUrl = new Uri(builder.Configuration["Axiam:BaseUrl"] ?? "https://localhost:8443");
    options.DefaultTenantId = builder.Configuration["Axiam:TenantId"] ?? "acme";
});

var app = builder.Build();

// CONTRACT.md §10 literal form — the contract-mandated middleware registration
// (D-06). Extracts the Authorization: Bearer header or the axiam_access cookie,
// verifies it via the shared AxiamClient's internal JwksVerifier, and sets
// HttpContext.User to a ClaimsPrincipal (user_id/tenant_id/roles) on success.
app.UseMiddleware<AxiamAuthMiddleware>();

app.UseAuthorization();

app.MapControllers();

app.Run();

namespace AspNetCoreSample
{
    /// <summary>
    /// Demonstrates both SC#3 authorization halves against a live AXIAM server
    /// (manual-only run — see README.md):
    /// <list type="bullet">
    /// <item><description><c>GET /api/me</c> — <c>[Authorize]</c> only: proves the
    /// authentication half. No credential -&gt; 401 (framework's own authorization
    /// middleware, since <see cref="AxiamAuthMiddleware"/> passes an unauthenticated
    /// request through untouched); a valid, verified token -&gt; 200 with the
    /// injected <see cref="ClaimsPrincipal"/>'s claims echoed back.</description></item>
    /// <item><description><c>GET /api/documents/{id}</c> —
    /// <c>[Authorize(Policy="documents:read")]</c>: proves the D-08 authorization
    /// half. A valid token whose caller is denied the <c>documents:read</c> action
    /// by the AXIAM server's RBAC engine -&gt; 403 (<c>AuthzError</c>); a valid token
    /// whose caller is allowed -&gt; 200. Every check is a FRESH
    /// <c>CheckAccessAsync</c> call — never a client-side cache.</description></item>
    /// </list>
    /// </summary>
    [ApiController]
    [Route("api")]
    public sealed class DocumentsController : ControllerBase
    {
        /// <summary>Authentication-only endpoint (SC#3 authn half).</summary>
        [HttpGet("me")]
        [Authorize]
        public IActionResult Me()
        {
            string? userId = User.FindFirst("user_id")?.Value;
            string? tenantId = User.FindFirst("tenant_id")?.Value;
            IEnumerable<string> roles = User.FindAll(ClaimTypes.Role).Select(c => c.Value);
            return Ok(new { userId, tenantId, roles });
        }

        /// <summary>Policy-based authorization endpoint (SC#3/D-08 authz half) —
        /// routes through <see cref="AxiamPolicyHandler"/> to a fresh
        /// <c>CheckAccessAsync("documents:read", ...)</c> call.</summary>
        [HttpGet("documents/{id:guid}")]
        [Authorize(Policy = "documents:read")]
        public IActionResult GetDocument(Guid id) => Ok(new { id, status = "ok" });
    }
}

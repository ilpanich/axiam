using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.AspNetCore.Tests.Fixtures;
using Axiam.Sdk.Options;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Axiam.Sdk.AspNetCore.Tests;

/// <summary>
/// SC#3 integration test: proves <see cref="AxiamAuthMiddleware"/> +
/// <see cref="AxiamPolicyHandler"/> protect real ASP.NET Core 8+ endpoints through the
/// actual authentication/authorization pipeline (<see cref="TestServer"/>, not a unit
/// stub) — no-token 401, valid-token 200 with a populated
/// <see cref="System.Security.Claims.ClaimsPrincipal"/>, wrong-tenant-token 401,
/// policy-deny 403, policy-allow 200.
/// </summary>
[Trait("Category", "Integration")]
public sealed class AspNetCoreMiddlewareTests
{
    private const string TenantId = "acme-tenant";
    private const string OtherTenantId = "other-tenant";
    private static readonly Uri BaseUrl = new("https://axiam.test");

    [Fact]
    public async Task NoToken_ProtectedEndpoint_Returns401()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ValidToken_CorrectTenant_ProtectedEndpoint_Returns200_WithClaimsPrincipal()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string userId = Guid.NewGuid().ToString();
        string token = fixture.SignJwt(userId, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(userId, body); // proves a real ClaimsPrincipal (user_id claim) was injected
    }

    [Fact]
    public async Task WrongTenantToken_ProtectedEndpoint_Returns401()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        // Signature-valid, but for a DIFFERENT tenant than the app is configured for —
        // proves the mandatory post-signature tenant_id check (Pitfall 3).
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), OtherTenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/protected").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    [Fact]
    public async Task ValidToken_PolicyDeny_Returns403()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { AllowAccess = false };
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "viewer" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/documents").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task ValidToken_PolicyAllow_Returns200()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument()) { AllowAccess = true };
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        HttpResponseMessage response = await client.GetAsync("/documents").ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    // --- CSRF cookie double-submit (CR: java/spring-disabled-csrf-protection, C# analog) ---

    [Fact]
    public async Task CookieAuth_StateChangingPost_WithoutCsrfHeader_Returns403()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string token = fixture.SignJwt(Guid.NewGuid().ToString(), TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/protected");
        request.Headers.Add("Cookie", $"axiam_access={token}; axiam_csrf=csrf-abc");
        // No X-CSRF-Token header attached.

        HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    [Fact]
    public async Task CookieAuth_StateChangingPost_WithMatchingCsrfHeader_Returns200()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string userId = Guid.NewGuid().ToString();
        string token = fixture.SignJwt(userId, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/protected");
        request.Headers.Add("Cookie", $"axiam_access={token}; axiam_csrf=csrf-abc");
        request.Headers.Add("X-CSRF-Token", "csrf-abc");

        HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(userId, body);
    }

    [Fact]
    public async Task BearerAuth_StateChangingPost_WithoutCsrfHeader_Returns200()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string userId = Guid.NewGuid().ToString();
        string token = fixture.SignJwt(userId, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));

        using var request = new HttpRequestMessage(HttpMethod.Post, "/protected");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        // No CSRF cookie/header at all — a Bearer-header request is CSRF-immune by
        // construction (a cross-site attacker cannot set custom headers).

        HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(userId, body);
    }

    [Fact]
    public async Task CookieAuth_Get_WithoutCsrfHeader_Returns200()
    {
        var fixture = new JwksFixture();
        var serverHandler = new FakeAxiamServerHandler(fixture.BuildJwksDocument());
        using IHost host = await CreateHostAsync(serverHandler).ConfigureAwait(false);
        HttpClient client = host.GetTestClient();
        string userId = Guid.NewGuid().ToString();
        string token = fixture.SignJwt(userId, TenantId, new[] { "admin" }, DateTimeOffset.UtcNow.AddMinutes(15));

        using var request = new HttpRequestMessage(HttpMethod.Get, "/protected");
        request.Headers.Add("Cookie", $"axiam_access={token}");
        // No CSRF cookie/header — a safe method must not require one.

        HttpResponseMessage response = await client.SendAsync(request).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(userId, body);
    }

    /// <summary>
    /// Builds an in-memory ASP.NET Core 8+ host (<see cref="TestServer"/>) wiring
    /// <c>AddAxiamAspNetCore</c>, <c>UseMiddleware&lt;AxiamAuthMiddleware&gt;()</c>, an
    /// <c>[Authorize]</c>-equivalent ("/protected") endpoint, and an
    /// <c>[Authorize(Policy="documents:read")]</c>-equivalent ("/documents") endpoint.
    /// The shared <see cref="AxiamClient"/> is built via the internal
    /// <c>CreateForTesting</c> test-only seam pointed at <paramref name="serverHandler"/>
    /// instead of a real socket, and registered BEFORE
    /// <c>AddAxiamAspNetCore</c> is called — exercising the D-07 <c>TryAdd*</c>
    /// precedence guarantee (an explicit consumer registration always wins).
    /// </summary>
    private static async Task<IHost> CreateHostAsync(FakeAxiamServerHandler serverHandler)
    {
        AxiamClient fakeClient = AxiamClient.CreateForTesting(
            BaseUrl,
            TenantId,
            new AxiamClientOptions { BaseUrl = BaseUrl, TenantId = TenantId },
            serverHandler);

        IHostBuilder builder = new HostBuilder()
            .ConfigureWebHost(webHost =>
            {
                webHost.UseTestServer();
                webHost.ConfigureServices(services =>
                {
                    services.AddRouting();
                    services.AddSingleton(fakeClient); // registered first — TryAdd* below must not overwrite it
                    services.AddAxiamAspNetCore(options =>
                    {
                        options.BaseUrl = BaseUrl;
                        options.DefaultTenantId = TenantId;
                    });
                });
                webHost.Configure(app =>
                {
                    app.UseRouting();
                    app.UseMiddleware<AxiamAuthMiddleware>();
                    app.UseAuthorization();
                    app.UseEndpoints(endpoints =>
                    {
                        endpoints.MapGet("/protected", async context =>
                        {
                            string? userId = context.User.FindFirst("user_id")?.Value;
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync(userId ?? string.Empty).ConfigureAwait(false);
                        }).RequireAuthorization();

                        endpoints.MapGet("/documents", async context =>
                        {
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync("ok").ConfigureAwait(false);
                        }).RequireAuthorization("documents:read");

                        endpoints.MapPost("/protected", async context =>
                        {
                            string? userId = context.User.FindFirst("user_id")?.Value;
                            context.Response.StatusCode = StatusCodes.Status200OK;
                            await context.Response.WriteAsync(userId ?? string.Empty).ConfigureAwait(false);
                        }).RequireAuthorization();
                    });
                });
            });

        return await builder.StartAsync().ConfigureAwait(false);
    }

    /// <summary>
    /// Fake AXIAM server transport: serves the JWKS document at
    /// <c>GET /oauth2/jwks</c> (backing <c>AxiamClient.JwksVerifier</c>'s local
    /// verification fast path) and a controllable allow/deny decision at
    /// <c>POST /api/v1/authz/check</c> (backing <c>AxiamClient.Authz.CheckAccessAsync</c>).
    /// Never touches a real socket — plugged in via the internal
    /// <c>AxiamClient.CreateForTesting</c> seam.
    /// </summary>
    private sealed class FakeAxiamServerHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;

        public bool AllowAccess { get; set; } = true;

        public FakeAxiamServerHandler(string jwksJson) => _jwksJson = jwksJson;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request.Method == HttpMethod.Get && request.RequestUri?.AbsolutePath == "/oauth2/jwks")
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json"),
                });
            }

            if (request.Method == HttpMethod.Post && request.RequestUri?.AbsolutePath == "/api/v1/authz/check")
            {
                string body = "{\"allowed\":" + (AllowAccess ? "true" : "false") + "}";
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = new StringContent(body, Encoding.UTF8, "application/json"),
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }
}

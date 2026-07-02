using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Rest;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// CR-01 regression suite: proves the REST transport implements CONTRACT.md &#167;3 cookie
/// double-submit against a fake server that enforces the SAME check the real AXIAM server
/// does — it requires the <c>X-CSRF-Token</c> request header to match the <c>axiam_csrf</c>
/// value it issued, and (like the real server) delivers that value ONLY via a cookie,
/// never as an <c>X-CSRF-Token</c> response header. The pre-fix code only ever read the
/// response header, so <c>_csrfToken</c> stayed <c>null</c> and every state-changing call
/// (refresh/logout/authz) 403'd; these tests fail on that old behavior and pass once
/// <see cref="AxiamHttpMessageHandler"/> reads the <c>axiam_csrf</c> cookie from the shared
/// cookie jar.
/// </summary>
/// <remarks>
/// The test drives a real <see cref="HttpClient"/> pipeline whose outermost link is the
/// production <see cref="AxiamHttpMessageHandler"/>, with a <see cref="CookieContainer"/>
/// seeded exactly as the server's <c>Set-Cookie</c> headers would have populated it after
/// login. (The full <c>CreateForTesting</c> fake-transport seam bypasses the
/// <see cref="HttpClientHandler"/> cookie manager, so cookie-jar population is modeled
/// directly here — the code under test, <see cref="AxiamHttpMessageHandler"/>'s cookie-jar
/// read + double-submit header injection, is fully exercised.)
/// </remarks>
[Trait("Category", "Fast")]
public class CsrfDoubleSubmitTests
{
    private static readonly Uri BaseUri = new("https://axiam.test");
    private const string CsrfValue = "csrf-token-abc123";

    [Fact]
    public async Task StateChangingRequest_EchoesAxiamCsrfCookie_AsXCsrfHeader_AndServerAccepts()
    {
        var jar = new CookieContainer();
        // Exactly what the real server's login Set-Cookie headers would have populated:
        // an access token cookie AND the csrf cookie — but NO X-CSRF-Token response header.
        jar.Add(BaseUri, new Cookie("axiam_access", "access-jwt-value"));
        jar.Add(BaseUri, new Cookie("axiam_csrf", CsrfValue));

        var server = new CsrfEnforcingServer(CsrfValue);
        using var guard = new RefreshGuard(_ =>
            Task.FromException<TokenPair>(new InvalidOperationException("refresh must not be triggered on a 200 flow")));
        using var handler = new AxiamHttpMessageHandler(jar, BaseUri, "acme", guard) { InnerHandler = server };
        using var http = new HttpClient(handler) { BaseAddress = BaseUri };

        using HttpResponseMessage response = await http.PostAsync(
            "/api/v1/authz/check", JsonBody("""{"action":"users:get"}"""));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(CsrfValue, server.LastCsrfHeader);
    }

    [Fact]
    public async Task RefreshEndpoint_CarriesCsrfHeaderFromCookieJar()
    {
        var jar = new CookieContainer();
        jar.Add(BaseUri, new Cookie("axiam_access", "access-jwt-value"));
        jar.Add(BaseUri, new Cookie("axiam_csrf", CsrfValue));

        var server = new CsrfEnforcingServer(CsrfValue);
        using var guard = new RefreshGuard(_ =>
            Task.FromException<TokenPair>(new InvalidOperationException("not used")));
        using var handler = new AxiamHttpMessageHandler(jar, BaseUri, "acme", guard) { InnerHandler = server };
        using var http = new HttpClient(handler) { BaseAddress = BaseUri };

        using HttpResponseMessage response = await http.PostAsync(
            AxiamHttpMessageHandler.RefreshPath, JsonBody("""{"tenant_id":"t","org_id":"o"}"""));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(CsrfValue, server.LastCsrfHeader);
    }

    [Fact]
    public async Task StateChangingRequest_WithoutCsrfCookie_OmitsHeader_AndServerRejects()
    {
        var jar = new CookieContainer();
        // Session established but the csrf cookie is absent (e.g. never issued) — the SDK
        // must omit the header (§3 fallback), and the double-submit server rejects it.
        jar.Add(BaseUri, new Cookie("axiam_access", "access-jwt-value"));

        var server = new CsrfEnforcingServer(CsrfValue);
        using var guard = new RefreshGuard(_ =>
            Task.FromException<TokenPair>(new InvalidOperationException("not used")));
        using var handler = new AxiamHttpMessageHandler(jar, BaseUri, "acme", guard) { InnerHandler = server };
        using var http = new HttpClient(handler) { BaseAddress = BaseUri };

        using HttpResponseMessage response = await http.PostAsync(
            "/api/v1/authz/check", JsonBody("""{"action":"users:get"}"""));

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
        Assert.Null(server.LastCsrfHeader);
    }

    [Fact]
    public async Task NonStateChangingRequest_DoesNotAttachCsrfHeader()
    {
        var jar = new CookieContainer();
        jar.Add(BaseUri, new Cookie("axiam_access", "access-jwt-value"));
        jar.Add(BaseUri, new Cookie("axiam_csrf", CsrfValue));

        var server = new CsrfEnforcingServer(CsrfValue) { AllowMissingCsrf = true };
        using var guard = new RefreshGuard(_ =>
            Task.FromException<TokenPair>(new InvalidOperationException("not used")));
        using var handler = new AxiamHttpMessageHandler(jar, BaseUri, "acme", guard) { InnerHandler = server };
        using var http = new HttpClient(handler) { BaseAddress = BaseUri };

        using HttpResponseMessage response = await http.GetAsync("/api/v1/authz/status");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        // CSRF is only echoed on POST/PUT/PATCH/DELETE (§3) — a GET must not carry it.
        Assert.Null(server.LastCsrfHeader);
    }

    private static HttpContent JsonBody(string json) => new StringContent(json, Encoding.UTF8, "application/json");

    /// <summary>
    /// Fake AXIAM server enforcing cookie double-submit exactly as the real
    /// <c>CsrfMiddleware</c> does: a state-changing request is accepted only if it carries
    /// an <c>X-CSRF-Token</c> header matching the issued value; otherwise 403. It never
    /// emits an <c>X-CSRF-Token</c> response header (matching the real server, which only
    /// sets the value via a cookie).
    /// </summary>
    private sealed class CsrfEnforcingServer : HttpMessageHandler
    {
        private static readonly HashSet<string> StateChanging =
            new(StringComparer.OrdinalIgnoreCase) { "POST", "PUT", "PATCH", "DELETE" };

        private readonly string _expectedCsrf;

        public CsrfEnforcingServer(string expectedCsrf) => _expectedCsrf = expectedCsrf;

        /// <summary>When true, accept state-changing requests even without a CSRF header (used only to isolate the GET case).</summary>
        public bool AllowMissingCsrf { get; init; }

        public string? LastCsrfHeader { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            LastCsrfHeader = request.Headers.TryGetValues("X-CSRF-Token", out IEnumerable<string>? values)
                ? values.FirstOrDefault()
                : null;

            bool requiresCsrf = StateChanging.Contains(request.Method.Method) && !AllowMissingCsrf;
            if (requiresCsrf && !string.Equals(LastCsrfHeader, _expectedCsrf, StringComparison.Ordinal))
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.Forbidden)
                {
                    Content = new StringContent("""{"error":"csrf_validation_failed"}""", Encoding.UTF8, "application/json"),
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("""{"allowed":true}""", Encoding.UTF8, "application/json"),
            });
        }
    }
}

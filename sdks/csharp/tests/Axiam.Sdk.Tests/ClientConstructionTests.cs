using System.Net;
using System.Net.Http;
using System.Reflection;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Options;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// SC#1 regression suite: proves <see cref="AxiamClient"/>'s tenant-required
/// constructor has no overload that permits omitting the tenant identifier
/// (CONTRACT.md &#167;5) and that <c>LoginAsync</c> returns a typed
/// <see cref="LoginResult"/> for both the immediate-success and MFA-challenge server
/// responses.
/// </summary>
[Trait("Category", "Fast")]
public class ClientConstructionTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");

    [Fact]
    public void OnlyOnePublicConstructor_Exists()
    {
        ConstructorInfo[] ctors = typeof(AxiamClient).GetConstructors(BindingFlags.Public | BindingFlags.Instance);
        Assert.Single(ctors);
    }

    [Fact]
    public void PublicConstructor_RequiresTenantId_WithNoDefaultValue()
    {
        ConstructorInfo ctor = typeof(AxiamClient).GetConstructors(BindingFlags.Public | BindingFlags.Instance).Single();
        ParameterInfo[] parameters = ctor.GetParameters();

        Assert.True(parameters.Length >= 2, "AxiamClient's constructor must accept at least (baseUrl, tenantId).");
        Assert.Equal(typeof(Uri), parameters[0].ParameterType);
        Assert.Equal(typeof(string), parameters[1].ParameterType);
        // No default value on the tenant parameter (SC#1) — no call shape can omit it.
        Assert.False(parameters[1].HasDefaultValue);

        // Every parameter AFTER tenantId is optional; tenantId itself sits before any
        // optional parameter, so there is no overload/call shape that skips it.
        for (int i = 2; i < parameters.Length; i++)
        {
            Assert.True(
                parameters[i].IsOptional,
                $"parameter '{parameters[i].Name}' after tenantId must be optional — tenantId is the only required, non-defaultable argument besides baseUrl (SC#1).");
        }
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_RejectsBlankTenantId_AtRuntime(string? blankTenantId)
    {
        Assert.Throws<ArgumentException>(() => new AxiamClient(BaseUrl, blankTenantId!));
    }

    [Fact]
    public async Task LoginAsync_ImmediateSuccess_ReturnsLoginResult_WithMfaRequiredFalse()
    {
        var handler = new FakeAuthHandler(
            HttpStatusCode.OK,
            """{"user":{"id":"11111111-1111-1111-1111-111111111111","username":"alice","email":"alice@example.com"},"session_id":"22222222-2222-2222-2222-222222222222","expires_in":900}""");
        using AxiamClient client = CreateClientWithFakeTransport(handler);

        LoginResult result = await client.LoginAsync("alice@example.com", "correct horse battery staple", CancellationToken.None);

        Assert.False(result.MfaRequired);
        Assert.Null(result.ChallengeToken);
    }

    [Fact]
    public async Task LoginAsync_MfaChallenge_ReturnsLoginResult_WithMfaRequiredTrue_AndChallengeToken()
    {
        var handler = new FakeAuthHandler(
            HttpStatusCode.Accepted,
            """{"mfa_required":true,"challenge_token":"chal-abc123","available_methods":["totp"]}""");
        using AxiamClient client = CreateClientWithFakeTransport(handler);

        LoginResult result = await client.LoginAsync("alice@example.com", "correct horse battery staple", CancellationToken.None);

        Assert.True(result.MfaRequired);
        Assert.NotNull(result.ChallengeToken);
        // Sensitive<T> never reveals the wrapped value via ToString (§7) — a non-vacuous
        // control proving the field really is wrapped, not a plain string field.
        Assert.Equal("[SENSITIVE]", result.ChallengeToken!.Value.ToString());
    }

    [Fact]
    public async Task LoginAsync_InvalidCredentials_ThrowsAuthError()
    {
        var handler = new FakeAuthHandler(HttpStatusCode.Unauthorized, "{}");
        using AxiamClient client = CreateClientWithFakeTransport(handler);

        await Assert.ThrowsAsync<Axiam.Sdk.Core.AuthError>(() =>
            client.LoginAsync("alice@example.com", "wrong-password", CancellationToken.None));
    }

    [Fact]
    public async Task RefreshAsync_NoSession_ThrowsAuthError_WithoutAnyNetworkCall()
    {
        var handler = new FakeAuthHandler(HttpStatusCode.OK, "{}");
        using AxiamClient client = CreateClientWithFakeTransport(handler);

        await Assert.ThrowsAsync<Axiam.Sdk.Core.AuthError>(() => client.RefreshAsync(CancellationToken.None));
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task LogoutAsync_NoSession_ThrowsAuthError_WithoutAnyNetworkCall()
    {
        var handler = new FakeAuthHandler(HttpStatusCode.OK, "{}");
        using AxiamClient client = CreateClientWithFakeTransport(handler);

        await Assert.ThrowsAsync<Axiam.Sdk.Core.AuthError>(() => client.LogoutAsync(CancellationToken.None));
        Assert.Equal(0, handler.RequestCount);
    }

    private static AxiamClient CreateClientWithFakeTransport(HttpMessageHandler fakeHandler)
    {
        // NOTE: this exercises AxiamClient's public LoginAsync/RefreshAsync/LogoutAsync
        // surface end-to-end against a fully fake transport (via the internal
        // CreateForTesting seam), including the real AxiamHttpMessageHandler header-
        // injection/401-retry logic. It does not re-validate the SDK's own cookie-jar/
        // TLS wiring — that is covered by AxiamHttpClientFactory's own Task 1 acceptance
        // criteria and dotnet build/test in CI (plan 21-07).
        var options = new AxiamClientOptions
        {
            BaseUrl = BaseUrl,
            TenantId = "acme",
            OrgSlug = "acme-org",
        };
        return AxiamClient.CreateForTesting(BaseUrl, "acme", options, fakeHandler);
    }

    private sealed class FakeAuthHandler : HttpMessageHandler
    {
        private readonly HttpStatusCode _status;
        private readonly string _json;

        public FakeAuthHandler(HttpStatusCode status, string json)
        {
            _status = status;
            _json = json;
        }

        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            var response = new HttpResponseMessage(_status)
            {
                Content = new StringContent(_json, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        }
    }
}

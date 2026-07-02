using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Tests.Fixtures;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// D-02 regression suite: proves <see cref="JwksVerifier"/> verifies a real BouncyCastle
/// Ed25519 signature against a real AXIAM-shaped JWKS document/JWT (via
/// <see cref="JwksFixture"/>, not a self-round-trip through the verifier's own code), pins
/// <c>alg</c> before any key lookup, enforces the mandatory cross-tenant claim check, and
/// fails closed (returns <c>null</c>, never throws) on every attacker-controlled input.
/// </summary>
[Trait("Category", "Fast")]
public class JwksVerifierTests
{
    private const string Tenant = "acme";
    private static readonly string[] Roles = ["admin"];

    /// <summary>
    /// Fake JWKS transport: serves the fixture's JWKS document from <c>/oauth2/jwks</c>
    /// and counts how many times it was hit, so tests can assert alg-pinning happens
    /// BEFORE any fetch, and that an unknown kid triggers exactly one refetch.
    /// </summary>
    private sealed class FakeJwksHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;

        public FakeJwksHandler(string jwksJson) => _jwksJson = jwksJson;

        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            Assert.Equal("/oauth2/jwks", request.RequestUri!.AbsolutePath);
            var response = new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json"),
            };
            return Task.FromResult(response);
        }
    }

    private static (JwksVerifier Verifier, JwksFixture Fixture, FakeJwksHandler Handler) CreateVerifier()
    {
        var fixture = new JwksFixture();
        var handler = new FakeJwksHandler(fixture.BuildJwksDocument());
        var http = new HttpClient(handler) { BaseAddress = new Uri("https://axiam.test") };
        var verifier = new JwksVerifier(http, new Uri("https://axiam.test"), TimeSpan.FromMinutes(5));
        return (verifier, fixture, handler);
    }

    [Fact]
    public async Task ValidToken_ReturnsClaims()
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = CreateVerifier();
        string jwt = fixture.SignJwt("user-1", Tenant, Roles, DateTimeOffset.UtcNow.AddMinutes(15));

        JsonElement? claims = await verifier.VerifyAsync(jwt, Tenant);

        Assert.NotNull(claims);
        Assert.Equal(Tenant, claims!.Value.GetProperty("tenant_id").GetString());
        Assert.Equal("user-1", claims.Value.GetProperty("sub").GetString());
    }

    [Fact]
    public async Task AlgConfusion_RejectedBeforeAnyKeyLookup()
    {
        (JwksVerifier verifier, JwksFixture fixture, FakeJwksHandler handler) = CreateVerifier();
        string token = BuildRawToken(
            header: new { alg = "none", kid = fixture.Kid },
            payload: new { sub = "user-1", tenant_id = Tenant, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds() },
            signaturePart: "unused-signature");

        JsonElement? claims = await verifier.VerifyAsync(token, Tenant);

        Assert.Null(claims);
        // alg is checked BEFORE the kid is ever resolved against the JWKS — no fetch
        // should have happened at all.
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task RS256Alg_Rejected()
    {
        (JwksVerifier verifier, JwksFixture fixture, FakeJwksHandler handler) = CreateVerifier();
        string token = BuildRawToken(
            header: new { alg = "RS256", kid = fixture.Kid },
            payload: new { sub = "user-1", tenant_id = Tenant, exp = DateTimeOffset.UtcNow.AddMinutes(15).ToUnixTimeSeconds() },
            signaturePart: "unused-signature");

        JsonElement? claims = await verifier.VerifyAsync(token, Tenant);

        Assert.Null(claims);
        Assert.Equal(0, handler.RequestCount);
    }

    [Fact]
    public async Task UnknownKid_TriggersExactlyOneRefetch_ThenRejects()
    {
        (JwksVerifier verifier, JwksFixture fixture, FakeJwksHandler handler) = CreateVerifier();
        string jwt = fixture.SignJwt(
            "user-1", Tenant, Roles, DateTimeOffset.UtcNow.AddMinutes(15), kidOverride: "does-not-exist-in-jwks");

        JsonElement? claims = await verifier.VerifyAsync(jwt, Tenant);

        Assert.Null(claims);
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task WrongTenant_RejectedAfterSignatureVerifies()
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = CreateVerifier();
        // Validly signed by the fixture's real key — but for a tenant the caller is
        // not configured for. Proves signature validity alone never authorizes a
        // tenant (JWKS is org-wide, Pitfall 3).
        string jwt = fixture.SignJwtForTenant("user-1", "some-other-tenant", Roles, DateTimeOffset.UtcNow.AddMinutes(15));

        JsonElement? claims = await verifier.VerifyAsync(jwt, Tenant);

        Assert.Null(claims);
    }

    [Fact]
    public async Task ExpiredToken_Rejected()
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = CreateVerifier();
        string jwt = fixture.SignJwt("user-1", Tenant, Roles, DateTimeOffset.UtcNow.AddMinutes(-5));

        JsonElement? claims = await verifier.VerifyAsync(jwt, Tenant);

        Assert.Null(claims);
    }

    [Fact]
    public async Task TamperedSignature_Rejected()
    {
        (JwksVerifier verifier, JwksFixture fixture, _) = CreateVerifier();
        string jwt = fixture.SignJwtWithTamperedSignature("user-1", Tenant, Roles, DateTimeOffset.UtcNow.AddMinutes(15));

        JsonElement? claims = await verifier.VerifyAsync(jwt, Tenant);

        Assert.Null(claims);
    }

    [Theory]
    [InlineData("")]
    [InlineData("only-one-part")]
    [InlineData("two.parts")]
    [InlineData("not@@base64.not@@base64.not@@base64")]
    [InlineData("a.b.")]
    public async Task MalformedInput_ReturnsNull_NeverThrows(string malformedToken)
    {
        (JwksVerifier verifier, _, _) = CreateVerifier();

        JsonElement? claims = await verifier.VerifyAsync(malformedToken, Tenant);

        Assert.Null(claims);
    }

    private static string BuildRawToken(object header, object payload, string signaturePart)
    {
        string h = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(header));
        string p = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(payload));
        return $"{h}.{p}.{signaturePart}";
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}

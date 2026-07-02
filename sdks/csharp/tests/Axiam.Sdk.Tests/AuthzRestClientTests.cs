using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Core;
using Axiam.Sdk.Rest;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// FND-04 regression suite: proves <see cref="AuthzRestClient"/> calls the exact
/// <c>/api/v1/authz/check</c> / <c>/api/v1/authz/check/batch</c> endpoints, maps
/// <c>allowed:true/false</c> correctly, routes a 403 through <see cref="ErrorMapper"/>
/// to <see cref="AuthzError"/>, preserves batch ordering, and never caches a decision
/// (every call hits the fake transport fresh — additive-only RBAC, CLAUDE.md).
/// </summary>
[Trait("Category", "Fast")]
public class AuthzRestClientTests
{
    private static readonly Uri BaseUrl = new("https://axiam.test");

    [Fact]
    public async Task CheckAccessAsync_Allowed_ReturnsTrue()
    {
        var handler = new FakeHandler(req =>
        {
            Assert.Equal("/api/v1/authz/check", req.RequestUri!.AbsolutePath);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonBody("""{"allowed":true}""") };
        });
        AuthzRestClient client = CreateClient(handler);

        bool allowed = await client.CheckAccessAsync("users:get", Guid.NewGuid());

        Assert.True(allowed);
    }

    [Fact]
    public async Task CheckAccessAsync_Denied_ReturnsFalse()
    {
        var handler = new FakeHandler(_ =>
            new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonBody("""{"allowed":false,"reason":"no matching role"}""") });
        AuthzRestClient client = CreateClient(handler);

        bool allowed = await client.CheckAccessAsync("users:delete", Guid.NewGuid());

        Assert.False(allowed);
    }

    [Fact]
    public async Task CheckAccessAsync_Forbidden_MapsToAuthzError()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = JsonBody("{}") });
        AuthzRestClient client = CreateClient(handler);

        await Assert.ThrowsAsync<AuthzError>(() => client.CheckAccessAsync("users:get", Guid.NewGuid()));
    }

    [Fact]
    public async Task CanAsync_IsAnAliasForCheckAccessAsync()
    {
        var handler = new FakeHandler(req =>
        {
            Assert.Equal("/api/v1/authz/check", req.RequestUri!.AbsolutePath);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonBody("""{"allowed":true}""") };
        });
        AuthzRestClient client = CreateClient(handler);

        bool allowed = await client.CanAsync("documents:read", Guid.NewGuid());

        Assert.True(allowed);
        Assert.Equal(1, handler.RequestCount);
    }

    [Fact]
    public async Task BatchCheckAsync_PreservesOrder()
    {
        var handler = new FakeHandler(req =>
        {
            Assert.Equal("/api/v1/authz/check/batch", req.RequestUri!.AbsolutePath);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonBody("""{"results":[{"allowed":true},{"allowed":false},{"allowed":true}]}"""),
            };
        });
        AuthzRestClient client = CreateClient(handler);

        var checks = new[]
        {
            new AuthzRestClient.AccessCheck("users:get", Guid.NewGuid()),
            new AuthzRestClient.AccessCheck("users:delete", Guid.NewGuid()),
            new AuthzRestClient.AccessCheck("users:list", Guid.NewGuid()),
        };

        IReadOnlyList<bool> results = await client.BatchCheckAsync(checks);

        Assert.Equal(new[] { true, false, true }, results);
    }

    [Fact]
    public async Task BatchCheckAsync_Forbidden_MapsToAuthzError()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.Forbidden) { Content = JsonBody("{}") });
        AuthzRestClient client = CreateClient(handler);

        await Assert.ThrowsAsync<AuthzError>(() =>
            client.BatchCheckAsync(new[] { new AuthzRestClient.AccessCheck("users:get", Guid.NewGuid()) }));
    }

    [Fact]
    public async Task CheckAccessAsync_EveryCall_HitsTheFakeTransportFresh_NoLocalCache()
    {
        var handler = new FakeHandler(_ => new HttpResponseMessage(HttpStatusCode.OK) { Content = JsonBody("""{"allowed":true}""") });
        AuthzRestClient client = CreateClient(handler);
        Guid resourceId = Guid.NewGuid();

        await client.CheckAccessAsync("users:get", resourceId);
        await client.CheckAccessAsync("users:get", resourceId);
        await client.CheckAccessAsync("users:get", resourceId);

        // No client-side caching/short-circuiting of an authz decision (additive-only
        // RBAC constraint, CLAUDE.md) — three identical calls hit the transport three
        // times, never once-then-reused.
        Assert.Equal(3, handler.RequestCount);
    }

    private static HttpContent JsonBody(string json) => new StringContent(json, Encoding.UTF8, "application/json");

    // AuthzRestClient's constructor is `internal` (only AxiamClient is meant to build
    // one, exposed via AxiamClient.Authz) — visible here via the project-wide
    // InternalsVisibleTo("Axiam.Sdk.Tests") grant declared in Axiam.Sdk/Core/Sensitive.cs.
    private static AuthzRestClient CreateClient(FakeHandler handler) =>
        new(new HttpClient(handler) { BaseAddress = BaseUrl });

    private sealed class FakeHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpResponseMessage> _respond;

        public FakeHandler(Func<HttpRequestMessage, HttpResponseMessage> respond) => _respond = respond;

        public int RequestCount { get; private set; }

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            RequestCount++;
            return Task.FromResult(_respond(request));
        }
    }
}

using System.Net;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.Sdk.Grpc;
using Axiam.Sdk.Tests.Fixtures;
using Axiam.V1;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Grpc.Net.Client;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// D-10/&#167;9 gRPC transport regression suite: proves <see cref="AxiamGrpcAuthzClient"/>
/// resolves a granted/denied <c>CheckAccess</c>/<c>BatchCheckAccess</c> call, maps a
/// <c>PERMISSION_DENIED</c> status to <see cref="AuthzError"/> via the shared
/// <see cref="ErrorMapper"/>, drives EXACTLY ONE shared-guard refresh + one retry on
/// <c>UNAUTHENTICATED</c> (never a loop), and sources the wire <c>tenant_id</c>/
/// <c>subject_id</c> from the access token's claims — never from the raw configured
/// tenant string. Runs against a real, loopback, in-process gRPC server
/// (<c>Grpc.AspNetCore.Server</c> over cleartext HTTP/2) — no live AXIAM backend
/// required.
/// </summary>
[Trait("Category", "Fast")]
public class GrpcAuthzClientTests
{
    static GrpcAuthzClientTests()
    {
        // Kestrel below is configured for cleartext HTTP/2 (h2c) — the officially
        // documented switch to let Grpc.Net.Client's SocketsHttpHandler negotiate HTTP/2
        // without TLS for this loopback test server (no live AXIAM backend / cert needed).
        AppContext.SetSwitch("System.Net.Http.SocketsHttpHandler.Http2UnencryptedSupport", true);
    }

    [Fact]
    public async Task CheckAccessAsync_Allowed_ReturnsTrue()
    {
        var service = new FakeAuthorizationService(handleCheck: (_, _) => new CheckAccessResponse { Allowed = true });
        await using FakeGrpcServer server = await FakeGrpcServer.StartAsync(service);
        using GrpcChannel channel = CreateLoopbackChannel(server.Port);
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt(subject: "user-1", tenantId: "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(channel, refresh.Guard, "tenant-1", () => jwt);

        bool allowed = await client.CheckAccessAsync("documents:read", "doc-42");

        Assert.True(allowed);
        Assert.Equal(0, refresh.Count);
    }

    [Fact]
    public async Task CheckAccessAsync_Denied_ReturnsFalse()
    {
        var service = new FakeAuthorizationService(handleCheck: (_, _) => new CheckAccessResponse { Allowed = false, DenyReason = "no matching role" });
        await using FakeGrpcServer server = await FakeGrpcServer.StartAsync(service);
        using GrpcChannel channel = CreateLoopbackChannel(server.Port);
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(channel, refresh.Guard, "tenant-1", () => jwt);

        bool allowed = await client.CheckAccessAsync("documents:delete", "doc-42");

        Assert.False(allowed);
    }

    [Fact]
    public async Task CheckAccessAsync_PermissionDenied_MapsToAuthzError()
    {
        var service = new FakeAuthorizationService(
            handleCheck: (_, _) => throw new RpcException(new Status(StatusCode.PermissionDenied, "caller lacks documents:delete")));
        await using FakeGrpcServer server = await FakeGrpcServer.StartAsync(service);
        using GrpcChannel channel = CreateLoopbackChannel(server.Port);
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(channel, refresh.Guard, "tenant-1", () => jwt);

        await Assert.ThrowsAsync<AuthzError>(() => client.CheckAccessAsync("documents:delete", "doc-42"));
    }

    [Fact]
    public async Task CheckAccessAsync_Unauthenticated_TriggersExactlyOneRefreshThenRetries()
    {
        int callCount = 0;
        var service = new FakeAuthorizationService(handleCheck: (_, _) =>
        {
            int n = Interlocked.Increment(ref callCount);
            if (n == 1)
            {
                // First attempt: simulate an expired/invalid token — the shared
                // AuthInterceptor MUST drive exactly one RefreshGuard refresh and retry
                // exactly once (§9.3, no loop).
                throw new RpcException(new Status(StatusCode.Unauthenticated, "token expired"));
            }
            return new CheckAccessResponse { Allowed = true };
        });
        await using FakeGrpcServer server = await FakeGrpcServer.StartAsync(service);
        using GrpcChannel channel = CreateLoopbackChannel(server.Port);
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(channel, refresh.Guard, "tenant-1", () => jwt);

        bool allowed = await client.CheckAccessAsync("documents:read", "doc-42");

        Assert.True(allowed);
        Assert.Equal(2, callCount); // original attempt + exactly one retry
        Assert.Equal(1, refresh.Count); // exactly one shared-guard refresh — non-vacuous single-flight
    }

    [Fact]
    public async Task BatchCheckAsync_PreservesOrder()
    {
        var service = new FakeAuthorizationService(handleBatch: (req, _) =>
        {
            bool[] pattern = { true, false, true };
            var response = new BatchCheckAccessResponse();
            for (int i = 0; i < req.Requests.Count; i++)
            {
                response.Results.Add(new CheckAccessResponse { Allowed = pattern[i % pattern.Length] });
            }
            return response;
        });
        await using FakeGrpcServer server = await FakeGrpcServer.StartAsync(service);
        using GrpcChannel channel = CreateLoopbackChannel(server.Port);
        using var refresh = new RefreshCounter();
        string jwt = MintUnverifiedJwt("user-1", "tenant-1");

        using AxiamGrpcAuthzClient client = BuildClient(channel, refresh.Guard, "tenant-1", () => jwt);

        var checks = new[]
        {
            new AxiamGrpcAuthzClient.AccessCheck("users:get", "r1"),
            new AxiamGrpcAuthzClient.AccessCheck("users:delete", "r2"),
            new AxiamGrpcAuthzClient.AccessCheck("users:list", "r3"),
        };

        IReadOnlyList<bool> results = await client.BatchCheckAsync(checks);

        Assert.Equal(new[] { true, false, true }, results);
    }

    [Fact]
    public async Task CheckAccessAsync_NoActiveSession_ThrowsAuthError_WithoutAnyRpcCall()
    {
        var service = new FakeAuthorizationService();
        await using FakeGrpcServer server = await FakeGrpcServer.StartAsync(service);
        using GrpcChannel channel = CreateLoopbackChannel(server.Port);
        using var refresh = new RefreshCounter();

        using AxiamGrpcAuthzClient client = BuildClient(channel, refresh.Guard, "tenant-1", () => null);

        await Assert.ThrowsAsync<AuthError>(() => client.CheckAccessAsync("documents:read", "doc-42"));
        Assert.Empty(service.ReceivedChecks);
    }

    [Fact]
    public async Task CheckAccessAsync_ResolvesWireIdentity_FromTokenClaims_NotConfiguredTenantString()
    {
        const string claimTenantId = "44444444-4444-4444-4444-444444444444";
        const string claimSubjectId = "55555555-5555-5555-5555-555555555555";
        const string configuredTenantSlug = "acme-corp"; // deliberately NOT the claim's tenant_id
        string jwt = MintUnverifiedJwt(claimSubjectId, claimTenantId);

        CheckAccessRequest? received = null;
        var service = new FakeAuthorizationService(handleCheck: (req, _) =>
        {
            received = req;
            return new CheckAccessResponse { Allowed = true };
        });
        await using FakeGrpcServer server = await FakeGrpcServer.StartAsync(service);
        using GrpcChannel channel = CreateLoopbackChannel(server.Port);
        using var refresh = new RefreshCounter();

        using AxiamGrpcAuthzClient client = BuildClient(channel, refresh.Guard, configuredTenantSlug, () => jwt);

        await client.CheckAccessAsync("documents:read", "doc-1");

        Assert.NotNull(received);
        Assert.Equal(claimTenantId, received!.TenantId);
        Assert.Equal(claimSubjectId, received.SubjectId);
        Assert.NotEqual(configuredTenantSlug, received.TenantId);
    }

    [Fact]
    public async Task CheckAccessAsync_ResolvesWireIdentity_ViaSignatureVerifiedJwksClaims()
    {
        var fixture = new JwksFixture();
        const string tenantId = "66666666-6666-6666-6666-666666666666";
        const string subjectId = "77777777-7777-7777-7777-777777777777";
        string jwt = fixture.SignJwt(subjectId, tenantId, roles: new[] { "member" }, expiresAt: DateTimeOffset.UtcNow.AddMinutes(15));

        using var jwksHttpClient = new HttpClient(new FakeJwksHandler(fixture.BuildJwksDocument())) { BaseAddress = new Uri("https://axiam.test") };
        var jwksVerifier = new JwksVerifier(jwksHttpClient, new Uri("https://axiam.test"), TimeSpan.FromMinutes(5));

        CheckAccessRequest? received = null;
        var service = new FakeAuthorizationService(handleCheck: (req, _) =>
        {
            received = req;
            return new CheckAccessResponse { Allowed = true };
        });
        await using FakeGrpcServer server = await FakeGrpcServer.StartAsync(service);
        using GrpcChannel channel = CreateLoopbackChannel(server.Port);
        using var refresh = new RefreshCounter();

        // The configured tenant MUST equal the JWT's tenant_id claim for the
        // signature-verified path to succeed (JwksVerifier.VerifyAsync's mandatory
        // cross-tenant check, T-21-07) — this test proves the VERIFIED resolution path
        // itself works end-to-end (real BouncyCastle Ed25519 verification against a
        // fetched JWKS document), which the unverified-fallback tests above do not
        // exercise.
        using AxiamGrpcAuthzClient client = BuildClient(channel, refresh.Guard, tenantId, () => jwt, jwksVerifier);

        bool allowed = await client.CheckAccessAsync("documents:read", "doc-1");

        Assert.True(allowed);
        Assert.NotNull(received);
        Assert.Equal(tenantId, received!.TenantId);
        Assert.Equal(subjectId, received.SubjectId);
    }

    // ------------------------------------------------------------------
    // Test helpers
    // ------------------------------------------------------------------

    private static GrpcChannel CreateLoopbackChannel(int port) =>
        GrpcChannel.ForAddress($"http://127.0.0.1:{port}", new GrpcChannelOptions
        {
            HttpHandler = new SocketsHttpHandler(),
        });

    private static AxiamGrpcAuthzClient BuildClient(
        GrpcChannel channel, RefreshGuard guard, string tenantId, Func<string?> tokenAccessor, JwksVerifier? jwksVerifier = null)
    {
        var interceptor = new AuthInterceptor(tokenAccessor, tenantId, guard);
        CallInvoker invoker = channel.Intercept(interceptor);
        return new AxiamGrpcAuthzClient(invoker, jwksVerifier, tokenAccessor, tenantId);
    }

    /// <summary>
    /// Mints a JWT-shaped (but unsigned) token that the SDK's unverified-decode fallback
    /// (used whenever no <see cref="JwksVerifier"/> is supplied) can parse — no real
    /// signature is required because that fallback path never checks one; it only reads
    /// <c>sub</c>/<c>tenant_id</c> out of the payload segment as an operational hint.
    /// </summary>
    private static string MintUnverifiedJwt(string subject, string tenantId)
    {
        string header = Base64UrlEncode(Encoding.UTF8.GetBytes("""{"alg":"none"}"""));
        string payload = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(new { sub = subject, tenant_id = tenantId }));
        return $"{header}.{payload}.unsigned";
    }

    private static string Base64UrlEncode(byte[] bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    /// <summary>Test-double <see cref="RefreshGuard"/> wrapper counting how many times the
    /// underlying refresh delegate actually ran — the single-flight non-vacuousness proof
    /// for the UNAUTHENTICATED-retry test.</summary>
    private sealed class RefreshCounter : IDisposable
    {
        private int _count;

        public RefreshGuard Guard { get; }

        public int Count => _count;

        public RefreshCounter()
        {
            Guard = new RefreshGuard(_ =>
            {
                Interlocked.Increment(ref _count);
                return Task.FromResult(new TokenPair(
                    Sensitive.Of("refreshed-access"),
                    Sensitive.Of("refreshed-refresh"),
                    DateTimeOffset.UtcNow.AddMinutes(15)));
            });
        }

        public void Dispose() => Guard.Dispose();
    }

    /// <summary>Serves a fixed JWKS document body for every request — a fake
    /// <c>GET /oauth2/jwks</c> backing a real <see cref="JwksVerifier"/> instance.</summary>
    private sealed class FakeJwksHandler : HttpMessageHandler
    {
        private readonly string _jwksJson;

        public FakeJwksHandler(string jwksJson) => _jwksJson = jwksJson;

        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
            Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent(_jwksJson, Encoding.UTF8, "application/json"),
            });
    }

    /// <summary>Fake <c>AuthorizationService</c> gRPC service implementation — records every
    /// received <c>CheckAccess</c> request and answers via caller-supplied handlers, so each
    /// test can script granted/denied/error responses without a live AXIAM backend.</summary>
    private sealed class FakeAuthorizationService : AuthorizationService.AuthorizationServiceBase
    {
        private readonly Func<CheckAccessRequest, ServerCallContext, CheckAccessResponse> _handleCheck;
        private readonly Func<BatchCheckAccessRequest, ServerCallContext, BatchCheckAccessResponse> _handleBatch;

        public List<CheckAccessRequest> ReceivedChecks { get; } = new();

        public FakeAuthorizationService(
            Func<CheckAccessRequest, ServerCallContext, CheckAccessResponse>? handleCheck = null,
            Func<BatchCheckAccessRequest, ServerCallContext, BatchCheckAccessResponse>? handleBatch = null)
        {
            _handleCheck = handleCheck ?? ((_, _) => new CheckAccessResponse { Allowed = true });
            _handleBatch = handleBatch ?? ((req, context) =>
            {
                var response = new BatchCheckAccessResponse();
                foreach (CheckAccessRequest item in req.Requests)
                {
                    response.Results.Add(new CheckAccessResponse { Allowed = true });
                }
                return response;
            });
        }

        public override Task<CheckAccessResponse> CheckAccess(CheckAccessRequest request, ServerCallContext context)
        {
            ReceivedChecks.Add(request);
            return Task.FromResult(_handleCheck(request, context));
        }

        public override Task<BatchCheckAccessResponse> BatchCheckAccess(BatchCheckAccessRequest request, ServerCallContext context) =>
            Task.FromResult(_handleBatch(request, context));
    }

    /// <summary>Real, loopback, in-process gRPC server hosting a single
    /// <see cref="FakeAuthorizationService"/> instance over cleartext HTTP/2 on a random
    /// port — the officially documented way to test a <c>Grpc.Net.Client</c> client
    /// against a real gRPC server without a live AXIAM backend.</summary>
    private sealed class FakeGrpcServer : IAsyncDisposable
    {
        private readonly WebApplication _app;

        public int Port { get; }

        private FakeGrpcServer(WebApplication app, int port)
        {
            _app = app;
            Port = port;
        }

        public static async Task<FakeGrpcServer> StartAsync(FakeAuthorizationService service)
        {
            WebApplicationBuilder builder = WebApplication.CreateBuilder();
            builder.Logging.ClearProviders();
            builder.WebHost.ConfigureKestrel(options =>
                options.ListenLocalhost(0, listenOptions => listenOptions.Protocols = HttpProtocols.Http2));
            builder.Services.AddGrpc();
            builder.Services.AddSingleton(service);

            WebApplication app = builder.Build();
            app.MapGrpcService<FakeAuthorizationService>();
            await app.StartAsync().ConfigureAwait(false);

            IServerAddressesFeature addressesFeature = app.Services
                .GetRequiredService<IServer>()
                .Features
                .Get<IServerAddressesFeature>()!;
            int port = new Uri(addressesFeature.Addresses.First()).Port;

            return new FakeGrpcServer(app, port);
        }

        public async ValueTask DisposeAsync() => await _app.DisposeAsync().ConfigureAwait(false);
    }
}

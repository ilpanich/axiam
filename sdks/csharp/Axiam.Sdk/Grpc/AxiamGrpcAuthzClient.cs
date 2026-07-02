using System.Text.Json;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Axiam.V1;
using Grpc.Core;
using Grpc.Core.Interceptors;
using Grpc.Net.Client;

namespace Axiam.Sdk.Grpc;

/// <summary>
/// gRPC authorization transport (CONTRACT.md &#167;1/&#167;2/&#167;5/&#167;9, D-10).
/// Wraps ONE long-lived <see cref="GrpcChannel"/> (via <see cref="AxiamGrpcChannel"/> —
/// strict TLS, &#167;6) intercepted by an <see cref="AuthInterceptor"/> that shares
/// the EXACT SAME <see cref="RefreshGuard"/>/session <see cref="AxiamClient"/>'s REST
/// transport uses — never a second guard instance.
/// </summary>
/// <remarks>
/// <para>
/// The wire <c>tenant_id</c>/<c>subject_id</c> fields are resolved from the CURRENT
/// access token's claims — preferring a signature-VERIFIED resolution via
/// <see cref="JwksVerifier"/> (D-02) when available, falling back to an unverified
/// decode purely as an operational hint (mirrors <c>AxiamClient.DoHttpRefreshAsync</c>'s
/// own established pattern) when no verifier is supplied or local verification fails —
/// NEVER from the raw configured tenant identifier string. The real server
/// (<c>crates/axiam-api-grpc/src/services/authorization.rs</c>) independently
/// cross-validates both wire fields against its own verified JWT claims and rejects
/// <c>PERMISSION_DENIED</c> on any mismatch, so a wrong hint here can only ever produce a
/// denial — never an over-grant.
/// </para>
/// </remarks>
public sealed class AxiamGrpcAuthzClient : IDisposable
{
    private static readonly TimeSpan CheckAccessDeadline = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan BatchCheckDeadline = TimeSpan.FromSeconds(10);

    private readonly GrpcChannel? _ownedChannel;
    private readonly AuthorizationService.AuthorizationServiceClient _stub;
    private readonly JwksVerifier? _jwksVerifier;
    private readonly Func<string?> _tokenAccessor;
    private readonly string _tenantId;

    /// <summary>
    /// Constructs the gRPC authz transport from <paramref name="client"/>'s exposed
    /// internal seam (<c>RefreshGuard</c>, <c>JwksVerifier</c>, <c>CurrentAccessToken</c>,
    /// <c>BaseUrl</c>, <c>CustomCaPem</c>) — this constructor never modifies
    /// <see cref="AxiamClient"/> itself.
    /// </summary>
    /// <param name="client">The already-constructed REST <see cref="AxiamClient"/> whose
    /// session (RefreshGuard/tenant/token) this gRPC transport shares.</param>
    /// <param name="grpcTarget">
    /// The gRPC endpoint. Defaults to <paramref name="client"/>'s own REST
    /// <c>BaseUrl</c> when omitted — pass an explicit value when AXIAM's
    /// <c>AuthorizationService</c> is exposed on a distinct host/port from the REST API.
    /// </param>
    public AxiamGrpcAuthzClient(AxiamClient client, Uri? grpcTarget = null)
    {
        ArgumentNullException.ThrowIfNull(client);

        _tokenAccessor = () => client.CurrentAccessToken;
        _tenantId = client.TenantId;
        _jwksVerifier = client.JwksVerifier;

        var interceptor = new AuthInterceptor(_tokenAccessor, _tenantId, client.RefreshGuard);
        _ownedChannel = AxiamGrpcChannel.Create(grpcTarget ?? client.BaseUrl, client.CustomCaPem);
        _stub = new AuthorizationService.AuthorizationServiceClient(_ownedChannel.Intercept(interceptor));
    }

    /// <summary>
    /// Test-only seam: builds over an already-intercepted <see cref="CallInvoker"/> (e.g.
    /// an in-process/loopback test channel with its own <see cref="AuthInterceptor"/>
    /// already attached by the caller), bypassing the public constructor's strict-TLS
    /// <see cref="GrpcChannel"/> construction. Mirrors the Java sibling's package-private
    /// <c>GrpcAuthzClient(ManagedChannel, ...)</c> test constructor. Internal — only
    /// <c>GrpcAuthzClientTests</c> (same assembly) uses this.
    /// </summary>
    internal AxiamGrpcAuthzClient(CallInvoker invoker, JwksVerifier? jwksVerifier, Func<string?> tokenAccessor, string tenantId)
    {
        ArgumentNullException.ThrowIfNull(invoker);
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);

        _ownedChannel = null; // the caller owns the channel/server this invoker is bound to
        _stub = new AuthorizationService.AuthorizationServiceClient(invoker);
        _jwksVerifier = jwksVerifier;
        _tokenAccessor = tokenAccessor ?? throw new ArgumentNullException(nameof(tokenAccessor));
        _tenantId = tenantId;
    }

    /// <summary>A single authorization check request item for <see cref="BatchCheckAsync"/>.</summary>
    /// <param name="Action">The action to check (e.g. <c>"users:get"</c>).</param>
    /// <param name="ResourceId">The resource identifier the action targets.</param>
    /// <param name="Scope">Optional scope for sub-resource granularity.</param>
    /// <param name="SubjectId">
    /// Optional "check-as" subject override. Requires the caller to hold
    /// <c>authz:check_as</c> server-side; omit to check on behalf of the authenticated
    /// caller (resolved from the access token's own <c>sub</c> claim).
    /// </param>
    public sealed record AccessCheck(string Action, string ResourceId, string? Scope = null, string? SubjectId = null);

    /// <summary>
    /// <c>CheckAccess</c> (CONTRACT.md &#167;1). On <c>UNAUTHENTICATED</c>, the shared
    /// <c>AuthInterceptor</c> already drove exactly one shared-guard refresh and retried
    /// once (&#167;9.3) before this method ever observes a terminal failure. A terminal
    /// gRPC status maps through <see cref="ErrorMapper.FromGrpcStatus"/> — the same
    /// taxonomy the REST transport uses.
    /// </summary>
    public async Task<bool> CheckAccessAsync(
        string action, string resourceId, string? scope = null, string? subjectId = null, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(action);
        ArgumentException.ThrowIfNullOrWhiteSpace(resourceId);

        CheckAccessRequest wire = await BuildWireRequestAsync(action, resourceId, scope, subjectId, cancellationToken).ConfigureAwait(false);
        try
        {
            // AsyncUnaryCall<T> itself is not directly awaitable via ConfigureAwait — its
            // .ResponseAsync (a plain Task<T>) is the awaitable surface; `using` disposes
            // the call's underlying HTTP/2 stream resources once the response is consumed.
            using AsyncUnaryCall<CheckAccessResponse> call = _stub.CheckAccessAsync(
                wire, deadline: DateTime.UtcNow.Add(CheckAccessDeadline), cancellationToken: cancellationToken);
            CheckAccessResponse response = await call.ResponseAsync.ConfigureAwait(false);
            return response.Allowed;
        }
        catch (RpcException ex)
        {
            throw ErrorMapper.FromGrpcStatus(ex.StatusCode, DescriptionOf(ex));
        }
    }

    /// <summary>
    /// <c>BatchCheckAccess</c> (CONTRACT.md &#167;1); results are returned in the same
    /// order as <paramref name="checks"/>. Shares the same UNAUTHENTICATED
    /// single-flight-retry behavior as <see cref="CheckAccessAsync"/> (driven by the
    /// shared <c>AuthInterceptor</c>).
    /// </summary>
    public async Task<IReadOnlyList<bool>> BatchCheckAsync(IEnumerable<AccessCheck> checks, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(checks);

        var wireRequest = new BatchCheckAccessRequest();
        foreach (AccessCheck check in checks)
        {
            CheckAccessRequest wire = await BuildWireRequestAsync(check.Action, check.ResourceId, check.Scope, check.SubjectId, cancellationToken)
                .ConfigureAwait(false);
            wireRequest.Requests.Add(wire);
        }

        try
        {
            using AsyncUnaryCall<BatchCheckAccessResponse> call = _stub.BatchCheckAccessAsync(
                wireRequest, deadline: DateTime.UtcNow.Add(BatchCheckDeadline), cancellationToken: cancellationToken);
            BatchCheckAccessResponse response = await call.ResponseAsync.ConfigureAwait(false);
            return response.Results.Select(r => r.Allowed).ToList();
        }
        catch (RpcException ex)
        {
            throw ErrorMapper.FromGrpcStatus(ex.StatusCode, DescriptionOf(ex));
        }
    }

    /// <summary>The channel is shut down with the client — a no-op when this instance was
    /// built over a caller-owned <see cref="CallInvoker"/> (the internal test seam).</summary>
    public void Dispose() => _ownedChannel?.Dispose();

    // ------------------------------------------------------------------
    // Wire mapping (proto/axiam/v1/authorization.proto)
    // ------------------------------------------------------------------

    private async Task<CheckAccessRequest> BuildWireRequestAsync(
        string action, string resourceId, string? scope, string? subjectIdOverride, CancellationToken cancellationToken)
    {
        (string tenantId, string subjectId) = await ResolveWireIdentityAsync(subjectIdOverride, cancellationToken).ConfigureAwait(false);

        var wire = new CheckAccessRequest
        {
            TenantId = tenantId,
            SubjectId = subjectId,
            Action = action,
            ResourceId = resourceId,
        };
        if (scope is not null)
        {
            wire.Scope = scope;
        }
        return wire;
    }

    /// <summary>
    /// Resolves <c>(tenant_id, subject_id)</c> from the current access token's claims —
    /// preferring the signature-VERIFIED path (<see cref="JwksVerifier.VerifyAsync"/>)
    /// when a verifier is available, falling back to an unverified decode as an
    /// operational hint otherwise. NEVER falls back to the raw configured tenant
    /// identifier string.
    /// </summary>
    private async Task<(string TenantId, string SubjectId)> ResolveWireIdentityAsync(string? subjectIdOverride, CancellationToken cancellationToken)
    {
        string? access = _tokenAccessor();
        if (access is null)
        {
            throw new AuthError("no active session — call LoginAsync() before CheckAccessAsync()/BatchCheckAsync()");
        }

        JsonElement? claims = _jwksVerifier is not null
            ? await _jwksVerifier.VerifyAsync(access, _tenantId, cancellationToken).ConfigureAwait(false)
            : null;

        // Fall back to an unverified decode purely as an operational hint for the wire
        // fields — mirrors AxiamClient.DoHttpRefreshAsync's own established pattern. This
        // is NEVER an authorization decision: the server independently cross-validates
        // both wire fields against its own verified JWT claims and rejects
        // PERMISSION_DENIED on any mismatch, so a wrong hint here can only ever produce a
        // denial, never an over-grant.
        claims ??= DecodeUnverifiedClaims(access);

        if (claims is not { } resolvedClaims)
        {
            throw new AuthError("access token could not be verified or decoded — call RefreshAsync() first");
        }

        string tenantId = RequireClaim(resolvedClaims, "tenant_id");
        string subjectId = subjectIdOverride ?? RequireClaim(resolvedClaims, "sub");
        return (tenantId, subjectId);
    }

    private static string RequireClaim(JsonElement claims, string claimName)
    {
        if (!claims.TryGetProperty(claimName, out JsonElement value) || value.ValueKind != JsonValueKind.String)
        {
            throw new AuthError($"access token is missing the '{claimName}' claim required for gRPC authz checks");
        }
        return value.GetString()!;
    }

    private static string DescriptionOf(RpcException ex) => ex.Status.Detail is { Length: > 0 } detail ? detail : ex.StatusCode.ToString();

    private static JsonElement? DecodeUnverifiedClaims(string jwt)
    {
        string[] parts = jwt.Split('.');
        if (parts.Length != 3)
        {
            return null;
        }

        try
        {
            byte[] payloadBytes = Base64UrlDecode(parts[1]);
            using JsonDocument doc = JsonDocument.Parse(payloadBytes);
            return doc.RootElement.Clone();
        }
        catch
        {
            return null;
        }
    }

    private static byte[] Base64UrlDecode(string s)
    {
        string padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}

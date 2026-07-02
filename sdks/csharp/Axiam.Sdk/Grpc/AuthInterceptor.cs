using Axiam.Sdk.Auth;
using Grpc.Core;
using Grpc.Core.Interceptors;

namespace Axiam.Sdk.Grpc;

/// <summary>
/// Sync-safe <c>authorization</c>/<c>x-tenant-id</c> metadata injection on every outgoing
/// gRPC call (CONTRACT.md &#167;5), plus an <c>UNAUTHENTICATED</c> single-flight
/// refresh-and-retry (&#167;9, D-10) that drives the EXACT SAME shared
/// <see cref="RefreshGuard"/> the REST transport uses — never a second guard instance.
/// </summary>
/// <remarks>
/// <para>
/// The token accessor is a caller-supplied, non-blocking <see cref="Func{TResult}"/>
/// (mirrors the Java <c>AuthClientInterceptor</c>'s <c>Supplier&lt;String&gt;</c> and Go
/// <c>interceptor.go</c>'s <c>TokenFunc</c>) — this class NEVER calls
/// <see cref="RefreshGuard.RefreshIfNeededAsync"/> synchronously on the hot
/// <see cref="AsyncUnaryCall{TResponse}"/> interception path; the accessor is
/// read once per call to build outgoing metadata, and the guard is only ever awaited
/// (fully asynchronously) after an <c>UNAUTHENTICATED</c> response has already been
/// observed.
/// </para>
/// <para>
/// Sync-safety: every code path in this class is <c>async</c>/<c>await</c> all the way
/// down — there is no <c>.Result</c>/<c>.Wait()</c>/<c>.GetAwaiter().GetResult()</c>
/// anywhere, so this interceptor can never sync-over-async deadlock a caller's
/// synchronization context (there is none here to deadlock on, by construction).
/// </para>
/// </remarks>
public sealed class AuthInterceptor : Interceptor
{
    private const string AuthorizationHeader = "authorization";
    private const string TenantHeader = "x-tenant-id";

    private readonly Func<string?> _tokenAccessor;
    private readonly string _tenantId;
    private readonly RefreshGuard _refreshGuard;

    /// <param name="tokenAccessor">
    /// A non-blocking accessor for the currently cached access token (<c>null</c> when
    /// none is available yet). MUST NOT acquire <see cref="RefreshGuard"/>'s lock or
    /// perform I/O — this runs on the hot RPC path (mirrors the REST
    /// <c>AxiamHttpMessageHandler</c> and the Java/Go sibling interceptors' token-accessor
    /// discipline).
    /// </param>
    /// <param name="tenantId">
    /// The client's configured tenant identifier (CONTRACT.md &#167;5), injected as
    /// <c>x-tenant-id</c> metadata on every call — mirrors the REST
    /// <c>X-Tenant-Id</c> header's use of the raw configured value.
    /// </param>
    /// <param name="refreshGuard">
    /// The SAME <see cref="RefreshGuard"/> instance the client's REST transport uses
    /// (D-10's "one guard across REST + gRPC on one client") — never a second instance.
    /// </param>
    public AuthInterceptor(Func<string?> tokenAccessor, string tenantId, RefreshGuard refreshGuard)
    {
        _tokenAccessor = tokenAccessor ?? throw new ArgumentNullException(nameof(tokenAccessor));
        ArgumentException.ThrowIfNullOrWhiteSpace(tenantId);
        _tenantId = tenantId;
        _refreshGuard = refreshGuard ?? throw new ArgumentNullException(nameof(refreshGuard));
    }

    /// <summary>
    /// Injects auth/tenant metadata on every outgoing unary call (<c>CheckAccess</c>/
    /// <c>BatchCheckAccess</c> are both unary RPCs); on <c>UNAUTHENTICATED</c>, drives
    /// exactly one shared-guard refresh then retries the call exactly once (&#167;9.3 —
    /// never a loop). A second failure (including a second <c>UNAUTHENTICATED</c>, or a
    /// failure of the refresh itself) propagates to the caller as-is.
    /// </summary>
    public override AsyncUnaryCall<TResponse> AsyncUnaryCall<TRequest, TResponse>(
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> context,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
    {
        ClientInterceptorContext<TRequest, TResponse> authedContext = InjectAuthMetadata(context);
        AsyncUnaryCall<TResponse> call = continuation(request, authedContext);

        return new AsyncUnaryCall<TResponse>(
            HandleResponseAsync(call, request, context, continuation),
            call.ResponseHeadersAsync,
            call.GetStatus,
            call.GetTrailers,
            call.Dispose);
    }

    private async Task<TResponse> HandleResponseAsync<TRequest, TResponse>(
        AsyncUnaryCall<TResponse> call,
        TRequest request,
        ClientInterceptorContext<TRequest, TResponse> originalContext,
        AsyncUnaryCallContinuation<TRequest, TResponse> continuation)
        where TRequest : class
        where TResponse : class
    {
        try
        {
            return await call.ResponseAsync.ConfigureAwait(false);
        }
        catch (RpcException ex) when (ex.StatusCode == StatusCode.Unauthenticated)
        {
            // Exactly ONE refresh through the SHARED RefreshGuard (D-10) — never a second
            // guard instance. If the refresh itself throws, that exception propagates
            // as-is to this call's caller; no RPC retry is attempted in that case. `call`
            // (the failed original attempt) is disposed by the OUTER AsyncUnaryCall
            // wrapper this method feeds into (its dispose delegate is wired to this same
            // `call.Dispose`, see the AsyncUnaryCall<TRequest,TResponse> override above) —
            // not here, avoiding a double-dispose of the same underlying call.
            await _refreshGuard.RefreshIfNeededAsync(originalContext.Options.CancellationToken).ConfigureAwait(false);

            ClientInterceptorContext<TRequest, TResponse> retryContext = InjectAuthMetadata(originalContext);
            using AsyncUnaryCall<TResponse> retryCall = continuation(request, retryContext);
            // Retried EXACTLY once — whatever this call returns or throws (including a
            // second UNAUTHENTICATED) is the final outcome. No loop.
            return await retryCall.ResponseAsync.ConfigureAwait(false);
        }
    }

    private ClientInterceptorContext<TRequest, TResponse> InjectAuthMetadata<TRequest, TResponse>(
        ClientInterceptorContext<TRequest, TResponse> context)
        where TRequest : class
        where TResponse : class
    {
        // Build a FRESH Metadata rather than mutating context.Options.Headers in place:
        // when a caller supplied their own Headers/Metadata (e.g. a reused "default
        // options" object), mutating it directly would silently corrupt the caller's
        // instance and race two concurrent interceptor invocations sharing that list
        // (Metadata is a List<Entry> wrapper, not safe for concurrent mutation). Copy
        // every pre-existing NON-auth/NON-tenant entry into the fresh instance so
        // caller-supplied custom metadata is preserved.
        var headers = new Metadata();
        if (context.Options.Headers is { } existing)
        {
            foreach (Metadata.Entry entry in existing)
            {
                if (!string.Equals(entry.Key, AuthorizationHeader, StringComparison.OrdinalIgnoreCase) &&
                    !string.Equals(entry.Key, TenantHeader, StringComparison.OrdinalIgnoreCase))
                {
                    headers.Add(entry);
                }
            }
        }

        // Non-blocking read — NEVER refresh synchronously on this hot path (mirrors the
        // REST AxiamHttpMessageHandler and the Java/Go sibling interceptors' token-accessor
        // discipline).
        string? token = _tokenAccessor();
        if (token is not null)
        {
            headers.Add(AuthorizationHeader, $"Bearer {token}");
        }
        headers.Add(TenantHeader, _tenantId);

        CallOptions newOptions = context.Options.WithHeaders(headers);
        return new ClientInterceptorContext<TRequest, TResponse>(context.Method, context.Host, newOptions);
    }
}

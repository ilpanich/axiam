using System.Threading;
using System.Threading.Tasks;

namespace Axiam.Sdk.Auth;

/// <summary>
/// Single-flight token-refresh guard (D-10, CONTRACT.md &#167;9): guarantees exactly
/// one in-flight refresh call at a time, regardless of how many concurrent callers
/// observe an expired/near-expiry access token. One instance is constructed per
/// <c>AxiamClient</c> and shared across the REST and gRPC transports (D-10's
/// "one guard across REST + gRPC on one client" requirement) — never a second
/// instance per transport.
/// </summary>
/// <remarks>
/// Correctness invariants (mirrors the Java sibling's <c>RefreshGuard</c> double-check-
/// after-lock structure, adapted to <see cref="SemaphoreSlim"/> + <see cref="Task{T}"/>
/// per CONTRACT.md &#167;9's locked C# mechanism):
/// <list type="bullet">
/// <item>
/// <description>
/// The refresh delegate is deliberately awaited WHILE still holding the gate. This is
/// what makes every concurrent caller queue on <c>_gate.WaitAsync</c>: the first caller
/// to acquire the gate assigns <c>_inFlight</c> and awaits it before releasing; any
/// caller that later acquires the gate finds <c>_inFlight</c> already completed (and,
/// if still fresh, reuses it) instead of starting a redundant refresh (SC#2: 5
/// concurrent callers against an expired token ⇒ exactly 1 underlying refresh).
/// </description>
/// </item>
/// <item>
/// <description>
/// On failure, <c>_inFlight</c> is cleared before rethrowing so a failed refresh is
/// NEVER cached for the next caller — the next call always starts a fresh refresh
/// attempt (&#167;9.3: no retry loop inside the guard itself; the caller must
/// re-authenticate from scratch).
/// </description>
/// </item>
/// <item>
/// <description>
/// A subsequent call reuses an already-completed result only when it is still fresh
/// (more than <see cref="FreshnessMargin"/> from expiry) — never a stale or faulted one.
/// </description>
/// </item>
/// </list>
/// </remarks>
public sealed class RefreshGuard : IDisposable
{
    private static readonly TimeSpan FreshnessMargin = TimeSpan.FromSeconds(5);

    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly Func<CancellationToken, Task<TokenPair>> _doRefresh;
    private Task<TokenPair>? _inFlight;

    public RefreshGuard(Func<CancellationToken, Task<TokenPair>> doRefresh)
    {
        _doRefresh = doRefresh ?? throw new ArgumentNullException(nameof(doRefresh));
    }

    /// <summary>
    /// Called by both the reactive (401 / gRPC <c>UNAUTHENTICATED</c>) and proactive
    /// (near-expiry, JWKS-driven) refresh paths. Guarantees exactly one underlying
    /// refresh call regardless of how many callers invoke this concurrently.
    /// </summary>
    public async Task<TokenPair> RefreshIfNeededAsync(CancellationToken cancellationToken = default)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            // Double-checked: another waiter may have already completed a refresh (or
            // this call is the first to observe an in-flight one after it resolved) —
            // reuse a still-fresh completed result instead of starting a redundant
            // refresh.
            if (_inFlight is { IsCompletedSuccessfully: true } done &&
                done.Result.ExpiresAt > DateTimeOffset.UtcNow + FreshnessMargin)
            {
                return done.Result;
            }

            // Start exactly one refresh. Deliberately awaited HERE, while still
            // holding the gate — do not release the gate before awaiting. Every
            // concurrent caller blocked on _gate.WaitAsync above will, in turn,
            // observe this same completed Task<TokenPair> via the double-check
            // above once it becomes their turn, rather than invoking _doRefresh a
            // second time.
            _inFlight = _doRefresh(cancellationToken);
            return await _inFlight.ConfigureAwait(false);
        }
        catch
        {
            // Never cache a faulted refresh for the next caller — no retry loop
            // inside the guard (CONTRACT.md §9.3). The exception propagates as-is
            // (surfaces as AuthError from the delegate) to this waiter's caller;
            // the next call — whether from this or another waiter — starts a
            // brand-new refresh attempt rather than reusing the fault.
            _inFlight = null;
            throw;
        }
        finally
        {
            _gate.Release();
        }
    }

    public void Dispose() => _gate.Dispose();
}

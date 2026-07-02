using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Auth;
using Axiam.Sdk.Core;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// SC#2 regression suite (CONTRACT.md &#167;9, D-10): proves <see cref="RefreshGuard"/>
/// collapses N concurrent callers into exactly one underlying refresh, and that a failed
/// refresh is propagated to every waiter without ever being cached as a "poisoned"
/// result for the next call.
/// </summary>
[Trait("Category", "Fast")]
public class RefreshGuardSingleFlightTests
{
    private const string Tenant = "acme";

    private static TokenPair FreshTokenPair(int sequence) =>
        new(
            Sensitive.Of($"access-{sequence}"),
            Sensitive.Of($"refresh-{sequence}"),
            DateTimeOffset.UtcNow.AddMinutes(15));

    /// <summary>
    /// SC#2: 5 concurrent tasks calling the guard against an expired token trigger
    /// exactly 1 underlying refresh; all 5 receive the identical fresh <see cref="TokenPair"/>
    /// instance (proving result sharing, not 5 independent — merely equal-looking — refreshes).
    /// </summary>
    [Fact]
    public async Task FiveConcurrentCallers_TriggerExactlyOneRefresh_AndShareTheSameResult()
    {
        int callCount = 0;
        TokenPair produced = FreshTokenPair(sequence: 1);

        var guard = new RefreshGuard(async ct =>
        {
            Interlocked.Increment(ref callCount);
            // Small delay widens the concurrency window so all 5 callers genuinely
            // queue up on the gate before the first refresh resolves.
            await Task.Delay(50, ct);
            return produced;
        });

        // ToArray() forces synchronous invocation of RefreshIfNeededAsync for all 5
        // callers before any of them observes the delegate's Task.Delay yielding —
        // this is what genuinely exercises the SemaphoreSlim queuing behavior rather
        // than 5 fully sequential calls.
        Task<TokenPair>[] tasks = Enumerable.Range(0, 5)
            .Select(_ => guard.RefreshIfNeededAsync())
            .ToArray();

        TokenPair[] results = await Task.WhenAll(tasks);

        Assert.Equal(1, callCount);
        Assert.All(results, r => Assert.Same(produced, r));
    }

    /// <summary>
    /// When the refresh delegate throws, the failing call observes that exception
    /// AND <c>_inFlight</c> is cleared — a follow-up call re-invokes the delegate
    /// rather than reusing a cached fault (&#167;9.3: no retry loop, but also no
    /// permanently-poisoned guard).
    /// </summary>
    [Fact]
    public async Task FailedRefresh_PropagatesException_AndIsNeverCachedForTheNextCall()
    {
        int callCount = 0;
        var guard = new RefreshGuard(async ct =>
        {
            Interlocked.Increment(ref callCount);
            await Task.Delay(10, ct);
            throw new AuthError("refresh rejected");
        });

        AuthError first = await Assert.ThrowsAsync<AuthError>(() => guard.RefreshIfNeededAsync());
        Assert.Equal("refresh rejected", first.Message);
        Assert.Equal(1, callCount);

        // Non-vacuous: if the guard had cached the fault, this second call would
        // still throw but callCount would remain 1. It must increment to 2, proving
        // the delegate was genuinely re-invoked, not short-circuited on a cached
        // faulted Task.
        AuthError second = await Assert.ThrowsAsync<AuthError>(() => guard.RefreshIfNeededAsync());
        Assert.Equal("refresh rejected", second.Message);
        Assert.Equal(2, callCount);
    }

    /// <summary>
    /// All waiters queued behind a failing refresh observe the same failure — none of
    /// them silently succeed or hang, and every one of them independently re-triggers
    /// the delegate (proving the guard never short-circuits a subsequent waiter onto a
    /// cached faulted <c>_inFlight</c>).
    /// </summary>
    [Fact]
    public async Task ConcurrentCallers_AllObserveTheSameRefreshFailure()
    {
        int callCount = 0;
        var guard = new RefreshGuard(async ct =>
        {
            Interlocked.Increment(ref callCount);
            await Task.Delay(20, ct);
            throw new AuthError("refresh rejected");
        });

        Task<TokenPair>[] tasks = Enumerable.Range(0, 5)
            .Select(_ => guard.RefreshIfNeededAsync())
            .ToArray();

        foreach (Task<TokenPair> task in tasks)
        {
            AuthError error = await Assert.ThrowsAsync<AuthError>(() => task);
            Assert.Equal("refresh rejected", error.Message);
        }

        // Every one of the 5 waiters triggered its own fresh attempt because a
        // faulted _inFlight is cleared before the gate is released to the next
        // waiter (§9.3) — never cached as a single shared fault.
        Assert.Equal(5, callCount);
    }

    /// <summary>
    /// A call made after an already-fresh result exists reuses it without invoking
    /// the delegate again — proves the "still fresh" branch of the double-check, not
    /// just the concurrent-queue branch exercised above.
    /// </summary>
    [Fact]
    public async Task SubsequentCall_ReusesStillFreshResult_WithoutRefreshing()
    {
        int callCount = 0;
        TokenPair produced = FreshTokenPair(sequence: 7);
        var guard = new RefreshGuard(ct =>
        {
            Interlocked.Increment(ref callCount);
            return Task.FromResult(produced);
        });

        TokenPair firstResult = await guard.RefreshIfNeededAsync();
        TokenPair secondResult = await guard.RefreshIfNeededAsync();

        Assert.Equal(1, callCount);
        Assert.Same(produced, firstResult);
        Assert.Same(produced, secondResult);
    }
}

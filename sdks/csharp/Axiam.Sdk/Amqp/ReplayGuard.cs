using System;
using System.Collections.Concurrent;
using System.Globalization;
using System.Text.Json.Nodes;

namespace Axiam.Sdk.Amqp;

/// <summary>
/// The <c>key_version</c>/<c>nonce</c>/<c>issued_at</c> fields extracted from
/// an already HMAC-verified AMQP message body (<c>sdks/CONTRACT.md</c> §8
/// "v2 — Replay Protection", NEW-4). Extraction happens strictly AFTER
/// <see cref="Hmac.Verify"/> has returned <c>true</c> — these values are
/// meaningless (and MUST NOT be trusted) on an unverified body.
/// </summary>
/// <param name="KeyVersion">The message's declared <c>key_version</c>. Absent/unparseable is
/// represented as <c>0</c>, which is always below <see cref="ReplayGuard.MinKeyVersion"/> and
/// therefore rejected — a message that predates NEW-4 has no version field at all.</param>
/// <param name="Nonce">The message's <c>nonce</c> (a UUIDv4 string, echoed verbatim).</param>
/// <param name="IssuedAt">The message's <c>issued_at</c> (an RFC3339/ISO8601 UTC timestamp
/// string, echoed verbatim — never reformatted).</param>
public readonly record struct ReplayMetadata(int KeyVersion, string Nonce, string IssuedAt);

/// <summary>
/// Enforces the NEW-4 (<c>sdks/CONTRACT.md</c> §8 "v2 — Replay Protection")
/// consumer-side gates that run AFTER <see cref="Hmac.Verify"/> has already
/// succeeded on a delivery:
/// </summary>
/// <list type="number">
/// <item><description><c>key_version</c> below <see cref="MinKeyVersion"/> is rejected outright
/// (hard cutover, no v1 grace path — mirrors
/// <c>crates/axiam-amqp/src/messages.rs</c>'s <c>MIN_ACCEPTED_KEY_VERSION</c>).</description></item>
/// <item><description><c>issued_at</c> outside a ±<see cref="Skew"/> freshness window of the
/// consumer's clock is rejected (stale or future-dated message).</description></item>
/// <item><description>A <c>nonce</c> already seen within that freshness window is rejected as a
/// replay.</description></item>
/// </list>
/// <para>
/// The nonce dedup store is an in-memory, per-<see cref="ReplayGuard"/>
/// <see cref="ConcurrentDictionary{TKey,TValue}"/> mapping nonce to expiry.
/// Its TTL is 2×<see cref="Skew"/>: a nonce cannot legitimately recur once its
/// message has aged out of the ±skew freshness window, so entries older than
/// 2×skew are pruned opportunistically on every <see cref="Check"/> call,
/// keeping the store naturally bounded without a background task. This is a
/// defense-in-depth, process-local check — it resets on restart and does not
/// replace the server's durable per-tenant nonce store.
/// </para>
/// <para>
/// One <see cref="ReplayGuard"/> instance MUST be shared across every
/// delivery handled by a given consumer (constructed once per
/// <see cref="AxiamAmqpConsumer.StartAsync"/> call) — constructing a fresh
/// instance per delivery would make nonce dedup a no-op.
/// </para>
public sealed class ReplayGuard
{
    /// <summary>
    /// The lowest AMQP signed-envelope <c>key_version</c> this SDK will
    /// accept. A message with <c>key_version</c> below this predates the
    /// mandatory <c>nonce</c>/<c>issued_at</c> replay-protection fields and is
    /// rejected outright — a hard cutover, there is no v1 grace path (mirrors
    /// <c>crates/axiam-amqp/src/messages.rs</c>'s <c>MIN_ACCEPTED_KEY_VERSION</c>).
    /// </summary>
    public const int MinKeyVersion = 2;

    /// <summary>
    /// The default freshness window applied to a delivery's <c>issued_at</c>
    /// field (mirrors <c>crates/axiam-amqp/src/messages.rs</c>'s
    /// <c>DEFAULT_FRESHNESS_SKEW_SECS = 300</c>).
    /// </summary>
    public static readonly TimeSpan DefaultSkew = TimeSpan.FromSeconds(300);

    private readonly TimeSpan _skew;
    private readonly Func<DateTimeOffset> _clock;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _seenNonces = new();

    /// <summary>The freshness skew this guard was constructed with.</summary>
    public TimeSpan Skew => _skew;

    /// <summary>
    /// Creates a <see cref="ReplayGuard"/> with the given freshness skew
    /// (defaults to <see cref="DefaultSkew"/> when <paramref name="skew"/> is
    /// <c>null</c> or non-positive).
    /// </summary>
    public ReplayGuard(TimeSpan? skew = null)
        : this(skew, clock: null)
    {
    }

    /// <summary>
    /// Test-only seam: allows the "current time" the freshness check compares
    /// against to be overridden, so tests can exercise deterministic
    /// stale/fresh/future scenarios without depending on wall-clock time.
    /// Internal — never part of the public API surface.
    /// </summary>
    internal ReplayGuard(TimeSpan? skew, Func<DateTimeOffset>? clock)
    {
        _skew = skew is { } s && s > TimeSpan.Zero ? s : DefaultSkew;
        _clock = clock ?? (static () => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Parses <c>key_version</c>, <c>nonce</c>, and <c>issued_at</c> out of an
    /// already-verified message body. Never throws: a malformed body, or one
    /// missing <c>nonce</c>/<c>issued_at</c> entirely, returns <c>false</c>
    /// (which <see cref="Check"/>'s caller must treat as a rejection — an
    /// unparseable/absent replay-protection field is exactly as unsafe as a
    /// stale one). A missing/non-numeric <c>key_version</c> yields
    /// <see cref="ReplayMetadata.KeyVersion"/> == 0, which is always rejected
    /// by <see cref="Check"/> since it is below <see cref="MinKeyVersion"/>.
    /// </summary>
    public static bool TryExtractMetadata(byte[] body, out ReplayMetadata metadata)
    {
        metadata = default;
        try
        {
            JsonObject? node = JsonNode.Parse(body)?.AsObject();
            if (node is null)
            {
                return false;
            }

            int keyVersion = 0;
            if (node.TryGetPropertyValue("key_version", out JsonNode? kv) && kv is not null)
            {
                keyVersion = kv.GetValue<int>();
            }

            if (!node.TryGetPropertyValue("nonce", out JsonNode? nonceNode) || nonceNode is null)
            {
                return false;
            }

            if (!node.TryGetPropertyValue("issued_at", out JsonNode? issuedAtNode) || issuedAtNode is null)
            {
                return false;
            }

            string nonce = nonceNode.GetValue<string>();
            string issuedAt = issuedAtNode.GetValue<string>();

            metadata = new ReplayMetadata(keyVersion, nonce, issuedAt);
            return true;
        }
        catch
        {
            // Malformed body / wrong JSON value kind for a field -> treat as
            // extraction failure, never throw.
            return false;
        }
    }

    /// <summary>
    /// Validates <paramref name="metadata"/> against the NEW-4 replay-protection
    /// policy and, iff it passes, atomically records its nonce so a second
    /// delivery of the same nonce is rejected as a replay. Returns <c>true</c>
    /// iff the message passes all three checks:
    /// </summary>
    /// <list type="bullet">
    /// <item><description><c>key_version</c> &gt;= <see cref="MinKeyVersion"/>.</description></item>
    /// <item><description><c>issued_at</c> parses as an ISO8601/RFC3339 timestamp and lies
    /// within ±<see cref="Skew"/> of this guard's clock.</description></item>
    /// <item><description><c>nonce</c> has not already been seen within the freshness
    /// window.</description></item>
    /// </list>
    public bool Check(ReplayMetadata metadata)
    {
        if (metadata.KeyVersion < MinKeyVersion)
        {
            return false;
        }

        if (!DateTimeOffset.TryParse(
                metadata.IssuedAt,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out DateTimeOffset issuedAt))
        {
            return false;
        }

        DateTimeOffset now = _clock();
        TimeSpan age = now - issuedAt;
        if (age > _skew || age < -_skew)
        {
            return false; // stale or future-dated beyond the freshness window
        }

        Prune(now);

        return TryRecordNonce(metadata.Nonce, now);
    }

    /// <summary>
    /// Atomically records <paramref name="nonce"/> with a TTL of 2×<see cref="Skew"/>
    /// from <paramref name="now"/>, iff it is not already present with an
    /// unexpired entry. Returns <c>false</c> (replay) when the nonce is
    /// already recorded and has not yet expired.
    /// </summary>
    private bool TryRecordNonce(string nonce, DateTimeOffset now)
    {
        DateTimeOffset newExpiry = now + _skew + _skew;
        bool isReplay = false;

        _seenNonces.AddOrUpdate(
            nonce,
            addValueFactory: _ => newExpiry,
            updateValueFactory: (_, existingExpiry) =>
            {
                if (existingExpiry > now)
                {
                    isReplay = true;
                    return existingExpiry; // leave the existing (still-live) entry untouched
                }

                return newExpiry; // stale entry aged out of its own TTL -> nonce may be reused
            });

        return !isReplay;
    }

    /// <summary>
    /// Opportunistically removes expired nonce entries so the store stays
    /// bounded without a background task. Cheap relative to network I/O; run
    /// on every <see cref="Check"/> call, mirroring the reference Go SDK
    /// (<c>sdks/go/amqp/replay.go</c>).
    /// </summary>
    private void Prune(DateTimeOffset now)
    {
        foreach ((string nonce, DateTimeOffset expiry) in _seenNonces)
        {
            if (now >= expiry)
            {
                _seenNonces.TryRemove(nonce, out _);
            }
        }
    }
}

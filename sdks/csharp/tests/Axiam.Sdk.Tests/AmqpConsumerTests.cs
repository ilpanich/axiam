using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json.Nodes;
using System.Threading;
using System.Threading.Tasks;
using Axiam.Sdk.Amqp;
using Microsoft.Extensions.Logging;
using Moq;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Xunit;

namespace Axiam.Sdk.Tests;

/// <summary>
/// Proves <see cref="AxiamAmqpConsumer"/>'s <c>sdks/CONTRACT.md</c> §8
/// ack/nack matrix and verify-before-handler invariant across every branch,
/// using a Moq-based fake <see cref="IChannel"/> (recording
/// <c>BasicAckAsync</c>/<c>BasicNackAsync(tag, multiple, requeue)</c> calls)
/// and synthesized <see cref="BasicDeliverEventArgs"/> instances. The
/// delegate under test is obtained via
/// <see cref="AxiamAmqpConsumer.CreateReceivedHandler"/> and invoked
/// directly — no live broker is involved.
///
/// <para>
/// Valid/tampered bodies and the matching signing key are reused verbatim
/// from 21-01's real, Rust-signer-produced fixture
/// (<c>Fixtures/amqp_hmac_vectors.json</c>), so the HMAC-fail branch below is
/// proven against an authentic tampered signature, not a hand-rolled invalid
/// one.
/// </para>
/// </summary>
[Trait("Category", "Fast")]
public class AmqpConsumerTests
{
    private static readonly string FixturePath =
        Path.Combine(AppContext.BaseDirectory, "Fixtures", "amqp_hmac_vectors.json");

    private sealed record AckNackCall(string Type, ulong DeliveryTag, bool Multiple, bool Requeue);

    /// <summary>
    /// A hand-written fake <see cref="ILogger"/> recording the fully
    /// formatted text of every <c>LogWarning</c> call, so tests can assert on
    /// the exact logged message without pulling in a logging provider.
    /// </summary>
    private sealed class RecordingLogger : ILogger
    {
        public List<string> Warnings { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
            if (logLevel == LogLevel.Warning)
            {
                Warnings.Add(formatter(state, exception));
            }
        }
    }

    /// <summary>
    /// The fixture's "authz_request_valid" vector's <c>issued_at</c>
    /// (<c>Fixtures/amqp_hmac_vectors.json</c>) — every test below that needs a
    /// <see cref="ReplayGuard"/> passing the freshness check pins its clock to
    /// this instant (matching the reference Go SDK's <c>now func()</c> test seam)
    /// rather than depending on wall-clock time.
    /// </summary>
    private static readonly DateTimeOffset FixtureIssuedAt =
        DateTimeOffset.Parse("2026-07-10T12:00:00Z", CultureInfo.InvariantCulture);

    /// <summary>
    /// Builds a <see cref="ReplayGuard"/> whose clock is pinned to
    /// <see cref="FixtureIssuedAt"/> (or <paramref name="clock"/> when supplied),
    /// so fixture bodies signed at that fixed <c>issued_at</c> pass the freshness
    /// gate deterministically regardless of when the test actually runs.
    /// </summary>
    private static ReplayGuard NewGuard(TimeSpan? skew = null, Func<DateTimeOffset>? clock = null) =>
        new(skew, clock ?? (() => FixtureIssuedAt));

    private static (byte[] SigningKey, byte[] ValidBody, byte[] TamperedBody, string TamperedSignatureHex)
        LoadHmacFixtureBodies()
    {
        string json = File.ReadAllText(FixturePath);
        JsonObject root = JsonNode.Parse(json)!.AsObject();
        JsonArray vectors = root["vectors"]!.AsArray();

        JsonObject Find(string name) =>
            vectors.Select(v => v!.AsObject()).Single(v => v["name"]!.GetValue<string>() == name);

        JsonObject validVector = Find("authz_request_valid");
        JsonObject tamperedVector = Find("authz_request_tampered_action");

        byte[] signingKey = Convert.FromHexString(validVector["signing_key_hex"]!.GetValue<string>());
        byte[] validBody = Encoding.UTF8.GetBytes(validVector["message"]!.AsObject().DeepClone().ToJsonString());

        JsonObject tamperedMessage = tamperedVector["message"]!.AsObject().DeepClone().AsObject();
        byte[] tamperedBody = Encoding.UTF8.GetBytes(tamperedMessage.ToJsonString());
        string tamperedSignatureHex = tamperedMessage["hmac_signature"]!.GetValue<string>();

        return (signingKey, validBody, tamperedBody, tamperedSignatureHex);
    }

    private static (Mock<IChannel> ChannelMock, List<AckNackCall> Calls) FakeChannel()
    {
        var calls = new List<AckNackCall>();
        var mock = new Mock<IChannel>();

        // RabbitMQ.Client 7.x's IChannel.BasicAckAsync/BasicNackAsync return
        // ValueTask (not Task) — Moq's .Returns() must match that exactly.
        mock.Setup(c => c.BasicAckAsync(It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, CancellationToken>((tag, multiple, _) =>
                calls.Add(new AckNackCall("ack", tag, multiple, false)))
            .Returns(ValueTask.CompletedTask);

        mock.Setup(c => c.BasicNackAsync(
                It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, bool, CancellationToken>((tag, multiple, requeue, _) =>
                calls.Add(new AckNackCall("nack", tag, multiple, requeue)))
            .Returns(ValueTask.CompletedTask);

        return (mock, calls);
    }

    // RabbitMQ.Client 7.x's BasicDeliverEventArgs is constructor-initialized only
    // (get-only properties, no object-initializer/settable members) — all fields
    // are supplied positionally.
    private static BasicDeliverEventArgs Delivery(ulong deliveryTag, byte[] body) => new(
        consumerTag: "test-consumer",
        deliveryTag: deliveryTag,
        redelivered: false,
        exchange: "axiam.authz.request",
        routingKey: "authz.request",
        properties: new BasicProperties(),
        body: body,
        cancellationToken: CancellationToken.None);

    // ---- (a) success -> exactly one BasicAckAsync ---------------------------

    [Fact]
    public async Task ValidSignatureAndSuccessfulHandler_Acks()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        bool handlerInvoked = false;

        AsyncEventHandler<BasicDeliverEventArgs> received = AxiamAmqpConsumer.CreateReceivedHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            new RecordingLogger(),
            NewGuard());

        await received(new object(), Delivery(42, validBody));

        Assert.True(handlerInvoked, "handler must be invoked for a validly-signed body");
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("ack", call.Type);
        Assert.Equal(42UL, call.DeliveryTag);
        Assert.False(call.Multiple);
    }

    // ---- (b) HMAC-fail -> nack(no requeue) + handler NEVER invoked ----------

    [Fact]
    public async Task InvalidSignature_NacksWithoutRequeue_AndNeverInvokesHandler()
    {
        (byte[] signingKey, _, byte[] tamperedBody, string tamperedSignatureHex) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        bool handlerInvoked = false;

        AsyncEventHandler<BasicDeliverEventArgs> received = AxiamAmqpConsumer.CreateReceivedHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            logger,
            NewGuard());

        await received(new object(), Delivery(7, tamperedBody));

        Assert.False(handlerInvoked, "handler must NEVER be invoked for an unverified delivery");
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.Equal(7UL, call.DeliveryTag);
        Assert.False(call.Multiple);
        Assert.False(call.Requeue, "HMAC-fail must nack WITHOUT requeue");

        Assert.NotEmpty(logger.Warnings);

        // §8.4 security assertion: the log line must never contain the HMAC value.
        Assert.All(logger.Warnings, warning => Assert.DoesNotContain(tamperedSignatureHex, warning));
    }

    // ---- (c) PoisonMessageException -> nack(no requeue) ---------------------

    [Fact]
    public async Task PoisonMessageException_NacksWithoutRequeue()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();

        AsyncEventHandler<BasicDeliverEventArgs> received = AxiamAmqpConsumer.CreateReceivedHandler(
            channelMock.Object,
            signingKey,
            (_, _) => throw new PoisonMessageException("poison message"),
            new RecordingLogger(),
            NewGuard());

        await received(new object(), Delivery(99, validBody));

        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.Equal(99UL, call.DeliveryTag);
        Assert.False(call.Multiple);
        Assert.False(call.Requeue, "PoisonMessageException must nack WITHOUT requeue");
    }

    // ---- (d) transient handler exception -> nack(requeue) -------------------

    [Fact]
    public async Task TransientHandlerException_NacksWithRequeue()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();

        AsyncEventHandler<BasicDeliverEventArgs> received = AxiamAmqpConsumer.CreateReceivedHandler(
            channelMock.Object,
            signingKey,
            (_, _) => throw new InvalidOperationException("transient downstream failure"),
            new RecordingLogger(),
            NewGuard());

        await received(new object(), Delivery(13, validBody));

        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.Equal(13UL, call.DeliveryTag);
        Assert.False(call.Multiple);
        Assert.True(call.Requeue, "a transient (non-poison) handler exception must nack WITH requeue");
    }

    // ---- (e) NEW-4 replay protection: key_version < 2 -> nack(no requeue), handler never invoked ----

    [Fact]
    public async Task StaleKeyVersion_NacksWithoutRequeue_AndNeverInvokesHandler()
    {
        (byte[] signingKey, _, _, _) = LoadHmacFixtureBodies();

        // key_version is itself part of the signed canonical bytes (NEW-4), so
        // this is a FRESH, genuinely validly-signed message that just happens
        // to declare key_version=1 — not a mutated/tampered v2 body (that
        // would simply fail Hmac.Verify, proving nothing about the version
        // gate specifically). This models a legacy/downgrade producer whose
        // signature is cryptographically authentic but whose declared
        // key_version predates NEW-4's replay-protection guarantees.
        const string canonical =
            "{\"correlation_id\":\"11111111-1111-1111-1111-111111111111\"," +
            "\"tenant_id\":\"22222222-2222-2222-2222-222222222222\"," +
            "\"subject_id\":\"33333333-3333-3333-3333-333333333333\"," +
            "\"action\":\"read\"," +
            "\"resource_id\":\"44444444-4444-4444-4444-444444444444\"," +
            "\"key_version\":1," +
            "\"nonce\":\"60606060-6060-6060-6060-606060606060\"," +
            "\"issued_at\":\"2026-07-10T12:00:00Z\"}";
        const string signatureHex = "2f45fc1eb76d2b7f2cbafe214c13e1970e2a539831bef9abe2dd2b06480fff47";

        JsonObject message = JsonNode.Parse(canonical)!.AsObject();
        message["hmac_signature"] = signatureHex;
        byte[] staleKeyVersionBody = Encoding.UTF8.GetBytes(message.ToJsonString());

        Assert.True(Hmac.Verify(signingKey, staleKeyVersionBody), "test fixture must carry a genuinely valid HMAC signature");

        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        bool handlerInvoked = false;

        AsyncEventHandler<BasicDeliverEventArgs> received = AxiamAmqpConsumer.CreateReceivedHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            logger,
            NewGuard());

        await received(new object(), Delivery(21, staleKeyVersionBody));

        Assert.False(handlerInvoked, "handler must NEVER be invoked for a key_version < 2 delivery");
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.False(call.Requeue, "key_version < 2 must nack WITHOUT requeue");
        Assert.NotEmpty(logger.Warnings);
    }

    // ---- (f) NEW-4 replay protection: stale issued_at -> nack(no requeue), handler never invoked ----

    [Fact]
    public async Task StaleIssuedAt_NacksWithoutRequeue_AndNeverInvokesHandler()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        bool handlerInvoked = false;

        // A guard whose clock is one full day past the fixture's issued_at is
        // far outside any reasonable skew (default 5 minutes) — the message
        // is authentic (HMAC verifies) but stale.
        ReplayGuard guard = NewGuard(clock: () => FixtureIssuedAt.AddDays(1));

        AsyncEventHandler<BasicDeliverEventArgs> received = AxiamAmqpConsumer.CreateReceivedHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvoked = true;
                return Task.CompletedTask;
            },
            logger,
            guard);

        await received(new object(), Delivery(22, validBody));

        Assert.False(handlerInvoked, "handler must NEVER be invoked for a stale issued_at delivery");
        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.False(call.Requeue, "a stale issued_at must nack WITHOUT requeue");
        Assert.NotEmpty(logger.Warnings);
    }

    // ---- (g) NEW-4 replay protection: replayed nonce -> nack(no requeue), handler never invoked ----

    [Fact]
    public async Task ReplayedNonce_SecondDeliveryNacksWithoutRequeue_AndNeverInvokesHandlerForTheReplay()
    {
        (byte[] signingKey, byte[] validBody, _, _) = LoadHmacFixtureBodies();
        (Mock<IChannel> channelMock, List<AckNackCall> calls) = FakeChannel();
        var logger = new RecordingLogger();
        int handlerInvocations = 0;

        // One shared guard across both deliveries — nonce dedup is a no-op if
        // a fresh guard were built per delivery.
        ReplayGuard guard = NewGuard();

        AsyncEventHandler<BasicDeliverEventArgs> received = AxiamAmqpConsumer.CreateReceivedHandler(
            channelMock.Object,
            signingKey,
            (_, _) =>
            {
                handlerInvocations++;
                return Task.CompletedTask;
            },
            logger,
            guard);

        // First delivery of this nonce: accepted and acked.
        await received(new object(), Delivery(31, validBody));
        // Second delivery of the exact same (still authentic) body: rejected as a replay.
        await received(new object(), Delivery(32, validBody));

        Assert.Equal(1, handlerInvocations);
        Assert.Equal(2, calls.Count);
        Assert.Equal("ack", calls[0].Type);
        Assert.Equal("nack", calls[1].Type);
        Assert.False(calls[1].Requeue, "a replayed nonce must nack WITHOUT requeue");
        Assert.NotEmpty(logger.Warnings);
    }
}

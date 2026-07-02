using System;
using System.Collections.Generic;
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

        mock.Setup(c => c.BasicAckAsync(It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, CancellationToken>((tag, multiple, _) =>
                calls.Add(new AckNackCall("ack", tag, multiple, false)))
            .Returns(Task.CompletedTask);

        mock.Setup(c => c.BasicNackAsync(
                It.IsAny<ulong>(), It.IsAny<bool>(), It.IsAny<bool>(), It.IsAny<CancellationToken>()))
            .Callback<ulong, bool, bool, CancellationToken>((tag, multiple, requeue, _) =>
                calls.Add(new AckNackCall("nack", tag, multiple, requeue)))
            .Returns(Task.CompletedTask);

        return (mock, calls);
    }

    private static BasicDeliverEventArgs Delivery(ulong deliveryTag, byte[] body) => new()
    {
        ConsumerTag = "test-consumer",
        DeliveryTag = deliveryTag,
        Redelivered = false,
        Exchange = "axiam.authz.request",
        RoutingKey = "authz.request",
        BasicProperties = new BasicProperties(),
        Body = body,
    };

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
            new RecordingLogger());

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
            logger);

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
            new RecordingLogger());

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
            new RecordingLogger());

        await received(new object(), Delivery(13, validBody));

        AckNackCall call = Assert.Single(calls);
        Assert.Equal("nack", call.Type);
        Assert.Equal(13UL, call.DeliveryTag);
        Assert.False(call.Multiple);
        Assert.True(call.Requeue, "a transient (non-poison) handler exception must nack WITH requeue");
    }
}

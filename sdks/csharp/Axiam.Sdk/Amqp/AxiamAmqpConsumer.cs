using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;

namespace Axiam.Sdk.Amqp;

/// <summary>
/// AMQP event consumer: verify-before-handler HMAC gate plus the
/// <c>sdks/CONTRACT.md</c> §8 ack/nack matrix, built on <c>RabbitMQ.Client</c>
/// 7.x's async consumer API with automatic connection/topology recovery
/// enabled (D-11).
///
/// <para>
/// <see cref="StartAsync"/> NEVER hands an unverified delivery to the
/// caller-supplied handler — <see cref="Hmac.Verify"/> runs first, and the
/// handler call site is structurally unreachable until it returns
/// <c>true</c>. The remaining outcomes follow the exact §8 decision matrix:
/// </para>
/// <list type="bullet">
/// <item><description>HMAC verification fails → <c>BasicNackAsync(requeue: false)</c>
/// + a security-event log entry that never contains the received or
/// expected HMAC value; the handler is never invoked.</description></item>
/// <item><description>Handler returns normally → <c>BasicAckAsync</c>.</description></item>
/// <item><description>Handler throws <see cref="PoisonMessageException"/> (poison
/// message) → <c>BasicNackAsync(requeue: false)</c>.</description></item>
/// <item><description>Handler throws any other exception (transient/retryable)
/// → <c>BasicNackAsync(requeue: true)</c>.</description></item>
/// </list>
/// </summary>
public sealed class AxiamAmqpConsumer : IAsyncDisposable
{
    /// <summary>Default QoS prefetch count.</summary>
    public const ushort DefaultPrefetchCount = 10;

    /// <summary>Default network-recovery interval applied to the connection factory.</summary>
    public static readonly TimeSpan DefaultNetworkRecoveryInterval = TimeSpan.FromSeconds(5);

    private IConnection? _connection;
    private IChannel? _channel;

    /// <summary>
    /// Connects to <paramref name="amqpUri"/>, opens a channel with automatic
    /// recovery enabled, and registers an <see cref="AsyncEventingBasicConsumer"/>
    /// on <paramref name="queue"/> that verifies every delivery's HMAC-SHA256
    /// signature (§8, via <see cref="Hmac.Verify"/>) BEFORE
    /// <paramref name="handler"/> is invoked, then applies the §8 ack/nack
    /// matrix documented on this class.
    /// </summary>
    /// <param name="amqpUri">The AMQP connection URI.</param>
    /// <param name="queue">The queue name to consume from.</param>
    /// <param name="signingKey">The per-tenant AMQP HMAC signing secret (§8.1
    /// — obtain from the AXIAM management API; never hardcode).</param>
    /// <param name="handler">Invoked ONLY after HMAC verification succeeds.
    /// Throw <see cref="PoisonMessageException"/> to drop a message without
    /// requeue; any other exception is treated as transient and requeues.</param>
    /// <param name="logger">Receives the §8.4 security event on HMAC
    /// verification failure; the event never contains the HMAC value.
    /// Defaults to a silent no-op logger.</param>
    /// <param name="cancellationToken">Cancellation token for connection/channel
    /// setup and for every ack/nack call issued by the registered consumer.</param>
    public async Task StartAsync(
        string amqpUri,
        string queue,
        byte[] signingKey,
        Func<byte[], CancellationToken, Task> handler,
        ILogger? logger = null,
        CancellationToken cancellationToken = default)
    {
        logger ??= NullLogger.Instance;

        var factory = new ConnectionFactory
        {
            Uri = new Uri(amqpUri),
            AutomaticRecoveryEnabled = true, // default true — kept explicit for clarity (D-11)
            TopologyRecoveryEnabled = true, // default true
            NetworkRecoveryInterval = DefaultNetworkRecoveryInterval,
            ConsumerDispatchConcurrency = 1, // default; sequential dispatch — safe default,
                                              // bump only if the handler is proven concurrency-safe
        };

        _connection = await factory.CreateConnectionAsync(cancellationToken).ConfigureAwait(false);
        _channel = await _connection.CreateChannelAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        await _channel.BasicQosAsync(0, DefaultPrefetchCount, false, cancellationToken).ConfigureAwait(false);

        var consumer = new AsyncEventingBasicConsumer(_channel);
        consumer.ReceivedAsync += CreateReceivedHandler(_channel, signingKey, handler, logger, cancellationToken);

        await _channel.BasicConsumeAsync(queue, autoAck: false, consumerTag: string.Empty, noLocal: false,
            exclusive: false, arguments: null, consumer, cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Builds the §8 verify-before-handler / ack-nack-matrix delegate bound
    /// to <paramref name="channel"/>. Internal so <c>AmqpConsumerTests</c> can
    /// construct and invoke it directly against synthesized
    /// <see cref="BasicDeliverEventArgs"/> and a fake <see cref="IChannel"/>,
    /// proving every matrix branch without a live broker.
    /// </summary>
    internal static AsyncEventHandler<BasicDeliverEventArgs> CreateReceivedHandler(
        IChannel channel,
        byte[] signingKey,
        Func<byte[], CancellationToken, Task> handler,
        ILogger logger,
        CancellationToken cancellationToken = default)
    {
        return async (_, ea) =>
        {
            byte[] body = ea.Body.ToArray(); // MUST copy — library-owned memory is only valid
                                              // for the duration of this event (7.x migration note)

            if (!Hmac.Verify(signingKey, body))
            {
                // §8.4 security event: fact of failure + routing context ONLY.
                // NEVER the received or expected HMAC value.
                logger.LogWarning(
                    "axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue (exchange={Exchange}, routingKey={RoutingKey})",
                    ea.Exchange, ea.RoutingKey);
                await channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false, cancellationToken)
                    .ConfigureAwait(false);
                return; // handler is structurally unreachable for an unverified message
            }

            try
            {
                await handler(body, cancellationToken).ConfigureAwait(false); // handler NEVER sees an unverified message
                await channel.BasicAckAsync(ea.DeliveryTag, multiple: false, cancellationToken).ConfigureAwait(false);
            }
            catch (PoisonMessageException)
            {
                await channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: false, cancellationToken)
                    .ConfigureAwait(false); // poison message, no requeue
            }
            catch (Exception)
            {
                await channel.BasicNackAsync(ea.DeliveryTag, multiple: false, requeue: true, cancellationToken)
                    .ConfigureAwait(false); // transient/retryable, requeue
            }
        };
    }

    /// <inheritdoc />
    public async ValueTask DisposeAsync()
    {
        if (_channel is not null)
        {
            await _channel.CloseAsync().ConfigureAwait(false);
        }

        if (_connection is not null)
        {
            await _connection.CloseAsync().ConfigureAwait(false);
        }
    }
}

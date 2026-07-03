package io.axiam.sdk.amqp;

import com.rabbitmq.client.CancelCallback;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Delivery;
import org.slf4j.Logger;

import java.io.IOException;
import java.time.Duration;
import java.util.function.Consumer;

/**
 * AMQP event consumer: verify-before-handler HMAC gate plus the CONTRACT.md
 * &sect;8 ack/nack matrix, built on the RabbitMQ Java client's built-in
 * automatic recovery (D-13).
 *
 * <p>{@link #consume} NEVER hands an unverified delivery to the caller's
 * {@code handler} &mdash; {@link Hmac#verify(byte[], byte[])} runs first, and
 * the handler call site is structurally unreachable until it returns
 * {@code true}. The remaining outcomes follow the exact &sect;8 decision
 * matrix:
 *
 * <ul>
 *   <li>HMAC verification fails &rarr; {@code basicNack(tag, false, false)}
 *       (no requeue) + a security-event log entry that never contains the
 *       received or expected HMAC value; {@code handler} is never invoked.</li>
 *   <li>{@code handler} returns normally &rarr; {@code basicAck(tag, false)}.</li>
 *   <li>{@code handler} throws {@link ErrDrop} (poison message, 20-02) &rarr;
 *       {@code basicNack(tag, false, false)} (no requeue).</li>
 *   <li>{@code handler} throws any other exception (transient/retryable)
 *       &rarr; {@code basicNack(tag, false, true)} (requeue).</li>
 * </ul>
 *
 * <p>The RabbitMQ Java client's {@link ConnectionFactory} has automatic
 * connection + topology recovery ON by default since client 4.x &mdash; this
 * class does NOT hand-roll a reconnect loop (unlike {@code sdks/go}'s
 * {@code NotifyClose}-driven approach, which Java does not need). See
 * {@link #configureAutomaticRecovery(ConnectionFactory, Duration)} for the
 * documented, overridable recovery-interval helper (CF-03).
 */
public final class AmqpConsumer {

    /** Default QoS prefetch count (CF-03; matches {@code sdks/go}'s {@code defaultPrefetch=10}). */
    public static final int DEFAULT_PREFETCH = 10;

    /** Default network-recovery-interval applied by {@link #configureAutomaticRecovery(ConnectionFactory)}. */
    public static final Duration DEFAULT_NETWORK_RECOVERY_INTERVAL = Duration.ofSeconds(5);

    private AmqpConsumer() {
    }

    /**
     * Registers a manual-ack {@link DeliverCallback} on {@code channel} for
     * {@code queue}: every delivery's HMAC-SHA256 signature is verified
     * (&sect;8, via {@link Hmac#verify}) BEFORE {@code handler} is invoked,
     * then the &sect;8 ack/nack matrix (see class Javadoc) is applied. Sets
     * {@code basicQos(DEFAULT_PREFETCH)} (CF-03).
     *
     * <p>This method does not itself configure automatic recovery on the
     * underlying connection &mdash; call
     * {@link #configureAutomaticRecovery(ConnectionFactory, Duration)} on the
     * {@link ConnectionFactory} used to create {@code channel}'s connection
     * before opening it.
     *
     * @param channel    the AMQP channel to consume on; the caller owns its
     *                   lifecycle (creation/closing)
     * @param queue      the queue name to consume from
     * @param signingKey the per-tenant AMQP HMAC signing secret (&sect;8.1
     *                   &mdash; obtain from the AXIAM management API; never
     *                   hardcode)
     * @param handler    invoked ONLY after HMAC verification succeeds
     * @param logger     receives the &sect;8.4 security event on HMAC
     *                   verification failure; the event never contains the
     *                   HMAC value
     * @throws IOException if {@code basicQos}/{@code basicConsume} fails
     */
    public static void consume(Channel channel, String queue, byte[] signingKey,
                                Consumer<byte[]> handler, Logger logger) throws IOException {
        channel.basicQos(DEFAULT_PREFETCH);
        DeliverCallback deliverCallback = deliverCallback(channel, signingKey, handler, logger);
        CancelCallback cancelCallback = consumerTag -> {
            // No cancellation-specific handling required; the caller manages
            // channel/connection lifecycle.
        };
        channel.basicConsume(queue, false /* manual ack (D-13) */, deliverCallback, cancelCallback);
    }

    /**
     * Builds the &sect;8 verify-before-handler / ack-nack-matrix
     * {@link DeliverCallback} bound to {@code channel}. Package-private so
     * {@code AmqpConsumerTest} can construct and invoke it directly against
     * synthesized {@link Delivery} instances and a fake {@link Channel},
     * proving every matrix branch without a live broker.
     */
    static DeliverCallback deliverCallback(Channel channel, byte[] signingKey,
                                            Consumer<byte[]> handler, Logger logger) {
        return (consumerTag, delivery) -> {
            long deliveryTag = delivery.getEnvelope().getDeliveryTag();
            byte[] body = delivery.getBody();

            if (!Hmac.verify(signingKey, body)) {
                // §8.4 security event: fact of failure + routing context
                // ONLY. NEVER the received or expected HMAC value.
                logger.warn(
                        "axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue "
                                + "(exchange={}, routingKey={})",
                        delivery.getEnvelope().getExchange(), delivery.getEnvelope().getRoutingKey());
                channel.basicNack(deliveryTag, false, false); // multiple=false, requeue=false
                return; // handler is structurally unreachable for an unverified message
            }

            try {
                handler.accept(body); // handler NEVER sees an unverified message
                channel.basicAck(deliveryTag, false);
            } catch (ErrDrop drop) {
                channel.basicNack(deliveryTag, false, false); // poison message, no requeue
            } catch (Exception transientFailure) {
                channel.basicNack(deliveryTag, false, true); // retryable, requeue
            }
        };
    }

    /**
     * Applies the SDK's documented automatic-recovery defaults to
     * {@code factory}: {@code setAutomaticRecoveryEnabled(true)} (left ON
     * &mdash; the client default since 4.x) and
     * {@code setNetworkRecoveryInterval(recoveryInterval)} (overridable per
     * CF-03's "sane defaults, overridable"). This SDK MUST NOT disable
     * automatic recovery (D-13).
     *
     * @param factory          the {@link ConnectionFactory} to configure,
     *                         before {@link ConnectionFactory#newConnection()}
     *                         is called
     * @param recoveryInterval the reconnect backoff interval; must be positive
     */
    public static void configureAutomaticRecovery(ConnectionFactory factory, Duration recoveryInterval) {
        factory.setAutomaticRecoveryEnabled(true);
        factory.setNetworkRecoveryInterval(recoveryInterval.toMillis());
    }

    /**
     * Convenience overload applying {@link #DEFAULT_NETWORK_RECOVERY_INTERVAL}
     * (~5s, CF-03).
     *
     * @param factory the {@link ConnectionFactory} to configure
     */
    public static void configureAutomaticRecovery(ConnectionFactory factory) {
        configureAutomaticRecovery(factory, DEFAULT_NETWORK_RECOVERY_INTERVAL);
    }
}

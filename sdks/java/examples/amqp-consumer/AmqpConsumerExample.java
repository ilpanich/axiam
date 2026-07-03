package io.axiam.sdk.examples.amqpconsumer;

import com.rabbitmq.client.Channel;
import com.rabbitmq.client.Connection;
import com.rabbitmq.client.ConnectionFactory;

import io.axiam.sdk.amqp.AmqpConsumer;
import io.axiam.sdk.amqp.ErrDrop;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * Demonstrates {@link AmqpConsumer#consume} (CONTRACT.md &sect;8): every
 * delivery's HMAC-SHA256 signature is verified BEFORE the handler runs, and
 * the handler may throw {@link ErrDrop} to force a no-requeue nack for a
 * poison message (any other handler exception nacks WITH requeue). Imports
 * ONLY public SDK entry points ({@code io.axiam.sdk.amqp.AmqpConsumer},
 * {@code io.axiam.sdk.amqp.ErrDrop}).
 *
 * <p>Run: {@code AXIAM_AMQP_URI=... AXIAM_AMQP_QUEUE=... AXIAM_AMQP_SIGNING_KEY=... java AmqpConsumerExample.java}
 */
public final class AmqpConsumerExample {

    private static final Logger LOG = LoggerFactory.getLogger(AmqpConsumerExample.class);

    public static void main(String[] args) throws Exception {
        String amqpUri = getenv("AXIAM_AMQP_URI", "amqps://localhost:5671");
        String queue = getenv("AXIAM_AMQP_QUEUE", "axiam.authz.request");
        // §8.1: obtain the real per-tenant AMQP signing secret from the
        // AXIAM management API — never hardcode it in production code.
        byte[] signingKey = getenv("AXIAM_AMQP_SIGNING_KEY", "changeme-signing-key")
                .getBytes(StandardCharsets.UTF_8);

        ConnectionFactory factory = new ConnectionFactory();
        factory.setUri(amqpUri);
        // D-13: leave the RabbitMQ Java client's built-in automatic
        // connection/topology recovery ON — this SDK never hand-rolls a
        // reconnect loop.
        AmqpConsumer.configureAutomaticRecovery(factory);

        try (Connection connection = factory.newConnection();
             Channel channel = connection.createChannel()) {

            AmqpConsumer.consume(channel, queue, signingKey, body -> {
                String payload = new String(body, StandardCharsets.UTF_8);
                if (payload.isBlank()) {
                    // ErrDrop: poison-message sentinel — nacked WITHOUT
                    // requeue, unlike any other handler exception (which
                    // nacks WITH requeue as a retryable failure).
                    throw new ErrDrop("empty payload — dropping without requeue");
                }
                System.out.println("received verified message: " + payload);
            }, LOG);

            System.out.println("consuming from " + queue + " — press Ctrl+C to exit");
            Thread.currentThread().join();
        }
    }

    private static String getenv(String key, String fallback) {
        String v = System.getenv(key);
        return (v == null || v.isBlank()) ? fallback : v;
    }

    private AmqpConsumerExample() {
    }
}

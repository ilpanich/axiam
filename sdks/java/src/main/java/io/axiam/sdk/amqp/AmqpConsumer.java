package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.rabbitmq.client.CancelCallback;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.ConnectionFactory;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Delivery;
import org.slf4j.Logger;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
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

    /**
     * Default NEW-4 issued-at clock-skew tolerance: a v2 message's
     * {@code issued_at} must fall within &plusmn; this duration of "now" or
     * it is rejected as stale. Overridable via
     * {@link #consume(Channel, String, byte[], Consumer, Logger, Duration)}.
     */
    public static final Duration DEFAULT_ALLOWED_CLOCK_SKEW = Duration.ofSeconds(300);

    private static final ObjectMapper MAPPER = new ObjectMapper();

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
     * @param handler    invoked ONLY after HMAC verification AND the NEW-4
     *                   replay-protection checks (key_version, issued_at
     *                   freshness, nonce uniqueness &mdash; see
     *                   {@link #deliverCallback(Channel, byte[], Consumer, Logger, Duration, Clock, NonceStore)})
     *                   succeed
     * @param logger     receives the &sect;8.4 security event on HMAC
     *                   verification failure or a NEW-4 replay-protection
     *                   rejection; the event never contains the HMAC value
     * @throws IOException if {@code basicQos}/{@code basicConsume} fails
     */
    public static void consume(Channel channel, String queue, byte[] signingKey,
                                Consumer<byte[]> handler, Logger logger) throws IOException {
        consume(channel, queue, signingKey, handler, logger, DEFAULT_ALLOWED_CLOCK_SKEW);
    }

    /**
     * Overload of {@link #consume(Channel, String, byte[], Consumer, Logger)}
     * with a caller-supplied NEW-4 issued-at clock-skew tolerance in place of
     * {@link #DEFAULT_ALLOWED_CLOCK_SKEW}. A single {@link NonceStore} (TTL =
     * {@code 2 * allowedClockSkew}) is created for this registration and
     * shared across every delivery it handles, so nonce replay is detected
     * across the lifetime of the consumer, not just within one delivery.
     *
     * @param allowedClockSkew the &plusmn; tolerance applied to a message's
     *                         {@code issued_at} versus wall-clock now; must
     *                         be positive
     * @throws IOException if {@code basicQos}/{@code basicConsume} fails
     */
    public static void consume(Channel channel, String queue, byte[] signingKey,
                                Consumer<byte[]> handler, Logger logger,
                                Duration allowedClockSkew) throws IOException {
        channel.basicQos(DEFAULT_PREFETCH);
        NonceStore nonceStore = new NonceStore(allowedClockSkew.multipliedBy(2));
        DeliverCallback deliverCallback = deliverCallback(
                channel, signingKey, handler, logger, allowedClockSkew, Clock.systemUTC(), nonceStore);
        CancelCallback cancelCallback = consumerTag -> {
            // No cancellation-specific handling required; the caller manages
            // channel/connection lifecycle.
        };
        channel.basicConsume(queue, false /* manual ack (D-13) */, deliverCallback, cancelCallback);
    }

    /**
     * Builds the &sect;8 verify-before-handler / ack-nack-matrix
     * {@link DeliverCallback} bound to {@code channel}, using
     * {@link #DEFAULT_ALLOWED_CLOCK_SKEW}, the system clock, and a
     * freshly-created (per-call) {@link NonceStore}. Package-private so
     * {@code AmqpConsumerTest} can construct and invoke it directly against
     * synthesized {@link Delivery} instances and a fake {@link Channel},
     * proving every matrix branch without a live broker.
     */
    static DeliverCallback deliverCallback(Channel channel, byte[] signingKey,
                                            Consumer<byte[]> handler, Logger logger) {
        return deliverCallback(channel, signingKey, handler, logger, DEFAULT_ALLOWED_CLOCK_SKEW,
                Clock.systemUTC(), new NonceStore(DEFAULT_ALLOWED_CLOCK_SKEW.multipliedBy(2)));
    }

    /**
     * Full-control overload of {@link #deliverCallback(Channel, byte[], Consumer, Logger)}
     * exposing the NEW-4 clock-skew tolerance, {@link Clock} (for
     * deterministic testing of issued-at freshness), and {@link NonceStore}
     * (so a test, or {@link #consume}, can share ONE store across multiple
     * deliveries to prove/enforce replay detection across the consumer's
     * lifetime rather than per-delivery).
     *
     * <p>Verification order per delivery, matching CONTRACT.md &sect;8 plus
     * NEW-4:
     * <ol>
     *   <li>{@link Hmac#verify} &mdash; on failure, nack (no requeue),
     *       handler never invoked.</li>
     *   <li>NEW-4 replay-protection, evaluated ONLY once the HMAC has
     *       verified: {@code key_version < 2}, a stale/unparseable
     *       {@code issued_at} (outside &plusmn;{@code allowedClockSkew} of
     *       {@code clock.instant()}), a missing/blank {@code nonce}, or a
     *       {@code nonce} already recorded in {@code nonceStore} &mdash; any
     *       of these reject via the SAME nack-without-requeue path as an
     *       invalid signature, and the handler is never invoked.</li>
     *   <li>Otherwise the &sect;8 ack/nack matrix (class Javadoc) applies to
     *       the handler's outcome.</li>
     * </ol>
     */
    static DeliverCallback deliverCallback(Channel channel, byte[] signingKey,
                                            Consumer<byte[]> handler, Logger logger,
                                            Duration allowedClockSkew, Clock clock, NonceStore nonceStore) {
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

            String replayRejectReason = replayProtectionFailureReason(body, allowedClockSkew, clock, nonceStore);
            if (replayRejectReason != null) {
                // NEW-4 §8.4-style security event: reason + routing context
                // ONLY, never the HMAC value (this check runs strictly after
                // HMAC verification succeeded, so there is no signature to
                // leak here either way).
                logger.warn(
                        "axiam_sdk_security: AMQP NEW-4 replay-protection check failed ({}); nacking without "
                                + "requeue (exchange={}, routingKey={})",
                        replayRejectReason, delivery.getEnvelope().getExchange(),
                        delivery.getEnvelope().getRoutingKey());
                channel.basicNack(deliveryTag, false, false); // multiple=false, requeue=false
                return; // handler is structurally unreachable for a replay/stale/downgraded message
            }

            try {
                handler.accept(body); // handler NEVER sees an unverified/replayed message
                channel.basicAck(deliveryTag, false);
            } catch (ErrDrop drop) {
                channel.basicNack(deliveryTag, false, false); // poison message, no requeue
            } catch (Exception transientFailure) {
                channel.basicNack(deliveryTag, false, true); // retryable, requeue
            }
        };
    }

    /**
     * Evaluates the NEW-4 replay-protection checks against an
     * already-HMAC-verified {@code body}, returning {@code null} if the
     * message passes all of them or a short, HMAC-value-free rejection
     * reason string otherwise. Never throws: any parse failure is treated as
     * a rejection (default-deny), matching &sect;8.3's strict-mode posture
     * for the HMAC check itself.
     */
    private static String replayProtectionFailureReason(byte[] body, Duration allowedClockSkew,
                                                          Clock clock, NonceStore nonceStore) {
        try {
            JsonNode root = MAPPER.readTree(body);
            if (!(root instanceof ObjectNode node)) {
                return "unparseable message body";
            }

            JsonNode keyVersionNode = node.get("key_version");
            if (keyVersionNode == null || keyVersionNode.isNull() || !keyVersionNode.canConvertToInt()
                    || keyVersionNode.asInt() < 2) {
                return "key_version < 2";
            }

            JsonNode issuedAtNode = node.get("issued_at");
            if (issuedAtNode == null || issuedAtNode.isNull() || issuedAtNode.asText().isBlank()) {
                return "issued_at missing";
            }
            Instant issuedAt;
            try {
                issuedAt = OffsetDateTime.parse(issuedAtNode.asText()).toInstant();
            } catch (DateTimeParseException e) {
                return "issued_at unparseable";
            }
            Instant now = clock.instant();
            Duration drift = Duration.between(issuedAt, now).abs();
            if (drift.compareTo(allowedClockSkew) > 0) {
                return "issued_at outside allowed clock skew";
            }

            JsonNode nonceNode = node.get("nonce");
            if (nonceNode == null || nonceNode.isNull() || nonceNode.asText().isBlank()) {
                return "nonce missing";
            }
            String nonce = nonceNode.asText();
            if (!nonceStore.observe(nonce, now)) {
                return "nonce replay detected";
            }

            return null; // all NEW-4 checks passed
        } catch (Exception e) {
            return "replay-protection validation error (" + e.getClass().getSimpleName() + ")";
        }
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

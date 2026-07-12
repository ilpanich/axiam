package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Delivery;
import com.rabbitmq.client.Envelope;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Proves {@link AmqpConsumer}'s CONTRACT.md &sect;8 ack/nack matrix and
 * verify-before-handler invariant across every branch, using a fake
 * {@link Channel} (a {@link Proxy}-based test double recording
 * {@code basicAck}/{@code basicNack(tag, multiple, requeue)} calls) and
 * synthesized {@link Delivery} objects. The {@link DeliverCallback} under
 * test is obtained via {@link AmqpConsumer#deliverCallback} and invoked
 * directly &mdash; no live broker is involved.
 *
 * <p>Valid/tampered bodies + the matching signing key are reused verbatim
 * from 20-02's real, Rust-signer-produced fixture
 * ({@code amqp_hmac_vectors.json}), so the HMAC-fail branch below is proven
 * against an authentic tampered signature, not a hand-rolled invalid one.
 */
class AmqpConsumerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String FIXTURE_PATH = "/amqp_hmac_vectors.json";

    private List<AckNackCall> ackNackCalls;
    private Channel fakeChannel;

    private List<String> securityWarnings;
    private Logger fakeLogger;

    private byte[] signingKey;
    private byte[] validBody;
    private byte[] tamperedBody;

    /**
     * NEW-4: every vector in {@code amqp_hmac_vectors.json} now carries
     * {@code key_version=2} and a fixed {@code issued_at} of
     * {@code "2026-07-10T12:00:00Z"} (see that fixture's {@code _derivation}
     * note). These ack/nack-matrix tests are only exercising the pre-NEW-4
     * behavior (HMAC verify + handler outcome), so a {@link Clock} pinned to
     * that exact instant is used everywhere below to keep {@code issued_at}
     * "fresh" regardless of when the test actually runs; the NEW-4 checks
     * themselves are covered separately in {@link ReplayProtectionTest}.
     */
    private static final Instant FIXED_ISSUED_AT = Instant.parse("2026-07-10T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXED_ISSUED_AT, ZoneOffset.UTC);

    private NonceStore nonceStore;

    /** One recorded {@code basicAck}/{@code basicNack} invocation against {@link #fakeChannel}. */
    private record AckNackCall(String type, long deliveryTag, boolean multiple, boolean requeue) {
    }

    @BeforeEach
    void setUp() throws Exception {
        ackNackCalls = new ArrayList<>();
        fakeChannel = fakeChannel(ackNackCalls);

        securityWarnings = new ArrayList<>();
        fakeLogger = fakeLogger(securityWarnings);

        nonceStore = new NonceStore(Duration.ofSeconds(600));

        JsonNode root = loadFixture();
        JsonNode vectors = root.get("vectors");
        JsonNode validVector = findVector(vectors, "authz_request_valid");
        JsonNode tamperedVector = findVector(vectors, "authz_request_tampered_action");

        signingKey = HexFormat.of().parseHex(validVector.get("signing_key_hex").asText());
        validBody = MAPPER.writeValueAsBytes(validVector.get("message"));
        tamperedBody = MAPPER.writeValueAsBytes(tamperedVector.get("message"));
    }

    // ---- (a) success -> exactly one basicAck ------------------------------

    @Test
    void validSignatureAndSuccessfulHandlerAcks() throws Exception {
        AtomicBoolean handlerInvoked = new AtomicBoolean(false);
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                fakeChannel, signingKey, body -> handlerInvoked.set(true), fakeLogger,
                Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("consumer-tag", delivery(42L, validBody));

        assertTrue(handlerInvoked.get(), "handler must be invoked for a validly-signed body");
        assertEquals(1, ackNackCalls.size(), "exactly one ack/nack call expected");
        AckNackCall call = ackNackCalls.get(0);
        assertEquals("ack", call.type());
        assertEquals(42L, call.deliveryTag());
        assertFalse(call.multiple());
    }

    // ---- (b) HMAC-fail -> nack(no requeue) + handler NEVER invoked --------

    @Test
    void invalidSignatureNacksWithoutRequeueAndNeverInvokesHandler() throws Exception {
        AtomicBoolean handlerInvoked = new AtomicBoolean(false);
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                fakeChannel, signingKey, body -> handlerInvoked.set(true), fakeLogger,
                Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("consumer-tag", delivery(7L, tamperedBody));

        assertFalse(handlerInvoked.get(), "handler must NEVER be invoked for an unverified delivery");
        assertEquals(1, ackNackCalls.size(), "exactly one ack/nack call expected");
        AckNackCall call = ackNackCalls.get(0);
        assertEquals("nack", call.type());
        assertEquals(7L, call.deliveryTag());
        assertFalse(call.multiple());
        assertFalse(call.requeue(), "HMAC-fail must nack WITHOUT requeue");

        assertFalse(securityWarnings.isEmpty(), "a security event must be logged on HMAC failure");
    }

    @Test
    void securityLogNeverContainsAnHmacHexValue() throws Exception {
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                fakeChannel, signingKey, body -> { }, fakeLogger,
                Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("consumer-tag", delivery(7L, tamperedBody));

        JsonNode root = loadFixture();
        String tamperedSignature = findVector(root.get("vectors"), "authz_request_tampered_action")
                .get("message").get("hmac_signature").asText();

        assertFalse(securityWarnings.isEmpty(), "a security event must be logged on HMAC failure");
        for (String warning : securityWarnings) {
            assertFalse(warning.contains(tamperedSignature),
                    "security log line must never contain the HMAC value: " + warning);
        }
    }

    // ---- (c) ErrDrop -> nack(no requeue) -----------------------------------

    @Test
    void errDropFromHandlerNacksWithoutRequeue() throws Exception {
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                fakeChannel, signingKey, body -> {
                    throw new ErrDrop("poison message");
                }, fakeLogger, Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("consumer-tag", delivery(99L, validBody));

        assertEquals(1, ackNackCalls.size(), "exactly one ack/nack call expected");
        AckNackCall call = ackNackCalls.get(0);
        assertEquals("nack", call.type());
        assertEquals(99L, call.deliveryTag());
        assertFalse(call.multiple());
        assertFalse(call.requeue(), "ErrDrop must nack WITHOUT requeue");
    }

    // ---- (d) transient handler exception -> nack(requeue) -----------------

    @Test
    void transientHandlerExceptionNacksWithRequeue() throws Exception {
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                fakeChannel, signingKey, body -> {
                    throw new RuntimeException("transient downstream failure");
                }, fakeLogger, Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("consumer-tag", delivery(13L, validBody));

        assertEquals(1, ackNackCalls.size(), "exactly one ack/nack call expected");
        AckNackCall call = ackNackCalls.get(0);
        assertEquals("nack", call.type());
        assertEquals(13L, call.deliveryTag());
        assertFalse(call.multiple());
        assertTrue(call.requeue(), "a transient (non-ErrDrop) handler exception must nack WITH requeue");
    }

    // ---- fixtures / test doubles -------------------------------------------

    private static Delivery delivery(long deliveryTag, byte[] body) {
        Envelope envelope = new Envelope(deliveryTag, false, "axiam.authz.request", "authz.request");
        AMQP.BasicProperties properties = new AMQP.BasicProperties.Builder().build();
        return new Delivery(envelope, properties, body);
    }

    private static JsonNode loadFixture() throws Exception {
        try (InputStream in = AmqpConsumerTest.class.getResourceAsStream(FIXTURE_PATH)) {
            if (in == null) {
                throw new IllegalStateException("fixture not found on classpath: " + FIXTURE_PATH);
            }
            return MAPPER.readTree(in);
        }
    }

    private static JsonNode findVector(JsonNode vectors, String name) {
        for (JsonNode vector : vectors) {
            if (name.equals(vector.get("name").asText())) {
                return vector;
            }
        }
        throw new IllegalStateException("fixture vector not found: " + name);
    }

    /**
     * A {@link Proxy}-backed fake {@link Channel} recording every
     * {@code basicAck}/{@code basicNack} call; all other {@link Channel}
     * methods are no-ops (unused by {@link AmqpConsumer#deliverCallback}'s
     * returned callback, which is invoked directly in this test without
     * going through {@code basicConsume}).
     */
    private static Channel fakeChannel(List<AckNackCall> calls) {
        InvocationHandler handler = (proxy, method, args) -> {
            switch (method.getName()) {
                case "basicAck":
                    calls.add(new AckNackCall("ack", (long) args[0], (boolean) args[1], false));
                    return null;
                case "basicNack":
                    calls.add(new AckNackCall("nack", (long) args[0], (boolean) args[1], (boolean) args[2]));
                    return null;
                case "toString":
                    return "fakeChannel";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                default:
                    return defaultReturnValue(method.getReturnType());
            }
        };
        return (Channel) Proxy.newProxyInstance(
                Channel.class.getClassLoader(), new Class<?>[]{Channel.class}, handler);
    }

    /**
     * A {@link Proxy}-backed fake {@link Logger} recording the fully
     * formatted (SLF4J {@code {}}-placeholder substituted) text of every
     * {@code warn(...)} call, so tests can assert on the exact logged
     * message without a logging framework dependency.
     */
    private static Logger fakeLogger(List<String> warnings) {
        InvocationHandler handler = (proxy, method, args) -> {
            if ("warn".equals(method.getName()) && args != null && args.length > 0 && args[0] instanceof String) {
                warnings.add(formatSlf4j(args));
                return null;
            }
            switch (method.getName()) {
                case "toString":
                    return "fakeLogger";
                case "hashCode":
                    return System.identityHashCode(proxy);
                case "equals":
                    return proxy == args[0];
                case "getName":
                    return "fakeLogger";
                default:
                    return defaultReturnValue(method.getReturnType());
            }
        };
        return (Logger) Proxy.newProxyInstance(
                Logger.class.getClassLoader(), new Class<?>[]{Logger.class}, handler);
    }

    /** Substitutes SLF4J {@code {}} placeholders in {@code invocationArgs[0]} with the trailing arguments. */
    private static String formatSlf4j(Object[] invocationArgs) {
        String pattern = (String) invocationArgs[0];
        Object[] values;
        if (invocationArgs.length == 2 && invocationArgs[1] instanceof Object[]) {
            values = (Object[]) invocationArgs[1]; // varargs warn(String, Object...) overload
        } else {
            values = Arrays.copyOfRange(invocationArgs, 1, invocationArgs.length);
        }
        StringBuilder sb = new StringBuilder();
        int valueIndex = 0;
        int i = 0;
        while (i < pattern.length()) {
            if (i + 1 < pattern.length() && pattern.charAt(i) == '{' && pattern.charAt(i + 1) == '}') {
                sb.append(valueIndex < values.length ? String.valueOf(values[valueIndex++]) : "{}");
                i += 2;
            } else {
                sb.append(pattern.charAt(i));
                i++;
            }
        }
        return sb.toString();
    }

    private static Object defaultReturnValue(Class<?> returnType) {
        if (!returnType.isPrimitive()) {
            return null;
        }
        if (returnType == boolean.class) {
            return true; // isXEnabled(...) -> true so warn(...) calls are never short-circuited
        }
        if (returnType == void.class) {
            return null;
        }
        return 0;
    }
}

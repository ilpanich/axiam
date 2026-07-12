package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.rabbitmq.client.AMQP;
import com.rabbitmq.client.Channel;
import com.rabbitmq.client.DeliverCallback;
import com.rabbitmq.client.Delivery;
import com.rabbitmq.client.Envelope;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HexFormat;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * NEW-4 (AMQP replay protection): proves {@link AmqpConsumer}'s
 * post-HMAC-verification checks (key_version &ge; 2, {@code issued_at}
 * freshness within a clock-skew tolerance, nonce uniqueness) using the same
 * nack-without-requeue path as an invalid signature, without ever invoking
 * the handler.
 *
 * <p>Uses the real server-signed v2 vector
 * ({@code v2_reference_vectors.json}, ground truth for NEW-4) for the ACCEPT
 * case, and self-signed (same subkey, same canonicalization the fixture
 * proves this SDK reproduces &mdash; see {@link V2ReferenceVectorHmacTest})
 * mutated copies for each REJECT case, so every rejection is attributable
 * exclusively to the NEW-4 check under test rather than to an incidental
 * HMAC failure.
 */
class ReplayProtectionTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String FIXTURE_PATH = "/v2_reference_vectors.json";

    /** Matches the fixture's authz_request.issued_at ("2026-07-10T12:00:00Z"), so the ACCEPT case is fresh. */
    private static final Instant FIXTURE_ISSUED_AT = Instant.parse("2026-07-10T12:00:00Z");
    private static final Clock FIXED_CLOCK = Clock.fixed(FIXTURE_ISSUED_AT, ZoneOffset.UTC);

    private static JsonNode loadFixture() throws Exception {
        try (InputStream in = ReplayProtectionTest.class.getResourceAsStream(FIXTURE_PATH)) {
            if (in == null) {
                throw new IllegalStateException("fixture not found on classpath: " + FIXTURE_PATH);
            }
            return MAPPER.readTree(in);
        }
    }

    private static byte[] subkey(JsonNode root) {
        return HexFormat.of().parseHex(root.get("hkdf").get("derived_subkey_hex").asText());
    }

    /**
     * Reconstructs the true declaration-order wire body for {@code vector}
     * by parsing {@code canonical_signed_json} (NOT the fixture's
     * {@code message} convenience field, whose keys are alphabetized for
     * pretty-printing and do NOT reflect signing order &mdash; see
     * {@link V2ReferenceVectorHmacTest}'s class Javadoc) and appending
     * {@code hmac_signature} as a new trailing key.
     */
    private static ObjectNode wireNode(JsonNode vector) throws Exception {
        String canonicalSignedJson = vector.get("canonical_signed_json").asText();
        ObjectNode node = (ObjectNode) MAPPER.readTree(canonicalSignedJson);
        node.put("hmac_signature", vector.get("hmac_signature_hex").asText());
        return node;
    }

    /** Re-signs {@code node} (minus any existing hmac_signature) with {@code key}, mutating it in place. */
    private static void sign(ObjectNode node, byte[] key) throws Exception {
        node.remove("hmac_signature");
        byte[] canonical = MAPPER.writeValueAsBytes(node);
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        node.put("hmac_signature", HexFormat.of().formatHex(mac.doFinal(canonical)));
    }

    // ---- ACCEPT: real server-signed v2 vector, handler invoked, single ack ----

    @Test
    void validV2MessageIsAcceptedAndHandlerInvoked() throws Exception {
        JsonNode root = loadFixture();
        byte[] subkey = subkey(root);
        byte[] body = MAPPER.writeValueAsBytes(wireNode(root.get("authz_request")));

        List<AckNackCall> calls = new ArrayList<>();
        Channel fakeChannel = fakeChannel(calls);
        List<String> warnings = new ArrayList<>();
        Logger fakeLogger = fakeLogger(warnings);
        NonceStore nonceStore = new NonceStore(Duration.ofSeconds(600));

        AtomicInteger handlerInvocations = new AtomicInteger();
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                fakeChannel, subkey, body2 -> handlerInvocations.incrementAndGet(), fakeLogger,
                Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("consumer-tag", delivery(1L, body));

        assertEquals(1, handlerInvocations.get(), "handler must be invoked for a valid, fresh, non-replayed v2 message");
        assertEquals(1, calls.size());
        assertEquals("ack", calls.get(0).type());
        assertTrue(warnings.isEmpty(), "no security warning expected for an accepted message");
    }

    // ---- REJECT: key_version < 2 ------------------------------------------

    @Test
    void keyVersion1IsRejectedWithoutRequeueAndHandlerNeverInvoked() throws Exception {
        JsonNode root = loadFixture();
        byte[] subkey = subkey(root);
        ObjectNode message = wireNode(root.get("authz_request"));
        message.put("key_version", 1);
        sign(message, subkey); // valid HMAC over the mutated (key_version=1) body
        byte[] body = MAPPER.writeValueAsBytes(message);

        List<AckNackCall> calls = new ArrayList<>();
        Channel fakeChannel = fakeChannel(calls);
        List<String> warnings = new ArrayList<>();
        Logger fakeLogger = fakeLogger(warnings);
        NonceStore nonceStore = new NonceStore(Duration.ofSeconds(600));

        AtomicInteger handlerInvocations = new AtomicInteger();
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                fakeChannel, subkey, body2 -> handlerInvocations.incrementAndGet(), fakeLogger,
                Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("consumer-tag", delivery(2L, body));

        assertEquals(0, handlerInvocations.get(), "handler must never be invoked for key_version < 2");
        assertEquals(1, calls.size());
        AckNackCall call = calls.get(0);
        assertEquals("nack", call.type());
        assertFalse(call.requeue(), "key_version < 2 must nack WITHOUT requeue");
        assertFalse(warnings.isEmpty(), "a security event must be logged for the key_version rejection");
    }

    // ---- REJECT: stale issued_at -------------------------------------------

    @Test
    void staleIssuedAtIsRejectedWithoutRequeueAndHandlerNeverInvoked() throws Exception {
        JsonNode root = loadFixture();
        byte[] subkey = subkey(root);
        ObjectNode message = wireNode(root.get("authz_request"));
        // FIXED_CLOCK is pinned at the fixture's issued_at; push issued_at
        // back by one hour, well outside the default 5-minute skew.
        message.put("issued_at", FIXTURE_ISSUED_AT.minus(Duration.ofHours(1)).toString());
        sign(message, subkey);
        byte[] body = MAPPER.writeValueAsBytes(message);

        List<AckNackCall> calls = new ArrayList<>();
        Channel fakeChannel = fakeChannel(calls);
        List<String> warnings = new ArrayList<>();
        Logger fakeLogger = fakeLogger(warnings);
        NonceStore nonceStore = new NonceStore(Duration.ofSeconds(600));

        AtomicInteger handlerInvocations = new AtomicInteger();
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                fakeChannel, subkey, body2 -> handlerInvocations.incrementAndGet(), fakeLogger,
                Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("consumer-tag", delivery(3L, body));

        assertEquals(0, handlerInvocations.get(), "handler must never be invoked for a stale issued_at");
        assertEquals(1, calls.size());
        AckNackCall call = calls.get(0);
        assertEquals("nack", call.type());
        assertFalse(call.requeue(), "stale issued_at must nack WITHOUT requeue");
        assertFalse(warnings.isEmpty(), "a security event must be logged for the staleness rejection");
    }

    // ---- REJECT: nonce replay ------------------------------------------------

    @Test
    void replayedNonceIsRejectedOnSecondDeliveryWithSameStore() throws Exception {
        JsonNode root = loadFixture();
        byte[] subkey = subkey(root);
        byte[] body = MAPPER.writeValueAsBytes(wireNode(root.get("authz_request")));

        List<AckNackCall> calls = new ArrayList<>();
        Channel fakeChannel = fakeChannel(calls);
        List<String> warnings = new ArrayList<>();
        Logger fakeLogger = fakeLogger(warnings);
        // ONE store shared across both deliveries below, as AmqpConsumer#consume does across a
        // consumer's lifetime.
        NonceStore nonceStore = new NonceStore(Duration.ofSeconds(600));

        AtomicInteger handlerInvocations = new AtomicInteger();
        DeliverCallback callback = AmqpConsumer.deliverCallback(
                fakeChannel, subkey, body2 -> handlerInvocations.incrementAndGet(), fakeLogger,
                Duration.ofSeconds(300), FIXED_CLOCK, nonceStore);

        callback.handle("consumer-tag", delivery(4L, body));
        callback.handle("consumer-tag", delivery(5L, body)); // same nonce, second delivery

        assertEquals(1, handlerInvocations.get(), "handler must be invoked exactly once; the replay must be rejected");
        assertEquals(2, calls.size());

        AckNackCall first = calls.get(0);
        assertEquals("ack", first.type());
        assertEquals(4L, first.deliveryTag());

        AckNackCall second = calls.get(1);
        assertEquals("nack", second.type());
        assertEquals(5L, second.deliveryTag());
        assertFalse(second.requeue(), "a replayed nonce must nack WITHOUT requeue");
        assertFalse(warnings.isEmpty(), "a security event must be logged for the replay rejection");
    }

    // ---- test doubles (mirrors AmqpConsumerTest's) --------------------------

    private record AckNackCall(String type, long deliveryTag, boolean multiple, boolean requeue) {
    }

    private static Delivery delivery(long deliveryTag, byte[] body) {
        Envelope envelope = new Envelope(deliveryTag, false, "axiam.authz.request", "authz.request");
        AMQP.BasicProperties properties = new AMQP.BasicProperties.Builder().build();
        return new Delivery(envelope, properties, body);
    }

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

    private static String formatSlf4j(Object[] invocationArgs) {
        String pattern = (String) invocationArgs[0];
        Object[] values;
        if (invocationArgs.length == 2 && invocationArgs[1] instanceof Object[]) {
            values = (Object[]) invocationArgs[1];
        } else {
            values = java.util.Arrays.copyOfRange(invocationArgs, 1, invocationArgs.length);
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
            return true;
        }
        if (returnType == void.class) {
            return null;
        }
        return 0;
    }
}

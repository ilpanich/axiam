package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.InputStream;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Data-driven proof of {@link Hmac#verify(byte[], byte[])} against the real,
 * Rust-signer-produced cross-language fixture (originally derived for Phase
 * 19 / Python, vendored verbatim here). Each vector's {@code hmac_signature}
 * was computed by the canonical server signer
 * ({@code crates/axiam-amqp/src/messages.rs}'s {@code sign_payload}), so a
 * pass here proves byte-for-byte canonicalization compatibility, not just
 * internal self-consistency.
 *
 * <p>This test is non-vacuous by construction: the fixture contains both
 * {@code expected_valid == true} and {@code expected_valid == false}
 * vectors (see {@link #atLeastOneTrueAndOneFalseVectorExist()}), and it
 * would fail immediately if {@link Hmac} were changed to alphabetize keys
 * instead of preserving wire/insertion order — the tampered/wrong-key/
 * malformed vectors would then coincidentally still fail (as intended), but
 * {@code authz_request_valid}/{@code audit_event_valid} would flip to
 * false, since the server-computed signature is over declaration-order
 * bytes, not alphabetical-order bytes.
 */
class HmacVerifyTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String FIXTURE_PATH = "/amqp_hmac_vectors.json";

    private static JsonNode loadFixture() throws Exception {
        try (InputStream in = HmacVerifyTest.class.getResourceAsStream(FIXTURE_PATH)) {
            if (in == null) {
                throw new IllegalStateException("fixture not found on classpath: " + FIXTURE_PATH);
            }
            return MAPPER.readTree(in);
        }
    }

    static Stream<Arguments> vectors() throws Exception {
        JsonNode root = loadFixture();
        JsonNode vectors = root.get("vectors");
        Iterator<JsonNode> it = vectors.elements();
        Stream.Builder<Arguments> builder = Stream.builder();
        while (it.hasNext()) {
            JsonNode vector = it.next();
            String name = vector.get("name").asText();
            String signingKeyHex = vector.get("signing_key_hex").asText();
            // The "message" node is read via the SAME ObjectMapper used by
            // Hmac itself, so the ObjectNode preserves the exact key order
            // it was written in the fixture file (which is the Rust
            // struct-declaration order per the fixture's `_derivation` note).
            JsonNode message = vector.get("message");
            boolean expectedValid = vector.get("expected_valid").asBoolean();
            builder.add(Arguments.of(name, signingKeyHex, message, expectedValid));
        }
        return builder.build();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("vectors")
    void verifyMatchesExpectedValidity(String name, String signingKeyHex, JsonNode message,
                                        boolean expectedValid) throws Exception {
        byte[] signingKey = HexFormat.of().parseHex(signingKeyHex);
        // message is an ObjectNode read straight off the fixture file;
        // re-serializing it reproduces the exact wire bytes the vector
        // represents (including hmac_signature, if present) — Hmac.verify
        // is responsible for stripping it before recomputing.
        assertTrue(message instanceof ObjectNode, name + ": fixture message must be a JSON object");
        byte[] body = MAPPER.writeValueAsBytes(message);

        boolean actual = Hmac.verify(signingKey, body);

        assertEquals(expectedValid, actual, name + ": Hmac.verify result did not match expected_valid");
    }

    @Test
    void atLeastOneTrueAndOneFalseVectorExist() throws Exception {
        JsonNode root = loadFixture();
        JsonNode vectors = root.get("vectors");
        boolean sawTrue = false;
        boolean sawFalse = false;
        for (JsonNode vector : vectors) {
            if (vector.get("expected_valid").asBoolean()) {
                sawTrue = true;
            } else {
                sawFalse = true;
            }
        }
        assertTrue(sawTrue, "fixture must contain at least one expected_valid=true vector");
        assertTrue(sawFalse, "fixture must contain at least one expected_valid=false vector");
    }
}

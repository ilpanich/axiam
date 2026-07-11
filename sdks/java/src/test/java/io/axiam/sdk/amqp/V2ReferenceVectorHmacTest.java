package io.axiam.sdk.amqp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HexFormat;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * NEW-4 (AMQP replay protection) ground-truth cross-language proof: verifies
 * that {@link Hmac#verify} accepts the real, server-signed v2
 * {@code AuthzRequest} and {@code AuditEventMessage} vectors recorded in
 * {@code crates/axiam-amqp/tests/fixtures/v2_reference_vectors.json} (copied
 * verbatim to {@code v2_reference_vectors.json} on this module's test
 * classpath), and that the Jackson parse&rarr;remove(hmac_signature)&rarr;
 * writeValueAsBytes round-trip this SDK relies on reproduces the fixture's
 * {@code canonical_signed_json} byte-for-byte.
 *
 * <p><strong>Important fixture-reading note:</strong> the fixture's
 * {@code message} convenience field is serialized with its keys sorted
 * ALPHABETICALLY (a pretty-printing artifact of however the fixture file
 * itself was generated/dumped) &mdash; it is NOT in signing/declaration
 * order and must never be fed to {@link Hmac#verify} directly (Jackson would
 * canonicalize it in the wrong order and every assertion below would fail
 * with an HMAC mismatch). The one authoritative field for wire order is
 * {@code canonical_signed_json}: a JSON STRING whose own key order, as
 * written in the fixture text, is the true struct-declaration order (see
 * the fixture's {@code field_order} block). Every test below builds its
 * "wire body" by parsing {@code canonical_signed_json} (which preserves that
 * order through Jackson's insertion-order-preserving {@link ObjectNode}) and
 * appending {@code hmac_signature} as a new trailing key, then hands that to
 * {@link Hmac#verify} / round-trips it exactly as {@link Hmac} itself does.
 *
 * <p>The v2 schema adds {@code key_version}, {@code nonce}, and
 * {@code issued_at} (declaration order: after the schema-specific fields,
 * before {@code hmac_signature}). Because {@link Hmac} is schema-agnostic
 * (it operates on whatever {@link ObjectNode} keys are present, in their
 * original insertion order), no canonicalization change was required for
 * NEW-4 &mdash; this test is the proof of that claim, not just an assertion
 * of it.
 *
 * <p>The fixture's {@code hkdf.derived_subkey_hex} is used directly as the
 * HMAC key: this SDK's {@link Hmac} takes an already-derived per-tenant
 * signing key (HKDF subkey derivation is a server/key-management concern
 * outside this SDK's scope), so the pre-derived subkey is exactly the right
 * input for {@link Hmac#verify}.
 */
class V2ReferenceVectorHmacTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String FIXTURE_PATH = "/v2_reference_vectors.json";

    private static JsonNode loadFixture() throws Exception {
        try (InputStream in = V2ReferenceVectorHmacTest.class.getResourceAsStream(FIXTURE_PATH)) {
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
     * Reconstructs the signed wire body for {@code vector}: parses
     * {@code canonical_signed_json} (the true declaration-order bytes that
     * were actually HMAC'd) and appends {@code hmac_signature} as a new
     * trailing key, exactly as a real signed-then-serialized message would
     * look on the wire.
     */
    private static ObjectNode wireNode(JsonNode vector) throws Exception {
        String canonicalSignedJson = vector.get("canonical_signed_json").asText();
        ObjectNode node = (ObjectNode) MAPPER.readTree(canonicalSignedJson);
        node.put("hmac_signature", vector.get("hmac_signature_hex").asText());
        return node;
    }

    // ---- authz_request -----------------------------------------------------

    @Test
    void authzRequestVerifiesAgainstDerivedSubkey() throws Exception {
        JsonNode root = loadFixture();
        JsonNode vector = root.get("authz_request");
        byte[] subkey = subkey(root);

        byte[] wireBytes = MAPPER.writeValueAsBytes(wireNode(vector));

        assertTrue(Hmac.verify(subkey, wireBytes),
                "Hmac.verify must ACCEPT the real server-signed v2 authz_request vector");
    }

    @Test
    void authzRequestCanonicalRoundTripMatchesFixtureByteForByte() throws Exception {
        JsonNode root = loadFixture();
        JsonNode vector = root.get("authz_request");

        ObjectNode wireNode = wireNode(vector);
        wireNode.remove("hmac_signature");
        byte[] roundTripped = MAPPER.writeValueAsBytes(wireNode);

        byte[] expectedCanonical = vector.get("canonical_signed_json").asText().getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(expectedCanonical, roundTripped,
                "parse -> remove(hmac_signature) -> writeValueAsBytes must reproduce canonical_signed_json exactly");
    }

    @Test
    void authzRequestReproducesExpectedHmacHexByteForByte() throws Exception {
        JsonNode root = loadFixture();
        JsonNode vector = root.get("authz_request");
        byte[] subkey = subkey(root);

        byte[] canonical = vector.get("canonical_signed_json").asText().getBytes(StandardCharsets.UTF_8);

        String recomputedHex = HexFormat.of().formatHex(hmacSha256(subkey, canonical));
        assertEquals(vector.get("hmac_signature_hex").asText(), recomputedHex,
                "recomputed HMAC must match the fixture's expected hmac_signature_hex exactly");
    }

    // ---- audit_event ---------------------------------------------------------

    @Test
    void auditEventVerifiesAgainstDerivedSubkey() throws Exception {
        JsonNode root = loadFixture();
        JsonNode vector = root.get("audit_event");
        byte[] subkey = subkey(root);

        byte[] wireBytes = MAPPER.writeValueAsBytes(wireNode(vector));

        assertTrue(Hmac.verify(subkey, wireBytes),
                "Hmac.verify must ACCEPT the real server-signed v2 audit_event vector");
    }

    @Test
    void auditEventCanonicalRoundTripMatchesFixtureByteForByte() throws Exception {
        JsonNode root = loadFixture();
        JsonNode vector = root.get("audit_event");

        ObjectNode wireNode = wireNode(vector);
        wireNode.remove("hmac_signature");
        byte[] roundTripped = MAPPER.writeValueAsBytes(wireNode);

        byte[] expectedCanonical = vector.get("canonical_signed_json").asText().getBytes(StandardCharsets.UTF_8);
        assertArrayEquals(expectedCanonical, roundTripped,
                "parse -> remove(hmac_signature) -> writeValueAsBytes must reproduce canonical_signed_json exactly");
    }

    @Test
    void auditEventReproducesExpectedHmacHexByteForByte() throws Exception {
        JsonNode root = loadFixture();
        JsonNode vector = root.get("audit_event");
        byte[] subkey = subkey(root);

        byte[] canonical = vector.get("canonical_signed_json").asText().getBytes(StandardCharsets.UTF_8);

        String recomputedHex = HexFormat.of().formatHex(hmacSha256(subkey, canonical));
        assertEquals(vector.get("hmac_signature_hex").asText(), recomputedHex,
                "recomputed HMAC must match the fixture's expected hmac_signature_hex exactly");
    }

    private static byte[] hmacSha256(byte[] key, byte[] data) throws Exception {
        javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
        mac.init(new javax.crypto.spec.SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(data);
    }
}

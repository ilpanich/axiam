package io.axiam.sdk;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.io.Serializable;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * CR-04-class regression test for {@link Sensitive} (D-17, CONTRACT.md
 * &sect;7): proves the raw token value never survives {@code toString()} or
 * Jackson serialization, and that {@code Sensitive} fails closed on Java
 * serialization rather than leaking {@code value} via reflection.
 */
class SensitiveTest {

    private static final String RAW_TOKEN = "super-secret-token";
    private static final String REDACTED = "[SENSITIVE]";

    @Test
    void toStringReturnsRedactedPlaceholder() {
        Sensitive sensitive = Sensitive.of(RAW_TOKEN);

        assertTrue(sensitive.toString().equals(REDACTED), "toString() must return the redacted placeholder");
        assertFalse(sensitive.toString().contains(RAW_TOKEN), "toString() must never contain the raw token");
    }

    @Test
    void jacksonSerializationEmitsRedactedPlaceholder() throws Exception {
        ObjectMapper mapper = new ObjectMapper();

        String json = mapper.writeValueAsString(Sensitive.of(RAW_TOKEN));

        assertTrue(json.contains(REDACTED), "Jackson output must contain the redacted placeholder");
        assertFalse(json.contains(RAW_TOKEN), "Jackson output must never contain the raw token");
    }

    @Test
    void sensitiveIsNotSerializable() {
        assertFalse(Serializable.class.isAssignableFrom(Sensitive.class),
                "Sensitive must NOT implement java.io.Serializable (fail-closed on reflective serialization)");
    }
}

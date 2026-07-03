package io.axiam.sdk;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.util.Objects;

/**
 * Hardened wrapper for any token-carrying string value (access token,
 * refresh token, MFA challenge token, AMQP signing key) so it can never
 * accidentally leak via {@code toString()}, Jackson serialization, or Java's
 * reflective object serialization (CONTRACT.md &sect;7, D-17).
 *
 * <p>Mirrors {@code sdks/go}'s {@code Sensitive} (String/Format/GoString/
 * MarshalJSON quartet) and {@code sdks/typescript}'s private-{@code #value}
 * class. The raw value is reachable only via the package-internal
 * {@link #expose()} accessor — there is deliberately no public getter.
 *
 * <p>{@code Sensitive} intentionally does NOT implement
 * {@link java.io.Serializable}: Java's default serialization would
 * otherwise expose {@code value} via reflective field access even with
 * {@code toString()} redacted. Omitting {@code Serializable} means any
 * attempt to Java-serialize an object graph containing a {@code Sensitive}
 * field throws {@code NotSerializableException} at the first attempt — a
 * fail-closed (not fail-open) posture.
 */
@JsonSerialize(using = Sensitive.Redactor.class)
public final class Sensitive {

    private static final String REDACTED = "[SENSITIVE]";

    private final String value;

    private Sensitive(String value) {
        this.value = Objects.requireNonNull(value, "value");
    }

    public static Sensitive of(String value) {
        return new Sensitive(value);
    }

    @Override
    public String toString() {
        return REDACTED;
    }

    // Deliberately no equals()/hashCode() override exposing `value` via a
    // timing side channel; if equality is ever needed, use a constant-time
    // MessageDigest.isEqual comparison, never String.equals.

    /**
     * Package-internal accessor — never public. Only {@code io.axiam.sdk.*}
     * callers can reach the raw value.
     */
    String expose() {
        return value;
    }

    static final class Redactor extends StdSerializer<Sensitive> {

        Redactor() {
            super(Sensitive.class);
        }

        @Override
        public void serialize(Sensitive value, JsonGenerator gen, SerializerProvider provider) throws IOException {
            gen.writeString(REDACTED);
        }
    }
}

package io.axiam.sdk.amqp;

/**
 * Poison-message sentinel a {@code Consume} handler throws to signal that
 * the current delivery must be nacked <strong>without</strong> requeue,
 * rather than the default nack-with-requeue applied to any other non-null
 * handler exception (D-13, CONTRACT.md &sect;8).
 *
 * <p>Mirrors {@code sdks/go/amqp/errdrop.go}'s {@code ErrDrop} sentinel; a
 * dedicated exception type is used here (rather than a Go-style sentinel
 * value) since Java's handler contract is exception-based.
 */
public final class ErrDrop extends RuntimeException {

    public ErrDrop(String message) {
        super(message);
    }
}

package amqp

import (
	"context"
	"errors"
	"fmt"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

// defaultPrefetch is the default QoS prefetch count applied unless
// overridden via WithPrefetch (CF-03).
const defaultPrefetch = 10

// consumerTag identifies this SDK's consumer to the broker.
const consumerTag = "axiam-sdk-consumer"

// securityLogger is the minimal logging seam Consume uses to emit the §8.4
// security event on HMAC verification failure. It is intentionally narrow
// (one method) so callers can adapt any structured logger (e.g. slog) with a
// one-line closure, and so tests can supply a recording fake without pulling
// in a logging dependency. A nil securityLogger is valid — the security
// event is simply dropped (never a reason to fail closed on ack/nack).
type securityLogger interface {
	SecurityWarn(msg string, args ...any)
}

// noopLogger discards all security events. Used when no logger is
// configured (CF-02: observability is opt-in, off by default).
type noopLogger struct{}

func (noopLogger) SecurityWarn(string, ...any) {}

// AckableDelivery is the minimal seam over AMQP delivery acknowledgement
// this package needs. *amqp091.Delivery values satisfy it directly (see
// deliveryAdapter below); a recordingDelivery test fake also satisfies it,
// so verifyAndDispatch's nack-without-requeue security contract can be
// proven hermetically without a live broker.
type AckableDelivery interface {
	// Data returns the raw message payload bytes.
	Data() []byte
	// Ack acknowledges the delivery (message processed successfully).
	Ack()
	// Nack negatively acknowledges the delivery. requeue MUST be false on
	// every failure path this package drives (verification failure, parse
	// failure, ErrDrop) so poison/unverifiable messages do not loop the
	// queue; requeue is true only for a plain (non-ErrDrop) handler error.
	Nack(requeue bool)
}

// deliveryAdapter wraps *amqp091.Delivery to satisfy AckableDelivery. Ack/
// Nack failures are intentionally swallowed here (matching the Rust
// reference's `let _ = ...`): once the consumer loop has decided the
// outcome, there is no further recovery action available, and surfacing the
// ack/nack transport error would require either panicking or silently
// dropping it anyway.
type deliveryAdapter struct {
	d amqp091.Delivery
}

func (a deliveryAdapter) Data() []byte { return a.d.Body }

func (a deliveryAdapter) Ack() {
	_ = a.d.Ack(false)
}

func (a deliveryAdapter) Nack(requeue bool) {
	_ = a.d.Nack(false, requeue)
}

// Handler is the caller-supplied callback invoked only after a delivery's
// HMAC signature has been verified. Its return value drives the D-07 ack/
// nack matrix:
//
//	nil            -> Ack
//	ErrDrop        -> Nack WITHOUT requeue (poison message)
//	any other error -> Nack WITH requeue (transient/retryable)
type Handler func(ctx context.Context, e Event) error

// ConsumeOption configures Consume's behavior beyond its required
// parameters.
type ConsumeOption func(*consumeConfig)

type consumeConfig struct {
	prefetch int
	logger   securityLogger
}

// WithPrefetch overrides the default QoS prefetch count (CF-03).
func WithPrefetch(n int) ConsumeOption {
	return func(c *consumeConfig) {
		c.prefetch = n
	}
}

// WithSecurityLogger supplies a logger invoked with a security event when a
// delivery fails HMAC verification (§8.4). The event never includes the
// received or expected HMAC value. Optional; defaults to a no-op logger
// (CF-02: observability off by default).
func WithSecurityLogger(l securityLogger) ConsumeOption {
	return func(c *consumeConfig) {
		if l != nil {
			c.logger = l
		}
	}
}

// verifyAndDispatch verifies a single delivery's HMAC signature BEFORE
// invoking handler (§8, D-07's core security invariant), then maps the
// outcome to the ack/nack matrix:
//
//   - HMAC verification fails (missing/malformed/mismatched signature, or a
//     body that fails to parse as JSON once verified) -> Nack(false); a
//     security event is logged (never containing the HMAC value); handler
//     is NEVER invoked.
//   - handler(ctx, event) returns nil -> Ack.
//   - handler returns ErrDrop -> Nack(false) (poison message).
//   - handler returns any other error -> Nack(true) (transient, requeue).
//
// This is the load-bearing, separately-testable unit backing Consume's
// per-delivery loop — generic over AckableDelivery so it is exercised
// against recordingDelivery in tests without a live broker.
func verifyAndDispatch(ctx context.Context, delivery AckableDelivery, signingKey []byte, handler Handler, logger securityLogger) {
	if logger == nil {
		logger = noopLogger{}
	}

	body := delivery.Data()

	if !verifyHMAC(signingKey, body) {
		// Security event (§8.4): fact of failure only. NEVER the received
		// or expected HMAC value.
		logger.SecurityWarn("axiam_sdk_security: AMQP HMAC verification failed; nacking without requeue")
		delivery.Nack(false)
		return
	}

	event, err := parseEvent(body)
	if err != nil {
		logger.SecurityWarn("axiam_sdk_security: AMQP message body failed to parse after HMAC verification; nacking without requeue")
		delivery.Nack(false)
		return
	}

	if err := handler(ctx, event); err != nil {
		if errors.Is(err, ErrDrop) {
			delivery.Nack(false)
			return
		}
		delivery.Nack(true)
		return
	}

	delivery.Ack()
}

// Consume connects the SDK's ack/nack loop to ch, verifying every
// delivery's HMAC-SHA256 signature (CONTRACT.md §8) BEFORE invoking
// handler. The handler never sees an unverified message; verification
// failures are nacked without requeue and logged as a security event
// (D-07). Consume sets a configurable QoS prefetch (default 10, CF-03,
// overridable via WithPrefetch) and blocks until ctx is cancelled or the
// delivery channel closes.
//
// signingKey MUST be obtained from the AXIAM management API for the tenant
// whose queue is being consumed (§8.1) — hardcoding a signing key is
// prohibited.
func Consume(ctx context.Context, ch *amqp091.Channel, queue string, signingKey []byte, handler Handler, opts ...ConsumeOption) error {
	cfg := consumeConfig{prefetch: defaultPrefetch, logger: noopLogger{}}
	for _, opt := range opts {
		opt(&cfg)
	}

	if err := ch.Qos(cfg.prefetch, 0, false); err != nil {
		return fmt.Errorf("axiam: failed to set AMQP QoS: %w", err)
	}

	// Buffered with capacity >= 1 (Pitfall 4): amqp091-go sends on
	// NotifyClose synchronously then closes the channel — an unbuffered
	// receiver risks the connection goroutine deadlocking if nothing is
	// actively selecting on it at the moment of closure.
	closeNotify := ch.NotifyClose(make(chan *amqp091.Error, 1))

	deliveries, err := ch.Consume(queue, consumerTag, false, false, false, false, nil)
	if err != nil {
		return fmt.Errorf("axiam: failed to start AMQP consumer: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case closeErr, ok := <-closeNotify:
			if !ok {
				return fmt.Errorf("axiam: AMQP channel closed")
			}
			return fmt.Errorf("axiam: AMQP channel closed: %w", closeErr)
		case d, ok := <-deliveries:
			if !ok {
				return fmt.Errorf("axiam: AMQP delivery channel closed")
			}
			verifyAndDispatch(ctx, deliveryAdapter{d: d}, signingKey, handler, cfg.logger)
		}
	}
}

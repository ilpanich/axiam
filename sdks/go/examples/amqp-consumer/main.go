// Command amqp-consumer demonstrates amqp.Consume with a closure handler
// that shows the full ack/nack matrix (CONTRACT.md §8, D-07).
//
// The SDK verifies each delivery's HMAC-SHA256 signature BEFORE the handler
// closure ever sees the message body, and nacks-without-requeue on any
// verification failure. The handler here decides ack (return nil), a
// transient requeue-eligible failure (return a plain error), or a poison
// message that must never be requeued (return amqp.ErrDrop) — it never
// touches ack/nack directly; that is owned entirely by the SDK.
//
// This example is illustrative/compilable — it reads connection details
// from environment variables and does not require a live AMQP broker to
// `go build ./examples/amqp-consumer/...`. Running it end-to-end requires a
// reachable RabbitMQ broker at AMQP_URL.
//
// Run: go run ./examples/amqp-consumer
package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	amqp091 "github.com/rabbitmq/amqp091-go"

	"github.com/ilpanich/axiam/sdks/go/amqp"
)

func main() {
	amqpURL := getenv("AMQP_URL", "amqp://guest:guest@localhost:5672")
	queue := getenv("AXIAM_AMQP_QUEUE", "axiam.authz.request")

	// §8.1: the per-tenant AMQP signing secret MUST be obtained from the
	// AXIAM management API — never hardcoded. This example reads it from an
	// environment variable as a stand-in for that management-API fetch.
	signingKeyHex := getenv("AXIAM_AMQP_SIGNING_KEY_HEX", "00112233445566778899aabbccddeeff")
	signingKey, err := hex.DecodeString(signingKeyHex)
	if err != nil {
		log.Fatalf("invalid AXIAM_AMQP_SIGNING_KEY_HEX: %v", err)
	}

	conn, err := amqp091.Dial(amqpURL)
	if err != nil {
		log.Fatalf("failed to connect to AMQP broker: %v", err)
	}
	defer conn.Close()

	ch, err := conn.Channel()
	if err != nil {
		log.Fatalf("failed to open AMQP channel: %v", err)
	}
	defer ch.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	fmt.Printf("Consuming from %q — HMAC verification runs before every handler call.\n", queue)

	// The SDK owns the full ack/nack loop (D-07): handler is invoked only
	// after a delivery's HMAC signature has been verified.
	handler := func(_ context.Context, event amqp.Event) error {
		routingKey, ok := event.Fields["action"]
		if !ok {
			// Not the message shape this handler expects — treat as a
			// poison message rather than requeuing it forever.
			return amqp.ErrDrop
		}
		fmt.Printf("Verified AMQP event: action=%s\n", routingKey)
		return nil
	}

	if err := amqp.Consume(ctx, ch, queue, signingKey, handler, amqp.WithPrefetch(10)); err != nil {
		log.Fatalf("consume loop exited: %v", err)
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

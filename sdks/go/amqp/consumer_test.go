package amqp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

// recordingDelivery is a hermetic test fake implementing AckableDelivery: it
// never touches a live broker, only records which of Ack/Nack was called and
// with what requeue value, so the D-07 ack/nack matrix can be asserted
// directly (mirrors the Rust reference's RecordingDelivery, 16-04 SUMMARY).
type recordingDelivery struct {
	data []byte

	mu                sync.Mutex
	acked             int
	nackedRequeueTrue int
	nackedNoRequeue   int
}

func newRecordingDelivery(data []byte) *recordingDelivery {
	return &recordingDelivery{data: data}
}

func (d *recordingDelivery) Data() []byte { return d.data }

func (d *recordingDelivery) Ack() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.acked++
}

func (d *recordingDelivery) Nack(requeue bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if requeue {
		d.nackedRequeueTrue++
	} else {
		d.nackedNoRequeue++
	}
}

func (d *recordingDelivery) counts() (acked, nackRequeue, nackNoRequeue int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.acked, d.nackedRequeueTrue, d.nackedNoRequeue
}

// recordingLogger captures the formatted message of every security-event log
// call so tests can assert a security event fired AND that it never
// contains the HMAC value (§8.4).
type recordingLogger struct {
	mu       sync.Mutex
	messages []string
}

func (l *recordingLogger) SecurityWarn(msg string, _ ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.messages = append(l.messages, msg)
}

func (l *recordingLogger) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, len(l.messages))
	copy(out, l.messages)
	return out
}

func signedTestBody(t *testing.T, key []byte, action string) []byte {
	t.Helper()
	// Build canonical JSON the same way verifyHMAC re-serializes: sorted
	// keys, hmac_signature absent, then sign it and re-insert the field.
	canonical := []byte(`{"action":"` + action + `","correlation_id":"00000000-0000-0000-0000-000000000000"}`)
	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	sig := hex.EncodeToString(mac.Sum(nil))
	return []byte(`{"action":"` + action + `","correlation_id":"00000000-0000-0000-0000-000000000000","hmac_signature":"` + sig + `"}`)
}

func TestVerifyAndDispatch(t *testing.T) {
	key := []byte(fixtureSigningKey)

	t.Run("valid signature + nil handler error acks, handler invoked exactly once", func(t *testing.T) {
		data := signedTestBody(t, key, "read")
		d := newRecordingDelivery(data)
		var calls int32
		handler := func(_ context.Context, _ Event) error {
			atomic.AddInt32(&calls, 1)
			return nil
		}
		logger := &recordingLogger{}

		verifyAndDispatch(context.Background(), d, key, handler, logger)

		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Fatalf("expected handler invoked exactly once, got %d", got)
		}
		acked, nackRequeue, nackNoRequeue := d.counts()
		if acked != 1 || nackRequeue != 0 || nackNoRequeue != 0 {
			t.Fatalf("expected Ack(false) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
		}
	})

	t.Run("valid signature + plain handler error nacks WITH requeue", func(t *testing.T) {
		data := signedTestBody(t, key, "read")
		d := newRecordingDelivery(data)
		handler := func(_ context.Context, _ Event) error {
			return errors.New("transient downstream failure")
		}
		logger := &recordingLogger{}

		verifyAndDispatch(context.Background(), d, key, handler, logger)

		acked, nackRequeue, nackNoRequeue := d.counts()
		if acked != 0 || nackRequeue != 1 || nackNoRequeue != 0 {
			t.Fatalf("expected Nack(true) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
		}
	})

	t.Run("valid signature + ErrDrop nacks WITHOUT requeue", func(t *testing.T) {
		data := signedTestBody(t, key, "read")
		d := newRecordingDelivery(data)
		handler := func(_ context.Context, _ Event) error {
			return ErrDrop
		}
		logger := &recordingLogger{}

		verifyAndDispatch(context.Background(), d, key, handler, logger)

		acked, nackRequeue, nackNoRequeue := d.counts()
		if acked != 0 || nackRequeue != 0 || nackNoRequeue != 1 {
			t.Fatalf("expected Nack(false) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
		}
	})

	t.Run("invalid/missing signature nacks WITHOUT requeue, logs security event, handler never invoked", func(t *testing.T) {
		noSig := []byte(`{"action":"read","correlation_id":"00000000-0000-0000-0000-000000000000"}`)
		d := newRecordingDelivery(noSig)
		var calls int32
		handler := func(_ context.Context, _ Event) error {
			atomic.AddInt32(&calls, 1)
			return nil
		}
		logger := &recordingLogger{}

		verifyAndDispatch(context.Background(), d, key, handler, logger)

		if got := atomic.LoadInt32(&calls); got != 0 {
			t.Fatalf("handler must never be invoked when HMAC verification fails, got %d calls", got)
		}
		acked, nackRequeue, nackNoRequeue := d.counts()
		if acked != 0 || nackRequeue != 0 || nackNoRequeue != 1 {
			t.Fatalf("expected Nack(false) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
		}
		msgs := logger.all()
		if len(msgs) == 0 {
			t.Fatal("expected a security event to be logged on HMAC verification failure")
		}
	})

	t.Run("security event log never contains the HMAC value", func(t *testing.T) {
		data := signedTestBody(t, key, "read")
		// Corrupt the signature so verification fails and the security
		// event path fires, capturing the (wrong) signature value that
		// must never leak into the log line.
		tampered := []byte(`{"action":"read","correlation_id":"00000000-0000-0000-0000-000000000000","hmac_signature":"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}`)
		_ = data
		d := newRecordingDelivery(tampered)
		handler := func(_ context.Context, _ Event) error { return nil }
		logger := &recordingLogger{}

		verifyAndDispatch(context.Background(), d, key, handler, logger)

		msgs := logger.all()
		if len(msgs) == 0 {
			t.Fatal("expected a security event to be logged on HMAC verification failure")
		}
		for _, m := range msgs {
			if contains(m, "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff") {
				t.Fatalf("security event log line must never contain the HMAC value: %q", m)
			}
		}
	})
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && (len(haystack) >= len(needle)) && indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

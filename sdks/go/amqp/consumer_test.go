package amqp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
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

// signedTestBody builds a fresh, valid v2 AuthzRequest signed body: fresh
// (now) issued_at, a fresh random nonce, and key_version 2 — a message that
// passes both the HMAC check and the NEW-4 replay-protection gate. Used by
// tests that exercise the ack/nack dispatch matrix rather than the
// replay-protection gate itself.
func signedTestBody(t *testing.T, key []byte, action string) []byte {
	t.Helper()
	return signedTestBodyV2(t, key, action, 2, uuid.NewString(), time.Now().UTC().Format(time.RFC3339))
}

// signedTestBodyV2 builds a full, realistic v2 AuthzRequest whose bytes are
// in the SERVER's field-DECLARATION order (correlation_id, tenant_id,
// subject_id, action, resource_id, [scope], key_version, nonce, issued_at)
// with hmac_signature absent while signing — exactly what serde_json signs
// (crates/axiam-amqp/src/messages.rs). NOT alphabetical order (the old
// buggy contract). keyVersion, nonce, and issuedAt are parameterized so
// tests can exercise the NEW-4 replay-protection gate (stale issued_at,
// low key_version, replayed nonce).
func signedTestBodyV2(t *testing.T, key []byte, action string, keyVersion int, nonce string, issuedAt string) []byte {
	t.Helper()
	canonical := `{"correlation_id":"00000000-0000-0000-0000-000000000000",` +
		`"tenant_id":"00000000-0000-0000-0000-000000000000",` +
		`"subject_id":"00000000-0000-0000-0000-000000000000",` +
		`"action":"` + action + `",` +
		`"resource_id":"00000000-0000-0000-0000-000000000000",` +
		`"key_version":` + strconv.Itoa(keyVersion) + `,` +
		`"nonce":"` + nonce + `",` +
		`"issued_at":"` + issuedAt + `"}`
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(canonical))
	sig := hex.EncodeToString(mac.Sum(nil))
	// hmac_signature is attached as the trailing field after signing.
	return []byte(`{"correlation_id":"00000000-0000-0000-0000-000000000000",` +
		`"tenant_id":"00000000-0000-0000-0000-000000000000",` +
		`"subject_id":"00000000-0000-0000-0000-000000000000",` +
		`"action":"` + action + `",` +
		`"resource_id":"00000000-0000-0000-0000-000000000000",` +
		`"key_version":` + strconv.Itoa(keyVersion) + `,` +
		`"nonce":"` + nonce + `",` +
		`"issued_at":"` + issuedAt + `",` +
		`"hmac_signature":"` + sig + `"}`)
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

		verifyAndDispatch(context.Background(), d, key, handler, logger, newReplayGuard(defaultSkew))

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

		verifyAndDispatch(context.Background(), d, key, handler, logger, newReplayGuard(defaultSkew))

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

		verifyAndDispatch(context.Background(), d, key, handler, logger, newReplayGuard(defaultSkew))

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

		verifyAndDispatch(context.Background(), d, key, handler, logger, newReplayGuard(defaultSkew))

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

		verifyAndDispatch(context.Background(), d, key, handler, logger, newReplayGuard(defaultSkew))

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

// TestVerifyAndDispatch_ReplayProtection covers NEW-4: after HMAC
// verification succeeds, verifyAndDispatch must still reject (nack without
// requeue, security event logged, handler never invoked) a message whose
// key_version is below 2, whose issued_at is stale, or whose nonce has
// already been seen.
func TestVerifyAndDispatch_ReplayProtection(t *testing.T) {
	key := []byte(fixtureSigningKey)

	t.Run("key_version below 2 is rejected even though HMAC verifies", func(t *testing.T) {
		data := signedTestBodyV2(t, key, "read", 1, uuid.NewString(), time.Now().UTC().Format(time.RFC3339))
		d := newRecordingDelivery(data)
		var calls int32
		handler := func(_ context.Context, _ Event) error {
			atomic.AddInt32(&calls, 1)
			return nil
		}
		logger := &recordingLogger{}

		verifyAndDispatch(context.Background(), d, key, handler, logger, newReplayGuard(defaultSkew))

		if got := atomic.LoadInt32(&calls); got != 0 {
			t.Fatalf("handler must never be invoked when key_version < 2, got %d calls", got)
		}
		acked, nackRequeue, nackNoRequeue := d.counts()
		if acked != 0 || nackRequeue != 0 || nackNoRequeue != 1 {
			t.Fatalf("expected Nack(false) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
		}
		if len(logger.all()) == 0 {
			t.Fatal("expected a security event to be logged when key_version is below the minimum")
		}
	})

	t.Run("stale issued_at outside the freshness window is rejected", func(t *testing.T) {
		staleIssuedAt := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339) // default skew is 5m
		data := signedTestBodyV2(t, key, "read", 2, uuid.NewString(), staleIssuedAt)
		d := newRecordingDelivery(data)
		var calls int32
		handler := func(_ context.Context, _ Event) error {
			atomic.AddInt32(&calls, 1)
			return nil
		}
		logger := &recordingLogger{}

		verifyAndDispatch(context.Background(), d, key, handler, logger, newReplayGuard(defaultSkew))

		if got := atomic.LoadInt32(&calls); got != 0 {
			t.Fatalf("handler must never be invoked when issued_at is stale, got %d calls", got)
		}
		acked, nackRequeue, nackNoRequeue := d.counts()
		if acked != 0 || nackRequeue != 0 || nackNoRequeue != 1 {
			t.Fatalf("expected Nack(false) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
		}
		if len(logger.all()) == 0 {
			t.Fatal("expected a security event to be logged when issued_at is stale")
		}
	})

	t.Run("a future issued_at outside the freshness window is also rejected", func(t *testing.T) {
		futureIssuedAt := time.Now().UTC().Add(10 * time.Minute).Format(time.RFC3339)
		data := signedTestBodyV2(t, key, "read", 2, uuid.NewString(), futureIssuedAt)
		d := newRecordingDelivery(data)
		handler := func(_ context.Context, _ Event) error { return nil }
		logger := &recordingLogger{}

		verifyAndDispatch(context.Background(), d, key, handler, logger, newReplayGuard(defaultSkew))

		acked, nackRequeue, nackNoRequeue := d.counts()
		if acked != 0 || nackRequeue != 0 || nackNoRequeue != 1 {
			t.Fatalf("expected Nack(false) only, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
		}
	})

	t.Run("a replayed nonce (second delivery) is rejected; the first delivery still acks", func(t *testing.T) {
		nonce := uuid.NewString()
		issuedAt := time.Now().UTC().Format(time.RFC3339)
		data := signedTestBodyV2(t, key, "read", 2, nonce, issuedAt)
		guard := newReplayGuard(defaultSkew)
		logger := &recordingLogger{}
		var calls int32
		handler := func(_ context.Context, _ Event) error {
			atomic.AddInt32(&calls, 1)
			return nil
		}

		// First delivery of this nonce: HMAC verifies, replay gate passes
		// (nonce not yet seen), handler runs, message acks.
		first := newRecordingDelivery(data)
		verifyAndDispatch(context.Background(), first, key, handler, logger, guard)
		acked, nackRequeue, nackNoRequeue := first.counts()
		if acked != 1 || nackRequeue != 0 || nackNoRequeue != 0 {
			t.Fatalf("expected the first delivery to Ack, got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
		}

		// Second delivery reusing the SAME body (same nonce): HMAC still
		// verifies, but the replay gate must now reject it as a replay —
		// nacked without requeue, handler never invoked a second time.
		second := newRecordingDelivery(data)
		verifyAndDispatch(context.Background(), second, key, handler, logger, guard)

		if got := atomic.LoadInt32(&calls); got != 1 {
			t.Fatalf("handler must not be invoked again on a replayed nonce, got %d total calls", got)
		}
		acked, nackRequeue, nackNoRequeue = second.counts()
		if acked != 0 || nackRequeue != 0 || nackNoRequeue != 1 {
			t.Fatalf("expected the replayed delivery to Nack(false), got acked=%d nackRequeue=%d nackNoRequeue=%d", acked, nackRequeue, nackNoRequeue)
		}
	})
}

// TestReplayGuard_Check exercises the replayGuard policy directly (key_version
// gate, freshness window, nonce dedup with TTL pruning) without going
// through the full HMAC/dispatch pipeline.
func TestReplayGuard_Check(t *testing.T) {
	fixedNow := time.Date(2026, 7, 10, 12, 0, 0, 0, time.UTC)

	t.Run("rejects key_version below the minimum", func(t *testing.T) {
		g := newReplayGuard(5 * time.Minute)
		g.now = func() time.Time { return fixedNow }
		err := g.check(replayMeta{KeyVersion: 1, Nonce: uuid.NewString(), IssuedAt: fixedNow.Format(time.RFC3339)})
		if err == nil {
			t.Fatal("expected an error for key_version below the minimum")
		}
	})

	t.Run("rejects an unparseable issued_at", func(t *testing.T) {
		g := newReplayGuard(5 * time.Minute)
		g.now = func() time.Time { return fixedNow }
		err := g.check(replayMeta{KeyVersion: 2, Nonce: uuid.NewString(), IssuedAt: "not-a-timestamp"})
		if err == nil {
			t.Fatal("expected an error for an unparseable issued_at")
		}
	})

	t.Run("accepts a fresh nonce within the window and then rejects its replay", func(t *testing.T) {
		g := newReplayGuard(5 * time.Minute)
		g.now = func() time.Time { return fixedNow }
		meta := replayMeta{KeyVersion: 2, Nonce: uuid.NewString(), IssuedAt: fixedNow.Format(time.RFC3339)}
		if err := g.check(meta); err != nil {
			t.Fatalf("expected the first check to pass, got %v", err)
		}
		if err := g.check(meta); err == nil {
			t.Fatal("expected the second check of the same nonce to be rejected as a replay")
		}
	})

	t.Run("prunes nonces once they age past the 2xskew TTL", func(t *testing.T) {
		skew := 5 * time.Minute
		g := newReplayGuard(skew)
		current := fixedNow
		g.now = func() time.Time { return current }

		nonce := uuid.NewString()
		meta := replayMeta{KeyVersion: 2, Nonce: nonce, IssuedAt: current.Format(time.RFC3339)}
		if err := g.check(meta); err != nil {
			t.Fatalf("expected the first check to pass, got %v", err)
		}

		// Advance time past the nonce TTL (2xskew). Inspect the guard's
		// internal state directly to confirm the entry is pruned once its
		// TTL has elapsed (re-using the same, now-stale, issued_at would
		// fail the freshness check first, which is a separate concern from
		// map pruning).
		current = current.Add(2*skew + time.Second)
		g.mu.Lock()
		g.prune(current)
		_, stillPresent := g.seen[nonce]
		g.mu.Unlock()
		if stillPresent {
			t.Fatal("expected the nonce entry to be pruned once its TTL (2xskew) has elapsed")
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

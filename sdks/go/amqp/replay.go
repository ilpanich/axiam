package amqp

import (
	"fmt"
	"sync"
	"time"
)

// minKeyVersion is the lowest AMQP signed-envelope key_version this SDK will
// accept (NEW-4). A message with key_version below this predates the
// mandatory nonce/issued_at replay-protection fields and is rejected
// outright — a hard cutover, there is no v1 grace path (mirrors
// crates/axiam-amqp/src/messages.rs MIN_ACCEPTED_KEY_VERSION).
const minKeyVersion = 2

// defaultSkew is the default freshness window applied to a delivery's
// issued_at field: a message is accepted only when its issued_at lies
// within ±defaultSkew of the consumer's current clock, unless overridden via
// WithSkew (mirrors crates/axiam-amqp/src/messages.rs
// DEFAULT_FRESHNESS_SKEW_SECS = 300).
const defaultSkew = 5 * time.Minute

// replayGuard enforces the NEW-4 replay-protection checks that run AFTER
// HMAC verification has already succeeded: the key_version gate, the
// issued_at freshness window, and nonce dedup. One replayGuard is created
// per Consume call (or per test) and is safe for concurrent use — Consume
// dispatches deliveries sequentially today, but the guard does not assume
// that.
//
// The nonce dedup set is a plain map[nonce]expiry guarded by a mutex. Its
// TTL is 2×skew: a nonce cannot legitimately recur once its message has
// aged out of the ±skew freshness window, so entries older than 2×skew are
// pruned opportunistically on each check, keeping the map naturally bounded
// without a background goroutine.
type replayGuard struct {
	skew time.Duration
	now  func() time.Time // overridable in tests; defaults to time.Now

	mu   sync.Mutex
	seen map[string]time.Time // nonce -> expiry
}

// newReplayGuard creates a replayGuard with the given freshness skew. skew
// must be > 0; Consume/WithSkew enforce this before construction.
func newReplayGuard(skew time.Duration) *replayGuard {
	return &replayGuard{
		skew: skew,
		now:  time.Now,
		seen: make(map[string]time.Time),
	}
}

// check validates meta against the NEW-4 replay-protection policy: the
// key_version gate, the issued_at freshness window, and nonce dedup. It
// returns nil iff the message passes all three checks, in which case its
// nonce has also been recorded (so a second delivery of the same nonce is
// rejected as a replay). A non-nil error describes the first failing check;
// the caller treats any error identically (nack without requeue, security
// event logged, handler never invoked) — the distinction is for logging/
// debugging only, never surfaced to the handler.
func (g *replayGuard) check(meta replayMeta) error {
	if meta.KeyVersion < minKeyVersion {
		return fmt.Errorf("axiam: key_version %d is below the minimum accepted version %d", meta.KeyVersion, minKeyVersion)
	}

	issuedAt, err := time.Parse(time.RFC3339, meta.IssuedAt)
	if err != nil {
		return fmt.Errorf("axiam: issued_at %q is not a valid RFC3339 timestamp: %w", meta.IssuedAt, err)
	}

	now := g.now()
	if age := now.Sub(issuedAt); age > g.skew || age < -g.skew {
		return fmt.Errorf("axiam: issued_at %q is outside the ±%s freshness window", meta.IssuedAt, g.skew)
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.prune(now)
	if _, replay := g.seen[meta.Nonce]; replay {
		return fmt.Errorf("axiam: nonce has already been used (replay)")
	}
	// TTL = 2×skew (freshness window width): a nonce outside this age could
	// never have passed the freshness check above anyway, so this alone
	// keeps the map bounded without a background pruning goroutine.
	g.seen[meta.Nonce] = now.Add(2 * g.skew)
	return nil
}

// prune removes expired nonce entries. Callers must hold g.mu.
func (g *replayGuard) prune(now time.Time) {
	for nonce, expiry := range g.seen {
		if !now.Before(expiry) {
			delete(g.seen, nonce)
		}
	}
}

package axiam

import (
	"encoding/json"
	"fmt"
	"io"
)

// redacted is the placeholder every Sensitive redaction surface emits in
// place of the raw value (CONTRACT.md §7 / D-08).
const redacted = "[SENSITIVE]"

// Sensitive wraps a token-carrying string so it can never accidentally leak
// via fmt verbs, Go-syntax representation, or JSON encoding (CONTRACT.md §7,
// D-08). All token-carrying fields (access token, refresh token, MFA
// challenge token, AMQP signing key) MUST use this type.
//
// The raw value is reachable only via the package-internal expose()
// accessor — Sensitive deliberately has no public getter.
type Sensitive string

// String implements fmt.Stringer. Covers direct String() calls and the
// default fmt verb behavior for types without a more specific Format/GoString
// override (String() alone would still leak on %#v without GoString below).
func (Sensitive) String() string {
	return redacted
}

// Format implements fmt.Formatter, closing the fmt-verb leak path
// (%v/%+v/%s/%q/width/precision) that a bare String() method does not fully
// cover — this is the CR-04 leak class this type exists to prevent.
func (Sensitive) Format(f fmt.State, verb rune) {
	_, _ = io.WriteString(f, redacted)
}

// GoString implements fmt.GoStringer, covering %#v (Go-syntax
// representation), which bypasses String()/Format() entirely if not
// implemented.
func (Sensitive) GoString() string {
	return redacted
}

// MarshalJSON implements json.Marshaler so any struct embedding a Sensitive
// field serializes the redacted placeholder rather than the raw value.
func (Sensitive) MarshalJSON() ([]byte, error) {
	return json.Marshal(redacted)
}

// expose returns the raw wrapped value. This is the ONLY path to the raw
// value and is intentionally unexported — never call this from outside the
// package, and never pass its return value to a log/fmt/JSON sink.
func (s Sensitive) expose() string {
	return string(s)
}

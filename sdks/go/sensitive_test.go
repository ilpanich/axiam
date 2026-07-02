package axiam

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// TestSensitive_RedactsAllSurfaces proves Sensitive("secret") never leaks the
// raw value through any of the four redaction surfaces CONTRACT.md §7 / D-08
// require: String(), fmt verbs (%v/%+v/%s/%q), GoString() (%#v), and
// MarshalJSON. The raw value must only be reachable via the package-internal
// expose() accessor.
func TestSensitive_RedactsAllSurfaces(t *testing.T) {
	const rawSecret = "super-secret-token-value"
	sensitive := Sensitive(rawSecret)

	t.Run("String", func(t *testing.T) {
		got := sensitive.String()
		if got != "[SENSITIVE]" {
			t.Fatalf("String() = %q, want [SENSITIVE]", got)
		}
		if strings.Contains(got, rawSecret) {
			t.Fatalf("String() leaked raw secret: %q", got)
		}
	})

	t.Run("fmt %v", func(t *testing.T) {
		got := fmt.Sprintf("%v", sensitive)
		if got != "[SENSITIVE]" {
			t.Fatalf("%%v = %q, want [SENSITIVE]", got)
		}
		if strings.Contains(got, rawSecret) {
			t.Fatalf("%%v leaked raw secret: %q", got)
		}
	})

	t.Run("fmt %+v", func(t *testing.T) {
		got := fmt.Sprintf("%+v", sensitive)
		if got != "[SENSITIVE]" {
			t.Fatalf("%%+v = %q, want [SENSITIVE]", got)
		}
		if strings.Contains(got, rawSecret) {
			t.Fatalf("%%+v leaked raw secret: %q", got)
		}
	})

	t.Run("fmt %s", func(t *testing.T) {
		got := fmt.Sprintf("%s", sensitive)
		if got != "[SENSITIVE]" {
			t.Fatalf("%%s = %q, want [SENSITIVE]", got)
		}
		if strings.Contains(got, rawSecret) {
			t.Fatalf("%%s leaked raw secret: %q", got)
		}
	})

	t.Run("fmt %q", func(t *testing.T) {
		got := fmt.Sprintf("%q", sensitive)
		if strings.Contains(got, rawSecret) {
			t.Fatalf("%%q leaked raw secret: %q", got)
		}
		if !strings.Contains(got, "[SENSITIVE]") {
			t.Fatalf("%%q = %q, want to contain [SENSITIVE]", got)
		}
	})

	t.Run("GoString %#v", func(t *testing.T) {
		got := fmt.Sprintf("%#v", sensitive)
		if strings.Contains(got, rawSecret) {
			t.Fatalf("%%#v leaked raw secret: %q", got)
		}
		if !strings.Contains(got, "[SENSITIVE]") {
			t.Fatalf("%%#v = %q, want to contain [SENSITIVE]", got)
		}
	})

	t.Run("MarshalJSON", func(t *testing.T) {
		b, err := json.Marshal(sensitive)
		if err != nil {
			t.Fatalf("json.Marshal returned error: %v", err)
		}
		got := string(b)
		if got != `"[SENSITIVE]"` {
			t.Fatalf("json.Marshal = %s, want \"[SENSITIVE]\"", got)
		}
		if strings.Contains(got, rawSecret) {
			t.Fatalf("json.Marshal leaked raw secret: %s", got)
		}
	})

	t.Run("struct field via json.Marshal", func(t *testing.T) {
		type wrapper struct {
			Token Sensitive `json:"token"`
		}
		w := wrapper{Token: sensitive}
		b, err := json.Marshal(w)
		if err != nil {
			t.Fatalf("json.Marshal returned error: %v", err)
		}
		got := string(b)
		if strings.Contains(got, rawSecret) {
			t.Fatalf("struct json.Marshal leaked raw secret: %s", got)
		}
	})

	t.Run("expose returns raw value (package-internal only)", func(t *testing.T) {
		if got := sensitive.expose(); got != rawSecret {
			t.Fatalf("expose() = %q, want %q", got, rawSecret)
		}
	})
}

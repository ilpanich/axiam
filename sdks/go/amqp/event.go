package amqp

import "encoding/json"

// Event is the server message shape a Consume handler receives, after HMAC
// verification has already succeeded (CONTRACT.md §8, D-07). Extra is the
// full decoded JSON object (hmac_signature already removed) so callers can
// read message-type-specific fields (AuthzRequest/AuditEventMessage, etc.)
// without this package needing to model every server message type.
type Event struct {
	// Raw is the original message body bytes, exactly as received (before
	// hmac_signature removal), for callers that need to re-parse into a
	// specific message type.
	Raw []byte
	// Fields is the decoded JSON object with hmac_signature removed.
	Fields map[string]json.RawMessage
}

// parseEvent decodes body into an Event. It is only ever called AFTER
// verifyHMAC has succeeded for the same body (consumer.go), so a parse
// failure here indicates a body that verified but is not a JSON object —
// treated as a failure by the caller (nack without requeue, handler never
// invoked).
func parseEvent(body []byte) (Event, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		return Event{}, err
	}
	delete(fields, "hmac_signature")
	return Event{Raw: body, Fields: fields}, nil
}

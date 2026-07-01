package amqp

import "errors"

// ErrDrop is the sentinel a Consume handler returns to signal that the
// current delivery is a poison message: it must be nacked WITHOUT requeue
// rather than the default nack-WITH-requeue behavior applied to any other
// non-nil handler error (D-07, CONTRACT.md §8).
var ErrDrop = errors.New("axiam: drop message without requeue")

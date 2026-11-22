//! SA-15 (N2): where the authz consumer publishes a decision. Broker-free —
//! the routing decision is a pure function the consumer loop applies to the
//! delivery's AMQP `reply_to` property.

use axiam_amqp::authz_consumer::response_routing_key;
use axiam_amqp::connection::queues;

/// A request that names a `reply_to` queue gets its decision there, so each
/// producer can read its own decisions from a queue only it consumes.
#[test]
fn a_reply_to_routes_the_response_to_that_queue() {
    assert_eq!(
        response_routing_key(Some("amq.gen-JzTY20BRgKO-HjmUJj0wLg")),
        "amq.gen-JzTY20BRgKO-HjmUJj0wLg"
    );
    assert_eq!(
        response_routing_key(Some("amq.rabbitmq.reply-to.g1h2AA5yZXBseQ")),
        "amq.rabbitmq.reply-to.g1h2AA5yZXBseQ"
    );
}

/// Without a `reply_to` (or with an empty one) the response goes to the shared
/// queue as before SA-15 — the change is additive.
#[test]
fn without_reply_to_the_response_goes_to_the_shared_queue() {
    assert_eq!(response_routing_key(None), queues::AUTHZ_RESPONSE);
    assert_eq!(response_routing_key(Some("")), queues::AUTHZ_RESPONSE);
    assert_eq!(queues::AUTHZ_RESPONSE, "axiam.authz.response");
}

/// SR1-5: a `reply_to` naming one of the server's own queues (`axiam.` — the
/// mail and outbound work queues, their retry and dead-letter queues, the
/// audit and authz queues) is not honoured: the response goes to the shared
/// queue instead. Any other name is an integrator's and is honoured.
#[test]
fn a_reply_to_naming_a_server_internal_queue_is_not_honoured() {
    for queue in [
        "axiam.mail.outbound",
        "axiam.webhook",
        "axiam.webhook.retry",
        "axiam.ssf_push.dlq",
        "axiam.audit.events",
        "axiam.authz.request",
    ] {
        assert_eq!(
            response_routing_key(Some(queue)),
            queues::AUTHZ_RESPONSE,
            "{queue}"
        );
    }
    assert_eq!(
        response_routing_key(Some("billing.authz-replies")),
        "billing.authz-replies"
    );
}

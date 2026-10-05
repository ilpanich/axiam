//! P23W4-08 / T23.6.1: every outbound kind's consumer is supervised by the one
//! `spawn_outbound_consumer`; `main.rs` holds no copy of the reconnect loop.
//!
//! A source-level guard, because the loop lives in `main`, which no test can
//! call: a third kind (outbound SCIM, T23.6.2) must be one more call, not a
//! third copy of the loop.

const MAIN: &str = include_str!("../src/main.rs");

/// Occurrences of `needle` in the non-comment lines of `main.rs`.
fn code_occurrences(needle: &str) -> usize {
    MAIN.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| line.matches(needle).count())
        .sum()
}

#[test]
fn webhook_and_ssf_push_are_spawned_through_the_one_function() {
    assert_eq!(
        code_occurrences("spawn_outbound_consumer("),
        2,
        "one call per kind registered so far: webhook and SSF push"
    );
    assert!(MAIN.contains("OutboundKind::Webhook,\n            outbound_deliverers,"));
    assert!(MAIN.contains("OutboundKind::SsfPush,\n            ssf_deliverers,"));
}

#[test]
fn main_holds_no_copy_of_the_supervisor_loop() {
    assert_eq!(
        code_occurrences("run_outbound_consumer("),
        0,
        "the consume loop is started only by spawn_outbound_consumer"
    );
    for copied_log in [
        "Webhook AMQP consumer failed",
        "SSF push AMQP consumer failed",
        "Failed to (re)create webhook consumer channel",
        "Failed to (re)create SSF push consumer channel",
    ] {
        assert_eq!(
            code_occurrences(copied_log),
            0,
            "{copied_log:?} was a line of a copied supervisor loop"
        );
    }
}

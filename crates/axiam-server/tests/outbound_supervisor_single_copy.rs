//! P23W4-08 / T23.6.1: every outbound kind's consumer is supervised by the one
//! `spawn_outbound_consumer`; `main.rs` holds no copy of the reconnect loop.
//!
//! A source-level guard, because the loop lives in `main`, which no test can
//! call: a third kind (outbound SCIM, T23.6.2) is one more call, not a third copy
//! of the loop. The same file pins the rest of the SCIM wiring that only `main`
//! can express: its topology, and the provisioning sink every repository that
//! writes a provisioned field carries (D-57).

const MAIN: &str = include_str!("../src/main.rs");

/// Occurrences of `needle` in the non-comment lines of `main.rs`.
fn code_occurrences(needle: &str) -> usize {
    MAIN.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| line.matches(needle).count())
        .sum()
}

#[test]
fn every_kind_is_spawned_through_the_one_function() {
    assert_eq!(
        code_occurrences("spawn_outbound_consumer("),
        3,
        "one call per kind: webhook, SSF push and SCIM push"
    );
    assert!(MAIN.contains("OutboundKind::Webhook,\n            outbound_deliverers,"));
    assert!(MAIN.contains("OutboundKind::SsfPush,\n            ssf_deliverers,"));
    assert!(MAIN.contains("OutboundKind::ScimPush,\n            scim_deliverers,"));
    assert!(MAIN.contains("OutboundRetryConfig::from_env_for(OutboundKind::ScimPush)"));
}

#[test]
fn the_scim_push_topology_is_declared_beside_the_others() {
    assert_eq!(
        code_occurrences("declare_outbound_topology(OutboundKind::ScimPush)"),
        1
    );
    assert_eq!(
        code_occurrences("declare_outbound_topology(OutboundKind::SsfPush)"),
        1
    );
}

/// D-57: the user and group repositories report to one shared sink. Every
/// production construction that can write a provisioned field carries it —
/// the two repositories every service clones, the directory mapper's group
/// repository (a directory-sourced membership is a write) and the GDPR
/// deletion request's repository (it sets the status). The sink is bound to the
/// SCIM provisioner exactly once.
#[test]
fn the_provisioning_sink_reaches_every_repository_that_writes_a_provisioned_field() {
    assert_eq!(code_occurrences("with_provisioning_sink("), 4);
    assert_eq!(code_occurrences("provisioning_sink.bind("), 1);
    assert_eq!(
        code_occurrences("Late<dyn axiam_core::provisioning::ProvisioningSink>"),
        1,
        "one handle, created once"
    );
    // The only user-repository construction left without the sink reads
    // (`ScimTokenResolver::resolve` calls `get_by_id` and nothing else).
    let bare: Vec<&str> = MAIN
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .filter(|line| {
            line.contains("SurrealUserRepository::new(")
                || line.contains("SurrealGroupRepository::new(")
        })
        .collect();
    assert_eq!(bare.len(), 3, "{bare:?}");
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

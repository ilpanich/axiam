//! P23W4-08 / T23.6.1: every outbound kind's consumer is supervised by the one
//! `spawn_outbound_consumer`; the composition root holds no copy of the
//! reconnect loop.
//!
//! A source-level guard: a third kind (outbound SCIM, T23.6.2) is one more call,
//! not a third copy of the loop. The same file pins the rest of the SCIM wiring
//! the composition root expresses: its topology, and the provisioning sink every
//! repository that writes a provisioned field carries (D-57).
//!
//! Since G-8 (T23.8.1) the composition root is `boot.rs`, and a kind is
//! consumed through `OutboundTransport::spawn_consumer`, which picks the AMQP
//! loop (`spawn_outbound_consumer`) or the in-process one at start-up. The guard
//! therefore also pins that `messaging.rs` — the only place that chooses —
//! holds exactly one call of each.

const MAIN: &str = include_str!("../src/boot.rs");
const MESSAGING: &str = include_str!("../src/messaging.rs");

/// Occurrences of `needle` in the non-comment lines of `boot.rs`.
fn code_occurrences(needle: &str) -> usize {
    MAIN.lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| line.matches(needle).count())
        .sum()
}

/// Occurrences of `needle` in the non-comment lines of `messaging.rs`.
fn messaging_occurrences(needle: &str) -> usize {
    MESSAGING
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .map(|line| line.matches(needle).count())
        .sum()
}

#[test]
fn every_kind_is_spawned_through_the_one_function() {
    assert_eq!(
        code_occurrences("outbound.spawn_consumer("),
        4,
        "one call per kind: webhook, SSF push, SCIM push and CIBA ping"
    );
    assert_eq!(
        code_occurrences("spawn_outbound_consumer("),
        0,
        "the composition root never starts the AMQP loop itself"
    );
    assert_eq!(
        messaging_occurrences("spawn_outbound_consumer("),
        1,
        "the AMQP loop is started in exactly one place"
    );
    assert_eq!(
        messaging_occurrences("spawn_in_process_consumer("),
        1,
        "and so is the in-process one"
    );
    assert!(MAIN.contains("OutboundKind::Webhook,\n            outbound_deliverers,"));
    assert!(MAIN.contains("OutboundKind::SsfPush,\n            ssf_deliverers,"));
    assert!(MAIN.contains("OutboundKind::ScimPush,\n            scim_deliverers,"));
    assert!(MAIN.contains("OutboundRetryConfig::from_env_for(OutboundKind::ScimPush)"));
    // T23.7.2 (D-65): the fourth kind is one more call, not a fourth loop.
    assert!(MAIN.contains("OutboundKind::CibaPing,\n            ciba_ping_deliverers,"));
    assert!(MAIN.contains("OutboundRetryConfig::from_env_for(OutboundKind::CibaPing)"));
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

/// T23.7.2 (D-65): the CIBA ping topology is declared beside the others, and the
/// decision path's publisher, the mail notifier and the consumer are all wired
/// in `main` — a deployment that forgot one would record decisions and tell
/// nobody.
#[test]
fn the_ciba_ping_kind_and_the_mail_notifier_are_wired() {
    assert_eq!(
        code_occurrences("declare_outbound_topology(OutboundKind::CibaPing)"),
        1
    );
    assert_eq!(code_occurrences(".with_ping_publisher("), 1);
    assert_eq!(code_occurrences("CibaPingDeliverer::new("), 1);
    assert_eq!(code_occurrences("CibaMailNotifier::new("), 1);
    assert_eq!(
        code_occurrences("NoopCibaUserNotifier"),
        0,
        "the no-op notifier is no longer in the composition root"
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
fn the_composition_root_holds_no_copy_of_the_supervisor_loop() {
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

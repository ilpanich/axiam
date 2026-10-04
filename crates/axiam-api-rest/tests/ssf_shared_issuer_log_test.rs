//! **D-55** (F4 W4, P23W4-11, ilpanich/axiam#539): a change of the SSF
//! shared-issuer gate is logged **once** at `WARN` and audited as
//! `ssf.inactive_shared_issuer` once per tenant with SSF on — never per event,
//! never per request.
//!
//! Alone in its binary on purpose: `tracing::subscriber::set_default` overrides
//! the dispatcher on this thread only, while the per-callsite interest cache is
//! process-wide, so a concurrent test in the same process can leave the gate's
//! callsite cached as disabled and drop the line this test counts (the race
//! `axiam-amqp/tests/mail_consumer_template_test.rs` records). The fixtures are
//! `ssf_shared_issuer_support`'s.

#[macro_use]
mod ssf_shared_issuer_support;

use ssf_shared_issuer_support::*;

/// A change of state is logged once at `WARN` and audited once per tenant with
/// SSF on — not per event, not per request.
#[actix_rt::test]
async fn the_gate_is_logged_once_and_audited_per_tenant() {
    let capture = CapturedLog::default();
    let writer = capture.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_ansi(false)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let w = world(2, false).await;
    w.stream(SsfDeliveryMethod::Push).await;
    let state = w.state();
    let app = app!(state.clone(), w);
    for _ in 0..3 {
        let (status, _) = send(
            &app,
            request(Method::GET, &discovery_uri(w.tenant_id), None),
        )
        .await;
        assert_eq!(status, 404);
        w.emit(&state).await;
    }
    settle().await;

    let printed = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    let warnings = printed
        .lines()
        .filter(|l| l.contains("WARN") && l.contains("D-55"))
        .count();
    assert_eq!(warnings, 1, "one WARN line for the change");
    for tenant_id in w.tenant_ids().await {
        assert_eq!(
            w.audit_rows(tenant_id).await.len(),
            1,
            "one audit row per tenant with SSF on"
        );
    }
}

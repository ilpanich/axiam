//! **D-55** (F4 W4, P23W4-11, ilpanich/axiam#539) — SSF requires per-tenant
//! issuers in a deployment of more than one tenant.
//!
//! Without `AXIAM__AUTH__TENANT_ISSUER_PATHS` every tenant's SETs carry the same
//! `iss` and the same key, so an administrator of one tenant who registered
//! another tenant's receiver audience first could push SETs that receiver
//! accepts (T-390). The gate is *paths off **and** more than one tenant*; while
//! it holds SSF behaves for every tenant exactly as with `ssf_enabled` off.
//! These tests drive it over HTTP, through the production route table, the real
//! repositories on an in-memory database and the real gate; the outbox is a
//! recording double.
//!
//! The fixtures are in `ssf_shared_issuer_support`; the `WARN`-line test is in
//! `ssf_shared_issuer_log_test.rs`, a process of its own. Keys, headers and
//! tokens are generated at run time; no assertion or panic message formats a
//! header, a token or an address.

#[macro_use]
mod ssf_shared_issuer_support;

use ssf_shared_issuer_support::*;

// ---------------------------------------------------------------------------
// Paths off, two tenants: SSF is off for every tenant
// ---------------------------------------------------------------------------

/// Discovery answers its one empty `404`, the receiver API sees no stream, a
/// poll returns nothing, and an emission produces nothing.
#[actix_rt::test]
async fn with_paths_off_and_two_tenants_ssf_behaves_as_switched_off() {
    let w = world(2, false).await;
    let poll = w.stream(SsfDeliveryMethod::Poll).await;
    w.hold_one(&poll).await;
    let state = w.state();
    let app = app!(state.clone(), w);

    let (status, body) = send(
        &app,
        request(Method::GET, &discovery_uri(w.tenant_id), None),
    )
    .await;
    assert_eq!(status, 404, "discovery");
    assert!(body.is_empty(), "the one empty 404");

    let token = w.receiver_token();
    let (status, _) = send(
        &app,
        request(
            Method::GET,
            &format!("/ssf/v1/stream?stream_id={}", poll.id),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 404, "the receiver API sees no stream");

    let (status, body) = send(
        &app,
        request(
            Method::POST,
            &format!("/ssf/v1/poll/{}", poll.id),
            Some(&token),
        )
        .set_json(json!({"returnImmediately": true})),
    )
    .await;
    assert_eq!(status, 404, "a poll returns nothing");
    assert!(json_of(&body)["sets"].is_null(), "no SET in the answer");

    let (status, _) = send(
        &app,
        request(Method::POST, "/ssf/v1/verify", Some(&token))
            .set_json(json!({"stream_id": poll.id})),
    )
    .await;
    assert_eq!(status, 404, "nothing is verified");

    w.stream(SsfDeliveryMethod::Push).await;
    w.emit(&state).await;
    assert_eq!(w.told(), 0, "an emission produces nothing");
}

/// Turning `ssf_enabled` on while the gate holds is `400`, naming the cause;
/// a write that leaves it on is accepted.
#[actix_rt::test]
async fn with_paths_off_and_two_tenants_turning_ssf_on_is_refused() {
    let w = world(2, false).await;
    let mut off = system_defaults();
    off.ssf_enabled = false;
    SurrealSettingsRepository::new(w.db.clone())
        .set_org_settings(w.org_id, off.clone())
        .await
        .unwrap();
    let app = app!(w.state(), w);
    let token = w.admin_token();
    let uri = format!("/api/v1/organizations/{}/settings", w.org_id);

    let mut on = off;
    on.ssf_enabled = true;
    let (status, body) = send(
        &app,
        request(Method::PUT, &uri, Some(&token)).set_json(serde_json::to_value(&on).unwrap()),
    )
    .await;
    assert_eq!(status, 400, "turning SSF on is refused");
    let message = json_of(&body)["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        message.contains("ssf_enabled"),
        "the message names the setting"
    );
    assert!(message.contains("D-55"), "and the cause");
    let stored = SurrealSettingsRepository::new(w.db.clone())
        .get_org_settings(w.org_id)
        .await
        .unwrap();
    assert!(!stored.oidc.ssf_enabled, "nothing was written");
}

/// A tenant may turn SSF off while the gate holds, and is refused (`400`,
/// naming the cause) when it turns it back on: the override path is gated like
/// the organization's.
#[actix_rt::test]
async fn with_paths_off_and_two_tenants_a_tenant_cannot_turn_ssf_back_on() {
    let w = world(2, false).await;
    let app = app!(w.state(), w);
    let token = w.admin_token();

    let (status, _) = send(
        &app,
        request(Method::PUT, "/api/v1/settings", Some(&token))
            .set_json(json!({"ssf_enabled": false})),
    )
    .await;
    assert_eq!(status, 200, "turning SSF off is never refused");

    let (status, body) = send(
        &app,
        request(Method::PUT, "/api/v1/settings", Some(&token))
            .set_json(json!({"ssf_enabled": true})),
    )
    .await;
    assert_eq!(status, 400, "turning it back on is refused");
    let message = json_of(&body)["message"]
        .as_str()
        .unwrap_or_default()
        .to_owned();
    assert!(
        message.contains("ssf_enabled") && message.contains("D-55"),
        "the message names the setting and the cause"
    );
    let effective = SurrealSettingsRepository::new(w.db.clone())
        .get_effective_settings(w.org_id, w.tenant_id)
        .await
        .unwrap();
    assert!(!effective.oidc.ssf_enabled, "the tenant stays off");
}

/// With one tenant the gate is open: turning SSF on is accepted and the
/// settings carry no inactive reason.
#[actix_rt::test]
async fn with_paths_off_and_one_tenant_turning_ssf_on_is_accepted() {
    let w = world(1, false).await;
    let mut off = system_defaults();
    off.ssf_enabled = false;
    SurrealSettingsRepository::new(w.db.clone())
        .set_org_settings(w.org_id, off.clone())
        .await
        .unwrap();
    let app = app!(w.state(), w);
    let mut on = off;
    on.ssf_enabled = true;
    let (status, body) = send(
        &app,
        request(
            Method::PUT,
            &format!("/api/v1/organizations/{}/settings", w.org_id),
            Some(&w.admin_token()),
        )
        .set_json(serde_json::to_value(&on).unwrap()),
    )
    .await;
    assert_eq!(status, 200, "one tenant: SSF may be turned on");
    let settings = json_of(&body);
    assert_eq!(settings["oidc"]["ssf_enabled"], true);
    assert!(settings["oidc"]["ssf_inactive_reason"].is_null());
}

/// `get` on a stream and the settings API say SSF is inactive and why; the
/// registry routes keep working.
#[actix_rt::test]
async fn with_paths_off_and_two_tenants_a_stream_and_the_settings_say_why() {
    let w = world(2, false).await;
    let stream = w.stream(SsfDeliveryMethod::Poll).await;
    let app = app!(w.state(), w);
    let token = w.admin_token();

    let (status, body) = send(
        &app,
        request(
            Method::GET,
            &format!("/api/v1/tenants/{}/ssf/streams/{}", w.tenant_id, stream.id),
            Some(&token),
        ),
    )
    .await;
    assert_eq!(status, 200, "the registry still answers");
    let view = json_of(&body);
    assert_eq!(view["transmitter_active"], false);
    assert!(
        view["transmitter_inactive_reason"]
            .as_str()
            .is_some_and(|r| r.contains("D-55")),
        "the stream says why"
    );

    let (status, body) = send(&app, request(Method::GET, "/api/v1/settings", Some(&token))).await;
    assert_eq!(status, 200);
    let settings = json_of(&body);
    assert_eq!(settings["oidc"]["ssf_enabled"], true);
    assert!(
        settings["oidc"]["ssf_inactive_reason"]
            .as_str()
            .is_some_and(|r| r.contains("D-55")),
        "the settings say why"
    );
}

// ---------------------------------------------------------------------------
// A second tenant created in this process stops SSF at once
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_second_tenant_created_in_process_stops_ssf_without_waiting_for_the_cache() {
    let w = world(1, false).await;
    w.stream(SsfDeliveryMethod::Push).await;
    let state = w.state();
    let app = app!(state.clone(), w);

    let (status, _) = send(
        &app,
        request(Method::GET, &discovery_uri(w.tenant_id), None),
    )
    .await;
    assert_eq!(status, 200, "one tenant: SSF works");
    w.emit(&state).await;
    let before = w.told();
    assert!(before > 0, "one tenant: an emission produces events");

    tenant_in(&w.db, w.org_id, "d55-late").await;

    let (status, _) = send(
        &app,
        request(Method::GET, &discovery_uri(w.tenant_id), None),
    )
    .await;
    assert_eq!(status, 404, "the second tenant stopped SSF at once");
    w.emit(&state).await;
    assert_eq!(w.told(), before, "and nothing more is produced");
}

// ---------------------------------------------------------------------------
// Paths on, two tenants: SSF works, and the issuers differ
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn with_paths_on_two_tenants_keep_ssf_and_their_own_issuers() {
    let w = world(2, true).await;
    let poll = w.stream(SsfDeliveryMethod::Poll).await;
    w.hold_one(&poll).await;
    w.stream(SsfDeliveryMethod::Push).await;
    let state = w.state();
    let app = app!(state.clone(), w);

    let ids = w.tenant_ids().await;
    let other = *ids.iter().find(|t| **t != w.tenant_id).unwrap();
    let mut issuers = Vec::new();
    for tenant in [w.tenant_id, other] {
        let (status, body) = send(
            &app,
            request(
                Method::GET,
                &format!("/.well-known/ssf-configuration/t/{tenant}"),
                None,
            ),
        )
        .await;
        assert_eq!(status, 200, "discovery");
        issuers.push(json_of(&body)["issuer"].as_str().unwrap().to_owned());
    }
    assert_ne!(issuers[0], issuers[1], "each tenant its own issuer");

    let token = w.receiver_token();
    let (status, body) = send(
        &app,
        request(
            Method::POST,
            &format!("/ssf/v1/poll/{}", poll.id),
            Some(&token),
        )
        .set_json(json!({"returnImmediately": true})),
    )
    .await;
    assert_eq!(status, 200, "a poll works");
    let sets = json_of(&body)["sets"]
        .as_object()
        .cloned()
        .unwrap_or_default();
    assert_eq!(sets.len(), 1);
    let set = sets.values().next().unwrap().as_str().unwrap();
    let header = jsonwebtoken::decode_header(set).unwrap();
    let jwks = axiam_oauth2::oidc::build_jwks(&w.auth.jwt_public_key_pem).unwrap();
    let jwk = jwks
        .keys
        .iter()
        .find(|k| Some(&k.kid) == header.kid.as_ref())
        .unwrap();
    let verifier = jsonwebtoken::DecodingKey::from_ed_components(&jwk.x).unwrap();
    let verify = |iss: &str| {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
        validation.required_spec_claims.clear();
        validation.validate_exp = false;
        validation.set_audience(&[poll.audience.as_str()]);
        validation.set_issuer(&[iss]);
        jsonwebtoken::decode::<Value>(set, &verifier, &validation).is_ok()
    };
    assert!(verify(&issuers[0]), "the SET verifies as its own tenant's");
    assert!(
        !verify(&issuers[1]),
        "and not as the other tenant's: the issuer differs"
    );

    w.emit(&state).await;
    assert!(w.told() > 0, "an emission produces events");
    for tenant_id in ids {
        assert!(w.audit_rows(tenant_id).await.is_empty(), "nothing audited");
    }
}

// ---------------------------------------------------------------------------
// No way around the gate in production code
// ---------------------------------------------------------------------------

/// Production code obtains the D-55 decision `sign_set` needs only from
/// `SsfIssuerGate::check`: `SharedIssuerCheck::evaluate` (the one constructor)
/// is called nowhere else outside `#[cfg(test)]` code, so no caller can state
/// "open" without the gate having read the deployment.
// `test` names actix's module here; the plain test attribute is spelled out.
#[::core::prelude::v1::test]
fn production_code_takes_the_issuer_check_only_from_the_gate() {
    let crates = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let mut files = Vec::new();
    let mut stack = vec![crates];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if path.is_dir() {
                if name != "target" && name != "tests" && name != "benches" {
                    stack.push(path);
                }
            } else if name.ends_with(".rs") && path.components().any(|c| c.as_os_str() == "src") {
                files.push(path);
            }
        }
    }
    assert!(files.len() > 50, "the workspace sources were found");
    let mut gate_file_seen = false;
    for path in files {
        let text = std::fs::read_to_string(&path).unwrap();
        // Production code ends where the file's test module begins.
        let production = text.split("#[cfg(test)]").next().unwrap_or_default();
        let calls = production.matches("SharedIssuerCheck::evaluate(").count();
        let shown = path.display().to_string();
        if shown.ends_with("axiam-oauth2/src/ssf.rs") {
            gate_file_seen = true;
            let check = production
                .find("pub async fn check(")
                .expect("SsfIssuerGate::check");
            let end = check
                + production[check..]
                    .find("fn note(")
                    .expect("the gate's next method");
            let inside = production[check..end]
                .matches("SharedIssuerCheck::evaluate(")
                .count();
            assert_eq!(
                calls, inside,
                "in {shown}, only SsfIssuerGate::check evaluates the gate"
            );
        } else {
            assert_eq!(calls, 0, "{shown} evaluates the D-55 gate itself");
        }
    }
    assert!(gate_file_seen, "the gate's own file was scanned");
}

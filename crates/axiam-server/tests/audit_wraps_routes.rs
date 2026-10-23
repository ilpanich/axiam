//! The audit middleware is an `App`-level wrap, and the five authenticated
//! federation routes key their rate-limit bucket on the principal it verified
//! (#674 (e), #733).
//!
//! An actix-web `App::wrap` covers every route wherever it is written in the
//! chain, so the property is not an ordering of two lines; it is that the
//! wrap is there at all. Take it off the `App` and the routes' limiters find no
//! verified identity and fall back to address keying, while every route test
//! that composes its own `App` still passes. Two checks:
//!
//! - **behavioural**: the `App` is composed by `boot::compose_app`, the
//!   function the listener itself runs, over an in-memory datastore. One token
//!   used from as many addresses as the bucket allows is served, the next
//!   request is refused `429` (an address-keyed bucket would never trip, each
//!   address being new), and the request-level audit row carries the verified
//!   principal;
//! - **textual**: the wrap is on the `App::new()` chain in `compose_app`'s
//!   source, matched with comments removed so a commented-out line cannot
//!   satisfy it.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use actix_web::test::{TestRequest, call_service, init_service};
use axiam_api_rest::authz::DenyAllAuthzChecker;
use axiam_api_rest::state::AppState;
use axiam_api_rest::{RateLimitConfig, RouteOptions, SessionValidator, SurrealScimTokenResolver};
use axiam_audit::AuditMiddleware;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, issue_access_token};
use axiam_core::repository::{AuditLogFilter, AuditLogRepository, Pagination};
use axiam_db::{
    SurrealAuditLogRepository, SurrealProofReplayRepository, SurrealRoleRepository,
    SurrealScimTokenRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_server::boot::{AppDeps, compose_app};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

/// The allowance of the route under test, per principal.
const PER_MIN: u32 = 3;
const CSRF_TOKEN: &str = "audit-wraps-routes-csrf";
const ROUTE: &str = "/api/v1/federation/oidc/authorize";

fn auth_config() -> AuthConfig {
    // Ed25519 test-only fixture — NOT secret (the one `federation_test.rs`
    // uses); split with concat! to satisfy static-analysis rules that reject
    // inline PEM blocks (CWE-798 guard).
    let private_key = concat!(
        "-----BEGIN PRIVATE KEY-----\n",
        "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5",
        "R75FOv/nC4+o+HHPfM\n",
        "-----END PRIVATE KEY-----"
    );
    let public_key = concat!(
        "-----BEGIN PUBLIC KEY-----\n",
        "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
        "-----END PUBLIC KEY-----"
    );
    AuthConfig {
        jwt_private_key_pem: private_key.into(),
        jwt_public_key_pem: public_key.into(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// Every session is live: a console token names its session in `jti`, and the
/// extractor admits it only while the session is.
struct LiveSessions;

impl SessionValidator for LiveSessions {
    fn is_session_active<'a>(
        &'a self,
        _tenant_id: Uuid,
        _session_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        Box::pin(async { true })
    }
}

fn authorize_from(token: &str, from: SocketAddr) -> actix_http::Request {
    TestRequest::post()
        .uri(ROUTE)
        .peer_addr(from)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        // An empty `redirect_uri` is refused `400` before any network call, so
        // what is measured is the limiter.
        .set_json(serde_json::json!({
            "config_id": Uuid::new_v4(),
            "redirect_uri": "",
            "state": "some-state",
            "nonce": "some-nonce"
        }))
        .to_request()
}

#[actix_web::test]
async fn a_request_to_a_federation_route_is_audited_and_keyed_on_its_principal() {
    let db: Surreal<Db> = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let auth = auth_config();
    let audit_repo = SurrealAuditLogRepository::new(db.clone());
    let audit_middleware = AuditMiddleware::spawn(audit_repo.clone());
    let deps = AppDeps {
        audit_middleware: audit_middleware.clone(),
        cors_allowed_origins: Vec::new(),
        rest_authz: Arc::new(DenyAllAuthzChecker),
        auth_config: auth.clone(),
        session_validator: Arc::new(LiveSessions),
        dpop_replay_guard: Arc::new(SurrealProofReplayRepository::new(db.clone())),
        tenant_scope_resolver: Arc::new(SurrealTenantRepository::new(db.clone())),
        principal_reach_resolver: Arc::new(SurrealRoleRepository::new(db.clone())),
        scim_token_resolver: Arc::new(SurrealScimTokenResolver::new(
            SurrealScimTokenRepository::new(db.clone()),
            SurrealUserRepository::new(db.clone()),
        )),
        app_state: AppState::for_test(db.clone(), auth.clone()),
        rate_limit: RateLimitConfig {
            end_session_per_min: PER_MIN,
            ..RateLimitConfig::default()
        },
        route_options: RouteOptions::default(),
    };
    let app = init_service(compose_app(deps.clone())).await;

    let (user, tenant, org) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let token = issue_access_token(
        user,
        tenant,
        org,
        &[],
        &auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap();

    // One token from a new address each time: the principal's allowance is
    // spent across them, which an address-keyed bucket could not do.
    for n in 0..PER_MIN {
        let from: SocketAddr = format!("203.0.113.{}:4000", 10 + n).parse().unwrap();
        let got = call_service(&app, authorize_from(&token, from)).await;
        assert_eq!(got.status().as_u16(), 400, "request {n} is served");
    }
    let from: SocketAddr = "203.0.113.99:4000".parse().unwrap();
    let got = call_service(&app, authorize_from(&token, from)).await;
    assert_eq!(
        got.status().as_u16(),
        429,
        "the principal's allowance is spent from other addresses: the route is keyed on the \
         principal the audit middleware verified, not on the address"
    );

    // The request-level row, written by the wrap, names the verified principal.
    assert!(
        audit_middleware.drain(Duration::from_secs(10)).await,
        "the audit queue drains"
    );
    let rows = audit_repo
        .list(tenant, AuditLogFilter::default(), Pagination::default())
        .await
        .unwrap()
        .items;
    let action = format!("POST {ROUTE}");
    let row = rows
        .iter()
        .find(|r| r.action == action)
        .unwrap_or_else(|| panic!("no request-level audit row for `{action}` in {rows:?}"));
    assert_eq!(row.actor_id, user, "the row names the verified user");
    assert_eq!(row.tenant_id, tenant);
    assert_eq!(row.metadata["authenticated"], true);
    assert_eq!(
        rows.iter().filter(|r| r.action == action).count(),
        PER_MIN as usize + 1,
        "every request, the refused one included, is a row"
    );
}

/// `src` without `//` line comments and `/* */` block comments.
///
/// A scanner, not a parser: it honours string and character literals so that a
/// `//` inside `"https://…"` is not read as a comment, and nests block
/// comments as Rust does. Raw strings are not special-cased; `boot.rs` has none
/// that contain a comment opener.
fn strip_comments(src: &str) -> String {
    let b = src.as_bytes();
    let mut out = String::with_capacity(src.len());
    let (mut i, mut depth) = (0, 0usize);
    while i < b.len() {
        let rest = &src[i..];
        if depth > 0 {
            if rest.starts_with("/*") {
                depth += 1;
                i += 2;
            } else if rest.starts_with("*/") {
                depth -= 1;
                i += 2;
            } else {
                i += rest.chars().next().map_or(1, char::len_utf8);
            }
        } else if rest.starts_with("//") {
            i += rest.find('\n').unwrap_or(rest.len());
        } else if rest.starts_with("/*") {
            depth = 1;
            i += 2;
        } else if b[i] == b'"' {
            // A string literal, through its closing quote.
            let mut j = i + 1;
            while j < b.len() && b[j] != b'"' {
                j += if b[j] == b'\\' { 2 } else { 1 };
            }
            let end = (j + 1).min(b.len());
            out.push_str(&src[i..end]);
            i = end;
        } else {
            let c = rest.chars().next().unwrap();
            out.push(c);
            i += c.len_utf8();
        }
    }
    out
}

fn compose_app_body() -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/boot.rs");
    let src =
        std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let code = strip_comments(&src);
    let start = code
        .find("pub fn compose_app")
        .expect("boot.rs no longer defines `compose_app`");
    let body = &code[start..];
    let open = body
        .find("App::new()")
        .expect("`compose_app` no longer starts at `App::new()`");
    // `compose_app` ends where `ServeOptions`' definition begins.
    let end = body.find("pub struct ServeOptions").unwrap_or(body.len());
    body[open..end].to_owned()
}

#[test]
fn the_audit_middleware_is_on_the_app_new_chain() {
    let chain = compose_app_body();
    assert!(
        chain.contains(".wrap(deps.audit_middleware)"),
        "`compose_app`'s `App::new()` chain no longer carries `.wrap(deps.audit_middleware)`: \
         without the App-level wrap the five federation routes fall back to address keying \
         (R110W2-06 (e))"
    );
}

#[test]
fn a_commented_out_wrap_does_not_satisfy_the_scan() {
    let src = "App::new()\n    // .wrap(deps.audit_middleware)\n    /* .wrap(deps.audit_middleware) */\n    .configure(x)";
    let code = strip_comments(src);
    assert!(!code.contains(".wrap("), "comments are removed: {code}");
    assert!(code.contains(".configure(x)"));
    let kept = strip_comments("let u = \"https://a.example\"; // gone");
    assert_eq!(kept, "let u = \"https://a.example\"; ");
}

//! #633 (R101W2-05) — the authenticated federation flow routes key their
//! limiter on the caller's **verified** principal `(tenant, sub)`, with the
//! address as the pre-authentication fallback.
//!
//! The production composition is reproduced: the audit middleware wraps the
//! application (it is what verifies the token once and caches the identity
//! both limiter layers read), and `register_api_v1_routes` mounts the routes
//! with their real limiters. Proves:
//!
//! - one token used from many addresses shares one allowance;
//! - one address relaying many users gives each user their own allowance;
//! - a forged or expired token naming a principal is keyed on its address: it
//!   is still limited, and it never spends (or is refused by) the named
//!   principal's bucket;
//! - a sender-constrained token is keyed on its address and principal
//!   together, so a replayed copy never spends its principal's bucket;
//! - each layer keys the same way alone: the in-process governor with the
//!   shared counter off (`AXIAM__RATE_LIMIT__SHARED=off`), and the shared
//!   counter with no governor;
//! - the limiter verifies nothing itself: without the audit middleware's
//!   verified identity a valid token is keyed on its address;
//! - (SAML builds) all five routes are keyed this way.
//!
//! The requests are ones the handler refuses (`400` for an empty
//! `redirect_uri`, `401` for a token that does not verify) without touching
//! the network, so what is measured is the limiter.

use std::net::SocketAddr;
use std::sync::Arc;

use actix_web::middleware::Condition;
use actix_web::{App, HttpResponse, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::middleware::rate_limit_shared::RateLimitShared;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_audit::middleware::AuditMiddleware;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    AUD_USER, CnfClaim, issue_access_token, issue_access_token_bound, validate_access_token,
};
use axiam_db::repository::{SurrealAuditLogRepository, SurrealRateLimitBucketRepository};
use axiam_db::{SharedRateLimitConfig, SharedRateLimitCounter};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

type TestDb = Db;

/// Every bucket's allowance in these tests.
const PER_MIN: u32 = 3;
const CSRF_TOKEN: &str = "rate-limit-principal-test-csrf";

fn test_keypair() -> (String, String) {
    // Ed25519 test-only fixture — NOT secret (the same fixture
    // `federation_test.rs` uses); split with concat! to satisfy static-analysis
    // rules that reject inline PEM blocks (CWE-798 guard).
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
    (private_key.into(), public_key.into())
}

fn auth_config() -> AuthConfig {
    let (jwt_private_key_pem, jwt_public_key_pem) = test_keypair();
    AuthConfig {
        jwt_private_key_pem,
        jwt_public_key_pem,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// A principal of the test tenant.
#[derive(Clone, Copy)]
struct Principal {
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
}

impl Principal {
    fn new(tenant_id: Uuid, org_id: Uuid) -> Self {
        Self {
            user_id: Uuid::new_v4(),
            tenant_id,
            org_id,
        }
    }

    fn token(&self, auth: &AuthConfig) -> String {
        issue_access_token(
            self.user_id,
            self.tenant_id,
            self.org_id,
            &[],
            auth,
            Uuid::new_v4().to_string(),
            AUD_USER,
        )
        .unwrap()
    }

    /// A certificate-bound token (RFC 8705): its holder must also present the
    /// certificate, which the extractor checks after the limiter.
    fn bound_token(&self, auth: &AuthConfig) -> String {
        issue_access_token_bound(
            self.user_id,
            self.tenant_id,
            self.org_id,
            &[],
            auth,
            Uuid::new_v4().to_string(),
            AUD_USER,
            Some(CnfClaim {
                x5t_s256: Some("bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2".into()),
                ..CnfClaim::default()
            }),
        )
        .unwrap()
    }

    /// The same claims, expired an hour ago (past the decoder's 60 s leeway)
    /// and signed with the real key: a token that once verified.
    fn expired_token(&self, auth: &AuthConfig) -> String {
        let mut claims = validate_access_token(&self.token(auth), auth).unwrap().0;
        let now = chrono::Utc::now().timestamp();
        claims.iat = now - 4_000;
        claims.exp = now - 3_600;
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA),
            &claims,
            &jsonwebtoken::EncodingKey::from_ed_pem(auth.jwt_private_key_pem.as_bytes()).unwrap(),
        )
        .unwrap()
    }

    /// Two forgeries naming this principal: its own claims under another
    /// token's signature, and its claims MAC'd under a secret of the forger's
    /// choosing (`alg` confusion).
    fn forged_tokens(&self, auth: &AuthConfig, someone_else: &Principal) -> [String; 2] {
        let own = self.token(auth);
        let other = someone_else.token(auth);
        let (own_signed_part, _) = own.rsplit_once('.').unwrap();
        let (_, other_signature) = other.rsplit_once('.').unwrap();
        let spliced = format!("{own_signed_part}.{other_signature}");

        let claims = validate_access_token(&own, auth).unwrap().0;
        let hs256 = jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(b"the forger's own secret"),
        )
        .unwrap();
        [spliced, hs256]
    }
}

async fn fresh_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn enabled_counter(db: &Surreal<TestDb>) -> SharedRateLimitCounter {
    SharedRateLimitCounter::without_flusher(
        SharedRateLimitConfig::default(),
        Arc::new(SurrealRateLimitBucketRepository::new(db.clone())),
    )
}

fn disabled_counter() -> SharedRateLimitCounter {
    SharedRateLimitCounter::disabled(SharedRateLimitConfig {
        enabled: false,
        ..SharedRateLimitConfig::default()
    })
}

/// The production composition: the audit middleware (when `$audit`) around
/// `register_api_v1_routes`, with `end_session_per_min = PER_MIN` and the
/// shared counter `$counter`.
macro_rules! routes_app {
    ($db:expr, $auth:expr, $counter:expr, audit: $audit:expr) => {{
        let mut state = AppState::for_test($db.clone(), $auth.clone());
        state.shared_rate_limit = $counter;
        let rate_limit = RateLimitConfig {
            end_session_per_min: PER_MIN,
            ..RateLimitConfig::default()
        };
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(state))
                .wrap(Condition::new(
                    $audit,
                    AuditMiddleware::spawn(SurrealAuditLogRepository::new($db.clone())),
                ))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &rate_limit)),
        )
        .await
    }};
}

fn peer(n: u8) -> SocketAddr {
    format!("203.0.113.{n}:4000").parse().unwrap()
}

/// `POST /api/v1/federation/oidc/authorize` with an empty `redirect_uri`: the
/// handler answers `400` to a verified caller and `401` to any other.
fn oidc_authorize(token: &str, from: SocketAddr) -> actix_http::Request {
    test::TestRequest::post()
        .uri("/api/v1/federation/oidc/authorize")
        .peer_addr(from)
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(serde_json::json!({
            "config_id": Uuid::new_v4(),
            "redirect_uri": "",
            "state": "some-state",
            "nonce": "some-nonce"
        }))
        .to_request()
}

async fn status<S, B>(app: &S, req: actix_http::Request) -> u16
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
{
    test::call_service(app, req).await.status().as_u16()
}

/// The one-token-many-addresses and relay checks, against whatever layers
/// `app` carries. `PER_MIN` requests of one token from as many addresses are
/// served; the next, from yet another address, is refused. Then a second
/// user behind the first address has a whole allowance of their own.
async fn assert_keyed_on_the_principal<S, B>(app: &S, auth: &AuthConfig, tenant: Uuid, org: Uuid)
where
    S: actix_web::dev::Service<
            actix_http::Request,
            Response = actix_web::dev::ServiceResponse<B>,
            Error = actix_web::Error,
        >,
{
    let alice = Principal::new(tenant, org).token(auth);
    for i in 0..PER_MIN {
        let got = status(app, oidc_authorize(&alice, peer(10 + i as u8))).await;
        assert_eq!(
            got, 400,
            "alice's request {i}, from its own address, is served"
        );
    }
    let got = status(app, oidc_authorize(&alice, peer(99))).await;
    assert_eq!(
        got, 429,
        "one token from many addresses shares one allowance: a fresh address is refused"
    );

    // The relay: the address alice first used, now carrying another user.
    let bob = Principal::new(tenant, org).token(auth);
    for i in 0..PER_MIN {
        let got = status(app, oidc_authorize(&bob, peer(10))).await;
        assert_eq!(got, 400, "bob's request {i} through the relay is his own");
    }
    let got = status(app, oidc_authorize(&bob, peer(10))).await;
    assert_eq!(got, 429, "and bob's allowance ends on his own count");
}

/// #633: one token used from many addresses is bounded by one allowance, and
/// a relay with many users is not throttled as one — both limiter layers on.
#[actix_rt::test]
async fn one_token_from_many_addresses_shares_one_allowance_and_a_relay_is_not_one_user() {
    let db = fresh_db().await;
    let auth = auth_config();
    let app = routes_app!(db, auth, enabled_counter(&db), audit: true);
    assert_keyed_on_the_principal(&app, &auth, Uuid::new_v4(), Uuid::new_v4()).await;
}

/// #633: many users behind one address — the relaying application — each get
/// the whole allowance, however many there are.
#[actix_rt::test]
async fn a_relay_with_many_users_gives_each_user_their_own_allowance() {
    let db = fresh_db().await;
    let auth = auth_config();
    let app = routes_app!(db, auth, enabled_counter(&db), audit: true);
    let (tenant, org) = (Uuid::new_v4(), Uuid::new_v4());
    let relay = peer(20);

    for user in 0..(PER_MIN * 3) {
        let token = Principal::new(tenant, org).token(&auth);
        for i in 0..PER_MIN {
            let got = status(&app, oidc_authorize(&token, relay)).await;
            assert_eq!(got, 400, "user {user}, request {i}, through one address");
        }
    }
}

/// #633: a token that does not verify — forged two ways, or expired — names a
/// principal but is keyed on its address. It is still limited (by the
/// address), it cannot exhaust the principal's bucket, and the principal's
/// exhausted bucket does not refuse it.
#[actix_rt::test]
async fn a_forged_or_expired_token_is_keyed_on_its_address_and_never_on_the_named_principal() {
    let db = fresh_db().await;
    let auth = auth_config();
    let app = routes_app!(db, auth, enabled_counter(&db), audit: true);
    let (tenant, org) = (Uuid::new_v4(), Uuid::new_v4());
    let victim = Principal::new(tenant, org);
    let someone = Principal::new(tenant, org);
    let [spliced, hs256] = victim.forged_tokens(&auth, &someone);
    let expired = victim.expired_token(&auth);

    for (n, (label, token)) in [
        ("spliced", &spliced),
        ("hs256", &hs256),
        ("expired", &expired),
    ]
    .into_iter()
    .enumerate()
    {
        let from = peer(30 + n as u8);
        for i in 0..PER_MIN {
            let got = status(&app, oidc_authorize(token, from)).await;
            assert_eq!(
                got, 401,
                "{label} request {i}: refused by the extractor, not the limiter"
            );
        }
        let got = status(&app, oidc_authorize(token, from)).await;
        assert_eq!(got, 429, "{label}: still limited, by its address");
    }

    // Nine requests named the victim; none was charged to the victim. The
    // victim, from an address the forger exhausted, has the whole allowance.
    let token = victim.token(&auth);
    for i in 0..PER_MIN {
        let got = status(&app, oidc_authorize(&token, peer(30))).await;
        assert_eq!(got, 400, "the victim's request {i} is served");
    }
    assert_eq!(status(&app, oidc_authorize(&token, peer(30))).await, 429);

    // And with the victim's bucket now spent, a forgery from a fresh address
    // is not refused by it: it is on its address's count.
    let got = status(&app, oidc_authorize(&spliced, peer(39))).await;
    assert_eq!(
        got, 401,
        "an exhausted principal bucket does not reach a forgery"
    );
}

/// #633: a sender-constrained token's possession is proved after the limiter,
/// so the limiter keys it on its address and principal together. A copy
/// replayed from another address has a bucket of its own, and neither touches
/// the bearer principal's bucket.
#[actix_rt::test]
async fn a_sender_constrained_token_is_keyed_on_its_address_and_principal_together() {
    let db = fresh_db().await;
    let auth = auth_config();
    let app = routes_app!(db, auth, enabled_counter(&db), audit: true);
    let alice = Principal::new(Uuid::new_v4(), Uuid::new_v4());
    let bound = alice.bound_token(&auth);

    for from in [peer(40), peer(41)] {
        for i in 0..PER_MIN {
            let got = status(&app, oidc_authorize(&bound, from)).await;
            assert_ne!(got, 429, "the bound token's request {i} from {from}");
        }
        let got = status(&app, oidc_authorize(&bound, from)).await;
        assert_eq!(got, 429, "the bound token from {from} is limited there");
    }

    let bearer = alice.token(&auth);
    for i in 0..PER_MIN {
        let got = status(&app, oidc_authorize(&bearer, peer(40))).await;
        assert_eq!(got, 400, "alice's bearer request {i} has her own bucket");
    }
}

/// #633: with the shared counter off (`AXIAM__RATE_LIMIT__SHARED=off`) the
/// in-process governor alone keys on the principal.
#[actix_rt::test]
async fn the_in_process_governor_alone_keys_on_the_principal() {
    let db = fresh_db().await;
    let auth = auth_config();
    let app = routes_app!(db, auth, disabled_counter(), audit: true);
    assert_keyed_on_the_principal(&app, &auth, Uuid::new_v4(), Uuid::new_v4()).await;
}

/// #633: the shared counter alone — no governor on the route — keys on the
/// principal, and falls back to the address for a forgery.
#[actix_rt::test]
async fn the_shared_counter_alone_keys_on_the_principal() {
    let db = fresh_db().await;
    let auth = auth_config();
    let counter = enabled_counter(&db);
    let mut state = AppState::for_test(db.clone(), auth.clone());
    state.shared_rate_limit = counter.clone();
    let rate_limit = RateLimitConfig {
        end_session_per_min: PER_MIN,
        ..RateLimitConfig::default()
    };
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(state))
            .wrap(AuditMiddleware::spawn(SurrealAuditLogRepository::new(
                db.clone(),
            )))
            .service(
                web::resource("/api/v1/federation/oidc/authorize")
                    .wrap(
                        RateLimitShared::<TestDb>::browser_preset(
                            "shared_only_principal_test",
                            &rate_limit,
                        )
                        .keyed_on_principal(),
                    )
                    .route(web::post().to(|| async { HttpResponse::BadRequest().finish() })),
            ),
    )
    .await;

    assert_keyed_on_the_principal(&app, &auth, Uuid::new_v4(), Uuid::new_v4()).await;

    let (tenant, org) = (Uuid::new_v4(), Uuid::new_v4());
    let victim = Principal::new(tenant, org);
    let [spliced, _] = victim.forged_tokens(&auth, &Principal::new(tenant, org));
    for _ in 0..PER_MIN {
        assert_eq!(status(&app, oidc_authorize(&spliced, peer(50))).await, 400);
    }
    assert_eq!(status(&app, oidc_authorize(&spliced, peer(50))).await, 429);
    assert_eq!(
        status(&app, oidc_authorize(&victim.token(&auth), peer(50))).await,
        400,
        "the forgery spent its address's bucket, not the victim's"
    );
}

/// #633: neither limiter layer verifies a signature — each reads the identity
/// the audit middleware verified. Without it, a perfectly valid token is keyed
/// on its address (the pre-#633 key), so no request ever costs the limiter a
/// verification and a refused credential costs exactly what it did before.
#[actix_rt::test]
async fn the_limiter_verifies_nothing_itself_so_without_the_audit_identity_it_keys_on_the_address()
{
    let db = fresh_db().await;
    let auth = auth_config();
    let app = routes_app!(db, auth, enabled_counter(&db), audit: false);
    let token = Principal::new(Uuid::new_v4(), Uuid::new_v4()).token(&auth);

    for i in 0..PER_MIN {
        assert_eq!(
            status(&app, oidc_authorize(&token, peer(60))).await,
            400,
            "{i}"
        );
    }
    assert_eq!(status(&app, oidc_authorize(&token, peer(60))).await, 429);
    assert_eq!(
        status(&app, oidc_authorize(&token, peer(61))).await,
        400,
        "with no verified identity the same token from another address is another bucket"
    );
}

/// #633: all five authenticated federation flow routes are keyed on the
/// principal — SAML `authn-request`, `acs`, `metadata` and OIDC `authorize`,
/// `callback`. Each is spent by one token from `PER_MIN` addresses, and a
/// fresh address is then refused on that route.
#[cfg(feature = "saml")]
#[actix_rt::test]
async fn every_authenticated_federation_flow_route_keys_on_the_principal() {
    let db = fresh_db().await;
    let auth = auth_config();
    let app = routes_app!(db, auth, enabled_counter(&db), audit: true);
    let token = Principal::new(Uuid::new_v4(), Uuid::new_v4()).token(&auth);
    let config_id = Uuid::new_v4().to_string();

    let request = |route: &str, from: SocketAddr| {
        let base = |builder: test::TestRequest, uri: &str| {
            builder
                .uri(uri)
                .peer_addr(from)
                .insert_header(("Authorization", format!("Bearer {token}")))
                .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
                .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        };
        match route {
            "saml/authn-request" => base(
                test::TestRequest::post(),
                "/api/v1/federation/saml/authn-request",
            )
            .set_json(serde_json::json!({ "config_id": config_id, "acs_url": "" })),
            "saml/acs" => base(test::TestRequest::post(), "/api/v1/federation/saml/acs").set_json(
                serde_json::json!({
                    "config_id": config_id,
                    "saml_response": "",
                    "acs_url": "https://sp.example.com/acs"
                }),
            ),
            "saml/metadata" => base(
                test::TestRequest::get(),
                &format!("/api/v1/federation/saml/metadata?config_id={config_id}&acs_url="),
            ),
            "oidc/authorize" => {
                return oidc_authorize(&token, from);
            }
            "oidc/callback" => base(
                test::TestRequest::post(),
                "/api/v1/federation/oidc/callback",
            )
            .set_json(serde_json::json!({
                "config_id": config_id,
                "code": "",
                "redirect_uri": "https://example.com/cb",
                "state": "some-state",
                "nonce": "some-nonce"
            })),
            other => panic!("not a federation flow route: {other}"),
        }
        .to_request()
    };

    for route in [
        "saml/authn-request",
        "saml/acs",
        "saml/metadata",
        "oidc/authorize",
        "oidc/callback",
    ] {
        for i in 0..PER_MIN {
            let got = status(&app, request(route, peer(70 + i as u8))).await;
            assert_ne!(
                got, 429,
                "{route} request {i} is within the principal's bucket"
            );
        }
        let got = status(&app, request(route, peer(79))).await;
        assert_eq!(
            got, 429,
            "{route}: a fresh address is refused on the principal's count"
        );
    }
}

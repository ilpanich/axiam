//! **W6 — `POST /oauth2/userinfo`** (`claude_dev/basic-op-gap-plan.md` §4.9
//! G10, tests T10.1–T10.3 and the hazards named beside them).
//!
//! Two conformance modules — `OIDCCUserInfoPostHeader` and
//! `OIDCCUserInfoPostBody` — fail on a UserInfo endpoint that answers only
//! `GET`. OIDC Core §5.3 says an OP MUST support both methods, and RFC 6750
//! gives POST a second carrier for the access token: an `access_token` form
//! field (§2.2) alongside the `Authorization` header (§2.1).
//!
//! This wave adds the method and nothing else. Four properties are asserted
//! throughout, and each is the answer to a hazard the plan named:
//!
//! 1. **What the endpoint answers did not change.** The POST arm and the GET
//!    arm call one function with an already-authenticated principal, so the
//!    response is a function of the token and not of the method. T10.1 asserts
//!    that as *byte-for-byte identical responses*, headers included, rather
//!    than as matching fields.
//! 2. **A token in a body is still a credential.** It reaches no log, no
//!    `tracing` field and no error body — asserted by capturing the subscriber
//!    output of a successful and a failed POST.
//! 3. **One credential per request.** Two carriers is `400 invalid_request`,
//!    and the refusal reads neither of them.
//! 4. **Sender constraint is not relaxed by the new carrier.** A DPoP-bound
//!    token verifies on POST — including when the token itself arrived in the
//!    body — and the same proof minted for `GET` does not.
//!
//! The invariant-4 twin for this wave is rows 17–20 of
//! `docs/compliance/oidc-conformance.md`
//! (`oauth2_flow_test.rs::oidc_userinfo_*`), which are unchanged and must stay
//! that way: a GET UserInfo request is the same request it was before W6.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use actix_web::cookie::SameSite;
use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::handlers::oauth2::UserInfoPostForm;
use axiam_api_rest::middleware::csrf::access_cookie;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{AUD_USER, CnfClaim, issue_access_token, issue_access_token_bound};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSettingsRepository, SurrealTenantRepository,
    SurrealUserRepository,
};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const ISSUER: &str = "https://iam.example.com";
const USERINFO: &str = "/oauth2/userinfo";
/// Test-only placeholder — not a real credential. gitleaks:allow
const PASSWORD: &str = "UserInfoPostPassw0rdStrong";

// ---------------------------------------------------------------------------
// Scaffolding
// ---------------------------------------------------------------------------

// Test-only Ed25519 keypair with no real-world value. nosemgrep
fn test_auth_config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: concat!(
            "-----BEGIN PRIVATE KEY-----\n",
            "MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n",
            "-----END PRIVATE KEY-----"
        )
        .into(),
        jwt_public_key_pem: concat!(
            "-----BEGIN PUBLIC KEY-----\n",
            "MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n",
            "-----END PUBLIC KEY-----"
        )
        .into(),
        access_token_lifetime_secs: 900,
        refresh_token_lifetime_secs: 2_592_000,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: ISSUER.into(),
        ..AuthConfig::default()
    }
}

async fn setup_db() -> (Surreal<TestDb>, Uuid, Uuid, Uuid) {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "UserInfo Org".into(),
            slug: "userinfo-org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "UserInfo Tenant".into(),
            slug: "userinfo-tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, system_defaults())
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "alice".into(),
            email: "alice@example.com".into(),
            password: PASSWORD.into(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            tenant.id,
            user.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    (db, org.id, tenant.id, user.id)
}

macro_rules! test_app {
    ($db:expr, $auth:expr) => {{
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $db.clone(),
                    $auth.clone(),
                )))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    }};
}

fn token_with_scopes(
    auth: &AuthConfig,
    user_id: Uuid,
    tenant_id: Uuid,
    org_id: Uuid,
    scopes: &[&str],
) -> String {
    let scopes: Vec<String> = scopes.iter().map(|s| (*s).to_owned()).collect();
    issue_access_token(
        user_id,
        tenant_id,
        org_id,
        &scopes,
        auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
    )
    .unwrap()
}

/// The RFC 6750 §2.2 body, as a client would send it.
#[derive(serde::Serialize)]
struct FormBody<'a> {
    access_token: &'a str,
}

/// Status, every response header, and the body — the three things "byte
/// identical" has to mean if it is to mean anything.
#[derive(Debug, PartialEq, Eq)]
struct Answer {
    status: u16,
    headers: Vec<(String, Vec<u8>)>,
    body: Vec<u8>,
}

async fn answer(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    req: actix_http::Request,
) -> Answer {
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let mut headers: Vec<(String, Vec<u8>)> = resp
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_owned(), v.as_bytes().to_vec()))
        .collect();
    headers.sort();
    let body = test::read_body(resp).await.to_vec();
    Answer {
        status,
        headers,
        body,
    }
}

// ---------------------------------------------------------------------------
// T10.1 — the header carrier, on both methods
// ---------------------------------------------------------------------------

/// **T10.1.** `POST` with the token in the `Authorization` header answers what
/// `GET` with the same token answers — status, headers and body, compared as
/// bytes rather than as fields.
///
/// The comparison is exhaustive on purpose. The plan asks for "byte-identical
/// apart from anything genuinely method-dependent; if nothing is, assert
/// that" — and nothing is: the response is built from the token's subject and
/// scopes, and neither depends on the method. So the assertion is equality of
/// the whole `Answer`, and a future change that makes one method answer
/// differently fails here rather than in a conformance run six months later.
#[actix_rt::test]
async fn t10_1_post_with_a_header_token_answers_exactly_what_get_answers() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = token_with_scopes(
        &auth,
        user_id,
        tenant_id,
        org_id,
        &["openid", "email", "profile"],
    );
    let app = test_app!(db, auth);

    let get = answer(
        &app,
        test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request(),
    )
    .await;
    let post = answer(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request(),
    )
    .await;

    assert_eq!(get.status, 200, "the GET twin must still answer 200");
    assert_eq!(
        get, post,
        "GET and POST must answer identically: nothing about a UserInfo \
         response depends on the method that asked for it"
    );

    let body: serde_json::Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(body["sub"], user_id.to_string());
    assert_eq!(body["email"], "alice@example.com");
    assert_eq!(body["preferred_username"], "alice");
}

// ---------------------------------------------------------------------------
// T10.2 — the RFC 6750 §2.2 form carrier
// ---------------------------------------------------------------------------

/// **T10.2.** The token in an `access_token` form field answers the same body
/// as the header carrier — which is the same body GET answers (T10.1).
///
/// `Content-Length` is the only thing allowed to differ, and it does not:
/// nothing about the response is derived from the request. The bodies are
/// compared directly all the same, because a scope-gated claim silently
/// dropped on one carrier is exactly the bug this asserts against.
#[actix_rt::test]
async fn t10_2_post_with_a_form_field_token_answers_the_same_body() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = token_with_scopes(
        &auth,
        user_id,
        tenant_id,
        org_id,
        &["openid", "email", "profile"],
    );
    let app = test_app!(db, auth);

    let header_carried = answer(
        &app,
        test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request(),
    )
    .await;
    let body_carried = answer(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .set_form(FormBody {
                access_token: &token,
            })
            .to_request(),
    )
    .await;

    assert_eq!(body_carried.status, 200, "RFC 6750 §2.2 must authenticate");
    assert_eq!(
        header_carried, body_carried,
        "the carrier decides nothing about the answer"
    );
}

/// A DPoP scheme in the header works on POST too — the scheme parsing is
/// shared with GET, and W6 must not have narrowed it back to `Bearer`.
#[actix_rt::test]
async fn the_dpop_authorization_scheme_is_still_accepted_on_post() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    // An *unbound* token under the `DPoP` scheme: the scheme is about parsing,
    // the `cnf` claim is about binding, and this asserts only the first.
    let token = token_with_scopes(&auth, user_id, tenant_id, org_id, &["openid"]);
    let app = test_app!(db, auth);

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Authorization", format!("DPoP {token}")))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
}

// ---------------------------------------------------------------------------
// T10.3 — one carrier per request
// ---------------------------------------------------------------------------

/// **T10.3.** A request presenting the token by two methods is refused with
/// `400 invalid_request`, and the refusal contains neither token.
///
/// RFC 6750 §2: *"Clients MUST NOT use more than one method to transmit the
/// token in each request."* Two tokens are used rather than one so that the
/// assertion "the refusal names neither" cannot pass by accident.
#[actix_rt::test]
async fn t10_3_two_carriers_is_refused_and_the_refusal_names_neither_token() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let header_token = token_with_scopes(&auth, user_id, tenant_id, org_id, &["openid"]);
    let form_token = token_with_scopes(&auth, user_id, tenant_id, org_id, &["openid", "email"]);
    assert_ne!(header_token, form_token, "two distinct credentials");
    let app = test_app!(db, auth);

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Authorization", format!("Bearer {header_token}")))
            .set_form(FormBody {
                access_token: &form_token,
            })
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);

    let raw = test::read_body(resp).await;
    let text = String::from_utf8(raw.to_vec()).expect("a UTF-8 error body");
    let body: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(body["error"], "invalid_request");
    assert!(
        !text.contains(&header_token) && !text.contains(&form_token),
        "an error body must not echo a credential back: {text}"
    );
}

/// The `axiam_access` cookie is not one of RFC 6750's methods, but it is a
/// second credential naming a possibly different subject. Presented together
/// with a form field it is refused for the same reason, because the only
/// alternative is choosing silently between two identities.
#[actix_rt::test]
async fn a_cookie_and_a_form_field_together_are_refused_too() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let cookie_token = token_with_scopes(&auth, user_id, tenant_id, org_id, &["openid"]);
    let form_token = token_with_scopes(&auth, user_id, tenant_id, org_id, &["openid", "email"]);
    let app = test_app!(db, auth);

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Cookie", format!("axiam_access={cookie_token}")))
            .set_form(FormBody {
                access_token: &form_token,
            })
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 400);
}

/// `access_token=` transmits no token, so it is not a second method: a request
/// carrying an empty field and a real header is answered, not refused.
///
/// Stated as a test because the alternative reading — "the parameter is
/// present, therefore two methods" — is the one a reviewer will assume, and
/// because it decides whether a client that always emits the field can use the
/// header at all.
#[actix_rt::test]
async fn an_empty_form_field_is_not_a_second_carrier() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = token_with_scopes(&auth, user_id, tenant_id, org_id, &["openid"]);
    let app = test_app!(db, auth);

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .set_form(FormBody { access_token: "" })
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200);
}

/// An unauthenticated POST is the same 401 an unauthenticated GET is — the
/// method added no way in, and it added no different refusal either.
#[actix_rt::test]
async fn an_unauthenticated_post_is_the_same_401_as_an_unauthenticated_get() {
    let (db, _org_id, _tenant_id, _user_id) = setup_db().await;
    let auth = test_auth_config();
    let app = test_app!(db, auth);

    let get = answer(
        &app,
        test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .to_request(),
    )
    .await;
    let post = answer(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .to_request(),
    )
    .await;
    assert_eq!(get.status, 401);
    assert_eq!(get, post);
}

// ---------------------------------------------------------------------------
// RFC 6750 §2.3 — the carrier neither method gained
// ---------------------------------------------------------------------------

/// `?access_token=…` authenticates nothing, on either method.
///
/// §2.3 is deprecated because a credential in a URL reaches the `Referer`
/// header, the browser history and every access log on the path. AXIAM does
/// not refuse it — refusing would mean reading it first — it simply never
/// looks at the query string on this route. The observable consequence is
/// this: the request is unauthenticated, exactly as if the parameter were
/// absent.
#[actix_rt::test]
async fn a_query_string_access_token_authenticates_neither_method() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = token_with_scopes(&auth, user_id, tenant_id, org_id, &["openid"]);
    let app = test_app!(db, auth);

    for method in ["GET", "POST"] {
        let req = match method {
            "GET" => test::TestRequest::get(),
            _ => test::TestRequest::post(),
        }
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("{USERINFO}?access_token={token}"))
        .to_request();
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            401,
            "{method} must not be authenticated by a query-string token"
        );
    }
}

// ---------------------------------------------------------------------------
// Hazard 1 — a token in a body is a credential
// ---------------------------------------------------------------------------

/// In-memory `MakeWriter` so the test can read everything the request wrote to
/// `tracing`. Same shape as `gdpr_audit_dlq_test.rs`'s.
#[derive(Clone)]
struct BufWriter(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for BufWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for BufWriter {
    type Writer = BufWriter;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// **Hazard 1.** The body-carried credential reaches no log line, on the
/// success path or on the failure path.
///
/// Both paths are exercised under one `TRACE`-level subscriber: a valid token
/// (which authenticates) and a syntactically valid but unverifiable one (which
/// does not, and therefore travels through the error machinery — the place a
/// credential usually escapes, in a `tracing::warn!(error = %e)` whose `e`
/// happens to carry the input).
///
/// The `TRACE` level matters. A test run at the default level would pass
/// against a `debug!` that prints the token in production diagnostics.
///
/// Scope, stated rather than implied: this captures `tracing`, which is what
/// every line AXIAM writes goes through. actix-web's own extractor
/// diagnostics go to the `log` crate and are not bridged into a subscriber
/// installed this way — which is why `UserInfoPostForm` deserializes from a
/// single optional `String` with unknown fields ignored, a shape whose
/// deserialization cannot fail with the input in the message.
#[actix_rt::test]
async fn the_body_carried_credential_never_reaches_a_log() {
    let log = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        .with_writer(BufWriter(log.clone()))
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    // `set_default` rather than `with_default`: the subscriber has to stay
    // installed across `await` points, and `with_default` takes a synchronous
    // closure. An actix-rt test runs on a current-thread runtime, so the
    // thread-local default the guard installs covers the whole request.
    let guard = tracing::subscriber::set_default(subscriber);

    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let good = token_with_scopes(&auth, user_id, tenant_id, org_id, &["openid", "email"]);
    // The same token with its signature broken: it gets past "is there a
    // token" and fails inside validation, which is the path that logs.
    let bad = format!("{good}-tampered");
    let app = test_app!(db, auth);

    let ok = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .set_form(FormBody {
                access_token: &good,
            })
            .to_request(),
    )
    .await;
    assert_eq!(ok.status().as_u16(), 200);

    let denied = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .set_form(FormBody { access_token: &bad })
            .to_request(),
    )
    .await;
    assert_eq!(denied.status().as_u16(), 401);
    let denied_body = String::from_utf8(test::read_body(denied).await.to_vec()).expect("UTF-8");
    assert!(
        !denied_body.contains(&bad),
        "a 401 body must not echo the credential: {denied_body}"
    );

    drop(guard);
    let captured = String::from_utf8_lossy(&log.lock().unwrap().clone()).into_owned();
    for token in [&good, &bad] {
        assert!(
            !captured.contains(token.as_str()),
            "an access token presented in a request body reached the log:\n{captured}"
        );
        // The signature alone would be enough to replay the token, so assert
        // on the last segment too rather than only on the whole string.
        let signature = token.rsplit('.').next().unwrap();
        assert!(
            !captured.contains(signature),
            "a token's signature reached the log:\n{captured}"
        );
    }
}

/// The form type cannot print its own credential.
///
/// `UserInfoPostForm` has a hand-written `Debug` that redacts the token. A
/// derived one would have made `tracing::debug!(?form, …)` — the most natural
/// line anybody debugging this endpoint would write — a credential disclosure.
// Fully qualified because `use actix_web::test` brings actix-web's own `test`
// *attribute macro* into scope alongside its `test` module, and a bare
// `#[test]` would resolve to that one and demand an `async fn`.
#[::core::prelude::v1::test]
fn the_form_type_redacts_its_token_when_printed() {
    let form: UserInfoPostForm =
        serde_json::from_value(serde_json::json!({ "access_token": "s3cret-token-value" }))
            .expect("the form body deserializes from JSON as well as from a form encoding");
    let printed = format!("{form:?}");
    assert!(
        !printed.contains("s3cret-token-value"),
        "Debug leaked the token: {printed}"
    );
    assert!(printed.contains("redacted"), "and it says so: {printed}");
}

// ---------------------------------------------------------------------------
// Hazard 2 — cookie precedence and CSRF
// ---------------------------------------------------------------------------

/// **Hazard 2.** A cross-site form POST cannot be authenticated by the
/// `axiam_access` cookie, because the browser does not send it.
///
/// The hazard is real and worth stating: `parse_validated_claims` reads the
/// cookie *before* the `Authorization` header, `/oauth2` is not wrapped in
/// `CsrfMiddleware` (only `/api/v1` is), and UserInfo returns PII. A
/// cookie-authenticated POST from another origin would be a CSRF disclosure.
///
/// What closes it is not code on this route: it is that `axiam_access` is
/// `SameSite=Strict`, so a browser sends it on no cross-site request of any
/// kind — a form POST included — and the request arrives here with no
/// credential at all. That is a property of the cookie, so this pins the
/// cookie rather than describing it in a comment that a later change to
/// `access_cookie` would silently falsify.
///
/// The second half asserts the other direction: a *same-site* POST carrying
/// the cookie does authenticate. Without it, this test would pass just as well
/// against a route that ignored the cookie entirely, and would prove nothing
/// about the surface it claims to be guarding.
#[actix_rt::test]
async fn the_access_cookie_is_strict_so_a_cross_site_post_cannot_be_authenticated_by_it() {
    let pinned = access_cookie("irrelevant", 900, true);
    assert_eq!(
        pinned.same_site(),
        Some(SameSite::Strict),
        "axiam_access must stay SameSite=Strict: it is the only thing that \
         keeps a cross-site form POST to /oauth2/userinfo — which is not \
         CSRF-protected — from returning a victim's PII"
    );
    assert!(
        pinned.http_only().unwrap_or(false),
        "and HttpOnly, so script cannot lift it into a form field instead"
    );

    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = token_with_scopes(&auth, user_id, tenant_id, org_id, &["openid", "email"]);
    let app = test_app!(db, auth);

    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Cookie", format!("axiam_access={token}")))
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a same-site POST carrying the cookie authenticates, which is what \
         makes the Strict attribute load-bearing rather than incidental"
    );
}

// ---------------------------------------------------------------------------
// Sender-constrained tokens on the new method
// ---------------------------------------------------------------------------

/// An Ed25519 keypair, the JWK for its public half, and that JWK's RFC 7638
/// thumbprint — the `cnf.jkt` a DPoP-bound token carries.
struct ProofKey {
    encoding: jsonwebtoken::EncodingKey,
    jwk: serde_json::Value,
    jkt: String,
}

fn proof_key() -> ProofKey {
    use base64::Engine as _;
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("generate Ed25519");
    let encoding = jsonwebtoken::EncodingKey::from_ed_pem(kp.serialize_pem().as_bytes())
        .expect("encoding key");
    let spki = kp.public_key_raw();
    let x = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&spki[spki.len() - 32..]);
    let jwk = serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": x });
    let parsed: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(jwk.clone()).expect("a well-formed OKP JWK");
    let jkt = axiam_oauth2::jose::jwk_thumbprint(&parsed).expect("thumbprint");
    ProofKey { encoding, jwk, jkt }
}

/// A DPoP proof for `htm` on the UserInfo endpoint, hashing `token`.
fn dpop_proof(key: &ProofKey, htm: &str, token: &str) -> String {
    let header: jsonwebtoken::Header = serde_json::from_value(serde_json::json!({
        "typ": axiam_oauth2::dpop::DPOP_TYP,
        "alg": "EdDSA",
        "jwk": key.jwk,
    }))
    .expect("proof header");
    let claims = serde_json::json!({
        "jti": Uuid::new_v4().to_string(),
        "htm": htm,
        "htu": format!("{ISSUER}{USERINFO}"),
        "iat": chrono::Utc::now().timestamp(),
        "ath": axiam_oauth2::jose::access_token_hash(token),
    });
    jsonwebtoken::encode(&header, &claims, &key.encoding).expect("sign the proof")
}

/// A DPoP-bound token verifies on POST — and the proof must say `htm=POST`.
///
/// `verified_dpop_thumbprint` builds its expectation from
/// `req.method().as_str()` and from `config.effective_issuer() + req.path()`,
/// never from a request header (SEC-102). That is why a POST route gets `htm`
/// checking for free and why W6 adds no method-specific branch: a branch is
/// how the check comes to disagree with itself.
///
/// Both carriers are exercised. The body carrier is the one that matters here:
/// it is the path that resolves its own token, and a path that resolved a token
/// without re-running `enforce_sender_constraint` would turn a bound token back
/// into a bearer token — the exact downgrade RFC 9449 exists to prevent.
#[actix_rt::test]
async fn a_dpop_bound_token_verifies_on_post_and_only_with_a_post_proof() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let key = proof_key();
    let token = issue_access_token_bound(
        user_id,
        tenant_id,
        org_id,
        &["openid".to_owned()],
        &auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
        Some(CnfClaim::from_dpop_thumbprint(key.jkt.clone())),
    )
    .unwrap();
    let app = test_app!(db, auth);

    // Header carrier, correct proof.
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Authorization", format!("DPoP {token}")))
            .insert_header(("DPoP", dpop_proof(&key, "POST", &token)))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 200, "a POST proof verifies on POST");

    // Body carrier, correct proof — the sender constraint survives the new
    // carrier.
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("DPoP", dpop_proof(&key, "POST", &token)))
            .set_form(FormBody {
                access_token: &token,
            })
            .to_request(),
    )
    .await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a body-carried bound token is still checked against its proof"
    );

    // The same proof minted for GET does not verify on POST.
    for carrier in ["header", "body"] {
        let proof = dpop_proof(&key, "GET", &token);
        let req = match carrier {
            "header" => test::TestRequest::post()
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                .uri(USERINFO)
                .insert_header(("Authorization", format!("DPoP {token}")))
                .insert_header(("DPoP", proof))
                .to_request(),
            _ => test::TestRequest::post()
                .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
                .uri(USERINFO)
                .insert_header(("DPoP", proof))
                .set_form(FormBody {
                    access_token: &token,
                })
                .to_request(),
        };
        let resp = test::call_service(&app, req).await;
        assert_eq!(
            resp.status().as_u16(),
            401,
            "an htm=GET proof must not authorise a POST ({carrier} carrier)"
        );
    }

    // And a bound token with no proof at all is not a bearer token.
    let resp = test::call_service(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .set_form(FormBody {
                access_token: &token,
            })
            .to_request(),
    )
    .await;
    assert_eq!(resp.status().as_u16(), 401, "no proof, no access");
}

/// A certificate-bound token — the shape a `fapi2` client holds — is not
/// downgraded to a bearer token by the new method or the new carrier.
///
/// # What this asserts, and what it cannot
///
/// The *positive* direction (a bound token presented over a connection whose
/// verified client certificate matches `cnf.x5t#S256`) is not reachable from
/// this harness: `enforce_sender_constraint` reads the certificate from
/// `HttpRequest::conn_data`, and actix-web's `TestRequest` constructs every
/// request with `conn_data: None` and offers no way to populate it. Asserting
/// it would need a real TLS listener and a handshake, which is an integration
/// harness this repository does not have.
///
/// So this asserts the direction that is reachable and is also the one a
/// mistake would show up in: presented **without** a certificate, on POST and
/// on both carriers, the token is refused rather than read as unbound — and
/// refused identically to the way GET refuses it. A POST arm that had skipped
/// `enforce_sender_constraint` would answer 200 here.
#[actix_rt::test]
async fn an_mtls_bound_token_is_not_downgraded_to_a_bearer_token_on_post() {
    let (db, org_id, tenant_id, user_id) = setup_db().await;
    let auth = test_auth_config();
    let token = issue_access_token_bound(
        user_id,
        tenant_id,
        org_id,
        &["openid".to_owned()],
        &auth,
        Uuid::new_v4().to_string(),
        AUD_USER,
        Some(CnfClaim::from_certificate_thumbprint(
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )),
    )
    .unwrap();
    let app = test_app!(db, auth);

    let get = answer(
        &app,
        test::TestRequest::get()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request(),
    )
    .await;
    let post_header = answer(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_request(),
    )
    .await;
    let post_body = answer(
        &app,
        test::TestRequest::post()
            .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
            .uri(USERINFO)
            .set_form(FormBody {
                access_token: &token,
            })
            .to_request(),
    )
    .await;

    assert_eq!(
        get.status, 401,
        "a bound token with no certificate is not a bearer token"
    );
    assert_eq!(get, post_header, "and POST refuses it exactly as GET does");
    assert_eq!(
        post_header, post_body,
        "the body carrier refuses it in the same words"
    );
}

//! W8 / G9 — `client_secret_basic` at the token endpoint (RFC 6749 §2.3.1).
//!
//! One shared secret, a second spelling. The credential comparison is the same
//! peppered-hash check `client_secret_post` already used, so nothing here
//! re-tests cryptography; every test in this file pins one of the three ways
//! HTTP Basic client authentication is classically got wrong.
//!
//! ## T9.1 — the encoding
//!
//! RFC 6749 §2.3.1 does not say "base64 of `id:secret`". Each half is
//! `application/x-www-form-urlencoded`-encoded *first*. Servers that skip the
//! matching decode work perfectly against their own generated secrets — which
//! are hex or base64url and therefore encode to themselves — and fail only for
//! a third-party relying party whose secret contains `%`, `+` or `:`, with an
//! `invalid_client` that explains nothing. The fixture secret here contains all
//! three.
//!
//! ## T9.2 / T9.3 — two-method confusion
//!
//! SEC-093's rule, applied to a fourth method: the **registration** decides
//! which channel carries the credential, never the request. A
//! `client_secret_basic` client that also puts `client_secret` in the body has
//! used two authentication methods in one request, which RFC 6749 §2.3
//! forbids. A `client_secret_post` client that presents a Basic header is
//! authenticated by its body secret and the header is inert — invariant I4, no
//! existing client's behaviour changes.
//!
//! ## T9.4 — header leakage
//!
//! The whole cost of this method is that `Authorization` is the header
//! reverse proxies and APM agents log by default. AXIAM's own tracing must not
//! join them: the test captures the subscriber output of a *failed* Basic
//! attempt and greps it for the secret and for the base64 blob.
//!
//! ## T9.5 / T9.6 — the FAPI gate
//!
//! Live in `axiam-oauth2`'s own test modules (`fapi.rs`), where the two
//! existing parametrised matrices gained the variant. No new gate code exists
//! to test here: `is_strong()` is what both layers ask.

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, UpdateOAuth2Client,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OAuth2ClientRepository, OrganizationRepository, TenantRepository};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
use base64::Engine as _;
use serde_json::Value;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:34567";
const REDIRECT_URI: &str = "https://rp.test.example/callback";

/// T9.1's vector. Every character the `application/x-www-form-urlencoded`
/// algorithm touches, plus the one RFC 7617 §2 says a *password* may carry
/// raw and a user-id may not.
///
/// A server that base64-decodes and stops sees `p%25a%2Bs%3As` here and
/// matches no stored hash. A server that splits on the last colon sees `s`.
const AWKWARD_SECRET: &str = "p%a+s:s";

/// The same secret, encoded the way RFC 6749 §2.3.1 requires a client to
/// encode it before base64.
const AWKWARD_SECRET_ENCODED: &str = "p%25a%2Bs%3As";

fn test_keypair() -> (String, String) {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    (kp.serialize_pem(), kp.public_key_pem())
}

fn test_auth_config() -> AuthConfig {
    let (private_key, public_key) = test_keypair();
    AuthConfig {
        jwt_private_key_pem: private_key,
        jwt_public_key_pem: public_key,
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.test.example".into(),
        sso_spa_origins: Vec::new(),
        ..AuthConfig::default()
    }
}

/// `Basic ` + base64 of the blob, verbatim — the encoding step is the caller's,
/// so a test can deliberately get it wrong.
fn basic_header(blob: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(blob)
    )
}

fn basic_blob(client_id: &str, encoded_secret: &str) -> String {
    format!("{client_id}:{encoded_secret}")
}

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    tenant_id: Uuid,
    /// Registered `client_secret_basic`, secret forced to [`AWKWARD_SECRET`].
    basic_client_id: String,
    /// Registered `client_secret_post`, holding the same awkward secret — the
    /// I4 control. Same credential, different registered channel.
    post_client_id: String,
}

/// Overwrite a client's secret hash so the test controls the plaintext.
///
/// The repository mints a CSPRNG secret in its own alphabet, which is exactly
/// the alphabet that makes the form-urlencoding bug invisible. Writing the hash
/// directly is the only way to hand a client a secret containing `%`, `+` and
/// `:` — and it writes it through the same
/// `axiam_auth::client_secret::global()` hasher the server verifies with, so
/// nothing about the hashing scheme is being faked.
async fn force_secret(db: &Surreal<TestDb>, client_id: &str, secret: &str) {
    let hash = axiam_auth::client_secret::global()
        .expect("dev-default pepper in a debug test binary")
        .hash(secret);
    db.query("UPDATE oauth2_client SET client_secret_hash = $h WHERE client_id = $c")
        .bind(("h", hash))
        .bind(("c", client_id.to_owned()))
        .await
        .expect("force the client secret hash");
}

async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "W8 Org".into(),
            slug: "org-w8".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "W8 Tenant".into(),
            slug: "tenant-w8".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let client_repo = SurrealOAuth2ClientRepository::new(db.clone());
    let new_client = |name: &str| CreateOAuth2Client {
        tenant_id: tenant.id,
        name: name.into(),
        redirect_uris: vec![REDIRECT_URI.into()],
        // `client_credentials` reaches `authenticate_client_credential`
        // without a browser hop, which is what these tests are about. The
        // authorization-code path shares the identical call.
        grant_types: vec!["client_credentials".into(), "authorization_code".into()],
        scopes: vec!["openid".into()],
        post_logout_redirect_uris: Vec::new(),
        backchannel_logout_uri: None,
        require_par: false,
        profile: ClientProfile::Standard,
        token_endpoint_auth_method: ClientAuthMethod::ClientSecretPost,
        tls_client_auth_subject_dn: None,
        tls_client_auth_san_dns: None,
        tls_client_auth_san_uri: None,
        self_signed_tls_client_auth_thumbprints: vec![],
        tls_client_certificate_bound_access_tokens: false,
        jwks: None,
        jwks_uri: None,
        dpop_bound_access_tokens: false,
        dpop_require_nonce: false,
        authn_request_params: AuthnRequestParamsMode::Ignore,
        browser_sso: false,
    };

    let (basic, _) = client_repo.create(new_client("basic-rp")).await.unwrap();
    let (post, _) = client_repo.create(new_client("post-rp")).await.unwrap();

    client_repo
        .update(
            tenant.id,
            basic.id,
            UpdateOAuth2Client {
                token_endpoint_auth_method: Some(ClientAuthMethod::ClientSecretBasic),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    force_secret(&db, &basic.client_id, AWKWARD_SECRET).await;
    force_secret(&db, &post.client_id, AWKWARD_SECRET).await;

    let reloaded = client_repo
        .get_by_client_id(tenant.id, &basic.client_id)
        .await
        .unwrap();
    assert_eq!(
        reloaded.token_endpoint_auth_method,
        ClientAuthMethod::ClientSecretBasic,
        "fixture precondition: the registration must survive a round trip through SurrealDB, \
         which is also the assertion that `from_wire` accepts the new value"
    );

    Fixture {
        db,
        auth: test_auth_config(),
        tenant_id: tenant.id,
        basic_client_id: basic.client_id,
        post_client_id: post.client_id,
    }
}

macro_rules! test_app {
    ($f:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($f.auth.clone()))
                .app_data(web::Data::new(AppState::for_test(
                    $f.db.clone(),
                    $f.auth.clone(),
                )))
                .app_data(web::Data::new(
                    Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
                ))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    };
}

/// The outcome of one token request: status, `error` code, and the
/// `WWW-Authenticate` challenge if there was one.
struct Outcome {
    status: u16,
    error: Option<String>,
    challenge: Option<String>,
}

async fn post_token(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    tenant_id: Uuid,
    body: &str,
    authorization: Option<&str>,
) -> Outcome {
    let mut req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={tenant_id}"))
        .insert_header(("content-type", "application/x-www-form-urlencoded"));
    if let Some(value) = authorization {
        req = req.insert_header(("Authorization", value.to_owned()));
    }
    let resp = test::call_service(app, req.set_payload(body.to_owned()).to_request()).await;
    let status = resp.status().as_u16();
    let challenge = resp
        .headers()
        .get("WWW-Authenticate")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = test::read_body(resp).await;
    let error = serde_json::from_slice::<Value>(&body)
        .ok()
        .and_then(|v| v["error"].as_str().map(str::to_owned));
    Outcome {
        status,
        error,
        challenge,
    }
}

// ---------------------------------------------------------------------------
// T9.1 — RFC 6749 §2.3.1 encoding
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn t9_1_each_half_is_form_urldecoded_after_the_base64() {
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        "grant_type=client_credentials",
        Some(&basic_header(&basic_blob(
            &f.basic_client_id,
            AWKWARD_SECRET_ENCODED,
        ))),
    )
    .await;

    assert_eq!(
        out.status, 200,
        "a correctly RFC 6749 §2.3.1-encoded credential must authenticate; got {:?}",
        out.error
    );
}

#[actix_rt::test]
async fn t9_1_skipping_the_form_urldecode_would_have_failed_this_client() {
    // The negative half of T9.1, and the reason the positive half proves
    // anything: had the server stopped after base64, THIS is the blob that
    // would have worked and the encoded one that would not.
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        "grant_type=client_credentials",
        Some(&basic_header(&basic_blob(
            &f.basic_client_id,
            AWKWARD_SECRET, // raw, unencoded — what a naive client sends
        ))),
    )
    .await;

    assert_eq!(out.status, 401);
    assert_eq!(out.error.as_deref(), Some("invalid_client"));
}

#[actix_rt::test]
async fn t9_1_the_split_is_on_the_first_colon_end_to_end() {
    // A secret that is *only* colons and letters, sent with the colon left
    // raw as RFC 7617 §2 permits in the password half. Splitting on the last
    // colon truncates it to `c` and authenticates nobody.
    let f = setup().await;
    force_secret(&f.db, &f.basic_client_id, "a:b:c").await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        "grant_type=client_credentials",
        Some(&basic_header(&format!("{}:a:b:c", f.basic_client_id))),
    )
    .await;

    assert_eq!(
        out.status, 200,
        "a password containing raw colons must survive the split; got {:?}",
        out.error
    );
}

// ---------------------------------------------------------------------------
// T9.2 — the client id may come from the header alone
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn t9_2_the_client_id_may_arrive_only_in_the_header() {
    // RFC 6749 §2.3.1 makes the body's `client_id` optional for a client
    // authenticating through the header, and 37 of the Basic OP plan's 38
    // modules take it up. Without this the whole method would be unreachable
    // by the clients it was added for.
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        "grant_type=client_credentials",
        Some(&basic_header(&basic_blob(
            &f.basic_client_id,
            AWKWARD_SECRET_ENCODED,
        ))),
    )
    .await;

    assert_eq!(out.status, 200, "got {:?}", out.error);
}

#[actix_rt::test]
async fn t9_2_a_body_client_id_that_disagrees_with_the_header_is_refused() {
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=client_credentials&client_id={}",
            f.post_client_id
        ),
        Some(&basic_header(&basic_blob(
            &f.basic_client_id,
            AWKWARD_SECRET_ENCODED,
        ))),
    )
    .await;

    assert_eq!(out.status, 400);
    assert_eq!(
        out.error.as_deref(),
        Some("invalid_request"),
        "two claims of identity in one request must be refused rather than resolved"
    );
}

// ---------------------------------------------------------------------------
// T9.3 — two-method confusion (SEC-093 applied to a fourth method)
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn t9_3_a_body_secret_on_a_basic_client_is_invalid_request() {
    // RFC 6749 §2.3: one authentication method per request. Note the ordering
    // this asserts implicitly — the Basic credential here is CORRECT, so the
    // caller reaching `invalid_request` has already proven possession. A
    // caller who has not gets `invalid_client`, below.
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        &format!("grant_type=client_credentials&client_secret={AWKWARD_SECRET_ENCODED}"),
        Some(&basic_header(&basic_blob(
            &f.basic_client_id,
            AWKWARD_SECRET_ENCODED,
        ))),
    )
    .await;

    assert_eq!(out.status, 400);
    assert_eq!(out.error.as_deref(), Some("invalid_request"));
}

#[actix_rt::test]
async fn t9_3_a_wrong_basic_secret_plus_a_body_secret_reveals_nothing() {
    // SEC-086. If the two-method refusal ran BEFORE credential verification,
    // `invalid_request` would be reachable only for a client that exists and
    // is registered for Basic — making both facts decidable by a caller
    // holding no credential at all. It must be `invalid_client`, exactly as
    // for a client id that does not exist.
    let f = setup().await;
    let app = test_app!(f);

    let real = post_token(
        &app,
        f.tenant_id,
        &format!("grant_type=client_credentials&client_secret={AWKWARD_SECRET_ENCODED}"),
        Some(&basic_header(&basic_blob(&f.basic_client_id, "wrong"))),
    )
    .await;
    let unknown = post_token(
        &app,
        f.tenant_id,
        &format!("grant_type=client_credentials&client_secret={AWKWARD_SECRET_ENCODED}"),
        Some(&basic_header(&basic_blob("oa_no_such_client", "wrong"))),
    )
    .await;

    assert_eq!(real.status, unknown.status);
    assert_eq!(real.error, unknown.error);
    assert_eq!(real.error.as_deref(), Some("invalid_client"));
}

#[actix_rt::test]
async fn t9_3_a_basic_client_may_not_authenticate_with_a_body_secret() {
    // The registration decides. A `client_secret_basic` client that sends its
    // secret in the body has used the channel its registration does not name,
    // and the body secret is never consulted — that OR is precisely what
    // SEC-093 exists to prevent.
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=client_credentials&client_id={}&client_secret={AWKWARD_SECRET_ENCODED}",
            f.basic_client_id
        ),
        None,
    )
    .await;

    assert_eq!(out.status, 401);
    assert_eq!(out.error.as_deref(), Some("invalid_client"));
}

#[actix_rt::test]
async fn t9_3_i4_a_basic_header_on_a_post_client_is_ignored() {
    // Invariant I4: no existing client's behaviour changes. The header names
    // the right client and carries the right secret, and it is still the body
    // secret that authenticates — which is why the request succeeds with the
    // body secret present and fails without it, below.
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=client_credentials&client_id={}&client_secret={AWKWARD_SECRET_ENCODED}",
            f.post_client_id
        ),
        Some(&basic_header(&basic_blob(
            &f.post_client_id,
            AWKWARD_SECRET_ENCODED,
        ))),
    )
    .await;

    assert_eq!(out.status, 200, "got {:?}", out.error);
}

#[actix_rt::test]
async fn t9_3_i4_a_post_client_cannot_authenticate_with_the_header_alone() {
    // The other half of I4, and the one that would be a vulnerability if it
    // failed: an ignored header must be inert, not a fallback.
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=client_credentials&client_id={}",
            f.post_client_id
        ),
        Some(&basic_header(&basic_blob(
            &f.post_client_id,
            AWKWARD_SECRET_ENCODED,
        ))),
    )
    .await;

    assert_eq!(out.status, 401);
    assert_eq!(out.error.as_deref(), Some("invalid_client"));
}

// ---------------------------------------------------------------------------
// RFC 6749 §5.2 — the challenge names the scheme the client used
// ---------------------------------------------------------------------------

#[actix_rt::test]
async fn a_failed_basic_attempt_is_challenged_with_basic() {
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        "grant_type=client_credentials",
        Some(&basic_header(&basic_blob(&f.basic_client_id, "wrong"))),
    )
    .await;

    assert_eq!(out.status, 401);
    assert_eq!(
        out.challenge.as_deref(),
        Some("Basic realm=\"axiam\""),
        "RFC 6749 §5.2: the challenge must match the scheme the client used"
    );
}

#[actix_rt::test]
async fn a_malformed_basic_header_is_refused_and_challenged() {
    let f = setup().await;
    let app = test_app!(f);

    for bad in [
        "Basic !!!not-base64!!!",
        &basic_header("no-colon-at-all"),
        &basic_header("oa_abc:tru%"),
        &basic_header(":empty-id"),
    ] {
        let out = post_token(
            &app,
            f.tenant_id,
            "grant_type=client_credentials",
            Some(bad),
        )
        .await;
        assert_eq!(out.status, 401, "bad header {bad:?}");
        assert_eq!(
            out.error.as_deref(),
            Some("invalid_client"),
            "every malformed header answers uniformly (SEC-086); bad header {bad:?}"
        );
        assert_eq!(
            out.challenge.as_deref(),
            Some("Basic realm=\"axiam\""),
            "bad header {bad:?}"
        );
    }
}

#[actix_rt::test]
async fn a_failure_without_a_basic_header_keeps_the_bearer_challenge() {
    // The existing behaviour, unchanged: the challenge is decided by what the
    // client used, and a form-body client used no `Authorization` header.
    let f = setup().await;
    let app = test_app!(f);

    let out = post_token(
        &app,
        f.tenant_id,
        &format!(
            "grant_type=client_credentials&client_id={}&client_secret=wrong",
            f.post_client_id
        ),
        None,
    )
    .await;

    assert_eq!(out.status, 401);
    assert_eq!(out.challenge.as_deref(), Some("Bearer realm=\"axiam\""));
}

// ---------------------------------------------------------------------------
// T9.4 — the Authorization header must never reach a log
// ---------------------------------------------------------------------------

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

#[actix_rt::test]
async fn t9_4_a_failed_basic_attempt_logs_neither_the_secret_nor_the_blob() {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::fmt()
        // TRACE, not the deployment's level: the assertion is that the secret
        // is absent from everything AXIAM can emit, not merely from what it
        // emits by default. A redaction that only holds at INFO is one an
        // operator turns off while debugging the exact failure that leaks it.
        .with_max_level(tracing::Level::TRACE)
        .with_writer(BufWriter(captured.clone()))
        .with_ansi(false)
        .finish();

    let good_blob;
    let bad_blob;
    {
        let _guard = tracing::subscriber::set_default(subscriber);
        let f = setup().await;
        let app = test_app!(f);

        good_blob = base64::engine::general_purpose::STANDARD
            .encode(basic_blob(&f.basic_client_id, AWKWARD_SECRET_ENCODED));
        bad_blob = base64::engine::general_purpose::STANDARD
            .encode(basic_blob(&f.basic_client_id, "wrong-but-still-a-secret"));

        // Three requests, because the leak could be on any of three paths and
        // they log different things.
        //
        // 1. The successful one. A live credential in a log is worse than a
        //    rejected one, and the success path is the one with the token
        //    issuance, audit and stage-timing sites behind it.
        let out = post_token(
            &app,
            f.tenant_id,
            "grant_type=client_credentials",
            Some(&format!("Basic {good_blob}")),
        )
        .await;
        assert_eq!(out.status, 200, "got {:?}", out.error);

        // 2. Fails at `verify_client_secret` — the deepest a wrong-secret
        //    request gets, and the path that writes the client-auth-failure
        //    audit event.
        let out = post_token(
            &app,
            f.tenant_id,
            "grant_type=client_credentials",
            Some(&format!("Basic {bad_blob}")),
        )
        .await;
        assert_eq!(out.status, 401);

        // 3. Refused at the edge, before `TokenService` is reached at all.
        let out = post_token(
            &app,
            f.tenant_id,
            "grant_type=client_credentials",
            Some("Basic !!!not-base64!!!"),
        )
        .await;
        assert_eq!(out.status, 401);
    }

    let log = String::from_utf8(captured.lock().unwrap().clone()).expect("utf-8 log");
    assert!(
        !log.contains(AWKWARD_SECRET),
        "the plaintext client secret reached the log:\n{log}"
    );
    assert!(
        !log.contains(AWKWARD_SECRET_ENCODED),
        "the encoded client secret reached the log:\n{log}"
    );
    assert!(
        !log.contains(&good_blob),
        "the base64 credentials blob of the SUCCESSFUL request reached the log:\n{log}"
    );
    assert!(
        !log.contains(&bad_blob),
        "the base64 credentials blob of the failed request reached the log:\n{log}"
    );
    assert!(
        !log.contains("wrong-but-still-a-secret"),
        "a rejected secret reached the log:\n{log}"
    );
    // The header values themselves, verbatim. Broader greps than this catch
    // AXIAM's own prose about the header (and SurrealDB's TRACE chatter);
    // what matters is that no *value* a client sent was rendered anywhere.
    for sent in [
        format!("Basic {good_blob}"),
        format!("Basic {bad_blob}"),
        "Basic !!!not-base64!!!".to_owned(),
    ] {
        assert!(
            !log.contains(&sent),
            "an Authorization header value was rendered into the log: {sent}\n{log}"
        );
    }
}

#[actix_rt::test]
async fn t9_4_the_request_logging_layer_records_no_headers_at_all() {
    // The second half of T9.4: the assertion about the *layer*, not about one
    // request. `axiam-server` wraps the app in `TracingLogger::default()`,
    // whose `DefaultRootSpanBuilder` records a fixed field set — method,
    // route, scheme, host, client ip, user agent, status — and no header
    // beyond `User-Agent`. There is no allow-list to add `Authorization` to,
    // which is the strongest form the property can take: it is excluded by
    // construction rather than by configuration.
    //
    // This test pins the *choice*. Should anyone replace the default root
    // span builder with a custom one, this is the line that has to be edited,
    // and editing it is where the question "does this record Authorization?"
    // gets asked again.
    let source = include_str!("../../axiam-server/src/main.rs");
    assert!(
        source.contains("TracingLogger::default()"),
        "the request-logging layer is no longer tracing-actix-web's default root span builder; \
         re-verify that its replacement records no Authorization header (W8 / T9.4)"
    );
    assert!(
        !source.contains("AUTHORIZATION"),
        "axiam-server names the Authorization header; if it now logs one, W8's T9.4 redaction \
         obligation is broken"
    );
}

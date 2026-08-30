//! Regressions for principals that live in an organization's own reserved
//! scope, and for organization-level principals acting on a child tenant.
//!
//! Every case here is a flow an administrator of a freshly bootstrapped
//! deployment takes on their first day, and each one was broken in a different
//! way by the same underlying assumption: that a request always names a tenant,
//! and that the tenant it names is the one the caller lives in. Neither holds
//! at organization scope.
//!
//! * `POST /auth/reset` resolved no tenant at all when the caller named only an
//!   organization, and its enumeration-safe design then turned that into a
//!   silent success — `{"sent": true}` with no mail and nothing logged above
//!   debug. Every other workspace resolver in the codebase
//!   (`/auth/login`, `/auth/opaque/login/start`, `/auth/opaque/register/start`)
//!   already falls back to the organization tenant.
//! * `POST /auth/password/change` used the tenant the caller is *acting on*
//!   rather than the one it lives in, so an organization administrator who had
//!   switched to a child tenant could not change their own password.
//! * `POST /auth/opaque/register/start` refused a request that named only
//!   `tenant_id`, which is all the unauthenticated password-reset page has.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, Mutex};

use actix_web::{App, test, web};
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::state::AppState;
use axiam_api_rest::{
    ACTIVE_TENANT_HEADER, RateLimitConfig, SessionValidator, TenantScopeResolver,
    register_api_v1_routes,
};
use axiam_auth::config::AuthConfig;
use axiam_core::error::AxiamResult;
use axiam_core::models::mail::OutboundMailMessage;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::settings::system_defaults;
use axiam_core::models::tenant::{CreateTenant, ORGANIZATION_TENANT_SLUG, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    MailPublisher, OrganizationRepository, SettingsRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealOrganizationRepository, SurrealSessionRepository, SurrealSettingsRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:12345";
const ORG_SLUG: &str = "org-scope-gaps";
const CHILD_SLUG: &str = "child";
const ADMIN_USERNAME: &str = "super-admin";
const ADMIN_EMAIL: &str = "super-admin@example.com";
/// Test credentials are minted at runtime rather than written as literals.
///
/// These two have to satisfy the default password policy — `system_defaults()`
/// asks for 12+ characters, an uppercase and a digit — and a constant that does
/// is indistinguishable from a real credential to a scanner. Generating them
/// keeps the property the tests need without putting a password-shaped literal
/// in the tree, the same reason `test_auth_config()` below mints its signing
/// key here instead of embedding one.
static ADMIN_PASSWORD: LazyLock<String> = LazyLock::new(|| generated_password("adm"));
static ROTATED_PASSWORD: LazyLock<String> = LazyLock::new(|| generated_password("rot"));

/// A random password satisfying the default policy: 36 characters, an uppercase
/// and a digit in the fixed prefix, the rest from a fresh UUID.
fn generated_password(tag: &str) -> String {
    format!("Pw1-{tag}-{}", Uuid::new_v4().simple())
}

/// Generates a fresh Ed25519 JWT signing keypair at test runtime, so no literal
/// key material appears in source.
fn test_auth_config() -> AuthConfig {
    let kp =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair generation");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        ..AuthConfig::default()
    }
}

/// Records every enqueued mail message so a test can assert one was produced.
///
/// `/auth/reset` answers `{"sent": true}` for every outcome by design (D-15),
/// so the response body cannot distinguish "mail enqueued" from "silently did
/// nothing". The publisher is the only place that difference is observable,
/// which is exactly why the organization-scope bug survived so long.
#[derive(Clone, Default)]
struct RecordingPublisher {
    sent: Arc<Mutex<Vec<OutboundMailMessage>>>,
}

impl MailPublisher for RecordingPublisher {
    async fn publish(&self, msg: OutboundMailMessage) -> AxiamResult<()> {
        self.sent.lock().unwrap().push(msg);
        Ok(())
    }
}

struct Fixture {
    db: Surreal<TestDb>,
    org_id: Uuid,
    /// The organization's own reserved scope — where bootstrap puts the
    /// super-admin.
    org_tenant_id: Uuid,
    /// An ordinary tenant inside the same organization.
    child_tenant_id: Uuid,
    admin_id: Uuid,
}

/// An organization with its reserved scope, one ordinary child tenant, and an
/// organization-level administrator — the shape `POST /admin/bootstrap` leaves
/// behind, plus the first tenant such an administrator creates.
async fn setup() -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org Scope Gaps".into(),
            slug: ORG_SLUG.into(),
            metadata: None,
        })
        .await
        .unwrap();

    let tenant_repo = SurrealTenantRepository::new(db.clone());
    // `run_migrations` backfills an organization tenant for organizations that
    // already exist; this one is created afterwards, so it gets its reserved
    // scope here.
    let org_tenant = match tenant_repo.get_organization_tenant(org.id).await {
        Ok(t) => t,
        Err(_) => tenant_repo
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Organization,
                name: "Org Scope Gaps (organization)".into(),
                slug: ORGANIZATION_TENANT_SLUG.into(),
                metadata: None,
            })
            .await
            .unwrap(),
    };

    let child_tenant = tenant_repo
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Child Tenant".into(),
            slug: CHILD_SLUG.into(),
            metadata: None,
        })
        .await
        .unwrap();

    SurrealSettingsRepository::new(db.clone())
        .set_org_settings(org.id, system_defaults())
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let admin = user_repo
        .create(CreateUser {
            tenant_id: org_tenant.id,
            username: ADMIN_USERNAME.into(),
            email: ADMIN_EMAIL.into(),
            password: ADMIN_PASSWORD.clone(),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            org_tenant.id,
            admin.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    Fixture {
        db,
        org_id: org.id,
        org_tenant_id: org_tenant.id,
        child_tenant_id: child_tenant.id,
        admin_id: admin.id,
    }
}

/// Build the app, optionally swapping in a recording mail publisher.
///
/// Registers the session validator and the tenant-scope resolver the production
/// server registers. The latter is what makes `X-Axiam-Tenant` work at all: the
/// extractor fails closed without it, so a harness that omits it cannot
/// exercise an organization-level principal acting on a child tenant.
macro_rules! test_app {
    ($f:expr, $auth:expr, $state:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($auth.clone()))
                .app_data(web::Data::new($state))
                .app_data(web::Data::new(
                    Arc::new(SurrealSessionRepository::new($f.db.clone()))
                        as Arc<dyn SessionValidator>,
                ))
                .app_data(web::Data::new(
                    Arc::new(SurrealTenantRepository::new($f.db.clone()))
                        as Arc<dyn TenantScopeResolver>,
                ))
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

/// Sign the organization administrator in at organization scope — naming no
/// tenant, exactly as the browser does after bootstrap.
async fn login_at_org_scope(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    password: &str,
) -> (String, String) {
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/login")
        .set_json(json!({
            "org_slug": ORG_SLUG,
            "username_or_email": ADMIN_USERNAME,
            "password": password,
        }))
        .to_request();
    let resp = test::call_service(app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "organization-level login must succeed"
    );

    let mut access = None;
    let mut csrf = None;
    for cookie in resp.response().cookies() {
        match cookie.name() {
            "axiam_access" => access = Some(cookie.value().to_string()),
            "axiam_csrf" => csrf = Some(cookie.value().to_string()),
            _ => {}
        }
    }
    (access.expect("access cookie"), csrf.expect("csrf cookie"))
}

// ---------------------------------------------------------------------------
// `POST /auth/reset` at organization scope
// ---------------------------------------------------------------------------

/// The organization-level administrator asks for a password-reset mail.
///
/// The "Forgot password?" link on an organization-level sign-in carries only
/// `?org=<slug>` — there is no tenant to carry, which is the whole point of
/// organization scope. Resolution used to give up on that and fall into the
/// enumeration-safe no-op, so the endpoint answered `{"sent": true}` and no
/// mail was ever produced: a super-admin who forgot their password had no way
/// back into the deployment at all.
#[actix_rt::test]
async fn reset_at_organization_scope_enqueues_a_mail() {
    let f = setup().await;
    let auth = test_auth_config();

    let recorder = RecordingPublisher::default();
    let sent = recorder.sent.clone();
    let mut state = AppState::for_test(f.db.clone(), auth.clone());
    state.mail.mail_outbound_publisher = Arc::new(recorder);
    let app = test_app!(f, auth, state);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({ "org_slug": ORG_SLUG, "email": ADMIN_EMAIL }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    let sent = sent.lock().unwrap();
    assert_eq!(
        sent.len(),
        1,
        "naming only an organization must resolve its reserved scope and enqueue \
         a reset mail, exactly as /auth/login resolves it"
    );
    assert_eq!(sent[0].tenant_id, f.org_tenant_id);
    assert_eq!(sent[0].user_id, f.admin_id);
}

/// A blank `tenant_slug` is not a slug.
///
/// The browser posts `tenant_slug: ""` for an organization-level sign-in, and
/// so may an SDK that serializes an empty form field rather than omitting it.
/// `/auth/login` and `/auth/opaque/*` already normalise it; reset must too, or
/// the same form that signs in cannot ask for a reset.
#[actix_rt::test]
async fn reset_treats_a_blank_tenant_slug_as_organization_scope() {
    let f = setup().await;
    let auth = test_auth_config();

    let recorder = RecordingPublisher::default();
    let sent = recorder.sent.clone();
    let mut state = AppState::for_test(f.db.clone(), auth.clone());
    state.mail.mail_outbound_publisher = Arc::new(recorder);
    let app = test_app!(f, auth, state);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({
            "org_slug": ORG_SLUG,
            "tenant_slug": "",
            "email": ADMIN_EMAIL,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    assert_eq!(
        sent.lock().unwrap().len(),
        1,
        "a blank tenant_slug must mean organization scope, not an unresolvable tenant"
    );
}

/// Naming nothing at all stays an enumeration-safe no-op.
///
/// The fix above must not turn `/auth/reset` into an oracle for which
/// organizations exist: with no organization named there is nothing to resolve,
/// and the answer is the same uniform `{"sent": true}` as an unknown account.
#[actix_rt::test]
async fn reset_without_any_workspace_stays_a_silent_no_op() {
    let f = setup().await;
    let auth = test_auth_config();

    let recorder = RecordingPublisher::default();
    let sent = recorder.sent.clone();
    let mut state = AppState::for_test(f.db.clone(), auth.clone());
    state.mail.mail_outbound_publisher = Arc::new(recorder);
    let app = test_app!(f, auth, state);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({ "email": ADMIN_EMAIL }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["sent"], json!(true));
    assert!(sent.lock().unwrap().is_empty());
}

/// An unknown organization slug must be indistinguishable from a known one.
#[actix_rt::test]
async fn reset_with_an_unknown_org_slug_stays_a_silent_no_op() {
    let f = setup().await;
    let auth = test_auth_config();

    let recorder = RecordingPublisher::default();
    let sent = recorder.sent.clone();
    let mut state = AppState::for_test(f.db.clone(), auth.clone());
    state.mail.mail_outbound_publisher = Arc::new(recorder);
    let app = test_app!(f, auth, state);

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/reset")
        .set_json(json!({ "org_slug": "no-such-org", "email": ADMIN_EMAIL }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["sent"], json!(true));
    assert!(sent.lock().unwrap().is_empty());
}

// ---------------------------------------------------------------------------
// `POST /auth/password/change` while acting on another tenant
// ---------------------------------------------------------------------------

/// An organization administrator changes their own password while the admin UI
/// has a child tenant selected.
///
/// The password being changed is the caller's own, and the caller lives in the
/// organization's reserved scope — `X-Axiam-Tenant` says which tenant the
/// request *acts on*, which for this endpoint is nobody. Reading the acting
/// tenant instead looked the account up in the child tenant, found nothing, and
/// failed a password change for reasons the operator could not see: the only
/// visible difference was which row of the tenant switcher was highlighted.
#[actix_rt::test]
async fn an_org_admin_can_change_their_own_password_while_acting_on_a_child_tenant() {
    let f = setup().await;
    let auth = test_auth_config();
    let state = AppState::for_test(f.db.clone(), auth.clone());
    let app = test_app!(f, auth, state);

    let (access, csrf) = login_at_org_scope(&app, ADMIN_PASSWORD.as_str()).await;

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/password/change")
        // Both cookies plus the header: `/auth/password/change` is a
        // state-changing POST, so the CSRF double-submit check runs before the
        // handler is reached and would otherwise answer 403 for a reason that
        // has nothing to do with what this test is about.
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf))
        .insert_header((ACTIVE_TENANT_HEADER, f.child_tenant_id.to_string()))
        .set_json(json!({
            "current_password": ADMIN_PASSWORD.as_str(),
            "new_password": ROTATED_PASSWORD.as_str(),
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        204,
        "the caller's own password lives in the tenant it inhabits, not the one \
         it is acting on"
    );

    // And the new password is the one that now signs in.
    let (_, _) = login_at_org_scope(&app, ROTATED_PASSWORD.as_str()).await;
}

// ---------------------------------------------------------------------------
// `POST /auth/opaque/register/start` from an unauthenticated reset page
// ---------------------------------------------------------------------------

/// The password-reset page holds a `tenant_id` and a token, and nothing else.
///
/// The emailed link carries `?token=…&tenant_id=…`; there is no organization in
/// it, and the page has no session to learn one from. Demanding an organization
/// made enrolment impossible from the one flow that has to work under
/// `opaque_mode = required` — a user who forgot their password could complete
/// the reset and still be unable to sign in, because the reset wrote a password
/// and no registration record.
#[actix_rt::test]
async fn opaque_register_start_accepts_a_tenant_id_without_an_organization() {
    let f = setup().await;
    let auth = AuthConfig {
        opaque_session_key: Some([7u8; 32]),
        opaque_setup_key: Some([9u8; 32]),
        ..test_auth_config()
    };

    let mut defaults = system_defaults();
    defaults.opaque_mode = axiam_core::models::opaque::OpaqueMode::Optional;
    SurrealSettingsRepository::new(f.db.clone())
        .set_org_settings(f.org_id, defaults)
        .await
        .unwrap();

    let state = AppState::for_test(f.db.clone(), auth.clone());
    let app = test_app!(f, auth, state);

    let (_, request) =
        axiam_opaque::ClientRegistrationState::start(ROTATED_PASSWORD.as_str()).unwrap();
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/opaque/register/start")
        .set_json(json!({
            "tenant_id": f.child_tenant_id,
            "registration_request": request,
        }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "a tenant id identifies its organization on its own; requiring the \
         caller to name one too locks out every unauthenticated flow"
    );
}

// ---------------------------------------------------------------------------
// Self-service endpoints while acting on a child tenant
// ---------------------------------------------------------------------------
//
// `POST /auth/password/change` above was the first endpoint found to read the
// ACTING tenant for a request about the CALLER'S OWN record. It was not the
// only one: `GET /users/{id}`, `PUT /users/{id}`,
// `GET /users/{id}/mfa-methods` and `POST /auth/mfa/enroll` all did the same,
// which took the whole profile page down for an organization administrator with
// a tenant selected — the account page would not load, the security section was
// empty, and enrolling a second factor failed. The rule is now named in
// `authz::user_scope_tenant`, and these pin it from the outside.

/// A second principal, living in the CHILD tenant.
///
/// The counter-case for every test below: an organization administrator acting
/// on a child tenant must still reach that tenant's users. A fix that scoped
/// everything to the principal's own tenant would pass the self-service tests
/// and break administration entirely.
async fn create_child_tenant_user(f: &Fixture, username: &str) -> Uuid {
    let user_repo = SurrealUserRepository::new(f.db.clone());
    let u = user_repo
        .create(CreateUser {
            tenant_id: f.child_tenant_id,
            username: username.into(),
            email: format!("{username}@example.com"),
            password: generated_password("chi"),
            metadata: None,
        })
        .await
        .unwrap();
    user_repo
        .update(
            f.child_tenant_id,
            u.id,
            UpdateUser {
                status: Some(UserStatus::Active),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    u.id
}

/// `GET /api/v1/users/{id}` for the caller's own id, with a child tenant selected.
///
/// This is what "open my profile" is. The record lives in the organization's
/// reserved scope; reading the acting tenant looked it up in the child tenant,
/// found nothing, and answered 404 — so the profile page showed a load error
/// for an account that plainly exists.
#[actix_rt::test]
async fn an_org_admin_can_read_their_own_profile_while_acting_on_a_child_tenant() {
    let f = setup().await;
    let auth = test_auth_config();
    let state = AppState::for_test(f.db.clone(), auth.clone());
    let app = test_app!(f, auth, state);

    let (access, _) = login_at_org_scope(&app, ADMIN_PASSWORD.as_str()).await;

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{}", f.admin_id))
        .insert_header(("Cookie", format!("axiam_access={access}")))
        .insert_header((ACTIVE_TENANT_HEADER, f.child_tenant_id.to_string()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "the caller's own record lives in the tenant it inhabits, not the one \
         it is acting on"
    );
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(body["username"], json!(ADMIN_USERNAME));
    assert_eq!(
        body["tenant_id"],
        json!(f.org_tenant_id.to_string()),
        "and it is returned from the organization scope, not relabelled into \
         the tenant being acted on"
    );
}

/// The counter-case: administering somebody else still follows the header.
#[actix_rt::test]
async fn an_org_admin_still_reads_a_child_tenant_user_through_the_header() {
    let f = setup().await;
    let child_user = create_child_tenant_user(&f, "child-user").await;
    let auth = test_auth_config();
    let state = AppState::for_test(f.db.clone(), auth.clone());
    let app = test_app!(f, auth, state);

    let (access, _) = login_at_org_scope(&app, ADMIN_PASSWORD.as_str()).await;

    let with_header = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{child_user}"))
        .insert_header(("Cookie", format!("axiam_access={access}")))
        .insert_header((ACTIVE_TENANT_HEADER, f.child_tenant_id.to_string()))
        .to_request();
    assert_eq!(
        test::call_service(&app, with_header)
            .await
            .status()
            .as_u16(),
        200,
        "a request about ANOTHER user acts on the selected tenant, as before"
    );

    let without_header = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{child_user}"))
        .insert_header(("Cookie", format!("axiam_access={access}")))
        .to_request();
    assert_eq!(
        test::call_service(&app, without_header)
            .await
            .status()
            .as_u16(),
        404,
        "and without a selected tenant that user is not in scope at all — the \
         self-service rule must not widen anything"
    );
}

/// `PUT /api/v1/users/{id}` for the caller's own id — the profile edit form.
#[actix_rt::test]
async fn an_org_admin_can_edit_their_own_profile_while_acting_on_a_child_tenant() {
    let f = setup().await;
    let auth = test_auth_config();
    let state = AppState::for_test(f.db.clone(), auth.clone());
    let app = test_app!(f, auth, state);

    let (access, csrf) = login_at_org_scope(&app, ADMIN_PASSWORD.as_str()).await;

    let req = test::TestRequest::put()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{}", f.admin_id))
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf))
        .insert_header((ACTIVE_TENANT_HEADER, f.child_tenant_id.to_string()))
        .set_json(json!({ "metadata": { "display_name": "Org Admin" } }))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200);

    // The write landed on the row in the organization scope — not on a row
    // conjured in the child tenant, and not nowhere at all.
    let stored = SurrealUserRepository::new(f.db.clone())
        .get_by_id(f.org_tenant_id, f.admin_id)
        .await
        .unwrap();
    assert_eq!(
        stored.metadata["display_name"],
        json!("Org Admin"),
        "a self-update is written to the tenant the account lives in"
    );
}

/// `GET /api/v1/users/{id}/mfa-methods` for the caller's own id.
///
/// The Security section of the profile page. It came back empty rather than
/// erroring, which is what an account with no second factor looks like — so the
/// page invited an administrator who had already enrolled TOTP to enrol it
/// again.
#[actix_rt::test]
async fn an_org_admin_can_list_their_own_mfa_methods_while_acting_on_a_child_tenant() {
    let f = setup().await;
    let auth = test_auth_config();
    let state = AppState::for_test(f.db.clone(), auth.clone());
    let app = test_app!(f, auth, state);

    let (access, _) = login_at_org_scope(&app, ADMIN_PASSWORD.as_str()).await;

    let req = test::TestRequest::get()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/api/v1/users/{}/mfa-methods", f.admin_id))
        .insert_header(("Cookie", format!("axiam_access={access}")))
        .insert_header((ACTIVE_TENANT_HEADER, f.child_tenant_id.to_string()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "listing the caller's own factors must not depend on which tenant is \
         selected"
    );
}

/// `POST /api/v1/auth/mfa/enroll` — enrolling a second factor on the caller's
/// own account, with a child tenant selected.
#[actix_rt::test]
async fn an_org_admin_can_enroll_mfa_while_acting_on_a_child_tenant() {
    let f = setup().await;
    // TOTP secrets are AES-256-GCM encrypted at rest, so enrolment refuses to
    // run at all without a key — a 500 that has nothing to do with tenants.
    let auth = AuthConfig {
        mfa_encryption_key: Some([3u8; 32]),
        ..test_auth_config()
    };
    let state = AppState::for_test(f.db.clone(), auth.clone());
    let app = test_app!(f, auth, state);

    let (access, csrf) = login_at_org_scope(&app, ADMIN_PASSWORD.as_str()).await;

    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri("/api/v1/auth/mfa/enroll")
        .insert_header((
            "Cookie",
            format!("axiam_access={access}; axiam_csrf={csrf}"),
        ))
        .insert_header(("X-CSRF-Token", csrf))
        .insert_header((ACTIVE_TENANT_HEADER, f.child_tenant_id.to_string()))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "enrolment is about the caller's own account, wherever it is acting"
    );
    let body: Value = test::read_body_json(resp).await;
    assert!(
        body["secret_base32"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "a secret is minted for the account in the organization scope"
    );
}

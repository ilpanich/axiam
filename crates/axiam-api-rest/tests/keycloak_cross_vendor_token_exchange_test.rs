//! R5.4 (X4 cross-vendor proof) — exchange a token actually minted by a real
//! Keycloak, not a hand-rolled JWT shaped like one.
//!
//! `external_token_exchange_test.rs:19-27` names this gap explicitly: its
//! mock IdP (wiremock, an RSA key this test file itself controls) proves the
//! *seam* — signature verification, claim-shape handling, the SSRF-guarded
//! JWKS fetch — but "a hand-rolled 'Keycloak-shaped' token would prove only
//! that this file and this file's author agree." This file is the other
//! half: same seam, a real Keycloak container as the subject-token issuer.
//!
//! # This test is `#[ignore]`d and was never run by the agent that wrote it
//!
//! There is no docker daemon in that environment. This test compiles
//! (`cargo test -p axiam-api-rest --test keycloak_cross_vendor_token_exchange_test
//! -- --list`) and was read closely against the real Keycloak Admin REST API
//! and `axiam-federation`/`axiam-oauth2` source it drives, but it has never
//! executed against a live Keycloak. Do not read a green compile as a green
//! run.
//!
//! # How to run it for real
//!
//! ```text
//! docker compose -f docker/docker-compose.e2e.yml up -d --wait keycloak
//! KEYCLOAK_URL=http://localhost:8180 \
//!   cargo test -p axiam-api-rest --test keycloak_cross_vendor_token_exchange_test \
//!   -- --ignored --test-threads=1
//! ```
//!
//! `KEYCLOAK_URL` must be a loopback address reachable from wherever `cargo
//! test` itself runs (not a docker-internal service name) — see the SSRF
//! section below for why that is load-bearing, not incidental.
//!
//! # Why this runs against Keycloak over loopback, not against the
//! containerized `axiam-server`
//!
//! `docker-compose.e2e.yml`'s `axiam-server` service is production code
//! (`docker/Dockerfile.server`, built from PR source) and constructs its
//! `JwksCache`/`OidcFederationService` via `JwksCache::new()` — the SSRF
//! guard (SEC-054, `axiam_pki::ssrf`) active, as it always is in production.
//! That guard has **no allowlist mechanism**: `is_disallowed_ip` rejects
//! every RFC1918/loopback/link-local address unconditionally, and
//! `guarded_fetch` requires HTTPS on every hop unless the *test-only*
//! `allow_private` seam is set — which nothing in the compiled binary ever
//! sets. Docker Compose's internal network addresses (and the `keycloak`
//! service name, which resolves to one) are exactly the range that guard
//! exists to block. So the real, containerized `axiam-server`, run as
//! production runs it, **cannot** reach a same-network Keycloak to fetch its
//! JWKS — not as an oversight, but as SEC-054/D-01a doing its job. Making it
//! reach one would mean either weakening a reviewed security control or
//! adding a still-nonexistent operator-configurable allowlist, and neither
//! is this task's call to make unilaterally.
//!
//! What *is* available, and is exactly the mechanism
//! `external_token_exchange_test.rs` already uses for its wiremock IdP, is
//! the documented test seam: `JwksCache::new_allow_private_networks()` /
//! `OidcFederationService::discover`'s `allow_private` bit, built for
//! "cross-crate integration tests [to] point the JWKS fetcher at a loopback
//! mock server". Keycloak published on `localhost:8180` by
//! `docker-compose.e2e.yml` **is** a loopback server from the point of view
//! of a `cargo test` process running on the CI runner (not inside a
//! container) — so this file builds the same kind of in-process
//! `actix_web::test::init_service` app `external_token_exchange_test.rs`
//! does, wires the *same* test seam, and points it at Keycloak instead of
//! wiremock. Every other line of AXIAM code that runs — signature
//! verification, claim mapping, scope-map evaluation, RBAC, token minting —
//! is the same production code the containerized server would run; only the
//! IdP is swapped from "signed by a key this file generated" to "signed by a
//! real, independently-running Keycloak", which is the entire point of X4's
//! cross-vendor proof.
//!
//! # What this proves that the wiremock test cannot
//!
//! - The subject token is minted by Keycloak's actual token endpoint
//!   (Resource Owner Password Credentials), not assembled claim-by-claim.
//! - Keycloak's actual `.well-known/openid-configuration` and JWKS documents
//!   are fetched and parsed for real — their exact shape, not a shape this
//!   file's author guessed at.
//! - Keycloak's actual default claim shapes (`scope`, an `aud` claim
//!   produced by a real Audience protocol mapper) are what
//!   `axiam_federation::token_exchange::asserted_values` reads — proving the
//!   claim-shape table in that module's doc comment against the vendor it
//!   names, not a synthetic stand-in for it.

use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use actix_web::{App, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::authz::{AllowAllAuthzChecker, AuthzChecker};
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::federation::{
    CreateFederationConfig, FederationProtocol, SubjectMapping, TokenExchangeTrust,
};
use axiam_core::models::oauth2_client::CreateOAuth2Client;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::{CreatePermission, PermissionEffect};
use axiam_core::models::role::AssignmentScope;
use axiam_core::models::role::CreateRole;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    FederationConfigRepository, FederationLinkRepository, OAuth2ClientRepository,
    OrganizationRepository, PermissionRepository, RoleRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealFederationConfigRepository, SurrealFederationLinkRepository,
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealPermissionRepository,
    SurrealRoleRepository, SurrealTenantRepository, SurrealUserRepository,
};
use axiam_federation::jwks_cache::JwksCache;
use axiam_federation::oidc::OidcFederationService;
use axiam_oauth2::token_exchange::{TOKEN_EXCHANGE_GRANT_TYPE, TOKEN_TYPE_ACCESS_TOKEN};
use serde_json::{Value, json};
use std::sync::Arc;
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const TEST_PEER: &str = "127.0.0.1:34601";
const TEST_PASSWORD: &str = "test-only-placeholder-not-a-real-password"; // gitleaks:allow
const TEST_FED_ENC_KEY: [u8; 32] = [0x2a; 32];

/// The `aud` value Keycloak is made to stamp into the token, via an explicit
/// "Audience" protocol mapper set up at seed time — deliberately not left to
/// Keycloak's own default (which, absent a mapper, may omit an audience
/// naming this client at all). Controlling it explicitly, the way a real
/// integrator would, is what lets this file assert AXIAM's own configured
/// `accepted_audiences` against a known value instead of guessing Keycloak's
/// undocumented default.
const AXIAM_AUDIENCE: &str = "https://api.axiam.test";

/// Realm/client/user names. A fixed, distinctive realm name rather than a
/// random one: a fresh `docker compose up` gives a fresh Keycloak with no
/// such realm, and a fixed name makes a failed run's state inspectable by
/// hand (`docker compose exec keycloak ...`) without hunting for a UUID.
const REALM: &str = "axiam-x4-e2e";
const CLIENT_ID: &str = "axiam-cross-vendor-test";
const CLIENT_SECRET: &str = "x4-e2e-client-secret"; // gitleaks:allow -- ephemeral, torn down with the stack
const USERNAME: &str = "axiam-x4-user";
const USER_PASSWORD: &str = "X4-E2E-User-Pass1!"; // gitleaks:allow -- ephemeral, torn down with the stack
const CUSTOM_SCOPE: &str = "partner.orders.read";

fn keycloak_url() -> String {
    std::env::var("KEYCLOAK_URL").unwrap_or_else(|_| "http://localhost:8180".to_string())
}

fn keycloak_admin_user() -> String {
    std::env::var("E2E_KEYCLOAK_ADMIN").unwrap_or_else(|_| "admin".to_string())
}

fn keycloak_admin_password() -> String {
    std::env::var("E2E_KEYCLOAK_ADMIN_PASSWORD").unwrap_or_else(|_| "admin".to_string())
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// Keycloak Admin REST API — the same operations, and the same
// already-battle-tested pitfalls, as `benchmarks/runner/seed.sh`'s
// `seed_keycloak()` (bash). Reimplemented in Rust here because this fixture
// has to run from inside a `cargo test` process, not a shell step, but every
// field this sets exists because that script's comments document a real,
// previously-hit failure mode for omitting it (VERIFY_PROFILE required
// actions blocking ROPC, `directAccessGrantsEnabled` defaulting off, ...).
// ---------------------------------------------------------------------------

struct KeycloakAdmin {
    base: String,
    client: reqwest::Client,
    token: String,
}

impl KeycloakAdmin {
    async fn login() -> Self {
        let base = keycloak_url();
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("reqwest client");
        let resp = client
            .post(format!(
                "{base}/realms/master/protocol/openid-connect/token"
            ))
            .form(&[
                ("grant_type", "password"),
                ("client_id", "admin-cli"),
                ("username", &keycloak_admin_user()),
                ("password", &keycloak_admin_password()),
            ])
            .send()
            .await
            .expect("reach Keycloak's master realm token endpoint");
        assert!(
            resp.status().is_success(),
            "Keycloak admin login failed: {}",
            resp.status()
        );
        let body: Value = resp.json().await.expect("admin token response is JSON");
        let token = body["access_token"]
            .as_str()
            .expect("admin token response has access_token")
            .to_string();
        Self {
            base,
            client,
            token,
        }
    }

    async fn post(&self, path: &str, body: Value) -> (u16, Value) {
        let resp = self
            .client
            .post(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("POST {path} failed: {e}"));
        let status = resp.status().as_u16();
        let text = resp.text().await.unwrap_or_default();
        let json = serde_json::from_str(&text).unwrap_or(Value::Null);
        (status, json)
    }

    async fn put(&self, path: &str, body: Value) -> u16 {
        let resp = self
            .client
            .put(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .unwrap_or_else(|e| panic!("PUT {path} failed: {e}"));
        resp.status().as_u16()
    }

    async fn get(&self, path: &str) -> Value {
        let resp = self
            .client
            .get(format!("{}{path}", self.base))
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap_or_else(|e| panic!("GET {path} failed: {e}"));
        assert!(
            resp.status().is_success(),
            "GET {path} -> {}",
            resp.status()
        );
        resp.json().await.expect("valid JSON body")
    }
}

/// Fully seeds the realm this test needs: the realm itself, a confidential
/// client with ROPC + an Audience mapper stamping [`AXIAM_AUDIENCE`], a
/// custom default client scope (so every token from this client carries
/// [`CUSTOM_SCOPE`] in its `scope` claim without the caller having to ask for
/// it), and a fully-set-up user (no lingering `requiredActions`, or ROPC
/// fails "Account is not fully set up" — the exact pitfall
/// `benchmarks/runner/seed.sh` documents at length).
///
/// Returns the Keycloak-internal user id (`sub` of every token this user
/// gets), needed to create the AXIAM-side `FederationLink`.
async fn seed_keycloak(kc: &KeycloakAdmin) -> Uuid {
    // --- realm -----------------------------------------------------------
    kc.post("/admin/realms", json!({ "realm": REALM, "enabled": true }))
        .await;

    // --- a custom default client scope, so `scope` always carries
    //     CUSTOM_SCOPE without a per-request `scope=` parameter ------------
    kc.post(
        &format!("/admin/realms/{REALM}/client-scopes"),
        json!({
            "name": CUSTOM_SCOPE,
            "protocol": "openid-connect",
            "attributes": { "include.in.token.scope": "true" }
        }),
    )
    .await;
    let scopes = kc
        .get(&format!("/admin/realms/{REALM}/client-scopes"))
        .await;
    let scope_id = scopes
        .as_array()
        .expect("client-scopes list")
        .iter()
        .find(|s| s["name"] == CUSTOM_SCOPE)
        .and_then(|s| s["id"].as_str())
        .expect("the client scope this test just created")
        .to_string();

    // --- the confidential client ------------------------------------------
    kc.post(
        &format!("/admin/realms/{REALM}/clients"),
        json!({
            "clientId": CLIENT_ID,
            "secret": CLIENT_SECRET,
            "enabled": true,
            "publicClient": false,
            "serviceAccountsEnabled": true,
            "directAccessGrantsEnabled": true,
            "standardFlowEnabled": false,
            "redirectUris": ["https://orders.internal/*"]
        }),
    )
    .await;
    let clients = kc
        .get(&format!(
            "/admin/realms/{REALM}/clients?clientId={CLIENT_ID}"
        ))
        .await;
    let client_uuid = clients
        .as_array()
        .and_then(|a| a.first())
        .and_then(|c| c["id"].as_str())
        .expect("the client this test just created")
        .to_string();

    // Attach the custom scope as DEFAULT (not optional) — every token from
    // this client carries it, matching `TrustSpec::default()`'s
    // `scope_map` in `external_token_exchange_test.rs`, which the AXIAM side
    // of this test mirrors.
    let put_status = kc
        .put(
            &format!(
                "/admin/realms/{REALM}/clients/{client_uuid}/default-client-scopes/{scope_id}"
            ),
            Value::Null,
        )
        .await;
    assert!(
        put_status == 204 || put_status == 201,
        "attaching the default client scope failed: {put_status}"
    );

    // An explicit Audience protocol mapper: Keycloak does not, by default,
    // stamp a client's own `clientId` (or any fixed value) into `aud` —
    // that requires this mapper. Controlling `aud` explicitly is what makes
    // `AXIAM_AUDIENCE` a contract this test can assert, not a guess about
    // Keycloak's stock behaviour.
    kc.post(
        &format!("/admin/realms/{REALM}/clients/{client_uuid}/protocol-mappers/models"),
        json!({
            "name": "x4-audience",
            "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {
                "included.custom.audience": AXIAM_AUDIENCE,
                "id.token.claim": "false",
                "access.token.claim": "true"
            }
        }),
    )
    .await;

    // --- the user -----------------------------------------------------
    // firstName/lastName + requiredActions: [] are required for a loginable
    // account under Keycloak's declarative user profile (24+) — omitting
    // them attaches VERIFY_PROFILE on first login, which ROPC (a
    // non-interactive grant) cannot satisfy. Ported directly from
    // `benchmarks/runner/seed.sh`'s documented fix for exactly this.
    kc.post(
        &format!("/admin/realms/{REALM}/users"),
        json!({
            "username": USERNAME,
            "enabled": true,
            "email": "x4-e2e-user@example.invalid",
            "emailVerified": true,
            "firstName": "X4",
            "lastName": "E2E",
            "requiredActions": [],
            "credentials": [{ "type": "password", "value": USER_PASSWORD, "temporary": false }]
        }),
    )
    .await;
    let users = kc
        .get(&format!(
            "/admin/realms/{REALM}/users?username={USERNAME}&exact=true"
        ))
        .await;
    let user_id = users
        .as_array()
        .and_then(|a| a.first())
        .and_then(|u| u["id"].as_str())
        .expect("the user this test just created")
        .to_string();

    // Idempotency for local re-runs (mirrors seed.sh): a leftover user from
    // an earlier run keeps its old state on a 409, so force the fields ROPC
    // needs regardless.
    kc.put(
        &format!("/admin/realms/{REALM}/users/{user_id}"),
        json!({
            "enabled": true,
            "emailVerified": true,
            "firstName": "X4",
            "lastName": "E2E",
            "requiredActions": []
        }),
    )
    .await;

    Uuid::parse_str(&user_id).expect("Keycloak user ids are UUIDs")
}

/// Resource Owner Password Credentials against Keycloak's own token
/// endpoint — a real access token, signed by Keycloak's realm key, that
/// AXIAM has never seen constructed.
async fn mint_keycloak_access_token(client: &reqwest::Client) -> String {
    let base = keycloak_url();
    let resp = client
        .post(format!(
            "{base}/realms/{REALM}/protocol/openid-connect/token"
        ))
        .form(&[
            ("grant_type", "password"),
            ("client_id", CLIENT_ID),
            ("client_secret", CLIENT_SECRET),
            ("username", USERNAME),
            ("password", USER_PASSWORD),
        ])
        .send()
        .await
        .expect("reach Keycloak's realm token endpoint");
    assert!(
        resp.status().is_success(),
        "Keycloak ROPC login failed: {} — {}",
        resp.status(),
        resp.text().await.unwrap_or_default()
    );
    let body: Value = resp.json().await.expect("token response is JSON");
    body["access_token"]
        .as_str()
        .expect("token response has access_token")
        .to_string()
}

fn claims_of(token: &str) -> Value {
    use base64::Engine;
    let payload = token.split('.').nth(1).expect("a JWT has three parts");
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .expect("base64url payload");
    serde_json::from_slice(&bytes).expect("JSON payload")
}

// ---------------------------------------------------------------------------
// AXIAM-side fixture — deliberately the same shape as
// `external_token_exchange_test.rs::setup`/`TrustSpec::default()`, so the two
// files read as "same trust configuration, different issuer".
// ---------------------------------------------------------------------------

struct Fixture {
    db: Surreal<TestDb>,
    auth: AuthConfig,
    tenant_id: Uuid,
    client_id: String,
    client_secret: String,
}

fn test_auth_config() -> AuthConfig {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519");
    AuthConfig {
        jwt_private_key_pem: kp.serialize_pem(),
        jwt_public_key_pem: kp.public_key_pem(),
        access_token_lifetime_secs: 900,
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.axiam.test".into(),
        federation_encryption_key: Some(TEST_FED_ENC_KEY),
        ..AuthConfig::default()
    }
}

/// Build the AXIAM tenant/user/client/federation-config fixture, trusting
/// the real Keycloak realm [`seed_keycloak`] just set up. `keycloak_user_id`
/// is that realm's user `sub` — AXIAM links to it exactly the way an
/// operator would after seeing the first login attempt in an audit log.
async fn setup(keycloak_user_id: Uuid) -> Fixture {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();

    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "X4 Cross-Vendor Org".into(),
            slug: "org-x4-keycloak".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "X4 Cross-Vendor Tenant".into(),
            slug: "tenant-x4-keycloak".into(),
            metadata: None,
        })
        .await
        .unwrap();

    let user_repo = SurrealUserRepository::new(db.clone());
    let user = user_repo
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "keycloak-linked-user".into(),
            email: "keycloak-linked@example.com".into(),
            password: TEST_PASSWORD.into(),
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

    let (client, secret) = SurrealOAuth2ClientRepository::new(db.clone())
        .create(CreateOAuth2Client {
            tenant_id: tenant.id,
            name: "edge-gateway".into(),
            redirect_uris: vec!["https://orders.internal".into()],
            grant_types: vec![TOKEN_EXCHANGE_GRANT_TYPE.into()],
            scopes: vec!["read:orders".into()],
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
        })
        .await
        .unwrap();

    // RBAC: the linked user actually holds `read:orders`.
    let role_repo = SurrealRoleRepository::new(db.clone());
    let perm_repo = SurrealPermissionRepository::new(db.clone());
    let role = role_repo
        .create(CreateRole {
            tenant_id: tenant.id,
            name: "partner-role".into(),
            description: String::new(),
            is_global: true,
        })
        .await
        .unwrap();
    role_repo
        .assign_to_user(tenant.id, user.id, role.id, AssignmentScope::global())
        .await
        .unwrap();
    let perm = perm_repo
        .create(CreatePermission {
            tenant_id: tenant.id,
            action: "read:orders".into(),
            description: String::new(),
        })
        .await
        .unwrap();
    perm_repo
        .grant_to_role_with_effect(
            tenant.id,
            role.id,
            perm.id,
            Vec::new(),
            PermissionEffect::Allow,
        )
        .await
        .unwrap();

    // The federation config, trusting REAL Keycloak's discovery document —
    // AXIAM fetches it live during the exchange call below, it is not
    // supplied here.
    let mut scope_map = std::collections::BTreeMap::new();
    scope_map.insert(CUSTOM_SCOPE.to_string(), vec!["read:orders".to_string()]);

    let fed_repo = SurrealFederationConfigRepository::new(db.clone());
    let config = fed_repo
        .create(CreateFederationConfig {
            tenant_id: tenant.id,
            provider: "Keycloak (X4 e2e)".into(),
            protocol: FederationProtocol::OidcConnect,
            metadata_url: Some(format!(
                "{}/realms/{REALM}/.well-known/openid-configuration",
                keycloak_url()
            )),
            client_id: CLIENT_ID.into(),
            client_secret: "unused-for-exchange".into(),
            attribute_map: None,
            idp_signing_cert_pem: None,
            allowed_algorithms: Some(vec!["RS256".into()]),
            token_exchange: Some(TokenExchangeTrust {
                enabled: true,
                accepted_audiences: vec![AXIAM_AUDIENCE.to_string()],
                subject_mapping: SubjectMapping::LinkedOnly,
                scope_map,
                max_token_age_secs: 300,
                max_lifetime_secs: None,
            }),
            provider_kind: None,
            provider_slug: None,
            allow_tenant_inheritance: None,
            scopes: None,
            authorization_endpoint: None,
            token_endpoint: None,
            userinfo_endpoint: None,
            allowed_issuer_tenants: None,
            apple_team_id: None,
            apple_key_id: None,
            require_pkce: None,
            button_icon: None,
        })
        .await
        .unwrap();

    SurrealFederationLinkRepository::new(db.clone())
        .create(axiam_core::models::federation::CreateFederationLink {
            tenant_id: tenant.id,
            user_id: user.id,
            federation_config_id: config.id,
            external_subject: keycloak_user_id.to_string(),
            external_email: Some("x4-e2e-user@example.invalid".into()),
        })
        .await
        .unwrap();

    Fixture {
        db,
        auth: test_auth_config(),
        tenant_id: tenant.id,
        client_id: client.client_id,
        client_secret: secret,
    }
}

fn enc(s: &str) -> String {
    s.replace(':', "%3A").replace('/', "%2F")
}

// ---------------------------------------------------------------------------
// The test
// ---------------------------------------------------------------------------

/// A trusted-provider (X4) exchange where the subject token is real,
/// independently-issued Keycloak output — RFC 8693's token-exchange grant,
/// proved cross-vendor rather than against a fixture of this file's own
/// making.
///
/// `#[ignore]`d: needs a live Keycloak reachable at `KEYCLOAK_URL`
/// (default `http://localhost:8180`). See the module docs for how to run it.
#[actix_web::test]
#[ignore = "needs a live Keycloak container (docker/docker-compose.e2e.yml); see module docs"]
async fn a_real_keycloak_tokens_buys_a_scoped_axiam_token() {
    let kc = KeycloakAdmin::login().await;
    let keycloak_user_id = seed_keycloak(&kc).await;

    let f = setup(keycloak_user_id).await;

    let http = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let keycloak_token = mint_keycloak_access_token(&http).await;

    // Sanity on the real token before handing it to AXIAM — if this fails,
    // the seed above did not produce what the rest of the test assumes, and
    // that is a Keycloak-seeding bug, not an AXIAM one.
    let kc_claims = claims_of(&keycloak_token);
    assert_eq!(
        kc_claims["sub"],
        keycloak_user_id.to_string(),
        "Keycloak's own token names the user this test created"
    );

    let jwks_cache = Arc::new(JwksCache::new_allow_private_networks());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(f.auth.clone()))
            .app_data(web::Data::new({
                let mut state = AppState::for_test(f.db.clone(), f.auth.clone());
                // The loopback seam (see module docs): without it the SSRF
                // guard refuses real Keycloak on `localhost` for the same
                // reason it refuses the wiremock IdP in the sibling test.
                state.http_client = reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(std::time::Duration::from_secs(10))
                    .build()
                    .unwrap();
                state.jwks_cache = Arc::clone(&jwks_cache);
                state.federation.oidc_federation_service = Some(OidcFederationService::new(
                    state.federation.federation_config_repo.clone(),
                    state.federation.federation_link_repo.clone(),
                    state.user_repo.clone(),
                    state.http_client.clone(),
                    Arc::clone(&jwks_cache),
                    TEST_FED_ENC_KEY,
                ));
                assert!(
                    state.enable_external_token_exchange(),
                    "the federation service is installed, so X4 must switch on"
                );
                state
            }))
            .app_data(web::Data::new(
                Arc::new(AllowAllAuthzChecker) as Arc<dyn AuthzChecker>
            ))
            .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())),
    )
    .await;

    let body = format!(
        "grant_type={}&client_id={}&client_secret={}&subject_token={keycloak_token}&subject_token_type={}",
        enc(TOKEN_EXCHANGE_GRANT_TYPE),
        f.client_id,
        f.client_secret,
        enc(TOKEN_TYPE_ACCESS_TOKEN),
    );
    let req = test::TestRequest::post()
        .peer_addr(TEST_PEER.parse::<SocketAddr>().unwrap())
        .uri(&format!("/oauth2/token?tenant_id={}", f.tenant_id))
        .insert_header(("content-type", "application/x-www-form-urlencoded"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    let status = resp.status().as_u16();
    let response: Value = test::read_body_json(resp).await;

    assert_eq!(status, 200, "{response:?}");
    assert_eq!(response["token_type"], "Bearer");
    assert_eq!(
        response["scope"], "read:orders",
        "Keycloak's own `scope` claim carried {CUSTOM_SCOPE}, mapped by AXIAM's \
         configured scope_map to read:orders"
    );

    let axiam_claims = claims_of(response["access_token"].as_str().unwrap());
    assert!(
        axiam_claims["ext_exchange"]["iss"]
            .as_str()
            .unwrap()
            .contains(REALM),
        "the issued token's provenance must name the real Keycloak realm, got: {:?}",
        axiam_claims["ext_exchange"]
    );
    assert!(
        axiam_claims["exp"].as_i64().unwrap() > now(),
        "the issued AXIAM token must not already be expired"
    );
}

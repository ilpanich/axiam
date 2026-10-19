//! `POST /api/v1/network/decide` — the RADIUS placement decision (RADIUS D4,
//! W6.4; `claude_dev/radius-reply-profile-design.md` §3.4, §4.3, §4.4, §6.3, §7,
//! §8; threat T-468).
//!
//! # How the caller's certificate reaches the handler here
//!
//! The decision route's caller must present a token bound to its own
//! certificate over a connection whose TLS-verified client certificate is that
//! one. `actix_web::test::TestRequest` builds every request with no connection
//! data, so no test driven through it can carry a verified certificate (the
//! S-3 note in `m2m_management_test.rs`). These tests therefore run the real
//! route table behind a real `HttpServer` on a loopback socket, whose
//! `on_connect` hook inserts the [`VerifiedClientCert`] the TLS layer would have
//! — exactly what `axiam-server`'s `lift_verified_client_certificate` does after
//! rustls verified the chain. The hook stands in for the handshake; everything
//! from the extractor's sender-constraint check onwards is the production code.
//! The certificates are real: an organization root flagged as an mTLS trust
//! anchor, a signing CA per tenant, Ed25519 leaves issued by `CertService` and
//! bound to service accounts, so `DeviceAuthService::authenticate_der` verifies
//! every chain it is given.

use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use actix_web::dev::{Extensions, ServerHandle};
use actix_web::{App, HttpServer, test, web};
use axiam_api_rest::RateLimitConfig;
use axiam_api_rest::VerifiedClientCert;
use axiam_api_rest::authz::AuthzChecker;
use axiam_api_rest::handlers::network_decide::CERTIFICATE_BOUND_REFUSAL;
use axiam_api_rest::permissions::PERMISSION_REGISTRY;
use axiam_api_rest::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{CnfClaim, issue_access_token, issue_service_account_token};
use axiam_authz::AuthorizationEngine;
use axiam_authz::types::{AccessDecision, AccessRequest};
use axiam_core::error::AxiamResult;
use axiam_core::models::audit::{AuditLogEntry, AuditOutcome};
use axiam_core::models::certificate::{
    CertTrust, CertificateType, CreateCaCertificate, CreateCertificate, CreateIntermediateCa,
    KeyAlgorithm,
};
use axiam_core::models::network::{
    NETWORK_DECIDE, NETWORK_GRANT, NETWORK_JOIN, NETWORK_PROFILES_WRITE, NETWORK_READ,
    NETWORK_SEGMENTS_WRITE, NetworkSegmentKind, NetworkWriteClearance, NetworkWriteTarget,
    SetNetworkPolicy, branch_node_id, network_root_id, site_node_id,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::permission::PermissionEffect;
use axiam_core::models::role::{AssignmentScope, CreateRole};
use axiam_core::models::service_account::{CreateServiceAccount, UpdateServiceAccount};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::{CreateUser, UpdateUser, UserStatus};
use axiam_core::repository::{
    AuditLogFilter, AuditLogRepository, CaCertificateRepository, CertificateRepository,
    NetworkPolicyRepository, OrganizationRepository, Pagination, PermissionRepository,
    RoleRepository, ServiceAccountRepository, TenantRepository, UserRepository,
};
use axiam_db::repository::{
    SurrealAuditLogRepository, SurrealGroupRepository, SurrealNetworkPolicyRepository,
    SurrealOrganizationRepository, SurrealPermissionRepository, SurrealResourceRepository,
    SurrealRoleRepository, SurrealScopeRepository, SurrealServiceAccountRepository,
    SurrealTenantRepository, SurrealUserRepository,
};
use axiam_db::{
    SurrealCaCertificateRepository, SurrealCertificateRepository, seed_default_roles,
    seed_permissions,
};
use axiam_pki::cert::IssuingScope;
use axiam_pki::{CaService, CertService, PkiConfig};
use base64::Engine as _;
use serde_json::{Value, json};
use surrealdb::Surreal;
use surrealdb::engine::local::Mem;
use uuid::Uuid;

type TestDb = surrealdb::engine::local::Db;

const CSRF_TOKEN: &str = "test-csrf-token";
const PEER: &str = "198.51.100.7:40000";
const DECIDE: &str = "/api/v1/network/decide";
const ALLOW: PermissionEffect = PermissionEffect::Allow;
const DENY: PermissionEffect = PermissionEffect::Deny;

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

/// The CA key custodians, built the way the composition root builds them.
fn test_ca_custodians() -> Arc<axiam_pki::CaKeyCustodians> {
    Arc::new(
        axiam_pki::custodians_from_env(Some([0u8; 32])) // gitleaks:allow
            .expect("test CA key custodians"),
    )
}

/// Test-only PKI encryption key (32 zero bytes) — not a real key.
fn test_pki_config() -> PkiConfig {
    PkiConfig {
        encryption_key: Some([0u8; 32]), // gitleaks:allow
        ..Default::default()
    }
}

fn page() -> Pagination {
    Pagination {
        offset: 0,
        limit: 1000,
        search: None,
    }
}

/// A device: a service account, the certificate bound to it, and its DER.
#[derive(Clone)]
struct Device {
    account: Uuid,
    certificate: Uuid,
    der: Vec<u8>,
}

impl Device {
    fn fingerprint(&self) -> String {
        use sha2::Digest as _;
        hex::encode(sha2::Sha256::digest(&self.der))
    }

    fn body(&self, site: &str) -> Value {
        json!({
            "site": site,
            "certificate": base64::engine::general_purpose::STANDARD.encode(&self.der),
        })
    }

    /// The fingerprint form of [`Device::body`].
    fn fingerprint_body(&self, site: &str) -> Value {
        json!({ "site": site, "fingerprint": self.fingerprint() })
    }
}

/// Two tenants of one organization, each with the registry, the default roles
/// and a signing CA under the organization's trust anchor.
struct World {
    db: Surreal<TestDb>,
    org: Uuid,
    tenant: Uuid,
    other_tenant: Uuid,
    auth: AuthConfig,
    certs:
        CertService<SurrealCaCertificateRepository<TestDb>, SurrealCertificateRepository<TestDb>>,
    signing_ca: Vec<(Uuid, Uuid)>,
}

impl World {
    async fn new() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "Decide Org".into(),
                slug: "decide-org".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let tenants = SurrealTenantRepository::new(db.clone());
        let mut ids = Vec::new();
        for slug in ["decide-tenant", "decide-other"] {
            let tenant = tenants
                .create(CreateTenant {
                    organization_id: org.id,
                    kind: TenantKind::Standard,
                    name: slug.into(),
                    slug: slug.into(),
                    metadata: None,
                })
                .await
                .unwrap();
            seed_permissions(&db, tenant.id, PERMISSION_REGISTRY)
                .await
                .unwrap();
            seed_default_roles(&db, tenant.id, PERMISSION_REGISTRY)
                .await
                .unwrap();
            ids.push(tenant.id);
        }

        // The PKI: an organization root flagged as an mTLS trust anchor and a
        // signing CA per tenant beneath it, as an operator sets it up.
        let ca_repo = SurrealCaCertificateRepository::new(db.clone());
        let cas = CaService::new(
            ca_repo.clone(),
            test_pki_config(),
            Arc::new(tokio::sync::Semaphore::new(4)),
            test_ca_custodians(),
        );
        let root: CreateCaCertificate = serde_json::from_value(json!({
            "organization_id": org.id,
            "subject": "Decide Root CA",
            "key_algorithm": "Ed25519",
            "validity_days": 365,
        }))
        .unwrap();
        let root = cas.generate(root).await.unwrap().certificate.id;
        ca_repo
            .set_mtls_trust_anchor(org.id, root, true)
            .await
            .unwrap();
        let mut signing_ca = Vec::new();
        for tenant in &ids {
            let signing = cas
                .generate_intermediate(CreateIntermediateCa {
                    organization_id: org.id,
                    tenant_id: *tenant,
                    parent_ca_id: root,
                    subject: "Tenant Signing CA".into(),
                    key_algorithm: KeyAlgorithm::Ed25519,
                    validity_days: 364,
                })
                .await
                .unwrap();
            signing_ca.push((*tenant, signing.certificate.id));
        }
        let certs = CertService::new(
            ca_repo,
            SurrealCertificateRepository::new(db.clone()),
            test_pki_config(),
            Arc::new(tokio::sync::Semaphore::new(4)),
            test_ca_custodians(),
        );
        Self {
            db,
            org: org.id,
            tenant: ids[0],
            other_tenant: ids[1],
            auth: test_auth_config(),
            certs,
            signing_ca,
        }
    }

    fn engine(&self) -> Arc<dyn AuthzChecker> {
        Arc::new(AuthorizationEngine::new(
            SurrealRoleRepository::new(self.db.clone()),
            SurrealPermissionRepository::new(self.db.clone()),
            SurrealResourceRepository::new(self.db.clone()),
            SurrealScopeRepository::new(self.db.clone()),
            SurrealGroupRepository::new(self.db.clone()),
        ))
    }

    async fn permission_id(&self, tenant: Uuid, action: &str) -> Uuid {
        SurrealPermissionRepository::new(self.db.clone())
            .list(tenant, page())
            .await
            .unwrap()
            .items
            .into_iter()
            .find(|p| p.action == action)
            .unwrap_or_else(|| panic!("permission {action} not seeded"))
            .id
    }

    /// A non-global role of `tenant` carrying `grants`, made directly: test
    /// setup is not the subject of these tests (the write gate's is
    /// `network_gate_test.rs`).
    async fn role(&self, tenant: Uuid, grants: &[(&str, PermissionEffect)]) -> Uuid {
        let role = SurrealRoleRepository::new(self.db.clone())
            .create(CreateRole {
                tenant_id: tenant,
                name: format!("r-{}", Uuid::new_v4().simple()),
                description: String::new(),
                is_global: false,
            })
            .await
            .unwrap();
        let perms = SurrealPermissionRepository::new(self.db.clone());
        for (action, effect) in grants {
            perms
                .grant_to_role_with_effect(
                    tenant,
                    role.id,
                    self.permission_id(tenant, action).await,
                    vec![],
                    *effect,
                )
                .await
                .unwrap();
        }
        role.id
    }

    /// Assign `grants` to service account `account` of `tenant` at `node`.
    async fn grant(
        &self,
        tenant: Uuid,
        account: Uuid,
        grants: &[(&str, PermissionEffect)],
        node: Uuid,
    ) {
        let role = self.role(tenant, grants).await;
        SurrealRoleRepository::new(self.db.clone())
            .assign_to_service_account(tenant, account, role, AssignmentScope::from(Some(node)))
            .await
            .unwrap();
    }

    /// A device of `tenant`: a service account and an Ed25519 device
    /// certificate issued under the tenant's signing CA and bound to it.
    async fn device(&self, tenant: Uuid) -> Device {
        let (account, _secret) = SurrealServiceAccountRepository::new(self.db.clone())
            .create(CreateServiceAccount {
                tenant_id: tenant,
                name: format!("dev-{}", Uuid::new_v4().simple()),
                description: None,
            })
            .await
            .unwrap();
        let issuer = self
            .signing_ca
            .iter()
            .find(|(t, _)| *t == tenant)
            .unwrap()
            .1;
        let generated = self
            .certs
            .generate(
                self.org,
                IssuingScope::Tenant,
                CreateCertificate {
                    tenant_id: tenant,
                    issuer_ca_id: issuer,
                    subject: format!("press-{}", Uuid::new_v4().simple()),
                    cert_type: CertificateType::Device,
                    key_algorithm: KeyAlgorithm::Ed25519,
                    validity_days: 90,
                    metadata: None,
                    subject_alt_names: vec![],
                    user_id: None,
                },
                None,
                &[],
            )
            .await
            .unwrap();
        let certificate = generated.certificate.id;
        SurrealCertificateRepository::new(self.db.clone())
            .bind_to_service_account(tenant, certificate, account.id)
            .await
            .unwrap();
        let (_, pem) =
            x509_parser::pem::parse_x509_pem(generated.certificate.public_cert_pem.as_bytes())
                .unwrap();
        Device {
            account: account.id,
            certificate,
            der: pem.contents,
        }
    }

    /// A FreeRADIUS caller of the default tenant: a device-shaped service
    /// account holding `network:decide` at `node`.
    async fn caller_at(&self, node: Uuid) -> Device {
        let caller = self.device(self.tenant).await;
        self.grant(
            self.tenant,
            caller.account,
            &[(NETWORK_DECIDE, ALLOW)],
            node,
        )
        .await;
        caller
    }

    /// The caller's token, bound (`cnf.x5t#S256`) to its own certificate.
    fn bound_token(&self, caller: &Device) -> String {
        issue_service_account_token(
            caller.account,
            self.tenant,
            self.org,
            Uuid::new_v4().to_string(),
            Some(CnfClaim::from_certificate_thumbprint(
                axiam_oauth2::mtls::thumbprint_s256(&caller.der),
            )),
            &self.auth,
        )
        .unwrap()
    }

    /// An active network administrator's token: read, both writes and `grant`,
    /// tenant-wide.
    async fn netadmin(&self) -> String {
        let role = self
            .role(
                self.tenant,
                &[
                    (NETWORK_READ, ALLOW),
                    (NETWORK_SEGMENTS_WRITE, ALLOW),
                    (NETWORK_PROFILES_WRITE, ALLOW),
                    (NETWORK_GRANT, ALLOW),
                ],
            )
            .await;
        let users = SurrealUserRepository::new(self.db.clone());
        let user = users
            .create(CreateUser {
                tenant_id: self.tenant,
                username: format!("u{}", Uuid::new_v4().simple()),
                email: format!("{}@example.com", Uuid::new_v4().simple()),
                password: axiam_test_support::test_password(),
                metadata: None,
            })
            .await
            .unwrap();
        users
            .update(
                self.tenant,
                user.id,
                UpdateUser {
                    status: Some(UserStatus::Active),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        SurrealRoleRepository::new(self.db.clone())
            .assign_to_user(self.tenant, user.id, role, AssignmentScope::from(None))
            .await
            .unwrap();
        self.user_token(user.id)
    }

    fn user_token(&self, user: Uuid) -> String {
        issue_access_token(
            user,
            self.tenant,
            self.org,
            &[],
            &self.auth,
            Uuid::new_v4().to_string(),
            axiam_auth::token::AUD_USER,
        )
        .unwrap()
    }

    async fn audit(&self, action: &str) -> Vec<AuditLogEntry> {
        SurrealAuditLogRepository::new(self.db.clone())
            .list(
                self.tenant,
                AuditLogFilter {
                    action: Some(action.into()),
                    ..Default::default()
                },
                page(),
            )
            .await
            .unwrap()
            .items
    }

    /// The decision rows of this tenant that name `fingerprint`.
    async fn decisions_for(&self, fingerprint: &str) -> Vec<AuditLogEntry> {
        let mut rows = self.audit("network_decision.allowed").await;
        rows.extend(self.audit("network_decision.denied").await);
        rows.retain(|r| r.metadata["certificate_fingerprint"] == fingerprint);
        rows
    }
}

// ---------------------------------------------------------------------------
// The management side, through the routes (as an administrator would)
// ---------------------------------------------------------------------------

macro_rules! admin_app {
    ($w:expr) => {{
        test::init_service(
            App::new()
                .app_data(web::Data::new($w.auth.clone()))
                .app_data(web::Data::new($w.engine()))
                .app_data(web::Data::new(AppState::for_test(
                    $w.db.clone(),
                    $w.auth.clone(),
                )))
                .configure(|cfg| {
                    register_api_v1_routes::<TestDb>(cfg, &RateLimitConfig::default())
                }),
        )
        .await
    }};
}

async fn admin_call(
    app: &impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    >,
    token: &str,
    uri: &str,
    body: Value,
) -> Value {
    let req = test::TestRequest::post()
        .uri(uri)
        .peer_addr(PEER.parse().unwrap())
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("Cookie", format!("axiam_csrf={CSRF_TOKEN}")))
        .insert_header(("X-CSRF-Token", CSRF_TOKEN))
        .set_json(body)
        .to_request();
    let resp = test::call_service(app, req).await;
    let status = resp.status().as_u16();
    let body: Value = test::read_body_json(resp).await;
    assert_eq!(status, 201, "{uri}: {body}");
    body
}

/// A site's segments, made through the management routes, each with a profile.
struct Site {
    corp: Value,
    iot: Value,
    quarantine: Value,
}

/// `hq` with `corp` (VLAN 10, rank 10), `iot` (VLAN 20, rank 20) and the
/// quarantine segment `q` (VLAN 999); each with a profile of 1800 s.
async fn site(w: &World, key: &str) -> Site {
    let app = admin_app!(w);
    let admin = w.netadmin().await;
    let mut made = Vec::new();
    for (kind, name, vlan, rank) in [
        ("access", "corp", 10, Some(10)),
        ("access", "iot", 20, Some(20)),
        ("quarantine", "q", 999, None),
    ] {
        let segment = admin_call(
            &app,
            &admin,
            "/api/v1/network/segments",
            json!({
                "kind": kind,
                "site_key": key,
                "name": name,
                "vlan_id": vlan,
                "filter_ids": ["corp-acl", "iot-acl"],
                "rank": rank,
            }),
        )
        .await;
        admin_call(
            &app,
            &admin,
            "/api/v1/network/profiles",
            json!({
                "segment_id": segment["id"],
                "segment_version": segment["version"],
                "profile": {
                    "session_timeout_secs": 1800,
                    "idle_timeout_secs": 600,
                    "filter_id": if name == "iot" { "iot-acl" } else { "corp-acl" },
                    "service_type": "framed_user",
                },
            }),
        )
        .await;
        made.push(segment);
    }
    Site {
        quarantine: made.pop().unwrap(),
        iot: made.pop().unwrap(),
        corp: made.pop().unwrap(),
    }
}

fn id(v: &Value) -> Uuid {
    v["id"].as_str().unwrap().parse().unwrap()
}

// ---------------------------------------------------------------------------
// The decision side, through a real listener
// ---------------------------------------------------------------------------

/// A running server whose every connection presents `presented` as the
/// TLS-verified client certificate (or none).
struct Listener {
    base: String,
    handle: ServerHandle,
    client: reqwest::Client,
}

impl Listener {
    async fn decide(&self, token: &str, body: Value) -> (u16, Value) {
        let resp = self
            .client
            .post(format!("{}{DECIDE}", self.base))
            .header("Authorization", format!("Bearer {token}"))
            .json(&body)
            .send()
            .await
            .expect("the listener answers");
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }

    async fn stop(self) {
        self.handle.stop(false).await;
    }
}

fn serve(
    w: &World,
    presented: Option<&Device>,
    limits: RateLimitConfig,
    authz: Arc<dyn AuthzChecker>,
) -> Listener {
    let mut state = AppState::for_test(w.db.clone(), w.auth.clone());
    state.rate_limit_cfg = limits.clone();
    let auth = w.auth.clone();
    let der = presented.map(|d| d.der.clone());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = HttpServer::new(move || {
        let limits = limits.clone();
        App::new()
            .app_data(web::Data::new(auth.clone()))
            .app_data(web::Data::new(authz.clone()))
            .app_data(web::Data::new(state.clone()))
            .configure(move |cfg| register_api_v1_routes::<TestDb>(cfg, &limits))
    })
    // What `lift_verified_client_certificate` does once rustls verified the
    // peer's chain to a configured anchor.
    .on_connect(move |_conn: &dyn std::any::Any, ext: &mut Extensions| {
        if let Some(der) = &der {
            ext.insert(VerifiedClientCert::from_der(der, CertTrust::ChainedToAnchor).unwrap());
        }
    })
    .workers(1)
    .listen(listener)
    .expect("listen")
    .run();
    let handle = server.handle();
    actix_rt::spawn(server);
    Listener {
        base: format!("http://{addr}"),
        handle,
        client: reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .build()
            .unwrap(),
    }
}

fn attribute<'a>(reply: &'a Value, name: &str) -> &'a Value {
    reply["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == name)
        .unwrap_or_else(|| panic!("no {name} in {reply}"))
}

// ---------------------------------------------------------------------------
// Allow, with the profile's attributes
// ---------------------------------------------------------------------------

/// A device that may join `iot` is placed there: the segment's tunnel triple
/// (tag 0 on the integers, no tag octet on the VLAN string) and the profile's
/// fields, `Session-Timeout` clamped to the tenant's current cap. One audit row
/// with the placement and the certificate's fingerprint — never its subject.
#[actix_rt::test]
async fn a_device_is_placed_with_its_segments_attributes() {
    let w = World::new().await;
    let s = site(&w, "hq").await;
    let caller = w.caller_at(network_root_id(w.tenant)).await;
    let device = w.device(w.tenant).await;
    w.grant(
        w.tenant,
        device.account,
        &[(NETWORK_JOIN, ALLOW)],
        id(&s.iot),
    )
    .await;
    // Lowered below the stored 1800 after the profile was written (allowed:
    // reads clamp, which only narrows).
    let actor = Uuid::new_v4();
    SurrealNetworkPolicyRepository::new(w.db.clone())
        .set(
            w.tenant,
            SetNetworkPolicy {
                session_timeout_max_secs: 900,
                expected_version: 0,
                actor,
            },
            // Test setup stands in for the gate, as for the segments above.
            &NetworkWriteClearance::issued_by_the_network_gate(
                w.tenant,
                actor,
                NetworkWriteTarget::PolicyWrite,
            ),
        )
        .await
        .unwrap();
    let srv = serve(&w, Some(&caller), RateLimitConfig::default(), w.engine());

    let (status, body) = srv.decide(&w.bound_token(&caller), device.body("hq")).await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(body["allow"], true);
    let reply = &body["reply"];
    assert_eq!(reply["dictionary"], "axiam-radius-reply/1");
    assert_eq!(
        attribute(reply, "Tunnel-Type"),
        &json!({"name": "Tunnel-Type", "number": 64, "value": 13, "tag": 0})
    );
    assert_eq!(
        attribute(reply, "Tunnel-Medium-Type"),
        &json!({"name": "Tunnel-Medium-Type", "number": 65, "value": 6, "tag": 0})
    );
    assert_eq!(
        attribute(reply, "Tunnel-Private-Group-Id"),
        &json!({"name": "Tunnel-Private-Group-Id", "number": 81, "value": "20"}),
        "the VLAN string carries no tag octet"
    );
    assert_eq!(attribute(reply, "Session-Timeout")["value"], 900);
    assert_eq!(attribute(reply, "Idle-Timeout")["value"], 600);
    assert_eq!(attribute(reply, "Termination-Action")["value"], 1);
    assert_eq!(attribute(reply, "Filter-Id")["value"], "iot-acl");
    assert_eq!(attribute(reply, "Service-Type")["value"], 2);
    assert_eq!(reply["attributes"].as_array().unwrap().len(), 8);

    // The fingerprint form is the same decision.
    let (status, body2) = srv
        .decide(
            &w.bound_token(&caller),
            json!({"site": "hq", "fingerprint": device.fingerprint().to_uppercase()}),
        )
        .await;
    assert_eq!(status, 200, "{body2}");
    assert_eq!(body2, body);

    let rows = w.decisions_for(&device.fingerprint()).await;
    assert_eq!(rows.len(), 2, "one row per decision: {rows:?}");
    let row = &rows[0];
    assert_eq!(row.action, "network_decision.allowed");
    assert_eq!(row.outcome, AuditOutcome::Success);
    assert_eq!(row.actor_id, caller.account);
    assert_eq!(row.resource_id, Some(id(&s.iot)));
    let m = &row.metadata;
    assert_eq!(m["reason"], "placement:access");
    assert_eq!(m["site"], "hq");
    assert_eq!(m["vlan_id"], 20);
    assert_eq!(m["subject_id"], device.account.to_string());
    assert_eq!(m["certificate_id"], device.certificate.to_string());
    assert_eq!(m["session_timeout_secs"], 900);
    assert_eq!(m["session_timeout_clamped"], true);
    assert_eq!(m["method"], "eap_tls");
    // §8: the certificate's subject (its common name) is not in the row.
    let rendered = serde_json::to_string(m).unwrap();
    assert!(!rendered.contains("press-"), "{rendered}");
    srv.stop().await;
}

// ---------------------------------------------------------------------------
// Revocation, a disabled account, another tenant
// ---------------------------------------------------------------------------

/// A revoked certificate, and a disabled account, are `allow: false` at the
/// very next request (T-462's CRL lag closes for D4), with no reason on the
/// wire and the internal one in the row.
#[actix_rt::test]
async fn revocation_and_a_disabled_account_refuse_at_the_next_request() {
    let w = World::new().await;
    let s = site(&w, "hq").await;
    let caller = w.caller_at(network_root_id(w.tenant)).await;
    let revoked = w.device(w.tenant).await;
    let disabled = w.device(w.tenant).await;
    for d in [&revoked, &disabled] {
        w.grant(w.tenant, d.account, &[(NETWORK_JOIN, ALLOW)], id(&s.corp))
            .await;
    }
    let srv = serve(&w, Some(&caller), RateLimitConfig::default(), w.engine());
    let token = w.bound_token(&caller);
    for d in [&revoked, &disabled] {
        let (status, body) = srv.decide(&token, d.body("hq")).await;
        assert_eq!(
            (status, body["allow"].clone()),
            (200, json!(true)),
            "{body}"
        );
    }

    SurrealCertificateRepository::new(w.db.clone())
        .revoke(w.tenant, revoked.certificate)
        .await
        .unwrap();
    SurrealServiceAccountRepository::new(w.db.clone())
        .update(
            w.tenant,
            disabled.account,
            UpdateServiceAccount {
                status: Some(UserStatus::Inactive),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    for (d, reason) in [
        (&revoked, "certificate:revoked"),
        (&disabled, "account:inactive"),
    ] {
        let (status, body) = srv.decide(&token, d.body("hq")).await;
        assert_eq!(status, 200);
        assert_eq!(body, json!({"allow": false}), "no reason on the wire");
        let rows = w.decisions_for(&d.fingerprint()).await;
        let last = rows
            .iter()
            .find(|r| r.action == "network_decision.denied")
            .expect("a denied row");
        assert_eq!(last.outcome, AuditOutcome::Denied);
        assert_eq!(last.metadata["reason"], reason);
    }
    srv.stop().await;
}

/// A certificate another tenant issued and bound — valid, and placed in its own
/// tenant — is `allow: false` here (§7), and the caller's tenant's row records
/// it by fingerprint alone: no id of the other tenant's certificate or account.
#[actix_rt::test]
async fn another_tenants_certificate_is_refused() {
    let w = World::new().await;
    let s = site(&w, "hq").await;
    let caller = w.caller_at(network_root_id(w.tenant)).await;
    let foreign = w.device(w.other_tenant).await;
    // Even holding a join allow on this tenant's segment id changes nothing:
    // the subject is never the other tenant's account.
    w.grant(
        w.other_tenant,
        foreign.account,
        &[(NETWORK_JOIN, ALLOW)],
        id(&s.corp),
    )
    .await;
    let srv = serve(&w, Some(&caller), RateLimitConfig::default(), w.engine());

    let (status, body) = srv
        .decide(&w.bound_token(&caller), foreign.body("hq"))
        .await;
    assert_eq!(status, 200);
    assert_eq!(body, json!({"allow": false}));
    let rows = w.decisions_for(&foreign.fingerprint()).await;
    assert_eq!(rows.len(), 1);
    let m = &rows[0].metadata;
    assert_eq!(m["reason"], "certificate:not_in_tenant");
    assert!(
        m.get("certificate_id").is_none() && m.get("subject_id").is_none(),
        "{m}"
    );
    // A certificate nobody issued reads the same.
    let mut forged = foreign.clone();
    forged.der[40] ^= 0xff;
    let (status, body) = srv.decide(&w.bound_token(&caller), forged.body("hq")).await;
    assert_eq!((status, body), (200, json!({"allow": false})));
    let rows = w.decisions_for(&forged.fingerprint()).await;
    assert_eq!(rows[0].metadata["reason"], "certificate:not_in_tenant");
    srv.stop().await;
}

// ---------------------------------------------------------------------------
// Quarantine by deny-override (§4.4)
// ---------------------------------------------------------------------------

/// Q1/Q2/Q4 of the note's table: a join allow on the site (the parent of
/// `corp` and `iot`) places the device on `corp` (the lowest rank); a deny at
/// `/network/zones` beats that parent allow and the device lands on the
/// quarantine segment its baseline allows; without the baseline it is refused.
#[actix_rt::test]
async fn a_quarantine_deny_beats_a_parent_allow() {
    let w = World::new().await;
    let s = site(&w, "hq").await;
    let caller = w.caller_at(network_root_id(w.tenant)).await;
    let free = w.device(w.tenant).await;
    let quarantined = w.device(w.tenant).await;
    let unbaselined = w.device(w.tenant).await;
    let zones_site = site_node_id(w.tenant, NetworkSegmentKind::Access, "hq");
    let quarantine_site = site_node_id(w.tenant, NetworkSegmentKind::Quarantine, "hq");
    for d in [&free, &quarantined, &unbaselined] {
        w.grant(w.tenant, d.account, &[(NETWORK_JOIN, ALLOW)], zones_site)
            .await;
    }
    for d in [&free, &quarantined] {
        w.grant(
            w.tenant,
            d.account,
            &[(NETWORK_JOIN, ALLOW)],
            quarantine_site,
        )
        .await;
    }
    let zones = branch_node_id(w.tenant, NetworkSegmentKind::Access);
    for d in [&quarantined, &unbaselined] {
        w.grant(w.tenant, d.account, &[(NETWORK_JOIN, DENY)], zones)
            .await;
    }
    let srv = serve(&w, Some(&caller), RateLimitConfig::default(), w.engine());
    let token = w.bound_token(&caller);

    let (_, body) = srv.decide(&token, free.body("hq")).await;
    assert_eq!(
        attribute(&body["reply"], "Tunnel-Private-Group-Id")["value"],
        "10"
    );

    let (_, body) = srv.decide(&token, quarantined.body("hq")).await;
    assert_eq!(body["allow"], true, "{body}");
    assert_eq!(
        attribute(&body["reply"], "Tunnel-Private-Group-Id")["value"],
        "999"
    );
    let rows = w.decisions_for(&quarantined.fingerprint()).await;
    let m = &rows[0].metadata;
    assert_eq!(m["reason"], "placement:quarantine");
    assert_eq!(m["segment_id"], s.quarantine["id"]);

    let (_, body) = srv.decide(&token, unbaselined.body("hq")).await;
    assert_eq!(body, json!({"allow": false}));
    let rows = w.decisions_for(&unbaselined.fingerprint()).await;
    assert_eq!(rows[0].metadata["reason"], "placement:no_candidate");
    srv.stop().await;
}

// ---------------------------------------------------------------------------
// The caller
// ---------------------------------------------------------------------------

/// A caller holding `network:decide` only on another site is `403` for this
/// one, naming the permission, with an audit row; it is answered for its own.
#[actix_rt::test]
async fn a_caller_without_network_decide_on_the_site_is_403() {
    let w = World::new().await;
    site(&w, "hq").await;
    site(&w, "branch").await;
    let caller = w
        .caller_at(site_node_id(w.tenant, NetworkSegmentKind::Access, "branch"))
        .await;
    // Its decide must also cover the branch's quarantine node, which the
    // decision reads: grant it there too, so `branch` is answered.
    w.grant(
        w.tenant,
        caller.account,
        &[(NETWORK_DECIDE, ALLOW)],
        site_node_id(w.tenant, NetworkSegmentKind::Quarantine, "branch"),
    )
    .await;
    let device = w.device(w.tenant).await;
    let srv = serve(&w, Some(&caller), RateLimitConfig::default(), w.engine());
    let token = w.bound_token(&caller);

    let (status, body) = srv.decide(&token, device.body("hq")).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "authorization_denied");
    assert_eq!(body["action"], NETWORK_DECIDE);
    let refused = w.audit("network_decision.refused").await;
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0].metadata["rule"], "4.2:decide");
    assert!(
        w.decisions_for(&device.fingerprint()).await.is_empty(),
        "a refused caller asks no decision"
    );

    let (status, body) = srv.decide(&token, device.body("branch")).await;
    assert_eq!((status, body), (200, json!({"allow": false})));
    srv.stop().await;
}

/// The caller's token must be bound to its own certificate: a plain bearer
/// token of the same account, a token bound to another certificate, a bound
/// token on a connection presenting no certificate, a token bound to the
/// presented certificate that is no longer the caller's own (revoked), and a
/// person's token are all `401`, and none of them reaches a decision.
#[actix_rt::test]
async fn only_a_certificate_bound_service_account_token_is_admitted() {
    let w = World::new().await;
    site(&w, "hq").await;
    let caller = w.caller_at(network_root_id(w.tenant)).await;
    let other = w.caller_at(network_root_id(w.tenant)).await;
    let device = w.device(w.tenant).await;
    let srv = serve(&w, Some(&caller), RateLimitConfig::default(), w.engine());
    let bare = serve(&w, None, RateLimitConfig::default(), w.engine());

    let bearer = issue_service_account_token(
        caller.account,
        w.tenant,
        w.org,
        Uuid::new_v4().to_string(),
        None,
        &w.auth,
    )
    .unwrap();
    let (status, body) = srv.decide(&bearer, device.body("hq")).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(
        body["message"],
        format!("Authentication failed: {CERTIFICATE_BOUND_REFUSAL}")
    );

    // Bound to another account's certificate, presented over this one.
    let (status, _) = srv.decide(&w.bound_token(&other), device.body("hq")).await;
    assert_eq!(status, 401);
    // Bound, but the connection presents no certificate.
    let (status, _) = bare
        .decide(&w.bound_token(&caller), device.body("hq"))
        .await;
    assert_eq!(status, 401);

    // A person — even a network administrator.
    let admin = w.netadmin().await;
    let (status, body) = srv.decide(&admin, device.body("hq")).await;
    assert_eq!(status, 401, "{body}");

    // The caller's own certificate revoked: the bound token stops at once.
    let token = w.bound_token(&caller);
    let (status, _) = srv.decide(&token, device.body("hq")).await;
    assert_eq!(status, 200);
    SurrealCertificateRepository::new(w.db.clone())
        .revoke(w.tenant, caller.certificate)
        .await
        .unwrap();
    let (status, _) = srv.decide(&token, device.body("hq")).await;
    assert_eq!(status, 401);

    assert_eq!(
        w.decisions_for(&device.fingerprint()).await.len(),
        1,
        "only the admitted request was decided"
    );
    srv.stop().await;
    bare.stop().await;
}

/// A closed body: an unknown key (a MAC address) is a `400` naming it, so
/// nothing §8 keeps out of the trail can be posted into it; and exactly one of
/// the two certificate forms.
#[actix_rt::test]
async fn the_body_is_closed() {
    let w = World::new().await;
    site(&w, "hq").await;
    let caller = w.caller_at(network_root_id(w.tenant)).await;
    let device = w.device(w.tenant).await;
    let srv = serve(&w, Some(&caller), RateLimitConfig::default(), w.engine());
    let token = w.bound_token(&caller);
    let mut with_mac = device.body("hq");
    with_mac["calling_station_id"] = json!("02-00-00-00-00-01");
    let (status, body) = srv.decide(&token, with_mac).await;
    assert_eq!(status, 400);
    assert!(
        body["message"]
            .as_str()
            .unwrap()
            .contains("calling_station_id"),
        "{body}"
    );
    for bad in [
        json!({"site": "hq"}),
        json!({"site": "hq", "certificate": "AA==", "fingerprint": device.fingerprint()}),
        json!({"site": "h q", "fingerprint": device.fingerprint()}),
        json!({"site": "hq", "fingerprint": "abc"}),
        json!({"site": "hq", "certificate": "not base64!"}),
    ] {
        let (status, body) = srv.decide(&token, bad.clone()).await;
        assert_eq!(status, 400, "{bad}: {body}");
    }
    srv.stop().await;
}

// ---------------------------------------------------------------------------
// A stored profile that no longer validates
// ---------------------------------------------------------------------------

/// A profile edited in the datastore behind the API (an administrative
/// `Service-Type`, which the write path refuses) is not rendered: its segment
/// is no candidate, the decision is `allow: false`, and one
/// `reply_profile.invalid` row names the rule — one per window, not one per
/// decision.
#[actix_rt::test]
async fn a_stored_profile_that_no_longer_validates_refuses_and_is_audited_once() {
    let w = World::new().await;
    let s = site(&w, "hq").await;
    let caller = w.caller_at(network_root_id(w.tenant)).await;
    let device = w.device(w.tenant).await;
    w.grant(
        w.tenant,
        device.account,
        &[(NETWORK_JOIN, ALLOW)],
        id(&s.iot),
    )
    .await;
    let srv = serve(&w, Some(&caller), RateLimitConfig::default(), w.engine());
    let token = w.bound_token(&caller);
    let (_, body) = srv.decide(&token, device.body("hq")).await;
    assert_eq!(body["allow"], true);

    w.db.query(
        "UPDATE type::record('reply_profile', $id) SET service_type = 'administrative_user'",
    )
    .bind(("id", s.iot["id"].as_str().unwrap().to_owned()))
    .await
    .unwrap()
    .check()
    .unwrap();

    for _ in 0..3 {
        let (status, body) = srv.decide(&token, device.body("hq")).await;
        assert_eq!((status, body), (200, json!({"allow": false})));
    }
    let invalid = w.audit("reply_profile.invalid").await;
    assert_eq!(
        invalid.len(),
        1,
        "one row per profile per window: {invalid:?}"
    );
    let m = &invalid[0].metadata;
    assert_eq!(m["rule"], "3.3:admin-class");
    assert_eq!(m["segment_id"], s.iot["id"]);
    assert_eq!(invalid[0].resource_id, Some(id(&s.iot)));
    let rows = w.decisions_for(&device.fingerprint()).await;
    assert_eq!(
        rows.iter()
            .filter(|r| r.metadata["reason"] == "placement:no_candidate")
            .count(),
        3
    );
    srv.stop().await;
}

// ---------------------------------------------------------------------------
// The limiter
// ---------------------------------------------------------------------------

/// The bucket is the caller's `sub` (D-6): two callers from one address are
/// independent — the first spending its allowance does not touch the second's.
#[actix_rt::test]
async fn the_limiter_is_keyed_on_the_caller() {
    let w = World::new().await;
    site(&w, "hq").await;
    let first = w.caller_at(network_root_id(w.tenant)).await;
    let second = w.caller_at(network_root_id(w.tenant)).await;
    let device = w.device(w.tenant).await;
    let limits = RateLimitConfig {
        network_decide_per_min: 1,
        ..RateLimitConfig::default()
    };
    let a = serve(&w, Some(&first), limits.clone(), w.engine());
    let b = serve(&w, Some(&second), limits.clone(), w.engine());

    let (status, _) = a.decide(&w.bound_token(&first), device.body("hq")).await;
    assert_eq!(status, 200);
    let (status, body) = a.decide(&w.bound_token(&first), device.body("hq")).await;
    assert_eq!(status, 429, "{body}");
    assert_eq!(body["error"], "rate_limit_exceeded");
    // Same address (both listeners are on 127.0.0.1), another caller.
    let (status, body) = b.decide(&w.bound_token(&second), device.body("hq")).await;
    assert_eq!(status, 200, "{body}");
    a.stop().await;
    b.stop().await;
}

#[actix_rt::test]
async fn the_shipped_allowance_is_six_thousand_in_every_profile() {
    use axiam_api_rest::RateLimitProfile;
    assert_eq!(RateLimitConfig::default().network_decide_per_min, 6_000);
    for profile in [RateLimitProfile::Gateway, RateLimitProfile::Mesh] {
        let mut cfg = RateLimitConfig {
            profile,
            ..RateLimitConfig::default()
        };
        cfg.apply_profile(|_| false);
        assert_eq!(cfg.network_decide_per_min, 6_000, "{profile:?}");
    }
    assert_eq!(
        axiam_api_rest::handlers::network_decide::bucket_key(Uuid::nil(), Uuid::nil()),
        format!("network_decide:{}:{}", Uuid::nil(), Uuid::nil())
    );
}

// ---------------------------------------------------------------------------
// One cost (T-457)
// ---------------------------------------------------------------------------

/// Records every `check_access_batch` the handler makes, then forwards it.
struct Counting {
    inner: Arc<dyn AuthzChecker>,
    batches: Mutex<Vec<(Uuid, String, usize)>>,
}

impl AuthzChecker for Counting {
    fn check_access<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AxiamResult<AccessDecision>> + Send + 'a>>
    {
        self.inner.check_access(request)
    }

    fn check_access_batch<'a>(
        &'a self,
        requests: &'a [AccessRequest],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = AxiamResult<Vec<AccessDecision>>> + Send + 'a>,
    > {
        let first = requests.first();
        self.batches.lock().unwrap().push((
            first.map_or(Uuid::nil(), |r| r.subject_id),
            first.map_or(String::new(), |r| r.action.clone()),
            requests.len(),
        ));
        self.inner.check_access_batch(requests)
    }
}

/// Every kind of answer takes the same path: one `network:decide` batch for the
/// caller, then exactly **one** `network:join` batch over every enabled segment
/// of the site — for a placement, for "no candidate", for another tenant's
/// certificate, for an unknown one and for an unknown fingerprint alike. No
/// early return skips the batch. That each verifies exactly one certificate is
/// the handler's unit test
/// `every_path_verifies_one_certificate_and_every_refusal_the_callers` (#706).
#[actix_rt::test]
async fn every_answer_runs_one_join_batch_over_the_whole_site() {
    let w = World::new().await;
    let s = site(&w, "hq").await;
    let caller = w.caller_at(network_root_id(w.tenant)).await;
    let placed = w.device(w.tenant).await;
    w.grant(
        w.tenant,
        placed.account,
        &[(NETWORK_JOIN, ALLOW)],
        id(&s.corp),
    )
    .await;
    let unplaced = w.device(w.tenant).await;
    let foreign = w.device(w.other_tenant).await;
    let mut unknown = placed.clone();
    unknown.der[40] ^= 0xff;
    let counting = Arc::new(Counting {
        inner: w.engine(),
        batches: Mutex::new(Vec::new()),
    });
    let srv = serve(
        &w,
        Some(&caller),
        RateLimitConfig::default(),
        counting.clone(),
    );
    let token = w.bound_token(&caller);

    for (request, allow) in [
        (placed.body("hq"), true),
        (unplaced.body("hq"), false),
        (foreign.body("hq"), false),
        (unknown.body("hq"), false),
        (unknown.fingerprint_body("hq"), false),
    ] {
        counting.batches.lock().unwrap().clear();
        let (_, body) = srv.decide(&token, request).await;
        assert_eq!(body["allow"], allow, "{body}");
        let batches = counting.batches.lock().unwrap().clone();
        assert_eq!(batches.len(), 2, "{batches:?}");
        assert_eq!(batches[0].1, NETWORK_DECIDE);
        assert_eq!(batches[0].0, caller.account);
        assert_eq!(batches[1].1, NETWORK_JOIN);
        assert_eq!(batches[1].2, 3, "every enabled segment of the site");
    }
    srv.stop().await;
}

fn median(mut samples: Vec<Duration>) -> Duration {
    samples.sort();
    samples[samples.len() / 2]
}

/// The statistical half of T-457 (the precedent is the password-reset timing
/// test in `axiam-auth`): interleaved samples of a placement, of "no
/// candidate", of another tenant's certificate and of a fingerprint no tenant
/// holds (#706), compared by their medians.
/// No refusal may be measurably faster (or slower) than the placement:
/// the band is a factor of 1.5 either way. Interleaving puts every kind under
/// the same load, so a shared runner moves every median together (they
/// sit within about 15 % of each other here); an early return that skips the
/// site's reads, the batch and the row lands near 0.57 and outside it — which
/// the structural test above also pins, exactly.
#[actix_rt::test]
async fn allow_no_candidate_and_another_tenant_cost_the_same() {
    const ROUNDS: usize = 31;
    const BAND_LOW: f64 = 1.0 / 1.5;
    const BAND_HIGH: f64 = 1.5;
    let w = World::new().await;
    let s = site(&w, "hq").await;
    let caller = w.caller_at(network_root_id(w.tenant)).await;
    let placed = w.device(w.tenant).await;
    w.grant(
        w.tenant,
        placed.account,
        &[(NETWORK_JOIN, ALLOW)],
        id(&s.corp),
    )
    .await;
    // "No candidate" for a device that holds a join elsewhere, so its account
    // has role assignments as the placed one's does.
    let unplaced = w.device(w.tenant).await;
    w.grant(
        w.tenant,
        unplaced.account,
        &[(NETWORK_JOIN, ALLOW)],
        Uuid::new_v4(),
    )
    .await;
    let foreign = w.device(w.other_tenant).await;
    let mut unknown = placed.clone();
    unknown.der[40] ^= 0xff;
    let srv = serve(&w, Some(&caller), RateLimitConfig::default(), w.engine());
    let token = w.bound_token(&caller);

    let kinds = [
        ("allow", placed.body("hq")),
        ("no candidate", unplaced.body("hq")),
        ("other tenant", foreign.body("hq")),
        ("unknown fingerprint", unknown.fingerprint_body("hq")),
    ];
    // Warm the listener, the connection path and the datastore's plans.
    for (_, body) in &kinds {
        srv.decide(&token, body.clone()).await;
    }
    let mut samples: Vec<Vec<Duration>> = vec![Vec::new(); kinds.len()];
    for round in 0..ROUNDS {
        // Rotate the order each round, so no kind always goes first.
        for k in 0..kinds.len() {
            let i = (k + round) % kinds.len();
            let started = Instant::now();
            let (status, _) = srv.decide(&token, kinds[i].1.clone()).await;
            samples[i].push(started.elapsed());
            assert_eq!(status, 200);
        }
    }
    let medians: Vec<Duration> = samples.into_iter().map(median).collect();
    eprintln!(
        "network decide medians: {}",
        kinds
            .iter()
            .zip(&medians)
            .map(|(k, m)| format!("{} {m:?}", k.0))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let allow = medians[0].as_secs_f64();
    for (k, m) in kinds.iter().zip(&medians).skip(1) {
        let ratio = m.as_secs_f64() / allow;
        assert!(
            (BAND_LOW..=BAND_HIGH).contains(&ratio),
            "{}: median {:?} against the placement's {:?} (ratio {ratio:.2})",
            k.0,
            m,
            medians[0]
        );
    }
    srv.stop().await;
}

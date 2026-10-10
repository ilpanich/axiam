//! #565 (T-102) — the certificate revocation list route, and a revoked
//! certificate at the token endpoint.
//!
//! The route tests drive the REAL `register_api_v1_routes` wiring with no
//! credential at all, so they fail if the route ever moves behind
//! `AuthzMiddleware` or loses its limiter. The token-endpoint test runs
//! `TokenService::exchange` — the function `POST /oauth2/token` calls — from
//! the state the harness builds, so it uses the certificate lookup the
//! composition wires, against a leaf the real `CertService` issued and the real
//! repository revoked. It is not driven over HTTP because the certificate
//! reaches the handler as connection data set by the TLS listener, which an
//! actix test request cannot carry.
//!
//! Run with: cargo test -p axiam-api-rest --test crl_test

use actix_web::http::{StatusCode, header};
use actix_web::{App, test, web};
use axiam_api_rest::config::rate_limit::RateLimitConfig;
use axiam_api_rest::server::register_api_v1_routes;
use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::certificate::{
    CertTrust, CertificateType, CreateCaCertificate, CreateCertificate, KeyAlgorithm,
};
use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::repository::{OAuth2ClientRepository, OrganizationRepository, TenantRepository};
use axiam_db::repository::{
    SurrealOAuth2ClientRepository, SurrealOrganizationRepository, SurrealTenantRepository,
};
use axiam_oauth2::error::OAuth2Error;
use axiam_oauth2::mtls::PresentedCertificate;
use axiam_oauth2::token::{TokenRequest, TokenRequestContext};
use axiam_pki::IssuingScope;
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;
use x509_parser::prelude::FromDer;
use x509_parser::revocation_list::CertificateRevocationList;

type TestDb = Db;

async fn test_db() -> Surreal<TestDb> {
    let db = Surreal::new::<Mem>(()).await.unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    db
}

fn auth_config() -> AuthConfig {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
    AuthConfig {
        jwt_private_key_pem: key.serialize_pem(),
        jwt_public_key_pem: key.public_key_pem(),
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.crl.example".into(),
        ..AuthConfig::default()
    }
}

/// An organization with a tenant, both as rows, and the state over them.
struct Fixture {
    db: Surreal<TestDb>,
    state: AppState<TestDb>,
    org: Uuid,
    tenant: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let db = test_db().await;
        let org = SurrealOrganizationRepository::new(db.clone())
            .create(CreateOrganization {
                name: "CRL Org".into(),
                slug: "org-crl".into(),
                metadata: None,
            })
            .await
            .unwrap();
        let tenant = SurrealTenantRepository::new(db.clone())
            .create(CreateTenant {
                organization_id: org.id,
                kind: TenantKind::Standard,
                name: "CRL Tenant".into(),
                slug: "tenant-crl".into(),
                metadata: None,
            })
            .await
            .unwrap();
        Self {
            state: AppState::for_test(db.clone(), auth_config()),
            db,
            org: org.id,
            tenant: tenant.id,
        }
    }

    async fn ca(&self) -> Uuid {
        self.state
            .pki
            .ca_service
            .generate(CreateCaCertificate {
                organization_id: self.org,
                subject: "CRL Route Root".into(),
                key_algorithm: KeyAlgorithm::Ed25519,
                validity_days: 365,
                intermediate_subject: None,
                intermediate_validity_days: None,
                issue_from_root: false,
            })
            .await
            .expect("CA")
            .certificate
            .id
    }

    async fn leaf(&self, ca: Uuid, subject: &str) -> axiam_core::models::certificate::Certificate {
        self.state
            .pki
            .cert_service
            .generate(
                self.org,
                IssuingScope::Organization,
                CreateCertificate {
                    tenant_id: self.tenant,
                    issuer_ca_id: ca,
                    subject: subject.into(),
                    cert_type: CertificateType::Service,
                    key_algorithm: KeyAlgorithm::Ed25519,
                    validity_days: 30,
                    metadata: None,
                    subject_alt_names: vec![],
                },
                None,
                &[],
            )
            .await
            .expect("leaf")
            .certificate
    }
}

macro_rules! build_app {
    ($state:expr, $cfg:expr) => {
        test::init_service(
            App::new()
                .app_data(web::Data::new($state.clone()))
                .configure(|cfg| register_api_v1_routes::<TestDb>(cfg, &$cfg)),
        )
        .await
    };
}

fn crl_request(org: Uuid, ca: Uuid, peer: &str) -> test::TestRequest {
    test::TestRequest::get()
        .uri(&format!("/pki/v1/{org}/ca/{ca}/crl"))
        .peer_addr(peer.parse().unwrap())
}

/// The route answers an anonymous caller with the DER list, the media type
/// RFC 5280 §4.2.1.13 names and caching headers bounded by `nextUpdate`, and a
/// `304` to a caller revalidating the list it holds.
#[actix_web::test]
async fn the_crl_route_serves_the_list_to_anyone_with_caching_headers() {
    let f = Fixture::new().await;
    let ca = f.ca().await;
    let revoked = f.leaf(ca, "svc-revoked").await;
    f.state
        .pki
        .cert_service
        .revoke(f.tenant, revoked.id)
        .await
        .unwrap();
    let app = build_app!(f.state, RateLimitConfig::default());

    let resp = test::call_service(
        &app,
        crl_request(f.org, ca, "203.0.113.30:4000").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "no credential is needed");
    let headers = resp.headers().clone();
    assert_eq!(
        headers.get(header::CONTENT_TYPE).unwrap(),
        "application/pkix-crl"
    );
    let cache_control = headers
        .get(header::CACHE_CONTROL)
        .unwrap()
        .to_str()
        .unwrap();
    let max_age: u64 = cache_control
        .strip_prefix("public, max-age=")
        .expect("public, max-age")
        .parse()
        .unwrap();
    assert!(max_age > 0 && max_age <= axiam_pki::crl::DEFAULT_CRL_NEXT_UPDATE_SECS);
    assert!(headers.get(header::LAST_MODIFIED).is_some());
    let etag = headers
        .get(header::ETAG)
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();

    let body = test::read_body(resp).await;
    let (_, list) = CertificateRevocationList::from_der(&body).expect("a DER CRL");
    assert_eq!(list.iter_revoked_certificates().count(), 1);

    let resp = test::call_service(
        &app,
        crl_request(f.org, ca, "203.0.113.30:4000")
            .insert_header((header::IF_NONE_MATCH, etag))
            .to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);

    // Another organization's id for the same CA is not found, not served.
    let resp = test::call_service(
        &app,
        crl_request(Uuid::new_v4(), ca, "203.0.113.30:4000").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// The route carries its own limiter from the first commit (plan §7 rule 6):
/// past `crl_per_min` from one address it answers `429`, and another address
/// is unaffected.
#[actix_web::test]
async fn the_crl_route_is_rate_limited_per_ip() {
    const CRL_PER_MIN: u32 = 3;
    let f = Fixture::new().await;
    let ca = f.ca().await;
    let cfg = RateLimitConfig {
        crl_per_min: CRL_PER_MIN,
        ..RateLimitConfig::default()
    };
    let app = build_app!(f.state, cfg);

    for i in 0..CRL_PER_MIN {
        let resp = test::call_service(
            &app,
            crl_request(f.org, ca, "203.0.113.31:4000").to_request(),
        )
        .await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "request {i} is within the limit"
        );
    }
    let resp = test::call_service(
        &app,
        crl_request(f.org, ca, "203.0.113.31:4000").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    let resp = test::call_service(
        &app,
        crl_request(f.org, ca, "203.0.113.32:4000").to_request(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "the bucket is per address");
}

/// The issue's first test: a leaf AXIAM issued authenticates its
/// `tls_client_auth` client at the token endpoint, and once revoked it does
/// not — although its chain is exactly as valid as it was.
#[actix_web::test]
async fn a_revoked_leaf_is_refused_at_the_token_endpoint_under_tls_client_auth() {
    let f = Fixture::new().await;
    let ca = f.ca().await;
    let leaf = f.leaf(ca, "svc-mtls").await;
    let (client, _secret) = SurrealOAuth2ClientRepository::new(f.db.clone())
        .create(CreateOAuth2Client {
            tenant_id: f.tenant,
            name: "mtls-service".into(),
            redirect_uris: vec![],
            grant_types: vec!["client_credentials".into()],
            scopes: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::TlsClientAuth,
            tls_client_auth_subject_dn: Some("CN=svc-mtls".into()),
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
            allowed_resources: Vec::new(),
            managed_by: ManagedBy::Admin,
            ciba: Default::default(),
        })
        .await
        .unwrap();

    let (_, block) = x509_parser::pem::parse_x509_pem(leaf.public_cert_pem.as_bytes()).unwrap();
    // What the listener hands over for a certificate that chained to an
    // anchor — the AXIAM CA flagged as one.
    let ctx = TokenRequestContext {
        client_certificate: Some(PresentedCertificate::from_der(
            &block.contents,
            CertTrust::ChainedToAnchor,
        )),
        ..Default::default()
    };
    let request = || -> TokenRequest {
        serde_json::from_value(serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": client.client_id,
        }))
        .unwrap()
    };
    let tokens = &f.state.oauth2.token_service;

    tokens
        .exchange(f.tenant, request(), &ctx)
        .await
        .expect("the active leaf authenticates its client");

    f.state
        .pki
        .cert_service
        .revoke(f.tenant, leaf.id)
        .await
        .unwrap();
    match tokens.exchange(f.tenant, request(), &ctx).await {
        Err(OAuth2Error::InvalidClient(description)) => {
            assert_eq!(description, "invalid client credentials")
        }
        other => panic!("a revoked leaf must be refused with invalid_client, got {other:?}"),
    }
}

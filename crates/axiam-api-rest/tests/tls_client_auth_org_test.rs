//! R1W1-02 — a `tls_client_auth` client authenticates only with a certificate
//! of its own organization.
//!
//! The deployment has one mTLS listener, and it trusts every organization's
//! flagged anchors at once; any organization administrator can flag a CA of
//! their own, an imported one whose key they hold included. A registered
//! subject DN matched under *some* anchor therefore let one organization mint a
//! certificate carrying another organization's client DN and take that
//! client's tokens. These tests run `TokenService::exchange` — what
//! `POST /oauth2/token` calls — from the state the harness builds, with the
//! certificate as the listener hands it over: its trust level and the chain the
//! handshake verified it through, as fingerprints. Not over HTTP, for the
//! reason `crl_test.rs` gives: an actix test request carries no TLS connection.
//!
//! Run with: cargo test -p axiam-api-rest --test tls_client_auth_org_test

use axiam_api_rest::state::AppState;
use axiam_auth::config::AuthConfig;
use axiam_core::models::certificate::{
    CertTrust, CertificateType, CreateCaCertificate, CreateCertificate, ImportCaCertificate,
    KeyAlgorithm,
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
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use sha2::{Digest, Sha256};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, Mem};
use uuid::Uuid;

/// The DN the victim organization's client registered.
const VICTIM_DN: &str = "CN=victim-client";

fn auth_config() -> AuthConfig {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ed25519 keypair");
    AuthConfig {
        jwt_private_key_pem: key.serialize_pem(),
        jwt_public_key_pem: key.public_key_pem(),
        jwt_issuer: "axiam-test".into(),
        oauth2_issuer_url: "https://id.r1w1-02.example".into(),
        ..AuthConfig::default()
    }
}

/// A CA outside AXIAM whose key the test holds — what an administrator who
/// imports a keyless CA and flags it keeps offline.
struct ExternalCa {
    params: CertificateParams,
    key: KeyPair,
    pem: String,
    fingerprint: String,
}

impl ExternalCa {
    fn new(name: &str) -> Self {
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.distinguished_name.push(DnType::CommonName, name);
        let cert = params.self_signed(&key).unwrap();
        Self {
            fingerprint: hex::encode(Sha256::digest(cert.der())),
            pem: cert.pem(),
            params,
            key,
        }
    }

    /// A leaf carrying the victim client's DN, signed by this CA.
    fn leaf_with_victim_dn(&self) -> Vec<u8> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, "victim-client");
        params
            .signed_by(&key, &Issuer::from_params(&self.params, &self.key))
            .unwrap()
            .der()
            .to_vec()
    }
}

/// Two organizations: the victim's, with two tenants, and the attacker's.
struct Fixture {
    state: AppState<Db>,
    db: Surreal<Db>,
    victim_org: Uuid,
    victim_tenant: Uuid,
    sibling_tenant: Uuid,
    attacker_org: Uuid,
}

impl Fixture {
    async fn new() -> Self {
        let db = Surreal::new::<Mem>(()).await.unwrap();
        db.use_ns("test").use_db("test").await.unwrap();
        axiam_db::run_migrations(&db).await.unwrap();
        let orgs = SurrealOrganizationRepository::new(db.clone());
        let tenants = SurrealTenantRepository::new(db.clone());
        let mut org_ids = Vec::new();
        for slug in ["victim-org", "attacker-org"] {
            org_ids.push(
                orgs.create(CreateOrganization {
                    name: slug.into(),
                    slug: slug.into(),
                    metadata: None,
                })
                .await
                .unwrap()
                .id,
            );
        }
        let mut tenant_ids = Vec::new();
        for (org, slug) in [(org_ids[0], "victim"), (org_ids[0], "sibling")] {
            tenant_ids.push(
                tenants
                    .create(CreateTenant {
                        organization_id: org,
                        kind: TenantKind::Standard,
                        name: slug.into(),
                        slug: slug.into(),
                        metadata: None,
                    })
                    .await
                    .unwrap()
                    .id,
            );
        }
        Self {
            state: AppState::for_test(db.clone(), auth_config()),
            db,
            victim_org: org_ids[0],
            victim_tenant: tenant_ids[0],
            sibling_tenant: tenant_ids[1],
            attacker_org: org_ids[1],
        }
    }

    /// Import `ca` into `org` without its key, as a trust anchor would be.
    async fn import(&self, org: Uuid, ca: &ExternalCa) {
        let imported = self
            .state
            .pki
            .ca_service
            .import(ImportCaCertificate {
                organization_id: org,
                public_cert_pem: ca.pem.clone(),
                private_key_pem: None,
            })
            .await
            .expect("import the CA");
        assert_eq!(imported.fingerprint, ca.fingerprint);
    }

    /// The victim's `tls_client_auth` client, registered with [`VICTIM_DN`].
    async fn victim_client(&self) -> String {
        let (client, _secret) = SurrealOAuth2ClientRepository::new(self.db.clone())
            .create(CreateOAuth2Client {
                tenant_id: self.victim_tenant,
                name: "victim-service".into(),
                redirect_uris: vec![],
                grant_types: vec!["client_credentials".into()],
                scopes: vec![],
                post_logout_redirect_uris: vec![],
                backchannel_logout_uri: None,
                require_par: false,
                profile: ClientProfile::Standard,
                token_endpoint_auth_method: ClientAuthMethod::TlsClientAuth,
                tls_client_auth_subject_dn: Some(VICTIM_DN.into()),
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
        client.client_id
    }

    /// Whether `certificate` authenticates `client_id` at the token endpoint.
    /// Only `invalid_client` counts as a refusal; any other error fails the
    /// test, named by its variant and never by its payload.
    async fn authenticates(&self, client_id: &str, certificate: PresentedCertificate) -> bool {
        let request: TokenRequest = serde_json::from_value(serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": client_id,
        }))
        .unwrap();
        let ctx = TokenRequestContext {
            client_certificate: Some(certificate),
            ..Default::default()
        };
        match self
            .state
            .oauth2
            .token_service
            .exchange(self.victim_tenant, request, &ctx)
            .await
        {
            Ok(_) => true,
            Err(OAuth2Error::InvalidClient(_)) => false,
            Err(_) => panic!("the token endpoint failed with an error other than invalid_client"),
        }
    }
}

/// What the listener hands over for a certificate that chained, through
/// `issuer_path` (nearest issuer first, anchor last).
fn chained(der: &[u8], issuer_path: &[&str]) -> PresentedCertificate {
    PresentedCertificate::from_der(der, CertTrust::ChainedToAnchor)
        .with_issuer_path(issuer_path.iter().map(|s| (*s).to_owned()).collect())
}

/// The issue's attack: the attacker organization imports a CA whose key it
/// holds — flagged, it is one of the listener's anchors — and mints a leaf
/// with the victim client's DN. It is refused. The same leaf shape under a CA
/// the victim's organization holds authenticates, which is the control.
#[actix_web::test]
async fn a_certificate_chained_to_another_organizations_anchor_is_refused_for_tls_client_auth() {
    let f = Fixture::new().await;
    let client_id = f.victim_client().await;

    let attacker_ca = ExternalCa::new("Attacker Anchor");
    f.import(f.attacker_org, &attacker_ca).await;
    let forged = attacker_ca.leaf_with_victim_dn();
    assert!(
        !f.authenticates(&client_id, chained(&forged, &[&attacker_ca.fingerprint]))
            .await,
        "a leaf under another organization's anchor must not authenticate the victim's client"
    );

    let victim_ca = ExternalCa::new("Victim Anchor");
    f.import(f.victim_org, &victim_ca).await;
    let genuine = victim_ca.leaf_with_victim_dn();
    assert!(
        f.authenticates(&client_id, chained(&genuine, &[&victim_ca.fingerprint]))
            .await,
        "a leaf under the client's own organization's anchor authenticates it"
    );

    // An anchor no organization records (one placed in a bundle by hand), a
    // chain the listener could not report, and a chain whose anchor is the
    // victim's but that runs through the attacker's CA: all refused.
    let unrecorded = ExternalCa::new("Unrecorded Anchor");
    let leaf = unrecorded.leaf_with_victim_dn();
    assert!(
        !f.authenticates(&client_id, chained(&leaf, &[&unrecorded.fingerprint]))
            .await,
        "an anchor no organization holds"
    );
    assert!(
        !f.authenticates(&client_id, chained(&genuine, &[])).await,
        "no verified chain"
    );
    assert!(
        !f.authenticates(
            &client_id,
            chained(&forged, &[&attacker_ca.fingerprint, &victim_ca.fingerprint])
        )
        .await,
        "a chain through another organization's CA"
    );
}

/// A leaf AXIAM issued is the client's only when AXIAM issued it in the
/// client's tenant: a sibling tenant of the same organization, under the same
/// organization CA, can be issued the same common name.
#[actix_web::test]
async fn an_axiam_issued_leaf_from_another_tenant_is_refused_for_tls_client_auth() {
    let f = Fixture::new().await;
    let client_id = f.victim_client().await;
    let ca = f
        .state
        .pki
        .ca_service
        .generate(CreateCaCertificate {
            organization_id: f.victim_org,
            subject: "Victim Org Root".into(),
            key_algorithm: KeyAlgorithm::Ed25519,
            validity_days: 365,
            intermediate_subject: None,
            intermediate_validity_days: None,
            issue_from_root: false,
        })
        .await
        .unwrap()
        .certificate;
    let issue = |tenant_id: Uuid| {
        let certs = f.state.pki.cert_service.clone();
        let org = f.victim_org;
        let issuer = ca.id;
        async move {
            let leaf = certs
                .generate(
                    org,
                    IssuingScope::Organization,
                    CreateCertificate {
                        tenant_id,
                        issuer_ca_id: issuer,
                        subject: "victim-client".into(),
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
                .certificate;
            let (_, block) =
                x509_parser::pem::parse_x509_pem(leaf.public_cert_pem.as_bytes()).unwrap();
            block.contents
        }
    };

    let sibling_leaf = issue(f.sibling_tenant).await;
    assert!(
        !f.authenticates(&client_id, chained(&sibling_leaf, &[&ca.fingerprint]))
            .await,
        "a leaf AXIAM issued in another tenant must not authenticate the client"
    );
    let own_leaf = issue(f.victim_tenant).await;
    assert!(
        f.authenticates(&client_id, chained(&own_leaf, &[&ca.fingerprint]))
            .await,
        "a leaf AXIAM issued in the client's tenant authenticates it"
    );
}

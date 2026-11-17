//! Item B of the 1.1.0 atomicity audit: a WebAuthn assertion signs in once.
//!
//! The authentication ceremony's challenge travels in a stateless state token,
//! and nothing recorded it as used: a captured (state token, assertion) pair
//! verified again for the token's whole lifetime, and two copies sent together
//! each opened a session. The signature counter was never stored either, so a
//! cloned authenticator went unnoticed.
//!
//! These tests drive the real ceremony — `WebauthnService` over the SurrealDB
//! credential repository, on `surrealkv` — with a software authenticator: a
//! P-256 key whose credential is stored as `webauthn-rs` stores one, and
//! assertions signed exactly as W3C WebAuthn §6.3.3 lays them out. After a
//! successful finish each test does what the REST handler does next
//! (`create_session_and_tokens`), so "one session" is counted, not assumed.

use std::sync::Arc;

use axiam_auth::config::AuthConfig;
use axiam_auth::service::AuthService;
use axiam_auth::webauthn::WebauthnService;
use axiam_core::models::organization::CreateOrganization;
use axiam_core::models::session::{Amr, AuthenticationEvidence};
use axiam_core::models::tenant::{CreateTenant, TenantKind};
use axiam_core::models::user::CreateUser;
use axiam_core::models::webauthn_credential::{CreateWebauthnCredential, WebauthnCredentialType};
use axiam_core::models::webauthn_policy::WebauthnUserVerification;
use axiam_core::repository::{
    OrganizationRepository, TenantRepository, UserRepository, WebauthnCredentialRepository,
};
use axiam_db::repository::{
    SurrealFederationLinkRepository, SurrealOrganizationRepository, SurrealRefreshTokenRepository,
    SurrealSessionRepository, SurrealTenantRepository, SurrealUserRepository,
    SurrealWebauthnCredentialRepository,
};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ring::rand::SystemRandom;
use ring::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use sha2::{Digest, Sha256};
use surrealdb::Surreal;
use surrealdb::engine::local::{Db, SurrealKv};
use uuid::Uuid;
use webauthn_rs::prelude::{Passkey, PublicKeyCredential};

const TEST_PRIVATE_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key

const TEST_PUBLIC_KEY: &str = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";

/// The AES-256-GCM key the test deployment encrypts MFA material with: random
/// per process, stable within one, so every step of a test sees the same key
/// and no key-shaped literal appears in the source.
fn mfa_key() -> [u8; 32] {
    static KEY: std::sync::OnceLock<[u8; 32]> = std::sync::OnceLock::new();
    *KEY.get_or_init(|| {
        let mut key = [0u8; 32];
        key[..16].copy_from_slice(Uuid::new_v4().as_bytes());
        key[16..].copy_from_slice(Uuid::new_v4().as_bytes());
        key
    })
}
const RP_ID: &str = "localhost";
const ORIGIN: &str = "http://localhost:8090";
/// Rounds of the parallel double-submit per run; the test was also run 20
/// times in a row.
const ROUNDS: usize = 8;

fn config() -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: TEST_PRIVATE_KEY.into(),
        jwt_public_key_pem: TEST_PUBLIC_KEY.into(),
        jwt_issuer: "axiam-test".into(),
        mfa_encryption_key: Some(mfa_key()),
        webauthn_rp_id: RP_ID.into(),
        webauthn_rp_origin: ORIGIN.into(),
        webauthn_rp_name: "AXIAM-Test".into(),
        ..AuthConfig::default()
    }
}

/// A P-256 authenticator holding one credential.
struct SoftAuthenticator {
    key: EcdsaKeyPair,
    rng: SystemRandom,
    cred_id: Vec<u8>,
}

impl SoftAuthenticator {
    fn new() -> Self {
        let rng = SystemRandom::new();
        let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &rng).unwrap();
        let key = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8.as_ref(), &rng)
            .unwrap();
        Self {
            key,
            rng,
            cred_id: Uuid::new_v4().as_bytes().to_vec(),
        }
    }

    /// The credential as `webauthn-rs` serialises a registered passkey: an
    /// ES256 key, counter 0, registered with user verification, no attestation.
    fn passkey_json(&self) -> String {
        let point = self.key.public_key().as_ref();
        assert_eq!(point.len(), 65, "an uncompressed P-256 point");
        let json = serde_json::json!({
            "cred": {
                "cred_id": URL_SAFE_NO_PAD.encode(&self.cred_id),
                "cred": {
                    "type_": "ES256",
                    "key": { "EC_EC2": {
                        "curve": "SECP256R1",
                        "x": point[1..33].to_vec(),
                        "y": point[33..65].to_vec(),
                    } }
                },
                "counter": 0,
                "transports": null,
                "user_verified": true,
                "backup_eligible": false,
                "backup_state": false,
                "registration_policy": "required",
                "extensions": {},
                "attestation": { "data": "None", "metadata": "None" },
                "attestation_format": "None"
            }
        });
        let passkey: Passkey = serde_json::from_value(json).expect("a webauthn-rs passkey");
        serde_json::to_string(&passkey).unwrap()
    }

    /// An assertion over `challenge` (base64url, as the challenge JSON carries
    /// it) reporting signature counter `counter`.
    fn assert(&self, challenge: &str, counter: u32, user: Uuid) -> PublicKeyCredential {
        let client_data = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.get",
            "challenge": challenge,
            "origin": ORIGIN,
            "crossOrigin": false,
        }))
        .unwrap();
        let mut auth_data = Sha256::digest(RP_ID.as_bytes()).to_vec();
        auth_data.push(0x05); // UP | UV
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut signed = auth_data.clone();
        signed.extend_from_slice(&Sha256::digest(&client_data));
        let signature = self.key.sign(&self.rng, &signed).unwrap();
        serde_json::from_value(serde_json::json!({
            "id": URL_SAFE_NO_PAD.encode(&self.cred_id),
            "rawId": URL_SAFE_NO_PAD.encode(&self.cred_id),
            "response": {
                "authenticatorData": URL_SAFE_NO_PAD.encode(&auth_data),
                "clientDataJSON": URL_SAFE_NO_PAD.encode(&client_data),
                "signature": URL_SAFE_NO_PAD.encode(signature.as_ref()),
                "userHandle": URL_SAFE_NO_PAD.encode(user.as_bytes()),
            },
            "extensions": {},
            "type": "public-key",
        }))
        .expect("a PublicKeyCredential")
    }
}

type Auth = AuthService<
    SurrealUserRepository<Db>,
    SurrealSessionRepository<Db>,
    SurrealFederationLinkRepository<Db>,
    SurrealRefreshTokenRepository<Db>,
>;

struct World {
    db: Surreal<Db>,
    _dir: tempfile::TempDir,
    org_id: Uuid,
    tenant_id: Uuid,
    user_id: Uuid,
    authenticator: SoftAuthenticator,
    webauthn: WebauthnService<SurrealWebauthnCredentialRepository<Db>>,
    auth: Auth,
}

async fn world() -> World {
    let dir = tempfile::TempDir::new().unwrap();
    let db = Surreal::new::<SurrealKv>(dir.path().join("race.db").to_string_lossy().into_owned())
        .await
        .unwrap();
    db.use_ns("test").use_db("test").await.unwrap();
    axiam_db::run_migrations(&db).await.unwrap();
    let org = SurrealOrganizationRepository::new(db.clone())
        .create(CreateOrganization {
            name: "Org".into(),
            slug: "org".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let tenant = SurrealTenantRepository::new(db.clone())
        .create(CreateTenant {
            organization_id: org.id,
            kind: TenantKind::Standard,
            name: "Tenant".into(),
            slug: "tenant".into(),
            metadata: None,
        })
        .await
        .unwrap();
    let user = SurrealUserRepository::new(db.clone())
        .create(CreateUser {
            tenant_id: tenant.id,
            username: "holder".into(),
            email: "holder@example.com".into(),
            password: axiam_test_support::test_password(),
            metadata: None,
        })
        .await
        .unwrap();

    let authenticator = SoftAuthenticator::new();
    let credentials = SurrealWebauthnCredentialRepository::new(db.clone());
    credentials
        .create(CreateWebauthnCredential {
            tenant_id: tenant.id,
            user_id: user.id,
            credential_id: URL_SAFE_NO_PAD.encode(&authenticator.cred_id),
            name: "soft key".into(),
            credential_type: WebauthnCredentialType::Passkey,
            passkey_json: axiam_auth::totp::encrypt_secret(
                &mfa_key(),
                authenticator.passkey_json().as_bytes(),
            )
            .unwrap(),
            aaguid: None,
            attestation_format: None,
            attested: false,
            authenticator_name: None,
        })
        .await
        .unwrap();

    let webauthn = WebauthnService::new(credentials, config()).unwrap();
    let auth = AuthService::new(
        SurrealUserRepository::new(db.clone()),
        SurrealSessionRepository::new(db.clone()),
        SurrealFederationLinkRepository::new(db.clone()),
        SurrealRefreshTokenRepository::new(db.clone()),
        config(),
        Arc::new(tokio::sync::Semaphore::new(4)),
    );
    World {
        db,
        _dir: dir,
        org_id: org.id,
        tenant_id: tenant.id,
        user_id: user.id,
        authenticator,
        webauthn,
        auth,
    }
}

/// `start_authentication` (the second-factor ceremony): the challenge and the
/// state token.
async fn start(w: &World) -> (String, String) {
    let (rcr, state_token) = w
        .webauthn
        .start_authentication(
            w.tenant_id,
            w.org_id,
            w.user_id,
            WebauthnUserVerification::Required,
        )
        .await
        .unwrap();
    let challenge = serde_json::to_value(&rcr).unwrap()["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    (challenge, state_token)
}

/// What `POST /auth/webauthn/authenticate/finish` does: the ceremony's finish,
/// then — only if it succeeded — a session.
async fn finish(w: &World, state_token: &str, assertion: &PublicKeyCredential) -> bool {
    let Ok((user_id, org_id)) = w
        .webauthn
        .finish_authentication(w.tenant_id, state_token, assertion)
        .await
    else {
        return false;
    };
    w.auth
        .create_session_and_tokens(
            user_id,
            w.tenant_id,
            org_id,
            None,
            None,
            AuthenticationEvidence::now(vec![Amr::Pwd, Amr::Hwk, Amr::Mfa]),
        )
        .await
        .unwrap();
    true
}

async fn sessions(w: &World) -> usize {
    let ids: Vec<String> =
        w.db.query("SELECT VALUE meta::id(id) FROM session WHERE user_id = $user_id")
            .bind(("user_id", w.user_id.to_string()))
            .await
            .unwrap()
            .take(0)
            .unwrap();
    ids.len()
}

async fn stored_sign_count(w: &World) -> Option<i64> {
    let counts: Vec<Option<i64>> =
        w.db.query("SELECT VALUE sign_count FROM webauthn_credential WHERE user_id = $user_id")
            .bind(("user_id", w.user_id.to_string()))
            .await
            .unwrap()
            .take(0)
            .unwrap();
    counts.into_iter().next().flatten()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_assertion_is_refused() {
    let w = world().await;
    let (challenge, token) = start(&w).await;
    let assertion = w.authenticator.assert(&challenge, 1, w.user_id);

    assert!(
        finish(&w, &token, &assertion).await,
        "the first finish signs in"
    );
    assert_eq!(
        stored_sign_count(&w).await,
        Some(1),
        "the counter is stored"
    );
    assert!(
        !finish(&w, &token, &assertion).await,
        "the same token and assertion again are refused"
    );
    assert_eq!(sessions(&w).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_parallel_double_submit_opens_exactly_one_session() {
    let w = Arc::new(world().await);
    for round in 0..ROUNDS {
        let (challenge, token) = start(&w).await;
        let counter = u32::try_from(round).unwrap() + 1;
        let assertion = w.authenticator.assert(&challenge, counter, w.user_id);
        let before = sessions(&w).await;

        let barrier = Arc::new(tokio::sync::Barrier::new(2));
        let submit = || {
            let (w, token, assertion, barrier) =
                (w.clone(), token.clone(), assertion.clone(), barrier.clone());
            tokio::spawn(async move {
                barrier.wait().await;
                finish(&w, &token, &assertion).await
            })
        };
        let (a, b) = (submit(), submit());
        let (a, b) = (a.await.unwrap(), b.await.unwrap());
        assert!(
            a ^ b,
            "round {round}: exactly one finish succeeds ({a}, {b})"
        );
        assert_eq!(
            sessions(&w).await,
            before + 1,
            "round {round}: exactly one session"
        );
    }
}

/// Two ceremonies started together each freeze the stored counter into their
/// state; the assertion that reaches the store second with the same counter
/// is refused — the comparison `webauthn-rs` makes against the frozen value
/// could not see it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_counter_that_does_not_increase_is_refused() {
    let w = world().await;
    let (c1, t1) = start(&w).await;
    let (c2, t2) = start(&w).await;
    assert!(finish(&w, &t1, &w.authenticator.assert(&c1, 5, w.user_id)).await);
    assert!(
        !finish(&w, &t2, &w.authenticator.assert(&c2, 5, w.user_id)).await,
        "a second assertion at counter 5 is a cloned key's"
    );
    assert_eq!(stored_sign_count(&w).await, Some(5));

    // Forward again is accepted.
    let (c3, t3) = start(&w).await;
    assert!(finish(&w, &t3, &w.authenticator.assert(&c3, 6, w.user_id)).await);
    assert_eq!(stored_sign_count(&w).await, Some(6));
    assert_eq!(sessions(&w).await, 2);
}

/// An authenticator that keeps no counter reports 0 every time, and is
/// accepted every time — WebAuthn §7.2 step 21 compares only when either
/// counter is non-zero. Each ceremony is still single-use.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_authenticator_without_a_counter_signs_in_once_per_ceremony() {
    let w = world().await;
    for _ in 0..3 {
        let (challenge, token) = start(&w).await;
        let assertion = w.authenticator.assert(&challenge, 0, w.user_id);
        assert!(finish(&w, &token, &assertion).await);
        assert!(!finish(&w, &token, &assertion).await);
    }
    assert_eq!(sessions(&w).await, 3);
    assert_eq!(stored_sign_count(&w).await, Some(0));
}

/// The usernameless ceremony spends its token the same way.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_replayed_discoverable_assertion_is_refused() {
    let w = world().await;
    let (rcr, token) = w
        .webauthn
        .start_discoverable_authentication(w.tenant_id, w.org_id)
        .await
        .unwrap();
    let challenge = serde_json::to_value(&rcr).unwrap()["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let assertion = w.authenticator.assert(&challenge, 1, w.user_id);

    let first = w
        .webauthn
        .finish_discoverable_authentication(w.tenant_id, &token, &assertion)
        .await;
    assert_eq!(first.unwrap(), (w.user_id, w.org_id));
    assert!(
        w.webauthn
            .finish_discoverable_authentication(w.tenant_id, &token, &assertion)
            .await
            .is_err()
    );
}

// ---------------------------------------------------------------------------
// SA-03 (N10): a ceremony state token is not an access token
// ---------------------------------------------------------------------------
//
// Both ceremonies' state tokens are signed with the access-token key and,
// before SA-03, carried every claim `AccessTokenClaims` requires (`sub`,
// `tenant_id`, `org_id`, `iss`, `iat`, `exp`, `jti`) and no `aud` — so
// `validate_access_token` admitted them, and every verifier with no session
// check (the gRPC interceptor and `ValidateToken`, RFC 8693 `subject_token`,
// UMA `claim_token`) took the discoverable token's nil `sub` or the
// second-factor token's real `sub` as an authenticated principal.

/// The `typ` every ceremony state token carries.
const STATE_TYP: &str = "axiam-webauthn-state+jwt";

fn assert_not_an_access_token(token: &str, ceremony: &str) {
    let decoded = axiam_auth::token::validate_access_token(token, &config());
    assert!(
        decoded.is_err(),
        "the {ceremony} state token was accepted as an access token: {:?}",
        decoded.map(|c| (c.0.sub, c.0.tenant_id, c.0.aud))
    );
    assert!(
        axiam_auth::token::decode_access_token_any_audience(token, &config()).is_err(),
        "introspection must not describe the {ceremony} state token as an access token"
    );
    let header = jsonwebtoken::decode_header(token).unwrap();
    assert_eq!(header.typ.as_deref(), Some(STATE_TYP));
    // S-8: a state token names no JWKS key.
    assert_eq!(
        header.kid, None,
        "the {ceremony} state token must carry no kid"
    );
}

/// N10 variant (b): `start_authentication` (`sub` = the user, obtainable with
/// the password factor alone).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n10_a_second_factor_state_token_is_not_an_access_token() {
    let w = world().await;
    let (_, token) = start(&w).await;
    assert_not_an_access_token(&token, "second-factor");
}

/// N10 variant (a): `start_discoverable_authentication` (public route,
/// `sub` = the nil UUID).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn n10_a_discoverable_state_token_is_not_an_access_token() {
    let w = world().await;
    let (_, token) = w
        .webauthn
        .start_discoverable_authentication(w.tenant_id, w.org_id)
        .await
        .unwrap();
    assert_not_an_access_token(&token, "discoverable");
}

/// The claims of a genuine ceremony state token — `purpose`, encrypted
/// `state` and all — re-signed with the deployment key under the header an
/// access token carries (`typ: at+jwt` and the JWKS `kid`). Only the header
/// differs from the token the ceremony issued, so only a `typ` check can tell
/// them apart.
fn resigned_as_access_token(state_token: &str) -> String {
    let payload = state_token.split('.').nth(1).expect("a compact JWS");
    let claims: serde_json::Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap();
    assert!(claims.get("purpose").is_some() && claims.get("state").is_some());
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.typ = Some(axiam_auth::token::TYP_ACCESS_TOKEN.into());
    header.kid = axiam_auth::token::ed25519_jwk_kid(TEST_PUBLIC_KEY);
    jsonwebtoken::encode(
        &header,
        &claims,
        &jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIVATE_KEY.as_bytes()).unwrap(),
    )
    .unwrap()
}

/// The other direction: a token typed `at+jwt` is refused where a ceremony
/// state token is expected, by both finish entry points, even when its claims
/// are a genuine state token's. The untouched token then still finishes, so
/// the refusal was the header's doing and spent nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_access_token_is_not_a_ceremony_state_token() {
    let w = world().await;

    // Second factor.
    let (challenge, state_token) = start(&w).await;
    let assertion = w.authenticator.assert(&challenge, 1, w.user_id);
    let forged = resigned_as_access_token(&state_token);
    let refused = w
        .webauthn
        .finish_authentication(w.tenant_id, &forged, &assertion)
        .await;
    assert!(
        refused.is_err(),
        "an at+jwt token with state claims finished the second-factor ceremony: {refused:?}"
    );
    assert!(finish(&w, &state_token, &assertion).await);

    // Usernameless.
    let (rcr, state_token) = w
        .webauthn
        .start_discoverable_authentication(w.tenant_id, w.org_id)
        .await
        .unwrap();
    let challenge = serde_json::to_value(&rcr).unwrap()["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let assertion = w.authenticator.assert(&challenge, 2, w.user_id);
    let forged = resigned_as_access_token(&state_token);
    let refused = w
        .webauthn
        .finish_discoverable_authentication(w.tenant_id, &forged, &assertion)
        .await;
    assert!(
        refused.is_err(),
        "an at+jwt token with state claims finished the usernameless ceremony: {refused:?}"
    );
    assert_eq!(
        w.webauthn
            .finish_discoverable_authentication(w.tenant_id, &state_token, &assertion)
            .await
            .unwrap(),
        (w.user_id, w.org_id)
    );
    assert_eq!(
        sessions(&w).await,
        1,
        "only the genuine second-factor finish"
    );
}

// ---------------------------------------------------------------------
// SR2-1 — the second-factor finish honours the credential epoch.
// ---------------------------------------------------------------------

/// The finish exactly as `POST /auth/webauthn/authenticate/finish` runs it,
/// keeping the error.
async fn finish_like_the_handler(
    w: &World,
    state_token: &str,
    assertion: &PublicKeyCredential,
) -> axiam_core::error::AxiamResult<(Uuid, Uuid)> {
    w.auth
        .finish_webauthn_authentication(&w.webauthn, w.tenant_id, state_token, assertion)
        .await
}

/// A password reset, as the reset handler writes it: a new hash.
async fn reset_the_password(w: &World) {
    SurrealUserRepository::new(w.db.clone())
        .update(
            w.tenant_id,
            w.user_id,
            axiam_core::models::user::UpdateUser {
                password_hash: Some(
                    axiam_auth::password::hash_password("A-brand-new-Passw0rd!", None).unwrap(),
                ),
                ..Default::default()
            },
        )
        .await
        .unwrap();
}

/// SR2-1: a ceremony started before a password reset cannot finish after it.
/// The refusal is the answer an invalid state token gets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sr2_1_a_ceremony_started_before_a_reset_cannot_finish_after_it() {
    let w = world().await;
    let (challenge, state_token) = start(&w).await;
    reset_the_password(&w).await;

    let assertion = w.authenticator.assert(&challenge, 1, w.user_id);
    let err = finish_like_the_handler(&w, &state_token, &assertion)
        .await
        .expect_err("a ceremony that predates the reset must not finish");
    assert!(
        matches!(
            &err,
            axiam_core::error::AxiamError::AuthenticationFailed { reason }
                if *reason == axiam_auth::error::AuthError::WebauthnStateInvalid.to_string()
        ),
        "expected the invalid-state-token answer, got {err:?}"
    );
    assert_eq!(sessions(&w).await, 0, "no session was opened");
    assert_eq!(
        stored_sign_count(&w).await.unwrap_or(0),
        0,
        "the refusal happened before the assertion was accepted"
    );
}

/// SR3-1: a ceremony descending from an MFA challenge built from the
/// credential a reset replaced cannot finish, even though the challenge's issue
/// time is after the epoch: the state token carries the challenge's credential
/// version, and the user's has moved on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sr3_1_a_ceremony_from_a_challenge_of_the_replaced_credential_cannot_finish() {
    let w = world().await;
    // The credential version the challenge was built under (a user nobody has
    // changed: 0), then the reset moves it, and the epoch is put before the
    // challenge's issue time, as the race leaves it.
    reset_the_password(&w).await;
    w.db.query("UPDATE type::record('user', $id) SET credential_changed_at = time::now() - 1h")
        .bind(("id", w.user_id.to_string()))
        .await
        .unwrap()
        .check()
        .unwrap();
    let (rcr, state_token) = w
        .webauthn
        .start_authentication_for_challenge(
            w.tenant_id,
            w.org_id,
            w.user_id,
            WebauthnUserVerification::Required,
            Some(chrono::Utc::now()),
            Some(0),
        )
        .await
        .unwrap();
    let challenge = serde_json::to_value(&rcr).unwrap()["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let assertion = w.authenticator.assert(&challenge, 1, w.user_id);
    let err = finish_like_the_handler(&w, &state_token, &assertion)
        .await
        .expect_err("a ceremony of the replaced credential must not finish");
    assert!(
        matches!(
            &err,
            axiam_core::error::AxiamError::AuthenticationFailed { reason }
                if *reason == axiam_auth::error::AuthError::WebauthnStateInvalid.to_string()
        ),
        "expected the invalid-state-token answer, got {err:?}"
    );
    assert_eq!(sessions(&w).await, 0, "no session was opened");

    // Control: the same ceremony under the user's current version finishes.
    let (rcr, state_token) = w
        .webauthn
        .start_authentication_for_challenge(
            w.tenant_id,
            w.org_id,
            w.user_id,
            WebauthnUserVerification::Required,
            Some(chrono::Utc::now()),
            Some(1),
        )
        .await
        .unwrap();
    let challenge = serde_json::to_value(&rcr).unwrap()["publicKey"]["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let assertion = w.authenticator.assert(&challenge, 1, w.user_id);
    finish_like_the_handler(&w, &state_token, &assertion)
        .await
        .expect("a ceremony under the current credential version finishes");
}

/// SR2-1 control: with no reset in between, the same ceremony finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sr2_1_control_a_ceremony_with_no_reset_still_finishes() {
    let w = world().await;
    let (challenge, state_token) = start(&w).await;
    let assertion = w.authenticator.assert(&challenge, 1, w.user_id);
    finish_like_the_handler(&w, &state_token, &assertion)
        .await
        .expect("no credential change: the ceremony finishes");
}

/// SR2-1 control: a ceremony started *after* the reset finishes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sr2_1_control_a_ceremony_started_after_a_reset_finishes() {
    let w = world().await;
    reset_the_password(&w).await;
    let (challenge, state_token) = start(&w).await;
    let assertion = w.authenticator.assert(&challenge, 1, w.user_id);
    finish_like_the_handler(&w, &state_token, &assertion)
        .await
        .expect("started after the reset: the ceremony finishes");
}

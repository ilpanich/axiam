//! Coverage for `WebauthnService` ceremony orchestration that does not
//! require a live authenticator: service construction, challenge start,
//! encryption-key gating, and state-token decode/validation branches.
//!
//! The `finish_*` verification steps that call into `webauthn-rs` with a real
//! authenticator response are intentionally not exercised (they need a browser
//! WebAuthn ceremony); instead the surrounding decode/ownership checks are
//! driven to their error branches.

use axiam_auth::config::AuthConfig;
use axiam_auth::webauthn::WebauthnService;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::webauthn_credential::{
    CreateWebauthnCredential, WebauthnCredential, WebauthnCredentialType,
};
use axiam_core::repository::WebauthnCredentialRepository;
use chrono::Utc;
use uuid::Uuid;
use webauthn_rs::prelude::{PublicKeyCredential, RegisterPublicKeyCredential};

const PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----";
const PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----";

fn config(with_key: bool) -> AuthConfig {
    AuthConfig {
        jwt_private_key_pem: PRIV_PEM.into(),
        jwt_public_key_pem: PUB_PEM.into(),
        jwt_issuer: "axiam-test".into(),
        webauthn_rp_id: "localhost".into(),
        webauthn_rp_origin: "http://localhost:8090".into(),
        webauthn_rp_name: "AXIAM-Test".into(),
        mfa_challenge_lifetime_secs: 300,
        mfa_encryption_key: if with_key { Some([3u8; 32]) } else { None },
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Mock WebauthnCredentialRepository
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct MockCredRepo {
    creds: Vec<WebauthnCredential>,
}

fn cred_with_json(passkey_json: &str) -> WebauthnCredential {
    WebauthnCredential {
        id: Uuid::new_v4(),
        tenant_id: Uuid::new_v4(),
        user_id: Uuid::new_v4(),
        credential_id: "cred-id".into(),
        name: "key".into(),
        credential_type: WebauthnCredentialType::SecurityKey,
        passkey_json: passkey_json.into(),
        created_at: Utc::now(),
        last_used_at: None,
    }
}

impl WebauthnCredentialRepository for MockCredRepo {
    async fn create(&self, input: CreateWebauthnCredential) -> AxiamResult<WebauthnCredential> {
        Ok(WebauthnCredential {
            id: Uuid::new_v4(),
            tenant_id: input.tenant_id,
            user_id: input.user_id,
            credential_id: input.credential_id,
            name: input.name,
            credential_type: input.credential_type,
            passkey_json: input.passkey_json,
            created_at: Utc::now(),
            last_used_at: None,
        })
    }
    async fn get_by_id(&self, _t: Uuid, _i: Uuid) -> AxiamResult<WebauthnCredential> {
        unimplemented!()
    }
    async fn list_by_user(&self, _t: Uuid, _u: Uuid) -> AxiamResult<Vec<WebauthnCredential>> {
        Ok(self.creds.clone())
    }
    async fn update_last_used(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
        Ok(())
    }
    async fn delete(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
        unimplemented!()
    }
    async fn count_by_user(&self, _t: Uuid, _u: Uuid) -> AxiamResult<u64> {
        Ok(self.creds.len() as u64)
    }
}

fn empty_repo() -> MockCredRepo {
    MockCredRepo { creds: vec![] }
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

#[test]
fn new_succeeds_with_valid_config() {
    let svc = WebauthnService::new(empty_repo(), config(true));
    assert!(svc.is_ok());
}

#[test]
fn new_rejects_invalid_rp_origin() {
    let mut c = config(true);
    c.webauthn_rp_origin = "http://%%%not a url".into();
    let err = WebauthnService::new(empty_repo(), c);
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// start_registration
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_registration_produces_challenge_and_token() {
    let svc = WebauthnService::new(empty_repo(), config(true)).unwrap();
    let (_ccr, token) = svc
        .start_registration(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), "alice")
        .await
        .expect("registration should start");
    assert!(!token.is_empty());
}

#[tokio::test]
async fn start_registration_without_encryption_key_errors() {
    let svc = WebauthnService::new(empty_repo(), config(false)).unwrap();
    let res = svc
        .start_registration(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), "alice")
        .await;
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// finish_registration — decode + ownership branches (no real authenticator)
// ---------------------------------------------------------------------------

fn dummy_register_response() -> RegisterPublicKeyCredential {
    // Structurally-valid-enough JSON to deserialize; never reaches the
    // webauthn-rs verify step because the tenant/user checks fail first.
    serde_json::from_value(serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "attestationObject": "AAAA",
            "clientDataJSON": "AAAA"
        },
        "extensions": {}
    }))
    .expect("register response deserializes")
}

#[tokio::test]
async fn finish_registration_rejects_tenant_mismatch() {
    let svc = WebauthnService::new(empty_repo(), config(true)).unwrap();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let (_ccr, token) = svc
        .start_registration(tenant, Uuid::new_v4(), user, "alice")
        .await
        .unwrap();
    // Different tenant → decode succeeds, tenant check fails.
    let res = svc
        .finish_registration(
            Uuid::new_v4(),
            user,
            &token,
            "my key",
            &dummy_register_response(),
        )
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn finish_registration_rejects_user_mismatch() {
    let svc = WebauthnService::new(empty_repo(), config(true)).unwrap();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let (_ccr, token) = svc
        .start_registration(tenant, Uuid::new_v4(), user, "alice")
        .await
        .unwrap();
    // Correct tenant, different caller user → user check fails.
    let res = svc
        .finish_registration(
            tenant,
            Uuid::new_v4(),
            &token,
            "my key",
            &dummy_register_response(),
        )
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn finish_registration_matching_tenant_and_user_fails_at_verification() {
    // Correct tenant AND correct caller user — passes both ownership checks
    // and reaches the webauthn-rs verification step, which then fails
    // because `dummy_register_response()` is not a real authenticator
    // response. Exercises the call-and-map_err region that the
    // wrong-tenant/wrong-user tests above never reach.
    let svc = WebauthnService::new(empty_repo(), config(true)).unwrap();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let (_ccr, token) = svc
        .start_registration(tenant, Uuid::new_v4(), user, "alice")
        .await
        .unwrap();
    let res = svc
        .finish_registration(tenant, user, &token, "my key", &dummy_register_response())
        .await;
    assert!(
        res.is_err(),
        "a bogus authenticator response must fail webauthn-rs verification"
    );
}

#[tokio::test]
async fn finish_registration_rejects_garbage_token() {
    let svc = WebauthnService::new(empty_repo(), config(true)).unwrap();
    let res = svc
        .finish_registration(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "not.a.jwt",
            "my key",
            &dummy_register_response(),
        )
        .await;
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// start_authentication
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_authentication_without_credentials_errors() {
    let svc = WebauthnService::new(empty_repo(), config(true)).unwrap();
    let res = svc
        .start_authentication(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn start_authentication_with_undecryptable_credentials_errors() {
    // Credential present but its passkey_json cannot be decrypted → the
    // decoded passkey set is empty → WebauthnNoCredentials.
    let repo = MockCredRepo {
        creds: vec![cred_with_json("not-valid-ciphertext")],
    };
    let svc = WebauthnService::new(repo, config(true)).unwrap();
    let res = svc
        .start_authentication(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
        .await;
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// finish_authentication — decode branch
// ---------------------------------------------------------------------------

fn dummy_auth_response() -> PublicKeyCredential {
    serde_json::from_value(serde_json::json!({
        "id": "AAAA",
        "rawId": "AAAA",
        "type": "public-key",
        "response": {
            "authenticatorData": "AAAA",
            "clientDataJSON": "AAAA",
            "signature": "AAAA"
        },
        "extensions": {}
    }))
    .expect("auth response deserializes")
}

#[tokio::test]
async fn finish_authentication_rejects_garbage_token() {
    let svc = WebauthnService::new(empty_repo(), config(true)).unwrap();
    let res = svc
        .finish_authentication(Uuid::new_v4(), "not.a.jwt", &dummy_auth_response())
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn finish_authentication_rejects_wrong_purpose_token() {
    // A registration state token has purpose "webauthn_register"; feeding it
    // to finish_authentication (expects "webauthn_authenticate") → invalid.
    let svc = WebauthnService::new(empty_repo(), config(true)).unwrap();
    let tenant = Uuid::new_v4();
    let (_ccr, token) = svc
        .start_registration(tenant, Uuid::new_v4(), Uuid::new_v4(), "alice")
        .await
        .unwrap();
    let res = svc
        .finish_authentication(tenant, &token, &dummy_auth_response())
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn decode_state_token_rejects_issuer_mismatch() {
    // Two services share signing keys but declare different `jwt_issuer`s.
    // A token minted by one must be rejected by the other even though the
    // signature itself verifies (Validation::set_issuer enforcement).
    let mut cfg_a = config(true);
    cfg_a.jwt_issuer = "issuer-a".into();
    let svc_a = WebauthnService::new(empty_repo(), cfg_a).unwrap();

    let mut cfg_b = config(true);
    cfg_b.jwt_issuer = "issuer-b".into();
    let svc_b = WebauthnService::new(empty_repo(), cfg_b).unwrap();

    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let (_ccr, token) = svc_a
        .start_registration(tenant, Uuid::new_v4(), user, "alice")
        .await
        .unwrap();

    let res = svc_b
        .finish_registration(tenant, user, &token, "my key", &dummy_register_response())
        .await;
    assert!(
        res.is_err(),
        "a token from a different issuer must be rejected"
    );
    assert!(matches!(
        res.unwrap_err(),
        AxiamError::AuthenticationFailed { .. }
    ));
}

#[tokio::test]
async fn decode_state_token_rejects_wrong_encryption_key() {
    // Same signing keys and issuer, but a different `mfa_encryption_key`:
    // the JWT signature/issuer/purpose all check out, so decode reaches the
    // embedded-ciphertext decrypt step and fails there with a distinct
    // `Crypto` error rather than the generic `WebauthnStateInvalid`.
    let mut cfg_a = config(true);
    cfg_a.mfa_encryption_key = Some([7u8; 32]);
    let svc_a = WebauthnService::new(empty_repo(), cfg_a).unwrap();

    let mut cfg_b = config(true);
    cfg_b.mfa_encryption_key = Some([9u8; 32]);
    let svc_b = WebauthnService::new(empty_repo(), cfg_b).unwrap();

    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let (_ccr, token) = svc_a
        .start_registration(tenant, Uuid::new_v4(), user, "alice")
        .await
        .unwrap();

    let res = svc_b
        .finish_registration(tenant, user, &token, "my key", &dummy_register_response())
        .await;
    assert!(
        res.is_err(),
        "a state token encrypted under a different key must fail to decrypt"
    );
    assert!(
        matches!(res.unwrap_err(), AxiamError::Crypto(_)),
        "decrypt failure must surface as Crypto, distinct from WebauthnStateInvalid"
    );
}

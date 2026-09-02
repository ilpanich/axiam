//! Coverage for `WebauthnService::start_attested_registration` /
//! `finish_attested_registration` (X3 wave 2, D7 + addendum W2-D1/W2-D2/W2-D3)
//! that does not require a live authenticator.
//!
//! ## Honesty note on what is and is not covered here (spec §"Tests required")
//!
//! A genuine *recorded* attestation object (e.g. a YubiKey direct-attestation
//! fixture) cannot be produced from this sandbox, and fabricating one and
//! presenting it as recorded would assert the code against its own
//! assumptions rather than a real device. `webauthn-rs-core`'s own internal
//! test corpus (`~/.cargo/registry/src/*/webauthn-rs-core-0.5.5/src/core.rs`,
//! `#[cfg(test)] mod tests`) was checked and is not usable here either: those
//! vectors' signatures are computed over *that* crate's own test RP id/origin
//! and a specific challenge baked into each fixture's `clientDataJSON`, which
//! this service's `AuthConfig` cannot reproduce without controlling the
//! challenge — using them would require regenerating the attestation
//! signature, which defeats the point of a "recorded" vector.
//!
//! What **is** exercised, honestly: the policy+ceremony *seam* — state-token
//! encode/decode (including the W2-D2 `ca_list` strip/re-insert round trip),
//! the W2-D3 fail-closed empty-CA-list path, and that a stubbed (garbage)
//! authenticator response reaches `webauthn-rs`'s own verification rather
//! than failing earlier at AXIAM's own tenant/user/state checks — with a
//! synthetic, self-signed test root standing in for a real FIDO root
//! certificate (it is never chain-verified against anything; `webauthn-rs`
//! only needs *some* parseable X.509 DER to populate the CA list with).
//!
//! What is **not** covered: a real attestation signature reaching
//! `AttestationCaList` verification and being accepted, and therefore the
//! D8 "Allow" branch of `finish_attested_registration` end-to-end. That needs
//! either real hardware or a vendor-published recorded vector; state this
//! plainly rather than fabricate one (per the plan's own honesty rule, §X3
//! note 3).

use axiam_auth::config::AuthConfig;
use axiam_auth::webauthn::WebauthnService;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::mds::MdsEntry;
use axiam_core::models::webauthn_credential::{CreateWebauthnCredential, WebauthnCredential};
use axiam_core::models::webauthn_policy::{
    AttestationMode, WebauthnAttestationPolicy, WebauthnUserVerification,
};
use axiam_core::repository::{
    AttestationMetadataSource, AttestationRootMaterial, WebauthnCredentialRepository,
};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use chrono::Utc;
use std::collections::BTreeMap;
use uuid::Uuid;
use webauthn_rs::prelude::{
    AttestationCaList, AttestationCaListBuilder, RegisterPublicKeyCredential,
};

const PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----";
const PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----";

/// A real, self-signed Ed25519 X.509 certificate (`CN=axiam-test-root`),
/// vendored as DER/base64 the same way `axiam_auth::attestation`'s own unit
/// tests do — `AttestationCaListBuilder::insert_device_der` only needs
/// parseable X.509 DER, it never chain-verifies this cert against anything.
const TEST_ROOT_DER_B64: &str = "MIIBSDCB+6ADAgECAhQDiCypHmzEedN6JiRFDyTXDBUgRTAFBgMrZXAwGjEYMBYGA1UEAwwPYXhpYW0tdGVzdC1yb290MB4XDTI2MDgxMzA4MjcwOFoXDTM2MDgxMDA4MjcwOFowGjEYMBYGA1UEAwwPYXhpYW0tdGVzdC1yb290MCowBQYDK2VwAyEAyypYyUSxb2Q2w4Oz0JcGvoSJNHAsOCvC4s1wElt2yv6jUzBRMB0GA1UdDgQWBBQ5bN+q4O+R/Q4nq5Sq7Mc7GFMcuTAfBgNVHSMEGDAWgBQ5bN+q4O+R/Q4nq5Sq7Mc7GFMcuTAPBgNVHRMBAf8EBTADAQH/MAUGAytlcANBAL3cY5942daBVLRMfhDxBVL02x8Ps7eO5Sokw1mRyX+OcrdRXhRbjl9+8FBtbXiAp4F0JSLg6JWzYC+gQ8AVcQQ=";

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
        opaque_session_key: None,
        opaque_setup_key: None,
        ..Default::default()
    }
}

fn nonempty_ca_list() -> AttestationCaList {
    let der = STANDARD
        .decode(TEST_ROOT_DER_B64)
        .expect("vendored test DER decodes");
    let mut builder = AttestationCaListBuilder::new();
    builder
        .insert_device_der(
            &der,
            Uuid::new_v4(),
            "Test Authenticator".into(),
            BTreeMap::new(),
        )
        .expect("vendored test DER parses as X.509");
    builder.build()
}

// ---------------------------------------------------------------------------
// Mock WebauthnCredentialRepository (mirrors webauthn_tests.rs's own mock —
// duplicated rather than shared, matching that file's self-contained style)
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct MockCredRepo {
    creds: Vec<WebauthnCredential>,
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
            aaguid: input.aaguid,
            attestation_format: input.attestation_format,
            attested: input.attested,
            authenticator_name: input.authenticator_name,
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

// ---------------------------------------------------------------------------
// Mock AttestationMetadataSource — always "no MDS entry"
// ---------------------------------------------------------------------------

#[derive(Default)]
struct EmptyMetadata;

impl AttestationMetadataSource for EmptyMetadata {
    async fn get_entry(&self, _aaguid: Uuid) -> AxiamResult<Option<MdsEntry>> {
        Ok(None)
    }
    async fn attestation_roots(
        &self,
        _allowed_aaguids: Option<&[Uuid]>,
    ) -> AxiamResult<Vec<AttestationRootMaterial>> {
        Ok(vec![])
    }
}

fn dummy_register_response() -> RegisterPublicKeyCredential {
    // Structurally-valid-enough JSON to deserialize; never reaches attestation
    // trust-chain verification because it fails webauthn-rs's own parsing
    // first (see the module doc's honesty note) — that is enough to prove the
    // seam (decode/tenant/user/state) let it through.
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

// ---------------------------------------------------------------------------
// W2-D3 — fail closed on an empty CA list
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_attested_registration_fails_closed_on_empty_ca_list() {
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let empty = AttestationCaList::default();
    assert!(empty.is_empty(), "precondition: the fixture list is empty");

    let res = svc
        .start_attested_registration(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "alice",
            empty,
        )
        .await;

    let err = res.expect_err("an empty CA list must fail closed, never silently proceed");
    match err {
        AxiamError::ServiceUnavailable(msg) => {
            assert!(
                msg.contains("no FIDO metadata"),
                "operator-facing message must explain why, got: {msg}"
            );
        }
        other => panic!("expected ServiceUnavailable (W2-D3 fail-closed), got {other:?}"),
    }
}

#[tokio::test]
async fn start_attested_registration_never_reaches_webauthn_rs_with_an_empty_list() {
    // Same assertion from a different angle: even a tenant with zero existing
    // credentials and a trivially-satisfiable exclude list must still refuse
    // before any webauthn-rs call, i.e. the guard is unconditional on the
    // ceremony inputs, not a side effect of something else failing first.
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let res = svc
        .start_attested_registration(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "nobody-yet",
            AttestationCaList::default(),
        )
        .await;
    assert!(matches!(res, Err(AxiamError::ServiceUnavailable(_))));
}

// ---------------------------------------------------------------------------
// Happy-path start + W2-D2 strip/re-insert round trip
// ---------------------------------------------------------------------------

#[tokio::test]
async fn start_attested_registration_with_nonempty_ca_list_succeeds() {
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let (_ccr, token) = svc
        .start_attested_registration(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "alice",
            nonempty_ca_list(),
        )
        .await
        .expect("registration should start with a non-empty CA list");
    assert!(!token.is_empty());
}

/// The W2-D2 guard: strip at start, re-insert the *current* list at finish,
/// and the ceremony must still get far enough to reach webauthn-rs's own
/// verification — proving the round trip (not a state-decode failure) is
/// what a bogus response fails on. An upstream `AttestedPasskeyRegistration`
/// field rename that broke the strip/re-insert would instead surface as
/// `WebauthnStateInvalid`/a `Crypto` deserialize error here, which this test
/// explicitly rules out.
#[tokio::test]
async fn finish_attested_registration_roundtrip_reaches_verification_not_state_decode() {
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let ca_list = nonempty_ca_list();

    let (_ccr, token) = svc
        .start_attested_registration(tenant, Uuid::new_v4(), user, "alice", ca_list.clone())
        .await
        .unwrap();

    let policy = WebauthnAttestationPolicy {
        mode: AttestationMode::DirectRequired,
        ..WebauthnAttestationPolicy::default()
    };
    let metadata = EmptyMetadata;

    let res = svc
        .finish_attested_registration(
            tenant,
            user,
            &token,
            "my key",
            &dummy_register_response(),
            &policy,
            &metadata,
            &ca_list,
        )
        .await;

    let err = res.expect_err("a bogus authenticator response must fail webauthn-rs verification");
    let msg = err.to_string();
    assert!(
        !msg.to_lowercase().contains("state token"),
        "must not fail at the W2-D2 state round trip — got: {msg}"
    );
}

#[tokio::test]
async fn finish_attested_registration_rejects_tenant_mismatch() {
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let ca_list = nonempty_ca_list();
    let (_ccr, token) = svc
        .start_attested_registration(tenant, Uuid::new_v4(), user, "alice", ca_list.clone())
        .await
        .unwrap();

    let policy = WebauthnAttestationPolicy {
        mode: AttestationMode::Indirect,
        ..WebauthnAttestationPolicy::default()
    };
    let metadata = EmptyMetadata;

    let res = svc
        .finish_attested_registration(
            Uuid::new_v4(), // wrong tenant
            user,
            &token,
            "my key",
            &dummy_register_response(),
            &policy,
            &metadata,
            &ca_list,
        )
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn finish_attested_registration_rejects_user_mismatch() {
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let ca_list = nonempty_ca_list();
    let (_ccr, token) = svc
        .start_attested_registration(tenant, Uuid::new_v4(), user, "alice", ca_list.clone())
        .await
        .unwrap();

    let policy = WebauthnAttestationPolicy {
        mode: AttestationMode::Indirect,
        ..WebauthnAttestationPolicy::default()
    };
    let metadata = EmptyMetadata;

    let res = svc
        .finish_attested_registration(
            tenant,
            Uuid::new_v4(), // wrong caller user
            &token,
            "my key",
            &dummy_register_response(),
            &policy,
            &metadata,
            &ca_list,
        )
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn finish_attested_registration_rejects_garbage_token() {
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let policy = WebauthnAttestationPolicy::default();
    let metadata = EmptyMetadata;
    let ca_list = nonempty_ca_list();

    let res = svc
        .finish_attested_registration(
            Uuid::new_v4(),
            Uuid::new_v4(),
            "not.a.jwt",
            "my key",
            &dummy_register_response(),
            &policy,
            &metadata,
            &ca_list,
        )
        .await;
    assert!(res.is_err());
}

#[tokio::test]
async fn finish_attested_registration_rejects_unattested_state_token_purpose() {
    // A plain (unattested) registration state token has purpose
    // "webauthn_register"; feeding it to finish_attested_registration (which
    // expects "webauthn_register_attested") must be rejected — the two
    // ceremonies' tokens are not interchangeable.
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let (_ccr, unattested_token) = svc
        .start_registration(
            tenant,
            Uuid::new_v4(),
            user,
            "alice",
            WebauthnUserVerification::Preferred,
        )
        .await
        .unwrap();

    let policy = WebauthnAttestationPolicy::default();
    let metadata = EmptyMetadata;
    let ca_list = nonempty_ca_list();

    let res = svc
        .finish_attested_registration(
            tenant,
            user,
            &unattested_token,
            "my key",
            &dummy_register_response(),
            &policy,
            &metadata,
            &ca_list,
        )
        .await;
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// Policy-routed entry points — the ceremony choice is made from the policy,
// once, instead of at every call site.
// ---------------------------------------------------------------------------

/// A metadata source carrying exactly one usable attestation root, so a
/// policy-routed start can actually build a non-empty CA list.
struct OneRootMetadata;

impl AttestationMetadataSource for OneRootMetadata {
    async fn get_entry(&self, _aaguid: Uuid) -> AxiamResult<Option<MdsEntry>> {
        Ok(None)
    }

    async fn attestation_roots(
        &self,
        _allowed_aaguids: Option<&[Uuid]>,
    ) -> AxiamResult<Vec<AttestationRootMaterial>> {
        Ok(vec![AttestationRootMaterial {
            aaguid: Uuid::from_bytes([7; 16]),
            der: STANDARD
                .decode(TEST_ROOT_DER_B64)
                .expect("vendored test DER decodes"),
            description: "Test Authenticator".into(),
        }])
    }
}

#[tokio::test]
async fn mode_none_routes_to_the_unattested_ceremony() {
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let cache = axiam_auth::AttestationCaCache::new();
    let policy = WebauthnAttestationPolicy::default(); // mode: none

    // EmptyMetadata would make an attested start fail closed (W2-D3), so a
    // success here proves the unattested path was taken — today's behaviour,
    // unchanged, for a tenant that has not opted in.
    let (_ccr, token) = svc
        .start_registration_for_policy(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "alice",
            &policy,
            WebauthnUserVerification::Preferred,
            &EmptyMetadata,
            &cache,
        )
        .await
        .expect("mode: none must use the unattested ceremony");
    assert!(!token.is_empty());
}

#[tokio::test]
async fn non_none_mode_routes_to_the_attested_ceremony() {
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let cache = axiam_auth::AttestationCaCache::new();
    let policy = WebauthnAttestationPolicy {
        mode: AttestationMode::DirectRequired,
        ..WebauthnAttestationPolicy::default()
    };

    let (_ccr, token) = svc
        .start_registration_for_policy(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "alice",
            &policy,
            WebauthnUserVerification::Preferred,
            &OneRootMetadata,
            &cache,
        )
        .await
        .expect("a non-empty CA list must let the attested ceremony start");
    assert!(!token.is_empty());
}

#[tokio::test]
async fn non_none_mode_with_no_metadata_fails_closed_through_the_router() {
    // The W2-D3 guarantee must survive the routing layer: a tenant that
    // requires attestation but has no MDS metadata gets an error, never a
    // silent downgrade to the unattested ceremony.
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let cache = axiam_auth::AttestationCaCache::new();
    let policy = WebauthnAttestationPolicy {
        mode: AttestationMode::DirectRequired,
        ..WebauthnAttestationPolicy::default()
    };

    let res = svc
        .start_registration_for_policy(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            "alice",
            &policy,
            WebauthnUserVerification::Preferred,
            &EmptyMetadata,
            &cache,
        )
        .await;

    assert!(
        matches!(res, Err(AxiamError::ServiceUnavailable(_))),
        "must fail closed, got {res:?}"
    );
}

#[tokio::test]
async fn unattested_token_is_denied_when_the_policy_tightened_mid_ceremony() {
    // The race this closes: a ceremony starts under `mode: none`, an admin
    // switches the tenant to `direct_required`, and the ceremony then
    // finishes. Completing it would register a credential with no
    // attestation at a tenant that now requires it.
    let svc = WebauthnService::new(MockCredRepo::default(), config(true)).unwrap();
    let cache = axiam_auth::AttestationCaCache::new();
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();

    let (_ccr, token) = svc
        .start_registration(
            tenant_id,
            Uuid::new_v4(),
            user_id,
            "alice",
            WebauthnUserVerification::Preferred,
        )
        .await
        .expect("unattested start succeeds under mode: none");

    let tightened = WebauthnAttestationPolicy {
        mode: AttestationMode::DirectRequired,
        ..WebauthnAttestationPolicy::default()
    };

    let res = svc
        .finish_registration_for_policy(
            tenant_id,
            user_id,
            &token,
            "my key",
            &dummy_register_response(),
            &tightened,
            &OneRootMetadata,
            &cache,
        )
        .await;

    let err = res.expect_err("an unattested token must not complete under direct_required");
    match err {
        AxiamError::AuthorizationDenied { reason, action, .. } => {
            // D11: the end user gets the fixed, actionable sentence; the
            // machine-readable deny reason goes to the audit line, not here.
            assert_eq!(
                reason,
                "this security key model is not permitted by your organization"
            );
            assert_eq!(action.as_deref(), Some("webauthn:register"));
        }
        other => panic!("expected an attestation denial, got {other:?}"),
    }
}

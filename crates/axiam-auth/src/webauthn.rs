//! WebAuthn registration and authentication ceremonies.
//!
//! Ceremony state (`PasskeyRegistration` / `PasskeyAuthentication`) is
//! serialized to JSON, encrypted with AES-256-GCM via [`totp::encrypt_secret`],
//! and embedded in a short-lived JWT. Passkey data is encrypted at rest before
//! storage in the database.
//!
//! ## X3 wave 2 — the attested registration ceremony (D7, addendum W2-D1/W2-D2)
//!
//! [`WebauthnService::start_attested_registration`] /
//! [`WebauthnService::finish_attested_registration`] are **additive** —
//! neither existing public method above them changed signature, so every
//! caller of the unattested ceremony (today's `mode: none` behavior) is
//! unaffected. They exist for a tenant whose policy has `mode != none`; the
//! caller (a later-wave REST handler) is responsible for choosing which pair
//! to call based on the resolved `WebauthnAttestationPolicy` — this service
//! does not hold a policy repository itself (kept free of a hard
//! `axiam-pki`/`axiam-db` dependency, W2-D4; see `crate::attestation`'s
//! module docs for the fuller rationale).
//!
//! **AXIAM's `mode` does not map onto `webauthn-rs`'s conveyance the way the
//! plan first assumed (verified against the real 0.5.5 source, addendum
//! W2-D1):** `Webauthn::start_attested_passkey_registration` always requests
//! `AttestationConveyancePreference::Direct` — there is no library-level
//! `indirect` attested ceremony. So the real mapping is:
//!
//! - `mode: none` → [`WebauthnService::start_registration`] /
//!   [`WebauthnService::finish_registration`], unchanged;
//! - `mode: indirect` → the attested ceremony below (wire conveyance is
//!   `direct`, not `indirect`) with the *lax* policy defaults
//!   (`unknown_aaguid: allow` is the caller's job to set on the resolved
//!   policy, not this module's);
//! - `mode: direct_required` → the same attested ceremony with the *strict*
//!   defaults.
//!
//! `start_attested_passkey_registration` also unconditionally requires user
//! verification and rejects synchronised authenticators
//! (`reject_synchronised_authenticators(true)`) — so **every** non-`none`
//! mode excludes iCloud Keychain / Google Password Manager passkeys and
//! hybrid (phone-as-authenticator) flows, not just `direct_required`. State
//! this plainly wherever it is documented for admins/users — do not describe
//! the wire value as `indirect`.

use axiam_core::error::AxiamResult;
use axiam_core::models::mds::MdsEntry;
use axiam_core::models::webauthn_credential::{
    CreateWebauthnCredential, WebauthnCredential, WebauthnCredentialType,
};
use axiam_core::models::webauthn_policy::{
    AttestationCandidate, AttestationDecision, AttestationDenyReason, AttestationMode,
    WebauthnAttestationPolicy, evaluate,
};
use axiam_core::repository::{AttestationMetadataSource, WebauthnCredentialRepository};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::*;

use crate::config::AuthConfig;
use crate::error::AuthError;
use crate::totp;

/// State-token `purpose` for the attested registration ceremony — distinct
/// from `"webauthn_register"` so a token minted for one ceremony can never be
/// replayed against the other's `finish_*` entry point.
const PURPOSE_REGISTER_ATTESTED: &str = "webauthn_register_attested";

// -------------------------------------------------------------------
// State-token JWT claims (wraps encrypted ceremony state)
// -------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct WebauthnStateClaims {
    /// User ID.
    sub: String,
    /// Tenant scope.
    tenant_id: String,
    /// Organization scope (needed for token issuance after auth).
    org_id: String,
    /// `"webauthn_register"` or `"webauthn_authenticate"`.
    purpose: String,
    /// AES-256-GCM encrypted, base64-encoded ceremony state JSON.
    state: String,
    iss: String,
    iat: i64,
    exp: i64,
}

// -------------------------------------------------------------------
// WebauthnService
// -------------------------------------------------------------------

/// Orchestrates WebAuthn registration and authentication ceremonies.
#[derive(Clone)]
pub struct WebauthnService<W: WebauthnCredentialRepository> {
    webauthn: Arc<Webauthn>,
    credential_repo: W,
    config: AuthConfig,
}

impl<W: WebauthnCredentialRepository> WebauthnService<W> {
    /// Build the service, constructing the inner `Webauthn` instance
    /// from the relying-party configuration in [`AuthConfig`].
    pub fn new(credential_repo: W, config: AuthConfig) -> Result<Self, AuthError> {
        let rp_origin = Url::parse(&config.webauthn_rp_origin)
            .map_err(|e| AuthError::Crypto(format!("invalid RP origin URL: {e}")))?;
        let builder = WebauthnBuilder::new(&config.webauthn_rp_id, &rp_origin)
            .map_err(|e| AuthError::Crypto(format!("WebAuthn builder: {e}")))?
            .rp_name(&config.webauthn_rp_name);
        let webauthn = builder
            .build()
            .map_err(|e| AuthError::Crypto(format!("WebAuthn build: {e}")))?;

        Ok(Self {
            webauthn: Arc::new(webauthn),
            credential_repo,
            config,
        })
    }

    // ---- Registration ceremony ----

    /// Start passkey registration.
    ///
    /// Returns the challenge JSON for the browser **and** a JWT state
    /// token that must be forwarded to [`finish_registration`].
    pub async fn start_registration(
        &self,
        tenant_id: Uuid,
        org_id: Uuid,
        user_id: Uuid,
        username: &str,
    ) -> AxiamResult<(CreationChallengeResponse, String)> {
        // Fetch existing credentials to exclude from re-registration.
        let existing = self
            .credential_repo
            .list_by_user(tenant_id, user_id)
            .await?;

        let encryption_key = self.require_encryption_key()?;
        let exclude_creds: Vec<Passkey> = existing
            .iter()
            .filter_map(|c| self.decrypt_passkey(&encryption_key, &c.passkey_json).ok())
            .collect();

        // Extract credential IDs for the exclusion list so the
        // authenticator skips already-registered credentials.
        let exclude_ids: Vec<CredentialID> =
            exclude_creds.iter().map(|p| p.cred_id().clone()).collect();

        let (ccr, reg_state) = self
            .webauthn
            .start_passkey_registration(user_id, username, username, Some(exclude_ids))
            .map_err(|e| AuthError::WebauthnRegistration(e.to_string()))?;

        let state_token =
            self.encode_state_token(user_id, tenant_id, org_id, "webauthn_register", &reg_state)?;

        Ok((ccr, state_token))
    }

    /// Complete passkey registration.
    ///
    /// Verifies the authenticator response, encrypts the resulting
    /// passkey, and persists it in the credential repository.
    pub async fn finish_registration(
        &self,
        tenant_id: Uuid,
        caller_user_id: Uuid,
        state_token: &str,
        credential_name: &str,
        response: &RegisterPublicKeyCredential,
    ) -> AxiamResult<WebauthnCredential> {
        let (user_id, decoded_tenant_id, _org_id, reg_state) =
            self.decode_state_token::<PasskeyRegistration>(state_token, "webauthn_register")?;

        if decoded_tenant_id != tenant_id {
            return Err(AuthError::WebauthnStateInvalid.into());
        }

        if user_id != caller_user_id {
            return Err(AuthError::WebauthnStateInvalid.into());
        }

        let passkey = self
            .webauthn
            .finish_passkey_registration(response, &reg_state)
            .map_err(|e| AuthError::WebauthnRegistration(e.to_string()))?;

        let encryption_key = self.require_encryption_key()?;

        // Default to SecurityKey; the API handler can override based
        // on client-side attestation metadata if available.
        let credential_type = WebauthnCredentialType::SecurityKey;

        // Serialize and encrypt the passkey for at-rest storage.
        let passkey_json_plain = serde_json::to_string(&passkey)
            .map_err(|e| AuthError::Crypto(format!("serialize passkey: {e}")))?;
        let passkey_json_enc =
            totp::encrypt_secret(&encryption_key, passkey_json_plain.as_bytes())?;

        // credential_id as base64url-no-pad for external correlation.
        let credential_id_str = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());

        let created = self
            .credential_repo
            .create(CreateWebauthnCredential {
                tenant_id,
                user_id,
                credential_id: credential_id_str,
                name: credential_name.to_string(),
                credential_type,
                passkey_json: passkey_json_enc,
                // D6/D7 (X3): this is the unattested `mode: none` ceremony
                // (today's behavior, unchanged) — no attestation metadata was
                // requested or resolved. Wiring the attested ceremony's
                // metadata capture into this service is wave 2 (X3
                // enforcement) work.
                aaguid: None,
                attestation_format: None,
                attested: false,
                authenticator_name: None,
            })
            .await?;

        Ok(created)
    }

    // ---- Authentication ceremony ----

    /// Start passkey authentication.
    ///
    /// Returns the challenge JSON for the browser **and** a JWT state
    /// token that must be forwarded to [`finish_authentication`].
    pub async fn start_authentication(
        &self,
        tenant_id: Uuid,
        org_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<(RequestChallengeResponse, String)> {
        let existing = self
            .credential_repo
            .list_by_user(tenant_id, user_id)
            .await?;

        if existing.is_empty() {
            return Err(AuthError::WebauthnNoCredentials.into());
        }

        let encryption_key = self.require_encryption_key()?;
        let passkeys: Vec<Passkey> = existing
            .iter()
            .filter_map(|c| self.decrypt_passkey(&encryption_key, &c.passkey_json).ok())
            .collect();

        if passkeys.is_empty() {
            return Err(AuthError::WebauthnNoCredentials.into());
        }

        let (rcr, auth_state) = self
            .webauthn
            .start_passkey_authentication(&passkeys)
            .map_err(|e| AuthError::WebauthnAuthentication(e.to_string()))?;

        let state_token = self.encode_state_token(
            user_id,
            tenant_id,
            org_id,
            "webauthn_authenticate",
            &auth_state,
        )?;

        Ok((rcr, state_token))
    }

    /// Complete passkey authentication.
    ///
    /// Verifies the authenticator assertion and updates the
    /// `last_used_at` timestamp on the matched credential. Returns the
    /// authenticated `user_id` on success.
    pub async fn finish_authentication(
        &self,
        tenant_id: Uuid,
        state_token: &str,
        response: &PublicKeyCredential,
    ) -> AxiamResult<(Uuid, Uuid)> {
        let (user_id, decoded_tenant_id, org_id, auth_state) =
            self.decode_state_token::<PasskeyAuthentication>(state_token, "webauthn_authenticate")?;

        if decoded_tenant_id != tenant_id {
            return Err(AuthError::WebauthnStateInvalid.into());
        }

        let auth_result = self
            .webauthn
            .finish_passkey_authentication(response, &auth_state)
            .map_err(|e| AuthError::WebauthnAuthentication(e.to_string()))?;

        // Update last_used_at for the credential that was used.
        let cred_id_b64 = URL_SAFE_NO_PAD.encode(auth_result.cred_id().as_ref());
        let credentials = self
            .credential_repo
            .list_by_user(tenant_id, user_id)
            .await?;
        if let Some(cred) = credentials.iter().find(|c| c.credential_id == cred_id_b64)
            && let Err(e) = self
                .credential_repo
                .update_last_used(tenant_id, cred.id)
                .await
        {
            tracing::warn!(
                credential_id = %cred.id,
                error = %e,
                "failed to update last_used_at for WebAuthn credential"
            );
        }

        Ok((user_id, org_id))
    }

    // ---- Private helpers ----

    fn require_encryption_key(&self) -> Result<[u8; 32], AuthError> {
        self.config
            .mfa_encryption_key
            .ok_or_else(|| AuthError::Crypto("MFA encryption key not configured".into()))
    }

    fn decrypt_passkey(&self, key: &[u8; 32], encrypted: &str) -> Result<Passkey, AuthError> {
        let json_bytes = totp::decrypt_secret(key, encrypted)?;
        let json_str = String::from_utf8(json_bytes)
            .map_err(|e| AuthError::Crypto(format!("passkey UTF-8: {e}")))?;
        serde_json::from_str(&json_str)
            .map_err(|e| AuthError::Crypto(format!("passkey deserialize: {e}")))
    }

    /// Encode a state token from an already-JSON-serialized state value.
    ///
    /// This is the low-level primitive [`Self::encode_state_token`] wraps for
    /// the common case (a `T: Serialize` state, no pre-processing). It exists
    /// separately so the attested-registration path (W2-D2) can strip
    /// `ca_list` out of the serialized `AttestedPasskeyRegistration` *before*
    /// encryption, without duplicating everything else this method does.
    fn encode_state_token_json(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        org_id: Uuid,
        purpose: &str,
        state_json_value: JsonValue,
    ) -> Result<String, AuthError> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let encryption_key = self.require_encryption_key()?;
        let state_json = serde_json::to_string(&state_json_value)
            .map_err(|e| AuthError::Crypto(format!("serialize state: {e}")))?;
        let encrypted_state = totp::encrypt_secret(&encryption_key, state_json.as_bytes())?;

        let now = chrono::Utc::now().timestamp();
        let claims = WebauthnStateClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            org_id: org_id.to_string(),
            purpose: purpose.into(),
            state: encrypted_state,
            iss: self.config.jwt_issuer.clone(),
            iat: now,
            exp: now + self.config.mfa_challenge_lifetime_secs as i64,
        };

        let key = EncodingKey::from_ed_pem(self.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad private key: {e}")))?;
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, &claims, &key)
            .map_err(|e| AuthError::Crypto(format!("JWT encode: {e}")))
    }

    fn encode_state_token<T: Serialize>(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        org_id: Uuid,
        purpose: &str,
        state: &T,
    ) -> Result<String, AuthError> {
        let state_json_value = serde_json::to_value(state)
            .map_err(|e| AuthError::Crypto(format!("serialize state: {e}")))?;
        self.encode_state_token_json(user_id, tenant_id, org_id, purpose, state_json_value)
    }

    /// Decode a state token down to its raw JSON state value, without
    /// deserializing it into a concrete type yet.
    ///
    /// [`Self::decode_state_token`] wraps this for the common case; the
    /// attested-registration path (W2-D2) uses this directly so it can
    /// re-insert the *current* `ca_list` into the value before deserializing
    /// it as `AttestedPasskeyRegistration`.
    fn decode_state_token_json(
        &self,
        token: &str,
        expected_purpose: &str,
    ) -> Result<(Uuid, Uuid, Uuid, JsonValue), AuthError> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};

        let key = DecodingKey::from_ed_pem(self.config.jwt_public_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad public key: {e}")))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);

        let data = jsonwebtoken::decode::<WebauthnStateClaims>(token, &key, &validation)
            .map_err(|_| AuthError::WebauthnStateInvalid)?;

        if data.claims.purpose != expected_purpose {
            return Err(AuthError::WebauthnStateInvalid);
        }

        let user_id: Uuid = data
            .claims
            .sub
            .parse()
            .map_err(|_| AuthError::WebauthnStateInvalid)?;
        let tenant_id: Uuid = data
            .claims
            .tenant_id
            .parse()
            .map_err(|_| AuthError::WebauthnStateInvalid)?;
        let org_id: Uuid = data
            .claims
            .org_id
            .parse()
            .map_err(|_| AuthError::WebauthnStateInvalid)?;

        let encryption_key = self.require_encryption_key()?;
        let state_bytes = totp::decrypt_secret(&encryption_key, &data.claims.state)?;
        let state_json = String::from_utf8(state_bytes)
            .map_err(|e| AuthError::Crypto(format!("state UTF-8: {e}")))?;
        let state_value: JsonValue = serde_json::from_str(&state_json)
            .map_err(|e| AuthError::Crypto(format!("state deserialize: {e}")))?;

        Ok((user_id, tenant_id, org_id, state_value))
    }

    fn decode_state_token<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        expected_purpose: &str,
    ) -> Result<(Uuid, Uuid, Uuid, T), AuthError> {
        let (user_id, tenant_id, org_id, state_value) =
            self.decode_state_token_json(token, expected_purpose)?;
        let state: T = serde_json::from_value(state_value)
            .map_err(|e| AuthError::Crypto(format!("state deserialize: {e}")))?;
        Ok((user_id, tenant_id, org_id, state))
    }

    /// Read a state token's `purpose` claim **after** verifying its
    /// signature, issuer and expiry.
    ///
    /// Used only by [`Self::finish_registration_for_policy`] to learn which
    /// ceremony a token belongs to before dispatching. The full validation
    /// runs first — an unsigned or expired token is rejected here, not
    /// classified — so this never turns the `purpose` claim into an
    /// attacker-chosen routing input.
    fn state_token_purpose(&self, token: &str) -> Result<String, AuthError> {
        use jsonwebtoken::{Algorithm, DecodingKey, Validation};

        let key = DecodingKey::from_ed_pem(self.config.jwt_public_key_pem.as_bytes())
            .map_err(|e| AuthError::Crypto(format!("bad public key: {e}")))?;

        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[&self.config.jwt_issuer]);
        validation.set_required_spec_claims(&["sub", "exp", "iat", "iss"]);

        let data = jsonwebtoken::decode::<WebauthnStateClaims>(token, &key, &validation)
            .map_err(|_| AuthError::WebauthnStateInvalid)?;
        Ok(data.claims.purpose)
    }

    // ---- Attested registration ceremony (X3 wave 2, D7 + W2-D1/W2-D2/W2-D3) ----

    /// Start the attested passkey registration ceremony (`mode: indirect` or
    /// `mode: direct_required` — see the module docs for why both use this
    /// same call).
    ///
    /// `ca_list` must already be built for the tenant's policy (typically via
    /// `crate::attestation::AttestationCaCache`, filtered to
    /// `allowed_aaguids` when the policy sets one) — this method does not
    /// build it itself, matching this service's W2-D4 "no policy/metadata
    /// dependency" design.
    ///
    /// **Fails closed (W2-D3):** an empty `ca_list` is rejected with
    /// [`AuthError::WebauthnAttestationUnavailable`] *before* calling into
    /// `webauthn-rs` — never a silent fallback to the unattested ceremony.
    pub async fn start_attested_registration(
        &self,
        tenant_id: Uuid,
        org_id: Uuid,
        user_id: Uuid,
        username: &str,
        ca_list: AttestationCaList,
    ) -> AxiamResult<(CreationChallengeResponse, String)> {
        if ca_list.is_empty() {
            return Err(AuthError::WebauthnAttestationUnavailable.into());
        }

        let existing = self
            .credential_repo
            .list_by_user(tenant_id, user_id)
            .await?;

        let encryption_key = self.require_encryption_key()?;
        let exclude_ids: Vec<CredentialID> = existing
            .iter()
            .filter_map(|c| self.decrypt_passkey(&encryption_key, &c.passkey_json).ok())
            .map(|p| p.cred_id().clone())
            .collect();

        let (ccr, reg_state) = self
            .webauthn
            .start_attested_passkey_registration(
                user_id,
                username,
                username,
                Some(exclude_ids),
                ca_list,
                None,
            )
            .map_err(|e| AuthError::WebauthnRegistration(e.to_string()))?;

        // W2-D2: strip `ca_list` out of the serialized state before it is
        // encrypted and embedded in the state token. On the live BLOB this
        // list is ~800 KB (255 unique roots) — embedding it in every
        // registration's state token is unacceptable, and it never
        // influences `CreationChallengeResponse` (verified by reading the
        // builder), so stripping it is invisible to the client.
        let mut state_value = serde_json::to_value(&reg_state)
            .map_err(|e| AuthError::Crypto(format!("serialize attested state: {e}")))?;
        let removed = state_value
            .as_object_mut()
            .and_then(|obj| obj.remove("ca_list"));
        if removed.is_none() {
            // Fail loudly rather than silently embedding the (huge) ca_list
            // unstripped — an upstream `webauthn-rs` field rename must break
            // this loudly, never degrade security silently (W2-D2).
            return Err(AuthError::Crypto(
                "AttestedPasskeyRegistration serialization did not contain a ca_list \
                 field to strip (W2-D2) — refusing to embed the state unstripped"
                    .into(),
            )
            .into());
        }

        let state_token = self.encode_state_token_json(
            user_id,
            tenant_id,
            org_id,
            PURPOSE_REGISTER_ATTESTED,
            state_value,
        )?;

        Ok((ccr, state_token))
    }

    /// Complete the attested passkey registration ceremony, enforce the
    /// tenant's attestation policy (D8), and persist the resulting credential
    /// with its attestation metadata (D6) on success.
    ///
    /// `current_ca_list` is re-inserted into the decoded state (W2-D2) —
    /// deliberately the **current** list, not the one captured at
    /// `start_attested_registration` time, so an MDS refresh between start
    /// and finish takes effect. `policy` and `metadata` drive the D8 policy
    /// decision; on denial this returns
    /// [`AuthError::WebauthnAttestationDenied`] and **never** persists a
    /// credential or touches any existing one (D7: "existing credentials are
    /// never auto-revoked" — this method has no delete/disable code path at
    /// all).
    #[allow(clippy::too_many_arguments)] // mirrors finish_registration's own parameter shape plus the three D8 policy inputs (policy/metadata/ca_list); grouping them into a struct would only move the naming problem, not remove it.
    pub async fn finish_attested_registration<M: AttestationMetadataSource>(
        &self,
        tenant_id: Uuid,
        caller_user_id: Uuid,
        state_token: &str,
        credential_name: &str,
        response: &RegisterPublicKeyCredential,
        policy: &WebauthnAttestationPolicy,
        metadata: &M,
        current_ca_list: &AttestationCaList,
    ) -> AxiamResult<WebauthnCredential> {
        let (user_id, decoded_tenant_id, _org_id, mut state_value) =
            self.decode_state_token_json(state_token, PURPOSE_REGISTER_ATTESTED)?;

        if decoded_tenant_id != tenant_id {
            return Err(AuthError::WebauthnStateInvalid.into());
        }
        if user_id != caller_user_id {
            return Err(AuthError::WebauthnStateInvalid.into());
        }

        // W2-D2: re-insert the CURRENT ca_list before deserializing.
        let ca_list_value = serde_json::to_value(current_ca_list)
            .map_err(|e| AuthError::Crypto(format!("serialize ca_list: {e}")))?;
        state_value
            .as_object_mut()
            .ok_or(AuthError::WebauthnStateInvalid)?
            .insert("ca_list".to_string(), ca_list_value);
        let reg_state: AttestedPasskeyRegistration = serde_json::from_value(state_value)
            .map_err(|e| AuthError::Crypto(format!("deserialize attested state: {e}")))?;

        let attested = match self
            .webauthn
            .finish_attested_passkey_registration(response, &reg_state)
        {
            Ok(a) => a,
            // W2-D1 point 3: a `none`/self-attested credential cannot survive
            // the attested ceremony — `finish_attested_passkey_registration`
            // rejects it with `AttestationNotVerifiable` (verified by reading
            // `webauthn-rs-core::attestation::verify_attestation_ca_chain`,
            // which returns `Ok(None)` for `ParsedAttestationData::None`/
            // `Self_`, which `register_credential_internal` then turns into
            // this error because a ca_list was supplied). Map it to the same
            // user-actionable denial D8 step 2 would have produced.
            Err(WebauthnError::AttestationNotVerifiable) => {
                tracing::warn!(
                    action = "webauthn.attestation_denied",
                    tenant_id = %tenant_id,
                    user_id = %user_id,
                    reason = ?AttestationDenyReason::AttestationRequired,
                    "WebAuthn registration denied: attestation could not be verified \
                     (no/self attestation presented to an attested ceremony)"
                );
                return Err(AuthError::WebauthnAttestationDenied {
                    reason: AttestationDenyReason::AttestationRequired,
                }
                .into());
            }
            Err(e) => return Err(AuthError::WebauthnRegistration(e.to_string()).into()),
        };

        let (aaguid, attestation_format) = extract_attestation_metadata(&attested);

        let mds_entry: Option<MdsEntry> = match aaguid {
            Some(id) => metadata.get_entry(id).await?,
            None => None,
        };
        let candidate = AttestationCandidate {
            aaguid,
            attestation_format: attestation_format.as_deref(),
            mds_entry: mds_entry.as_ref(),
        };

        if let AttestationDecision::Deny(reason) = evaluate(policy, &candidate) {
            tracing::warn!(
                action = "webauthn.attestation_denied",
                tenant_id = %tenant_id,
                user_id = %user_id,
                aaguid = ?aaguid,
                reason = ?reason,
                "WebAuthn registration denied by attestation policy"
            );
            return Err(AuthError::WebauthnAttestationDenied { reason }.into());
        }

        let authenticator_name = mds_entry.and_then(|e| e.description);

        let passkey: Passkey = Passkey::from(attested);
        let encryption_key = self.require_encryption_key()?;
        let passkey_json_plain = serde_json::to_string(&passkey)
            .map_err(|e| AuthError::Crypto(format!("serialize passkey: {e}")))?;
        let passkey_json_enc =
            totp::encrypt_secret(&encryption_key, passkey_json_plain.as_bytes())?;
        let credential_id_str = URL_SAFE_NO_PAD.encode(passkey.cred_id().as_ref());

        let created = self
            .credential_repo
            .create(CreateWebauthnCredential {
                tenant_id,
                user_id,
                credential_id: credential_id_str,
                name: credential_name.to_string(),
                credential_type: WebauthnCredentialType::SecurityKey,
                passkey_json: passkey_json_enc,
                aaguid,
                attestation_format,
                attested: true,
                authenticator_name,
            })
            .await?;

        Ok(created)
    }

    // ---- Policy-routed entry points (the ones callers should use) ----

    /// Start registration, choosing the ceremony from the tenant's policy.
    ///
    /// This exists so the choice between the attested and unattested ceremony
    /// is made in **one** place, from the policy, rather than at every call
    /// site. That choice is the whole feature: a caller that reaches for
    /// [`Self::start_registration`] directly for a `direct_required` tenant
    /// silently downgrades it to no attestation at all, and nothing else in
    /// the system would notice — no error, no audit line, just a policy that
    /// quietly stopped applying. Callers (REST/gRPC handlers) should use this
    /// and [`Self::finish_registration_for_policy`]; the two ceremony-specific
    /// methods remain public for tests and for callers that have already
    /// resolved the ceremony themselves.
    pub async fn start_registration_for_policy<M: AttestationMetadataSource>(
        &self,
        tenant_id: Uuid,
        org_id: Uuid,
        user_id: Uuid,
        username: &str,
        policy: &WebauthnAttestationPolicy,
        metadata: &M,
        ca_cache: &crate::attestation::AttestationCaCache,
    ) -> AxiamResult<(CreationChallengeResponse, String)> {
        if policy.mode == AttestationMode::None {
            return self
                .start_registration(tenant_id, org_id, user_id, username)
                .await;
        }

        let ca_list = ca_cache
            .get_or_build(metadata, policy.allowed_aaguids.as_deref())
            .await?;
        self.start_attested_registration(tenant_id, org_id, user_id, username, (*ca_list).clone())
            .await
    }

    /// Complete registration, routing on the ceremony that actually *started*
    /// and re-checking it against the policy in force **now**.
    ///
    /// Routing on the state token's `purpose` rather than on the current
    /// policy is deliberate: the token encodes which ceremony produced the
    /// challenge the authenticator answered, and that cannot be revised after
    /// the fact. But a policy can be tightened while a ceremony is in flight,
    /// so an unattested token arriving at a tenant that now requires
    /// attestation is **denied** rather than completed — the alternative is a
    /// window, however short, in which a newly-enforced policy can be
    /// sidestepped by a ceremony started a moment before it was applied.
    ///
    /// The reverse direction needs no special case: an attested token
    /// arriving at a now-`mode: none` tenant still goes through full
    /// attestation verification and the (now permissive) policy, which is
    /// strictly safer than the tenant's current setting requires.
    #[allow(clippy::too_many_arguments)] // finish_registration's five parameters plus the three policy inputs; a wrapper struct would relocate the naming, not reduce it.
    pub async fn finish_registration_for_policy<M: AttestationMetadataSource>(
        &self,
        tenant_id: Uuid,
        caller_user_id: Uuid,
        state_token: &str,
        credential_name: &str,
        response: &RegisterPublicKeyCredential,
        policy: &WebauthnAttestationPolicy,
        metadata: &M,
        ca_cache: &crate::attestation::AttestationCaCache,
    ) -> AxiamResult<WebauthnCredential> {
        if self.state_token_purpose(state_token)? == PURPOSE_REGISTER_ATTESTED {
            let ca_list = ca_cache
                .get_or_build(metadata, policy.allowed_aaguids.as_deref())
                .await?;
            return self
                .finish_attested_registration(
                    tenant_id,
                    caller_user_id,
                    state_token,
                    credential_name,
                    response,
                    policy,
                    metadata,
                    &ca_list,
                )
                .await;
        }

        if policy.mode != AttestationMode::None {
            tracing::warn!(
                action = "webauthn.attestation_denied",
                tenant_id = %tenant_id,
                user_id = %caller_user_id,
                reason = ?AttestationDenyReason::AttestationRequired,
                "WebAuthn registration denied: unattested ceremony finishing against a \
                 tenant whose attestation policy now requires attestation"
            );
            return Err(AuthError::WebauthnAttestationDenied {
                reason: AttestationDenyReason::AttestationRequired,
            }
            .into());
        }

        self.finish_registration(
            tenant_id,
            caller_user_id,
            state_token,
            credential_name,
            response,
        )
        .await
    }
}

/// Derive `(aaguid, attestation_format)` (D6) from an `AttestedPasskey`.
///
/// `AttestedPasskey` exposes no direct `attestation_format` getter (the
/// underlying `Credential::attestation_format` field is crate-private), so
/// this reads the AAGUID-bearing `AttestationMetadata` variant instead — the
/// attested ceremony only ever produces `Packed` or `Tpm` (W2-D1: the request
/// builder restricts `attestation_formats` to exactly those two), so matching
/// on that pair covers every value this method can actually see; `_ => (None,
/// None)` exists only as a fail-safe for a format this crate does not expect
/// here, not a path exercised by `webauthn-rs` 0.5.5's attested ceremony.
fn extract_attestation_metadata(attested: &AttestedPasskey) -> (Option<Uuid>, Option<String>) {
    match &attested.attestation().metadata {
        AttestationMetadata::Packed { aaguid } => (Some(*aaguid), Some("packed".to_string())),
        AttestationMetadata::Tpm { aaguid, .. } => (Some(*aaguid), Some("tpm".to_string())),
        _ => (None, None),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
//
// This module's ceremony entry points cannot be unit-tested without a real
// authenticator, but the STATE TOKEN machinery underneath them can be, and it
// is where this module's security properties actually live. A WebAuthn state
// token is the only thing carrying ceremony state between the two halves of a
// registration or authentication, across a boundary the browser controls — so
// what matters is not that a round trip works, but everything the decoder
// REFUSES.
//
// Four refusals are load-bearing, and each has a test below that fails if the
// check is removed:
//
//  * A token minted for one ceremony must not be redeemable in the other
//    (`purpose`). Without it, a registration state could be replayed into
//    `finish_authentication`.
//  * A token signed by any other key must not verify.
//  * A token from another issuer must not verify.
//  * An expired token must not verify.
//
// And one confidentiality property: the ceremony state is ENCRYPTED inside the
// JWT, not merely signed. A JWT payload is public — base64, not a secret — so
// a signed-only state would publish the challenge to anyone holding the token.

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::error::{AxiamError, AxiamResult};
    use axiam_core::models::webauthn_credential::{CreateWebauthnCredential, WebauthnCredential};
    use serde_json::json;

    // The Ed25519 pair the rest of this crate's tests use.
    const PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n-----END PRIVATE KEY-----"; // nosemgrep: generic.secrets.security.detected-private-key
    const PUB_PEM: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n-----END PUBLIC KEY-----";

    const KEY: [u8; 32] = [7u8; 32];

    /// The repo is never reached by any test here — every one of them stops
    /// inside the token/crypto helpers — so the doubles return errors rather
    /// than plausible rows. A test that accidentally reaches storage should
    /// fail loudly instead of quietly passing on fabricated data.
    #[derive(Clone)]
    struct UnusedRepo;

    impl WebauthnCredentialRepository for UnusedRepo {
        async fn create(&self, _i: CreateWebauthnCredential) -> AxiamResult<WebauthnCredential> {
            Err(AxiamError::Internal("repo must not be reached".into()))
        }
        async fn get_by_id(&self, _t: Uuid, _i: Uuid) -> AxiamResult<WebauthnCredential> {
            Err(AxiamError::Internal("repo must not be reached".into()))
        }
        async fn list_by_user(&self, _t: Uuid, _u: Uuid) -> AxiamResult<Vec<WebauthnCredential>> {
            Err(AxiamError::Internal("repo must not be reached".into()))
        }
        async fn update_last_used(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
            Err(AxiamError::Internal("repo must not be reached".into()))
        }
        async fn delete(&self, _t: Uuid, _i: Uuid) -> AxiamResult<()> {
            Err(AxiamError::Internal("repo must not be reached".into()))
        }
        async fn count_by_user(&self, _t: Uuid, _u: Uuid) -> AxiamResult<u64> {
            Err(AxiamError::Internal("repo must not be reached".into()))
        }
    }

    fn config() -> AuthConfig {
        AuthConfig {
            jwt_private_key_pem: PRIV_PEM.into(),
            jwt_public_key_pem: PUB_PEM.into(),
            jwt_issuer: "axiam-test".into(),
            mfa_encryption_key: Some(KEY),
            mfa_challenge_lifetime_secs: 300,
            webauthn_rp_id: "localhost".into(),
            webauthn_rp_origin: "http://localhost:8090".into(),
            webauthn_rp_name: "AXIAM-Test".into(),
            ..AuthConfig::default()
        }
    }

    fn service() -> WebauthnService<UnusedRepo> {
        WebauthnService::new(UnusedRepo, config()).expect("service builds from a valid config")
    }

    fn ids() -> (Uuid, Uuid, Uuid) {
        (
            Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
        )
    }

    // -- construction ------------------------------------------------------

    #[test]
    fn new_rejects_an_unparseable_rp_origin() {
        let cfg = AuthConfig {
            webauthn_rp_origin: "not a url".into(),
            ..config()
        };
        let err = WebauthnService::new(UnusedRepo, cfg)
            .err()
            .expect("an unparseable RP origin must not build a service");
        assert!(
            matches!(err, AuthError::Crypto(ref m) if m.contains("RP origin")),
            "expected an RP-origin Crypto error, got {err:?}"
        );
    }

    #[test]
    fn new_rejects_an_rp_id_that_does_not_match_the_origin() {
        // webauthn-rs enforces the RP ID / origin relationship itself. Pinning
        // it here means a config that would silently produce a service unable
        // to complete any ceremony fails at construction instead.
        let cfg = AuthConfig {
            webauthn_rp_id: "example.com".into(),
            webauthn_rp_origin: "http://localhost:8090".into(),
            ..config()
        };
        assert!(WebauthnService::new(UnusedRepo, cfg).is_err());
    }

    // -- the encryption key ------------------------------------------------

    #[test]
    fn an_absent_mfa_encryption_key_is_an_error_not_a_plaintext_fallback() {
        // The state is encrypted with this key. If a missing key degraded to
        // "store the state in the clear", the ceremony would keep working and
        // nothing would signal that the challenge had become public.
        let cfg = AuthConfig {
            mfa_encryption_key: None,
            ..config()
        };
        let svc = WebauthnService::new(UnusedRepo, cfg).unwrap();
        let (u, t, o) = ids();

        assert!(svc.require_encryption_key().is_err());
        let err = svc
            .encode_state_token_json(u, t, o, "webauthn_register", json!({"a": 1}))
            .unwrap_err();
        assert!(matches!(err, AuthError::Crypto(_)));
    }

    // -- round trip --------------------------------------------------------

    #[test]
    fn a_state_token_round_trips_its_ids_and_state() {
        let svc = service();
        let (u, t, o) = ids();
        let state = json!({"challenge": "abc", "nested": {"n": 1}});

        let token = svc
            .encode_state_token_json(u, t, o, "webauthn_register", state.clone())
            .unwrap();
        let (gu, gt, go, gs) = svc
            .decode_state_token_json(&token, "webauthn_register")
            .unwrap();

        assert_eq!((gu, gt, go), (u, t, o));
        assert_eq!(gs, state);
    }

    #[test]
    fn encode_state_token_accepts_any_serializable_state() {
        // The typed wrapper over the JSON primitive: same round trip, but
        // through `T: Serialize` / `T: DeserializeOwned`.
        let svc = service();
        let (u, t, o) = ids();
        let state = vec!["a".to_string(), "b".to_string()];

        let token = svc
            .encode_state_token(u, t, o, "webauthn_authenticate", &state)
            .unwrap();
        let (_, _, _, got): (Uuid, Uuid, Uuid, Vec<String>) = svc
            .decode_state_token(&token, "webauthn_authenticate")
            .unwrap();
        assert_eq!(got, state);
    }

    // -- the four refusals -------------------------------------------------

    #[test]
    fn a_registration_state_cannot_be_redeemed_as_an_authentication_state() {
        // The purpose check. Without it a captured registration token could be
        // fed to finish_authentication, which is the whole reason `purpose` is
        // in the claims rather than implied by the endpoint that receives it.
        let svc = service();
        let (u, t, o) = ids();
        let token = svc
            .encode_state_token_json(u, t, o, "webauthn_register", json!({"c": 1}))
            .unwrap();

        let err = svc
            .decode_state_token_json(&token, "webauthn_authenticate")
            .unwrap_err();
        assert!(matches!(err, AuthError::WebauthnStateInvalid));

        // ...and the same token is still valid for its own ceremony, so the
        // rejection is the purpose mismatch and not a broken token.
        assert!(
            svc.decode_state_token_json(&token, "webauthn_register")
                .is_ok()
        );
    }

    #[test]
    fn a_signature_is_bound_to_the_payload_it_was_made_over() {
        // The forged-signature case, done WITHOUT embedding a second private
        // key in the repository. Splicing a genuine signature from one token
        // onto another token's header and payload is the stronger property
        // anyway: the signature here is real, produced by the legitimate key,
        // and must still be refused because it was made over different claims.
        // A verifier that merely checked "a well-formed signature is present"
        // would accept this.
        let svc = service();
        let (u, t, o) = ids();
        let other_user = Uuid::parse_str("44444444-4444-4444-4444-444444444444").unwrap();

        let mine = svc
            .encode_state_token_json(u, t, o, "webauthn_register", json!({"c": 1}))
            .unwrap();
        let theirs = svc
            .encode_state_token_json(other_user, t, o, "webauthn_register", json!({"c": 2}))
            .unwrap();

        let mut parts: Vec<&str> = mine.split('.').collect();
        let borrowed_signature = theirs.split('.').nth(2).unwrap();
        parts[2] = borrowed_signature;
        let spliced = parts.join(".");

        assert!(matches!(
            svc.decode_state_token_json(&spliced, "webauthn_register"),
            Err(AuthError::WebauthnStateInvalid)
        ));

        // Both halves of the splice are individually valid, so the rejection is
        // the binding and not a broken input.
        assert!(
            svc.decode_state_token_json(&mine, "webauthn_register")
                .is_ok()
        );
        assert!(
            svc.decode_state_token_json(&theirs, "webauthn_register")
                .is_ok()
        );
    }

    #[test]
    fn a_corrupted_signature_is_refused() {
        let svc = service();
        let (u, t, o) = ids();
        let token = svc
            .encode_state_token_json(u, t, o, "webauthn_register", json!({}))
            .unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        let sig = parts[2].to_string();
        // Flip one base64url character of the signature.
        let mut chars: Vec<char> = sig.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let corrupted: String = chars.into_iter().collect();
        parts[2] = &corrupted;

        assert!(matches!(
            svc.decode_state_token_json(&parts.join("."), "webauthn_register"),
            Err(AuthError::WebauthnStateInvalid)
        ));
    }

    #[test]
    fn a_token_from_another_issuer_is_refused() {
        let issued_elsewhere = AuthConfig {
            jwt_issuer: "some-other-idp".into(),
            ..config()
        };
        let other = WebauthnService::new(UnusedRepo, issued_elsewhere).unwrap();
        let (u, t, o) = ids();
        let token = other
            .encode_state_token_json(u, t, o, "webauthn_register", json!({}))
            .unwrap();

        let err = service()
            .decode_state_token_json(&token, "webauthn_register")
            .unwrap_err();
        assert!(matches!(err, AuthError::WebauthnStateInvalid));
    }

    #[test]
    fn an_expired_token_is_refused() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        let svc = service();
        let (u, t, o) = ids();

        // Well past jsonwebtoken's default 60s leeway, so this asserts expiry
        // rather than clock tolerance.
        let past = chrono::Utc::now().timestamp() - 7200;
        let claims = WebauthnStateClaims {
            sub: u.to_string(),
            tenant_id: t.to_string(),
            org_id: o.to_string(),
            purpose: "webauthn_register".into(),
            state: totp::encrypt_secret(&KEY, b"{}").unwrap(),
            iss: "axiam-test".into(),
            iat: past,
            exp: past + 300,
        };
        let stale = jsonwebtoken::encode(
            &Header::new(Algorithm::EdDSA),
            &claims,
            &EncodingKey::from_ed_pem(PRIV_PEM.as_bytes()).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            svc.decode_state_token_json(&stale, "webauthn_register"),
            Err(AuthError::WebauthnStateInvalid)
        ));
        // state_token_purpose validates BEFORE reading the claim, so it must
        // refuse the same token rather than classify it.
        assert!(matches!(
            svc.state_token_purpose(&stale),
            Err(AuthError::WebauthnStateInvalid)
        ));
    }

    #[test]
    fn a_malformed_uuid_claim_is_refused_rather_than_defaulted() {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};
        let svc = service();

        for (sub, tenant, org) in [
            (
                "not-a-uuid",
                "22222222-2222-2222-2222-222222222222",
                "33333333-3333-3333-3333-333333333333",
            ),
            (
                "11111111-1111-1111-1111-111111111111",
                "not-a-uuid",
                "33333333-3333-3333-3333-333333333333",
            ),
            (
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
                "not-a-uuid",
            ),
        ] {
            let claims = WebauthnStateClaims {
                sub: sub.into(),
                tenant_id: tenant.into(),
                org_id: org.into(),
                purpose: "webauthn_register".into(),
                state: totp::encrypt_secret(&KEY, b"{}").unwrap(),
                iss: "axiam-test".into(),
                iat: chrono::Utc::now().timestamp(),
                exp: chrono::Utc::now().timestamp() + 300,
            };
            let token = jsonwebtoken::encode(
                &Header::new(Algorithm::EdDSA),
                &claims,
                &EncodingKey::from_ed_pem(PRIV_PEM.as_bytes()).unwrap(),
            )
            .unwrap();
            assert!(
                matches!(
                    svc.decode_state_token_json(&token, "webauthn_register"),
                    Err(AuthError::WebauthnStateInvalid)
                ),
                "a token whose scope claims do not parse must be refused, never \
                 silently scoped to the nil UUID"
            );
        }
    }

    // -- confidentiality ---------------------------------------------------

    #[test]
    fn the_ceremony_state_is_encrypted_in_the_payload_not_merely_signed() {
        // A JWT payload is base64, not a secret. This decodes the middle
        // segment exactly as any holder of the token could and asserts the
        // challenge is not sitting there in the clear.
        use base64::Engine;
        let svc = service();
        let (u, t, o) = ids();
        let secret_challenge = "challenge-that-must-not-leak";

        let token = svc
            .encode_state_token_json(
                u,
                t,
                o,
                "webauthn_register",
                json!({ "challenge": secret_challenge }),
            )
            .unwrap();

        let payload_b64 = token.split('.').nth(1).expect("a JWT has three segments");
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload_b64)
            .expect("the payload is base64url");
        let payload = String::from_utf8(payload).unwrap();

        assert!(
            !payload.contains(secret_challenge),
            "the ceremony state must be encrypted before it enters the JWT"
        );
        // The scope claims ARE public, and are meant to be.
        assert!(payload.contains(&t.to_string()));
    }

    #[test]
    fn a_state_sealed_under_a_different_key_will_not_open() {
        // Rotating mfa_encryption_key must invalidate outstanding ceremonies
        // rather than yield a corrupted state that deserializes into something.
        let svc = service();
        let (u, t, o) = ids();
        let token = svc
            .encode_state_token_json(u, t, o, "webauthn_register", json!({"c": 1}))
            .unwrap();

        let rotated = WebauthnService::new(
            UnusedRepo,
            AuthConfig {
                mfa_encryption_key: Some([9u8; 32]),
                ..config()
            },
        )
        .unwrap();
        assert!(
            rotated
                .decode_state_token_json(&token, "webauthn_register")
                .is_err()
        );
    }

    // -- passkey decryption ------------------------------------------------

    #[test]
    fn decrypt_passkey_rejects_every_shape_of_bad_ciphertext() {
        let svc = service();

        // Not valid AES-256-GCM output at all.
        assert!(svc.decrypt_passkey(&KEY, "not-base64-ciphertext").is_err());

        // Decrypts, but the plaintext is not UTF-8.
        let non_utf8 = totp::encrypt_secret(&KEY, &[0xff, 0xfe, 0xfd]).unwrap();
        assert!(matches!(
            svc.decrypt_passkey(&KEY, &non_utf8),
            Err(AuthError::Crypto(ref m)) if m.contains("UTF-8")
        ));

        // Valid UTF-8, but not a Passkey.
        let not_a_passkey = totp::encrypt_secret(&KEY, b"{\"unrelated\":true}").unwrap();
        assert!(matches!(
            svc.decrypt_passkey(&KEY, &not_a_passkey),
            Err(AuthError::Crypto(ref m)) if m.contains("deserialize")
        ));

        // Sealed under a different key.
        let other_key = totp::encrypt_secret(&[1u8; 32], b"{}").unwrap();
        assert!(svc.decrypt_passkey(&KEY, &other_key).is_err());
    }

    // -- purpose introspection ---------------------------------------------

    #[test]
    fn state_token_purpose_reports_the_purpose_of_a_valid_token() {
        let svc = service();
        let (u, t, o) = ids();

        for purpose in ["webauthn_register", "webauthn_authenticate"] {
            let token = svc
                .encode_state_token_json(u, t, o, purpose, json!({}))
                .unwrap();
            assert_eq!(svc.state_token_purpose(&token).unwrap(), purpose);
        }
    }

    #[test]
    fn state_token_purpose_refuses_a_tampered_token_rather_than_classifying_it() {
        // This is the routing input for finish_registration_for_policy. If it
        // read `purpose` from an unverified token, an attacker would choose
        // which ceremony branch runs.
        let svc = service();
        let (u, t, o) = ids();
        let token = svc
            .encode_state_token_json(u, t, o, "webauthn_register", json!({}))
            .unwrap();

        let mut parts: Vec<&str> = token.split('.').collect();
        let forged_payload = {
            use base64::Engine;
            let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .unwrap();
            let mut v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            v["purpose"] = json!("webauthn_authenticate");
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&v).unwrap())
        };
        parts[1] = &forged_payload;
        let tampered = parts.join(".");

        assert!(matches!(
            svc.state_token_purpose(&tampered),
            Err(AuthError::WebauthnStateInvalid)
        ));
    }

    #[test]
    fn a_structurally_invalid_token_is_refused_by_every_entry_point() {
        let svc = service();
        for junk in ["", "not-a-jwt", "a.b", "a.b.c.d", "aaa.bbb.ccc"] {
            assert!(svc.state_token_purpose(junk).is_err(), "purpose: {junk:?}");
            assert!(
                svc.decode_state_token_json(junk, "webauthn_register")
                    .is_err(),
                "decode: {junk:?}"
            );
        }
    }
}

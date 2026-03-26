//! WebAuthn registration and authentication ceremonies.
//!
//! Ceremony state (`PasskeyRegistration` / `PasskeyAuthentication`) is
//! serialized to JSON, encrypted with AES-256-GCM via [`totp::encrypt_secret`],
//! and embedded in a short-lived JWT. Passkey data is encrypted at rest before
//! storage in the database.

use axiam_core::error::AxiamResult;
use axiam_core::models::webauthn_credential::{
    CreateWebauthnCredential, WebauthnCredential, WebauthnCredentialType,
};
use axiam_core::repository::WebauthnCredentialRepository;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use webauthn_rs::Webauthn;
use webauthn_rs::prelude::*;

use crate::config::AuthConfig;
use crate::error::AuthError;
use crate::totp;

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

    fn encode_state_token<T: Serialize>(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        org_id: Uuid,
        purpose: &str,
        state: &T,
    ) -> Result<String, AuthError> {
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let encryption_key = self.require_encryption_key()?;
        let state_json = serde_json::to_string(state)
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

    fn decode_state_token<T: serde::de::DeserializeOwned>(
        &self,
        token: &str,
        expected_purpose: &str,
    ) -> Result<(Uuid, Uuid, Uuid, T), AuthError> {
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
        let state: T = serde_json::from_str(&state_json)
            .map_err(|e| AuthError::Crypto(format!("state deserialize: {e}")))?;

        Ok((user_id, tenant_id, org_id, state))
    }
}

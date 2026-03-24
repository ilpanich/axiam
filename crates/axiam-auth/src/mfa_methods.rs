//! MFA method listing and deletion service.
//!
//! Provides a unified view of all MFA methods (TOTP + WebAuthn)
//! and enforces the invariant that the last method cannot be removed
//! while MFA is enabled.

use axiam_core::error::AxiamResult;
use axiam_core::models::mfa_method::{MfaMethod, MfaMethodType};
use axiam_core::models::user::UpdateUser;
use axiam_core::models::webauthn_credential::WebauthnCredentialType;
use axiam_core::repository::{UserRepository, WebauthnCredentialRepository};
use uuid::Uuid;

use crate::error::AuthError;

/// Service for listing and managing a user's MFA methods.
#[derive(Clone)]
pub struct MfaMethodService<U: UserRepository, W: WebauthnCredentialRepository> {
    user_repo: U,
    credential_repo: W,
}

impl<U: UserRepository, W: WebauthnCredentialRepository> MfaMethodService<U, W> {
    pub fn new(user_repo: U, credential_repo: W) -> Self {
        Self {
            user_repo,
            credential_repo,
        }
    }

    /// List all MFA methods registered for a user.
    ///
    /// Returns TOTP (if configured) and all WebAuthn credentials,
    /// without exposing any secrets.
    pub async fn list_methods(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<MfaMethod>> {
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        let mut methods = Vec::new();

        // TOTP method (if enrolled and enabled).
        if user.mfa_enabled && user.mfa_secret.is_some() {
            methods.push(MfaMethod {
                method_id: "totp".into(),
                method_type: MfaMethodType::Totp,
                name: "TOTP Authenticator".into(),
                created_at: user.created_at,
                last_used_at: None,
            });
        }

        // WebAuthn credentials.
        let credentials = self
            .credential_repo
            .list_by_user(tenant_id, user_id)
            .await?;
        for cred in credentials {
            let method_type = match cred.credential_type {
                WebauthnCredentialType::Passkey => MfaMethodType::Passkey,
                WebauthnCredentialType::SecurityKey => MfaMethodType::SecurityKey,
            };
            methods.push(MfaMethod {
                method_id: cred.id.to_string(),
                method_type,
                name: cred.name,
                created_at: cred.created_at,
                last_used_at: cred.last_used_at,
            });
        }

        Ok(methods)
    }

    /// Return deduplicated method type strings for available methods.
    pub async fn available_method_types(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Vec<String>> {
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        let mut types = Vec::new();

        if user.mfa_secret.is_some() {
            types.push("totp".into());
        }

        let count = self
            .credential_repo
            .count_by_user(tenant_id, user_id)
            .await?;
        if count > 0 {
            types.push("webauthn".into());
        }

        Ok(types)
    }

    /// Delete an MFA method by ID.
    ///
    /// - `"totp"` removes the TOTP secret.
    /// - A UUID string removes the corresponding WebAuthn credential.
    ///
    /// Refuses to remove the last method when `mfa_enabled` is true.
    pub async fn delete_method(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        method_id: &str,
    ) -> AxiamResult<()> {
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;

        // Count total methods.
        let has_totp = user.mfa_enabled && user.mfa_secret.is_some();
        let webauthn_count = self
            .credential_repo
            .count_by_user(tenant_id, user_id)
            .await?;
        let total = (if has_totp { 1u64 } else { 0 }) + webauthn_count;

        // Prevent removing the last method when MFA is active.
        if total <= 1 && user.mfa_enabled {
            return Err(AuthError::MfaCannotRemoveLastMethod.into());
        }

        if method_id == "totp" {
            // Remove TOTP secret.
            let remaining_after = webauthn_count;
            let mut update = UpdateUser {
                mfa_secret: Some(None),
                ..Default::default()
            };
            if remaining_after == 0 {
                update.mfa_enabled = Some(false);
            }
            self.user_repo.update(tenant_id, user_id, update).await?;
        } else {
            // Parse as WebAuthn credential UUID.
            let cred_id: Uuid =
                method_id
                    .parse()
                    .map_err(|_| axiam_core::error::AxiamError::NotFound {
                        entity: "mfa_method".into(),
                        id: method_id.into(),
                    })?;

            // Verify it belongs to this user.
            let cred = self.credential_repo.get_by_id(tenant_id, cred_id).await?;
            if cred.user_id != user_id {
                return Err(axiam_core::error::AxiamError::NotFound {
                    entity: "mfa_method".into(),
                    id: method_id.into(),
                });
            }

            self.credential_repo.delete(tenant_id, cred_id).await?;

            // If no methods remain, disable MFA.
            let remaining_totp = if has_totp { 1u64 } else { 0 };
            let remaining_webauthn = webauthn_count - 1;
            if remaining_totp + remaining_webauthn == 0 {
                self.user_repo
                    .update(
                        tenant_id,
                        user_id,
                        UpdateUser {
                            mfa_enabled: Some(false),
                            ..Default::default()
                        },
                    )
                    .await?;
            }
        }

        Ok(())
    }
}

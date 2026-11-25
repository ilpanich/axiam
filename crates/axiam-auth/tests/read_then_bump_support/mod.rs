//! A user repository for the QR11-2 / QR12-1 race tests, shared by
//! `auth_service_test.rs` and `webauthn_single_use_test.rs`.

#![allow(dead_code)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axiam_core::error::AxiamResult;
use axiam_core::models::user::{CreateUser, UpdateUser};
use axiam_core::repository::UserRepository;
use uuid::Uuid;

/// A user repository that, once armed, replaces the user's password right
/// after the next `get_by_id` has returned (the caller holds the old row).
///
/// With `fail_pending_clear` set, `clear_pending_mfa_secret` fails as a
/// transient datastore error would (QR1-7: an administrator's MFA reset must
/// not leave sessions live because that one write failed).
#[derive(Clone)]
pub struct ReadThenBumpUserRepo<U> {
    pub inner: U,
    pub armed: Arc<AtomicBool>,
    pub fail_pending_clear: bool,
}

impl<U: UserRepository> UserRepository for ReadThenBumpUserRepo<U> {
    async fn create(&self, input: CreateUser) -> AxiamResult<axiam_core::models::user::User> {
        self.inner.create(input).await
    }
    async fn get_by_id(
        &self,
        tenant_id: Uuid,
        id: Uuid,
    ) -> AxiamResult<axiam_core::models::user::User> {
        let user = self.inner.get_by_id(tenant_id, id).await?;
        if self.armed.swap(false, Ordering::SeqCst) {
            self.inner
                .update(
                    tenant_id,
                    id,
                    UpdateUser {
                        password_hash: Some("$argon2id$raced".into()),
                        ..Default::default()
                    },
                )
                .await?;
        }
        Ok(user)
    }
    async fn get_by_username(
        &self,
        tenant_id: Uuid,
        username: &str,
    ) -> AxiamResult<axiam_core::models::user::User> {
        self.inner.get_by_username(tenant_id, username).await
    }
    async fn get_by_email(
        &self,
        tenant_id: Uuid,
        email: &str,
    ) -> AxiamResult<axiam_core::models::user::User> {
        self.inner.get_by_email(tenant_id, email).await
    }
    async fn update(
        &self,
        tenant_id: Uuid,
        id: Uuid,
        input: UpdateUser,
    ) -> AxiamResult<axiam_core::models::user::User> {
        self.inner.update(tenant_id, id, input).await
    }
    async fn delete(&self, tenant_id: Uuid, id: Uuid) -> AxiamResult<()> {
        self.inner.delete(tenant_id, id).await
    }
    async fn update_totp_step(&self, tenant_id: Uuid, id: Uuid, step: u64) -> AxiamResult<bool> {
        self.inner.update_totp_step(tenant_id, id, step).await
    }
    async fn stage_pending_mfa_secret(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        encrypted_secret: String,
    ) -> AxiamResult<()> {
        self.inner
            .stage_pending_mfa_secret(tenant_id, user_id, encrypted_secret)
            .await
    }
    async fn pending_mfa_secret(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> AxiamResult<Option<String>> {
        self.inner.pending_mfa_secret(tenant_id, user_id).await
    }
    async fn promote_pending_mfa_secret(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        expected: &str,
    ) -> AxiamResult<bool> {
        self.inner
            .promote_pending_mfa_secret(tenant_id, user_id, expected)
            .await
    }
    async fn clear_pending_mfa_secret(&self, tenant_id: Uuid, user_id: Uuid) -> AxiamResult<()> {
        if self.fail_pending_clear {
            return Err(axiam_core::error::AxiamError::Internal(
                "injected: pending-secret clear failed".into(),
            ));
        }
        self.inner
            .clear_pending_mfa_secret(tenant_id, user_id)
            .await
    }
    async fn consume_mfa_setup_token(
        &self,
        tenant_id: Uuid,
        jti: &str,
        expires_at: chrono::DateTime<chrono::Utc>,
    ) -> AxiamResult<()> {
        self.inner
            .consume_mfa_setup_token(tenant_id, jti, expires_at)
            .await
    }
    async fn mfa_setup_token_spent(&self, tenant_id: Uuid, jti: &str) -> AxiamResult<bool> {
        self.inner.mfa_setup_token_spent(tenant_id, jti).await
    }
    async fn list(
        &self,
        tenant_id: Uuid,
        pagination: axiam_core::repository::Pagination,
    ) -> AxiamResult<axiam_core::repository::PaginatedResult<axiam_core::models::user::User>> {
        self.inner.list(tenant_id, pagination).await
    }
    async fn increment_failed_logins(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        lockout_threshold: u32,
        base_lockout_secs: i64,
        backoff_multiplier: f64,
        max_lockout_secs: i64,
    ) -> AxiamResult<()> {
        self.inner
            .increment_failed_logins(
                tenant_id,
                user_id,
                lockout_threshold,
                base_lockout_secs,
                backoff_multiplier,
                max_lockout_secs,
            )
            .await
    }
    async fn anonymize_user(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        email_hash: &str,
        pseudonym: &str,
    ) -> AxiamResult<()> {
        self.inner
            .anonymize_user(tenant_id, user_id, email_hash, pseudonym)
            .await
    }
}

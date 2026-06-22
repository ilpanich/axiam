//! Periodic cleanup task for expired federation rows, GDPR purges, and export jobs.
//!
//! SurrealDB v3 does not support native TTL on rows (RESEARCH §7), so this task
//! periodically sweeps various tables:
//! - `saml_assertion_replay` and `federation_login_state`: expired rows
//! - `user`: accounts past their scheduled purge date (D-05/D-06/D-08)
//! - `export_job`: queued jobs waiting to have their encrypted blob generated (D-12)
//!
//! The task shuts down cleanly when the caller sends `true` through the watch
//! channel (D-09, D-24).

use std::sync::Arc;
use std::time::Duration;

use axiam_amqp::MailOutboundPublisher;
use axiam_auth::AuthService;
use axiam_auth::crypto::{encrypt_separate, gdpr_pseudonym};
use axiam_core::error::AxiamError;
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::gdpr::CreateErasureProof;
use axiam_core::models::mail::{MailType, OutboundMailMessage};
use axiam_core::repository::{
    AccountDeletionRepository, AssertionReplayRepository, AuditLogFilter, AuditLogRepository,
    ConsentRepository, ErasureProofRepository, ExportJobRepository, FederationLinkRepository,
    FederationLoginStateRepository, GroupRepository, MailPublisher, Pagination,
    PasswordHistoryRepository, RoleRepository, UserRepository, WebauthnCredentialRepository,
};
use axiam_db::{
    SurrealAccountDeletionRepository, SurrealAssertionReplayRepository, SurrealAuditLogRepository,
    SurrealConsentRepository, SurrealErasureProofRepository, SurrealExportJobRepository,
    SurrealFederationLinkRepository, SurrealFederationLoginStateRepository, SurrealGroupRepository,
    SurrealPasswordHistoryRepository, SurrealRefreshTokenRepository, SurrealRoleRepository,
    SurrealSessionRepository, SurrealUserRepository, SurrealWebauthnCredentialRepository,
};
use chrono::Utc;
use surrealdb::Connection;
use tokio::sync::watch;
use uuid::Uuid;

/// Concrete `AuthService` type alias used by `CleanupTask` (same repos as main.rs).
type AuthSvc<C> = AuthService<
    SurrealUserRepository<C>,
    SurrealSessionRepository<C>,
    SurrealFederationLinkRepository<C>,
    SurrealRefreshTokenRepository<C>,
>;

// ---------------------------------------------------------------------------
// CleanupTask
// ---------------------------------------------------------------------------

/// Background task that sweeps expired rows and runs GDPR purge + export jobs.
pub struct CleanupTask<C: Connection> {
    // Existing federation cleanup repos.
    replay_repo: Arc<SurrealAssertionReplayRepository<C>>,
    state_repo: Arc<SurrealFederationLoginStateRepository<C>>,
    // GDPR purge sweep (D-05/D-06/D-08).
    user_repo: Arc<SurrealUserRepository<C>>,
    auth_svc: Arc<AuthSvc<C>>,
    audit_repo: Arc<SurrealAuditLogRepository<C>>,
    account_deletion_repo: Arc<SurrealAccountDeletionRepository<C>>,
    erasure_proof_repo: Arc<SurrealErasureProofRepository<C>>,
    federation_link_repo: Arc<SurrealFederationLinkRepository<C>>,
    // Credential/authorization tables purged on erasure and surfaced in exports
    // (SEC-056, CQ-B38).
    role_repo: Arc<SurrealRoleRepository<C>>,
    group_repo: Arc<SurrealGroupRepository<C>>,
    webauthn_repo: Arc<SurrealWebauthnCredentialRepository<C>>,
    password_history_repo: Arc<SurrealPasswordHistoryRepository<C>>,
    // GDPR export sweep (D-12).
    export_job_repo: Arc<SurrealExportJobRepository<C>>,
    consent_repo: Arc<SurrealConsentRepository<C>>,
    mail_publisher: Arc<MailOutboundPublisher>,
    // Keys (None = skip the respective sweep with a warning).
    gdpr_pepper: Option<[u8; 32]>,
    export_encryption_key: Option<[u8; 32]>,
    interval: Duration,
    shutdown: watch::Receiver<bool>,
}

impl<C: Connection + Send + Sync + 'static> CleanupTask<C> {
    /// Construct a new `CleanupTask`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        replay_repo: Arc<SurrealAssertionReplayRepository<C>>,
        state_repo: Arc<SurrealFederationLoginStateRepository<C>>,
        user_repo: Arc<SurrealUserRepository<C>>,
        auth_svc: Arc<AuthSvc<C>>,
        audit_repo: Arc<SurrealAuditLogRepository<C>>,
        account_deletion_repo: Arc<SurrealAccountDeletionRepository<C>>,
        erasure_proof_repo: Arc<SurrealErasureProofRepository<C>>,
        federation_link_repo: Arc<SurrealFederationLinkRepository<C>>,
        role_repo: Arc<SurrealRoleRepository<C>>,
        group_repo: Arc<SurrealGroupRepository<C>>,
        webauthn_repo: Arc<SurrealWebauthnCredentialRepository<C>>,
        password_history_repo: Arc<SurrealPasswordHistoryRepository<C>>,
        export_job_repo: Arc<SurrealExportJobRepository<C>>,
        consent_repo: Arc<SurrealConsentRepository<C>>,
        mail_publisher: Arc<MailOutboundPublisher>,
        gdpr_pepper: Option<[u8; 32]>,
        export_encryption_key: Option<[u8; 32]>,
        interval: Duration,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            replay_repo,
            state_repo,
            user_repo,
            auth_svc,
            audit_repo,
            account_deletion_repo,
            erasure_proof_repo,
            federation_link_repo,
            role_repo,
            group_repo,
            webauthn_repo,
            password_history_repo,
            export_job_repo,
            consent_repo,
            mail_publisher,
            gdpr_pepper,
            export_encryption_key,
            interval,
            shutdown,
        }
    }

    /// Run the cleanup loop until a shutdown signal is received.
    ///
    /// Never returns `Err` — all sweep errors are logged at `warn` level and
    /// the loop continues (T-04-36).
    pub async fn run(mut self) -> Result<(), AxiamError> {
        let mut ticker = tokio::time::interval(self.interval);
        // Skip ticks that were missed while the sweep was running to prevent
        // catch-up storms after a pause (T-04-35).
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    // Existing federation cleanup sweeps.
                    match self.replay_repo.cleanup_expired().await {
                        Ok(n) if n > 0 => {
                            tracing::debug!(deleted = n, "saml_assertion_replay cleanup");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = ?e, "saml_assertion_replay cleanup failed");
                        }
                    }

                    match self.state_repo.cleanup_expired().await {
                        Ok(n) if n > 0 => {
                            tracing::debug!(deleted = n, "federation_login_state cleanup");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = ?e, "federation_login_state cleanup failed");
                        }
                    }

                    // GDPR purge sweep (D-01..D-06, D-08).
                    match self.sweep_pending_purges().await {
                        Ok(n) if n > 0 => {
                            tracing::info!(purged = n, "GDPR purge sweep completed");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = ?e, "GDPR purge sweep failed");
                        }
                    }

                    // GDPR export sweep (D-10..D-12).
                    match self.sweep_pending_exports().await {
                        Ok(n) if n > 0 => {
                            tracing::info!(exported = n, "GDPR export sweep completed");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = ?e, "GDPR export sweep failed");
                        }
                    }
                }
                changed = self.shutdown.changed() => {
                    if changed.is_ok() && *self.shutdown.borrow() {
                        tracing::info!("cleanup task received shutdown signal");
                        return Ok(());
                    }
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // GDPR purge sweep (D-01..D-06, D-08)
    // -----------------------------------------------------------------------

    /// Sweep users past their scheduled purge date and run the full purge pipeline.
    ///
    /// For each user:
    /// (a) Revoke all sessions (auth artifact cascade via `AuthService`).
    /// (b) Hard-delete federation links.
    /// (b2) Hard-delete WebAuthn credentials and password history (SEC-056).
    /// (c) Compute deterministic GDPR pseudonym via `gdpr_pseudonym`.
    /// (d) Anonymize user row in-place (D-05).
    /// (e) Pseudonymize all audit entries for this user (D-01/D-03/D-04).
    /// (f) Insert a PII-free erasure-proof record (D-06).
    /// (g) Mark the account_deletion row as completed.
    /// (h) Emit `gdpr.user_pseudonymized` audit event (actor = System).
    ///
    /// Returns the count of users purged.
    async fn sweep_pending_purges(&self) -> Result<u64, AxiamError> {
        let pepper = match self.gdpr_pepper {
            Some(p) => p,
            None => {
                tracing::warn!("GDPR purge sweep skipped — AXIAM__GDPR_PSEUDONYM_PEPPER not set");
                return Ok(0);
            }
        };

        let now = Utc::now();
        let due = self.user_repo.find_due_for_purge(now).await?;
        let mut purged: u64 = 0;

        for user in due {
            if let Err(e) = self
                .purge_single_user(user.id, user.tenant_id, pepper)
                .await
            {
                tracing::warn!(
                    error = ?e,
                    user_id = %user.id,
                    tenant_id = %user.tenant_id,
                    "purge failed for user — skipping"
                );
            } else {
                purged += 1;
            }
        }

        Ok(purged)
    }

    /// Run the full purge pipeline for a single user.
    async fn purge_single_user(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        pepper: [u8; 32],
    ) -> Result<(), AxiamError> {
        // (a) Revoke all sessions and OAuth2 refresh tokens.
        self.auth_svc
            .revoke_all_sessions(tenant_id, user_id)
            .await?;

        // (b) Hard-delete federation identity links.
        match self
            .federation_link_repo
            .get_by_user_id(tenant_id, user_id)
            .await
        {
            Ok(links) => {
                for link in links {
                    if let Err(e) = self.federation_link_repo.delete(tenant_id, link.id).await {
                        tracing::warn!(
                            error = %e,
                            %tenant_id,
                            link_id = %link.id,
                            "cleanup: failed to delete expired federation link; will retry next cycle"
                        );
                    }
                }
            }
            Err(e) => {
                tracing::warn!(error = ?e, user_id = %user_id, "failed to list federation links for purge");
            }
        }

        // (b2) Hard-delete stored credential material (SEC-056). Done with `?`
        // (fail-closed): erasure must not be certified while a user's passkeys or
        // password hashes remain. A transient failure aborts the purge and it is
        // retried next sweep — every step here is idempotent.
        let webauthn_creds = self.webauthn_repo.list_by_user(tenant_id, user_id).await?;
        for cred in webauthn_creds {
            self.webauthn_repo.delete(tenant_id, cred.id).await?;
        }
        // Prune the entire password-history chain (keep_count = 0 deletes all).
        self.password_history_repo
            .prune(tenant_id, user_id, 0)
            .await?;

        // (c) Compute deterministic pseudonym (keyed HMAC-SHA256, D-02).
        let pseudonym = gdpr_pseudonym(&pepper, tenant_id, user_id);

        // Derive email hash for anonymize_user from tenant+user IDs (original email
        // is no longer accessible at purge time — user already marked deletion_pending).
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(tenant_id.as_bytes());
        h.update(user_id.as_bytes());
        let email_hash = hex::encode(h.finalize());

        // (d) Pseudonymize audit entries (D-01/D-03/D-04).
        // Errors here are logged but not fatal.
        if let Err(e) = self
            .audit_repo
            .pseudonymize_actor(tenant_id, user_id, &pseudonym)
            .await
        {
            tracing::warn!(error = ?e, user_id = %user_id, "audit pseudonymization failed");
        }

        // (e) Insert erasure-proof record (D-06).
        self.erasure_proof_repo
            .create(CreateErasureProof {
                pseudonym: pseudonym.clone(),
                tenant_id,
                erased_at: Utc::now(),
            })
            .await?;

        // (f) Mark the account_deletion row as completed (lookup by user_id).
        // Done BEFORE anonymize_user so that on a re-run (if anonymize fails),
        // the row is already completed and will not be re-processed.
        match self
            .account_deletion_repo
            .find_pending_by_user_id(tenant_id, user_id)
            .await
        {
            Ok(Some(deletion)) => {
                if let Err(e) = self
                    .account_deletion_repo
                    .mark_completed(tenant_id, deletion.id)
                    .await
                {
                    tracing::warn!(
                        error = %e,
                        %tenant_id,
                        deletion_id = %deletion.id,
                        "cleanup: failed to mark account_deletion completed"
                    );
                }
            }
            Ok(None) => {
                tracing::debug!(user_id = %user_id, "no pending account_deletion row found at purge time");
            }
            Err(e) => {
                tracing::warn!(error = ?e, user_id = %user_id, "failed to find account_deletion row");
            }
        }

        // (g) Anonymize the user row in-place — LAST so that prior steps can
        // still access the user row on a partial-failure re-run (CQ-B38 / D-05).
        self.user_repo
            .anonymize_user(tenant_id, user_id, &email_hash, &pseudonym)
            .await?;

        // (h) Emit gdpr.user_pseudonymized audit event (actor = System/nil UUID).
        if let Err(e) = self
            .audit_repo
            .append(CreateAuditLogEntry {
                tenant_id,
                actor_id: Uuid::nil(),
                actor_type: ActorType::System,
                action: "gdpr.user_pseudonymized".into(),
                resource_id: None,
                outcome: AuditOutcome::Success,
                ip_address: None,
                metadata: Some(serde_json::json!({
                    "pseudonym": pseudonym,
                })),
            })
            .await
        {
            tracing::error!(
                error = %e,
                %tenant_id,
                "cleanup: failed to emit gdpr.user_pseudonymized audit event (GDPR legally significant)"
            );
        }

        tracing::info!(
            pseudonym = %pseudonym,
            tenant_id = %tenant_id,
            "user purged and pseudonymized"
        );

        Ok(())
    }

    // -----------------------------------------------------------------------
    // GDPR export sweep (D-10..D-13)
    // -----------------------------------------------------------------------

    /// Sweep queued export jobs and generate the encrypted blobs.
    ///
    /// For each job:
    /// (a) Aggregate all Art. 15 sections from the DB (secrets excluded, D-10).
    /// (b) Serialize to a single sectioned JSON object (D-11).
    /// (c) Encrypt with `export_encryption_key` (AES-256-GCM, D-12).
    /// (d) Call `set_ready` with a SHA-256-hashed 24h single-use download token.
    /// (e) Enqueue `ExportReady` mail with the raw token (D-12).
    ///
    /// Returns the count of jobs processed.
    async fn sweep_pending_exports(&self) -> Result<u64, AxiamError> {
        let key = match self.export_encryption_key {
            Some(k) => k,
            None => {
                tracing::warn!("GDPR export sweep skipped — AXIAM__EMAIL_ENCRYPTION_KEY not set");
                return Ok(0);
            }
        };

        let queued = self.export_job_repo.find_queued().await?;
        let mut processed: u64 = 0;

        for job in queued {
            if let Err(e) = self
                .process_export_job(job.id, job.tenant_id, job.user_id, key)
                .await
            {
                tracing::warn!(
                    error = ?e,
                    job_id = %job.id,
                    "export job processing failed — marking Failed (CQ-B38)"
                );
                // Mark as Failed so the job does not stay stuck as Queued
                // (CQ-B38 / REQ-14 AC-5).
                if let Err(mark_err) = self.export_job_repo.mark_failed(job.id).await {
                    tracing::warn!(
                        error = ?mark_err,
                        job_id = %job.id,
                        "failed to mark export job as Failed"
                    );
                }
            } else {
                processed += 1;
            }
        }

        Ok(processed)
    }

    /// Process a single queued export job.
    async fn process_export_job(
        &self,
        job_id: Uuid,
        tenant_id: Uuid,
        user_id: Uuid,
        key: [u8; 32],
    ) -> Result<(), AxiamError> {
        // (a)/(b) Aggregate Art. 15 inventory into one sectioned JSON.
        let export_json = self.aggregate_export_data(tenant_id, user_id).await?;
        let export_bytes = export_json.to_string().into_bytes();

        // (c) Encrypt the blob (D-12).
        let (nonce_b64, ct_b64) = encrypt_separate(&key, &export_bytes)
            .map_err(|e| AxiamError::Internal(format!("export encrypt failed: {e}")))?;

        // (d) Generate single-use 24h download token (D-13).
        let raw_download_token = Uuid::new_v4().to_string();
        let token_hash = {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(raw_download_token.as_bytes());
            hex::encode(h.finalize())
        };
        let expires_at = Utc::now() + chrono::Duration::hours(24);

        self.export_job_repo
            .set_ready(
                job_id,
                token_hash,
                Some(ct_b64),
                None, // file_path: stored as DB blob
                Some(nonce_b64),
                expires_at,
            )
            .await?;

        // (e) Enqueue ExportReady email.
        let download_url = format!("/api/v1/account/export/{}", raw_download_token);
        let msg = OutboundMailMessage {
            mail_type: MailType::ExportReady,
            tenant_id,
            org_id: Uuid::nil(), // mail consumer resolves from tenant at delivery
            user_id,
            to_address: String::new(), // mail consumer resolves from user_id
            template_context: serde_json::json!({
                "action_url": download_url,
                "expiry_time": expires_at.to_rfc3339(),
            }),
            attempt_count: 0,
            enqueued_at: Utc::now(),
        };
        if let Err(e) = self.mail_publisher.publish(msg).await {
            tracing::warn!(error = %e, job_id = %job_id, "failed to enqueue ExportReady mail");
        }

        tracing::info!(job_id = %job_id, "export job completed");
        Ok(())
    }

    /// Aggregate Art. 15 personal-data inventory for a user.
    ///
    /// EXCLUDED (D-10): `password_hash`, `mfa_secret`, any token_hash values.
    async fn aggregate_export_data(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
    ) -> Result<serde_json::Value, AxiamError> {
        // Profile — no password_hash or mfa_secret.
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        let profile = serde_json::json!({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "status": user.status,
            "mfa_enabled": user.mfa_enabled,
            "metadata": user.metadata,
            "created_at": user.created_at,
            "updated_at": user.updated_at,
        });

        // Consents — propagate errors (CQ-B38 / SEC-056): a section that fails to
        // query must fail the whole export job rather than emit a legally
        // incomplete Art. 15 inventory. `process_export_job` marks the job Failed.
        let consents = self.consent_repo.list_by_user(tenant_id, user_id).await?;
        let consents_json: Vec<_> = consents
            .iter()
            .map(|c| {
                serde_json::json!({
                    "consent_type": c.consent_type,
                    "version": c.version,
                    "accepted_at": c.accepted_at,
                    "ip_address": c.ip_address,
                })
            })
            .collect();

        // Audit entries where this user was the actor — paginated to collect ALL
        // entries regardless of volume (CQ-B38 / REQ-14 AC-5).
        const AUDIT_PAGE_SIZE: u64 = 1_000;
        let mut audit_items = Vec::new();
        let mut offset: u64 = 0;
        loop {
            let page = self
                .audit_repo
                .list(
                    tenant_id,
                    AuditLogFilter {
                        actor_id: Some(user_id),
                        action: None,
                        outcome: None,
                        resource_id: None,
                        from: None,
                        to: None,
                    },
                    Pagination {
                        offset,
                        limit: AUDIT_PAGE_SIZE,
                    },
                )
                .await?;
            let fetched = page.items.len() as u64;
            audit_items.extend(page.items);
            offset += fetched;
            if fetched < AUDIT_PAGE_SIZE {
                break;
            }
        }
        let audit_json: Vec<_> = audit_items
            .iter()
            .map(|e| {
                serde_json::json!({
                    "action": e.action,
                    "outcome": e.outcome,
                    "timestamp": e.timestamp,
                    "resource_id": e.resource_id,
                })
            })
            .collect();

        // Federation identities — propagate errors (CQ-B38 / SEC-056).
        let fed_links = self
            .federation_link_repo
            .get_by_user_id(tenant_id, user_id)
            .await?;
        let fed_json: Vec<_> = fed_links
            .iter()
            .map(|l| {
                serde_json::json!({
                    "federation_config_id": l.federation_config_id,
                    "external_subject": l.external_subject,
                    "created_at": l.created_at,
                })
            })
            .collect();

        // Role assignments (direct + inherited via groups), incl. resource scope.
        let assignments = self
            .role_repo
            .get_user_role_assignments(tenant_id, user_id)
            .await?;
        let assignments_json: Vec<_> = assignments
            .iter()
            .map(|a| {
                serde_json::json!({
                    "role_id": a.role.id,
                    "role_name": a.role.name,
                    "is_global": a.role.is_global,
                    "resource_id": a.resource_id,
                })
            })
            .collect();

        // Group memberships.
        let groups = self.group_repo.get_user_groups(tenant_id, user_id).await?;
        let groups_json: Vec<_> = groups
            .iter()
            .map(|g| {
                serde_json::json!({
                    "group_id": g.id,
                    "name": g.name,
                    "description": g.description,
                })
            })
            .collect();

        // WebAuthn credentials — metadata only; the encrypted `passkey_json`
        // secret material is intentionally EXCLUDED (D-10).
        let webauthn_creds = self.webauthn_repo.list_by_user(tenant_id, user_id).await?;
        let webauthn_json: Vec<_> = webauthn_creds
            .iter()
            .map(|c| {
                serde_json::json!({
                    "id": c.id,
                    "credential_id": c.credential_id,
                    "name": c.name,
                    "credential_type": c.credential_type,
                    "created_at": c.created_at,
                    "last_used_at": c.last_used_at,
                })
            })
            .collect();

        let export = serde_json::json!({
            "export_metadata": {
                "generated_at": Utc::now(),
                "tenant_id": tenant_id,
                "subject_id": user_id,
                "schema_version": "1.0",
            },
            "profile": profile,
            "consents": consents_json,
            "sessions": [],           // metadata only; short-lived, not retained
            "mfa": { "enabled": user.mfa_enabled }, // NO mfa_secret
            "federation_identities": fed_json,
            "assignments": assignments_json,
            "group_memberships": groups_json,
            "audit_entries": audit_json,
            "webauthn_credentials": webauthn_json,
        });

        Ok(export)
    }
}

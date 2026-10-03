//! The directory half of [`AuthService`]: just-in-time provisioning and the
//! administrator's act of linking an existing account (G-3, T23.3.3).
//!
//! A child module of `service` so it can reach the service's private fields
//! without widening them.
//!
//! # The rule both halves serve (D-28)
//!
//! **A directory never takes over a local account.** Provisioning only ever
//! *creates*, and only for a login name that matches nothing local; an entry
//! that would collide with an existing account's username or email — compared
//! ignoring case, in both columns — is refused with the ordinary
//! invalid-credentials failure and an audit row. Turning an existing account
//! into a directory account is [`AuthService::link_local_account_to_directory`],
//! an explicit act that resolves the entry through the directory, refuses one
//! already linked elsewhere, and retires every credential the account held that
//! the directory does not decide.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::directory::{
    DirectoryAuditSink, DirectoryAuthError, DirectoryFuture, DirectoryIdentity,
};
use axiam_core::models::user::{CreateDirectoryAccount, User, UserStatus};
use axiam_core::repository::{
    AuditLogRepository, CertificateRepository, FederationLinkRepository, RefreshTokenRepository,
    SessionRepository, UserRepository, WebauthnCredentialRepository,
};
use uuid::Uuid;

use super::{AuthService, LoginInput, LoginResult};
use crate::crypto_gate::acquire_hash_permit;
use crate::error::AuthError;

/// Audit action: a directory account was created at first sign-in.
pub const AUDIT_JIT_PROVISIONED: &str = "directory.jit_provisioned";
/// Audit action: a first sign-in the directory vouched for was refused —
/// because the entry collides with a local account, or because it lacks what a
/// local account needs. `metadata.reason` says which.
pub const AUDIT_JIT_REFUSED: &str = "directory.jit_refused";
/// Audit action: an administrator linked an existing account to its directory
/// entry.
pub const AUDIT_ACCOUNT_LINKED: &str = "directory.account_linked";
/// Audit action (T23.3.4): applying the directory group mapping changed a
/// user's memberships. Identifiers and counts only: the AXIAM groups added and
/// removed, and how many directory groups were resolved and mapped.
pub const AUDIT_GROUPS_MAPPED: &str = "directory.groups_mapped";
/// Audit action (T23.3.4): a sign-in the directory vouched for was refused
/// because the group mapping could not be applied — the directory could not be
/// asked, or the user is in more groups than the cap allows. Nothing was
/// changed.
pub const AUDIT_GROUP_MAPPING_REFUSED: &str = "directory.group_mapping_refused";

/// Longest username or display name taken from a directory, in characters.
const MAX_NAME_CHARS: usize = 255;
/// Longest e-mail address taken from a directory (RFC 5321 §4.5.3.1.3).
const MAX_EMAIL_CHARS: usize = 254;

/// The [`DirectoryAuditSink`] that appends to an [`AuditLogRepository`].
///
/// Lives here, not in `axiam-core`, because it logs a failed write and core has
/// no logging. It never fails its caller: the directory path has already done,
/// or refused, what the row describes.
pub struct RepositoryDirectoryAuditSink<A>(pub A);

impl<A: AuditLogRepository> DirectoryAuditSink for RepositoryDirectoryAuditSink<A> {
    fn record<'a>(&'a self, entry: CreateAuditLogEntry) -> DirectoryFuture<'a, ()> {
        Box::pin(async move {
            let tenant_id = entry.tenant_id;
            if let Err(error) = self.0.append(entry).await {
                tracing::error!(
                    target: "axiam::directory",
                    %tenant_id,
                    %error,
                    "a directory audit row could not be written"
                );
            }
        })
    }
}

/// What linking did, for the caller's response and the audit row.
#[derive(Debug, Clone)]
pub struct DirectoryLinkOutcome {
    /// The account after linking.
    pub user: User,
    /// WebAuthn credentials (passkeys, security keys) deleted.
    pub webauthn_credentials_deleted: u64,
    /// `User`-type certificates revoked.
    pub certificates_revoked: u64,
    /// `true` when the account was already linked to this very entry and the
    /// call only re-ran the revocations (the retry of an interrupted link).
    pub was_already_linked: bool,
}

/// The values a directory entry contributes to a new account, cleaned.
///
/// The directory is another party's system: whoever administers it chooses
/// every attribute, so a value is bounded, stripped of control and
/// bidirectional-override characters, and refused when it cannot be made into
/// what a local account holds, before it is stored or shown to anyone.
#[derive(Debug, PartialEq, Eq)]
struct JitProfile {
    username: String,
    email: String,
    display_name: Option<String>,
}

impl JitProfile {
    /// `None` when the entry cannot become an account: no usable e-mail
    /// address (a local account must have one) or no usable name.
    fn from_identity(identity: &DirectoryIdentity, typed_login: &str) -> Option<Self> {
        // The login name the entry answered to stands in when the mapped
        // username attribute is absent: the filter matched this entry by it.
        let username = identity
            .username
            .as_deref()
            .and_then(|raw| clean_identifier(raw, MAX_NAME_CHARS))
            .or_else(|| clean_identifier(typed_login, MAX_NAME_CHARS))?;
        let email = identity
            .email
            .as_deref()
            .and_then(|raw| clean_identifier(raw, MAX_EMAIL_CHARS))
            .filter(|email| plausible_email(email))?;
        let display_name = identity
            .display_name
            .as_deref()
            .and_then(clean_display_name);
        Some(Self {
            username,
            email,
            display_name,
        })
    }
}

/// A username or an address: trimmed, non-empty, bounded, and with no control
/// or whitespace characters at all. Refused rather than repaired — a repaired
/// name is a different name.
fn clean_identifier(raw: &str, max_chars: usize) -> Option<String> {
    let trimmed = raw.trim();
    let valid = !trimmed.is_empty()
        && trimmed.chars().count() <= max_chars
        && !trimmed
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || is_bidi_control(c));
    valid.then(|| trimmed.to_string())
}

/// One `@`, something on each side, a dot in the domain.
fn plausible_email(email: &str) -> bool {
    let mut parts = email.splitn(2, '@');
    let local = parts.next().unwrap_or("");
    let domain = parts.next().unwrap_or("");
    !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.contains('@')
}

/// A display name: control and bidirectional-override characters removed (a
/// right-to-left override makes a name render as something else), whitespace
/// runs collapsed, bounded. Dropped when nothing is left.
fn clean_display_name(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .filter(|c| !is_bidi_control(*c) && (!c.is_control() || c.is_whitespace()))
        .map(|c| if c.is_whitespace() { ' ' } else { c })
        .collect();
    let collapsed = cleaned.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.is_empty() {
        return None;
    }
    Some(collapsed.chars().take(MAX_NAME_CHARS).collect())
}

/// The Unicode directional formatting characters (UAX #9): embeddings,
/// overrides, isolates and the marks.
fn is_bidi_control(c: char) -> bool {
    matches!(
        c,
        '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

impl<
    U: UserRepository,
    S: SessionRepository,
    F: FederationLinkRepository,
    T: RefreshTokenRepository,
> AuthService<U, S, F, T>
{
    /// The just-in-time provisioning seam, called by
    /// [`Self::login_unknown_user`] with an entry the directory has just
    /// vouched for (a bind as that entry succeeded).
    ///
    /// Every refusal is the unknown-user answer, [`AuthError::InvalidCredentials`];
    /// the dummy verify has already run beside the bind, so nothing here
    /// changes what the caller sees or, beyond the work itself, how long.
    pub(super) async fn provision_directory_account(
        &self,
        input: &LoginInput,
        identity: DirectoryIdentity,
    ) -> AxiamResult<LoginResult> {
        let tenant_id = input.tenant_id;
        let Some(profile) = JitProfile::from_identity(&identity, &input.username_or_email) else {
            tracing::warn!(
                target: "axiam::directory",
                %tenant_id,
                "just-in-time provisioning refused: the directory entry has no usable \
                 username and e-mail address"
            );
            self.audit_directory(
                input,
                AUDIT_JIT_REFUSED,
                Uuid::nil(),
                serde_json::json!({
                    "reason": "unusable_attributes",
                    "directory_external_id": identity.external_id,
                }),
                AuditOutcome::Denied,
            )
            .await;
            return Err(AuthError::InvalidCredentials.into());
        };

        // D-28: a directory never takes over a local account. The names
        // compared are the entry's username, its address and what was typed,
        // against both columns of every account, ignoring case.
        let names = vec![
            profile.username.clone(),
            profile.email.clone(),
            input.username_or_email.clone(),
        ];
        if let Some(collision) = self
            .user_repo
            .find_identity_collision(tenant_id, &names)
            .await?
        {
            tracing::warn!(
                target: "axiam::directory",
                %tenant_id,
                existing_user_id = %collision.user_id,
                attribute = collision.attribute.as_str(),
                "just-in-time provisioning refused: the directory entry collides with a \
                 local account"
            );
            self.audit_directory(
                input,
                AUDIT_JIT_REFUSED,
                collision.user_id,
                serde_json::json!({
                    "reason": "collision",
                    "attribute": collision.attribute.as_str(),
                    "existing_user_id": collision.user_id.to_string(),
                    "directory_external_id": identity.external_id,
                }),
                AuditOutcome::Denied,
            )
            .await;
            return Err(AuthError::InvalidCredentials.into());
        }

        let metadata = match &profile.display_name {
            Some(name) => serde_json::json!({ "oidc": { "name": name } }),
            None => serde_json::json!({}),
        };
        let created = match self
            .user_repo
            .create_directory_account(CreateDirectoryAccount {
                tenant_id,
                username: profile.username.clone(),
                email: profile.email.clone(),
                external_id: identity.external_id.clone(),
                metadata,
            })
            .await
        {
            Ok(user) => {
                self.audit_directory_as(
                    input,
                    AUDIT_JIT_PROVISIONED,
                    ActorType::User,
                    user.id,
                    user.id,
                    serde_json::json!({
                        "source": "directory",
                        "directory_external_id": identity.external_id,
                    }),
                    AuditOutcome::Success,
                )
                .await;
                user
            }
            // The datastore refused: the username, the address or the entry is
            // taken. Either another first login for this same entry won a race
            // a moment ago — then its account is this login's account — or
            // something else holds the name, which is a collision after all.
            Err(AxiamError::AlreadyExists { .. }) => {
                match self
                    .user_repo
                    .get_by_username(tenant_id, &profile.username)
                    .await
                {
                    Ok(winner)
                        if winner
                            .directory_external_id
                            .as_deref()
                            .is_some_and(|marker| {
                                marker.eq_ignore_ascii_case(&identity.external_id)
                            }) =>
                    {
                        winner
                    }
                    Ok(_) | Err(AxiamError::NotFound { .. }) => {
                        tracing::warn!(
                            target: "axiam::directory",
                            %tenant_id,
                            "just-in-time provisioning refused: the name, the address or the \
                             entry is already held by another account"
                        );
                        self.audit_directory(
                            input,
                            AUDIT_JIT_REFUSED,
                            Uuid::nil(),
                            serde_json::json!({
                                "reason": "collision",
                                "attribute": "unique_constraint",
                                "directory_external_id": identity.external_id,
                            }),
                            AuditOutcome::Denied,
                        )
                        .await;
                        return Err(AuthError::InvalidCredentials.into());
                    }
                    Err(other) => return Err(other),
                }
            }
            Err(other) => return Err(other),
        };

        // T23.3.4: the new account holds no membership yet, so a lookup that
        // fails here leaves it granting nothing; the sign-in is refused and the
        // next one maps the groups.
        self.apply_directory_group_mapping(input, &created, &identity.dn)
            .await?;

        self.complete_authenticated_login(
            created,
            tenant_id,
            input.org_id,
            input.ip_address.clone(),
            input.user_agent.clone(),
            input.mfa_policy.clone(),
        )
        .await
    }

    /// Apply the tenant's directory group mapping for `user`, whose directory
    /// entry is `user_dn` (G-3, T23.3.4, D-30).
    ///
    /// Called on every successful directory sign-in, after the directory has
    /// vouched for the password and before the session (or an MFA challenge) is
    /// issued. **Fail closed:** when the mapping cannot be applied — the
    /// directory cannot be asked, the cap is hit, a write fails — the answer is
    /// the ordinary invalid-credentials failure, **not counted** against the
    /// account (the user did nothing wrong), with an audit row; memberships the
    /// directory may have revoked are never kept by letting the sign-in through.
    ///
    /// A changed membership set is audited (`directory.groups_mapped`) with
    /// identifiers and counts only; an unchanged one writes nothing, so a
    /// sign-in that maps nothing new leaves no row.
    pub(super) async fn apply_directory_group_mapping(
        &self,
        input: &LoginInput,
        user: &User,
        user_dn: &str,
    ) -> AxiamResult<()> {
        let Some(mapper) = &self.directory_group_mapper else {
            return Ok(());
        };
        match mapper
            .apply_for_user(input.tenant_id, user.id, user_dn)
            .await
        {
            Ok(outcome) => {
                if outcome.changed() {
                    self.audit_directory(
                        input,
                        AUDIT_GROUPS_MAPPED,
                        user.id,
                        serde_json::json!({
                            "source": "directory",
                            "groups_added": outcome.added,
                            "groups_removed": outcome.removed,
                            "added_count": outcome.added.len(),
                            "removed_count": outcome.removed.len(),
                            "manual_memberships_left": outcome.left_manual.len(),
                            "directory_groups_resolved": outcome.directory_groups_resolved,
                            "directory_groups_mapped": outcome.directory_groups_mapped,
                        }),
                        AuditOutcome::Success,
                    )
                    .await;
                }
                Ok(())
            }
            Err(error) => {
                tracing::warn!(
                    target: "axiam::directory",
                    tenant_id = %input.tenant_id,
                    user_id = %user.id,
                    outcome = ?error,
                    "directory sign-in refused: the group mapping could not be applied"
                );
                self.audit_directory(
                    input,
                    AUDIT_GROUP_MAPPING_REFUSED,
                    user.id,
                    serde_json::json!({
                        "reason": "mapping_not_applied",
                        "outcome": format!("{error:?}"),
                    }),
                    AuditOutcome::Failure,
                )
                .await;
                Err(AuthError::InvalidCredentials.into())
            }
        }
    }

    /// Link an **existing local account** to the directory entry it names
    /// (G-3, T23.3.3, D-28). An administrator's act: no route exists yet
    /// (T23.3.8 adds it) and nothing in the sign-in path calls it.
    ///
    /// * The entry is **resolved by the directory** — through the tenant's
    ///   configured filter with the account's username — never supplied by the
    ///   caller. None, or more than one, is `NotFound`.
    /// * An entry already linked to **another** account is refused
    ///   (`Conflict`): the marker is unique per tenant.
    /// * The account is marked ([`UserRepository::mark_directory_account`]:
    ///   marker set, local hash replaced with an unusable one, OPAQUE record
    ///   deleted), and then everything it holds that **authenticates without
    ///   the directory deciding** is retired: its WebAuthn credentials are
    ///   deleted, its `User`-type certificates revoked, and every session and
    ///   OAuth2 refresh token revoked. TOTP is kept: it is a second factor
    ///   *behind* the directory password.
    ///
    /// # One unit of work, by order rather than by transaction
    ///
    /// The revocations live behind four repositories, two of which keep a
    /// validation cache and publish revocations to a feed; a single SQL
    /// transaction across their tables would bypass both and leave revoked
    /// sessions valid until the cache expired. So the unit of work is an
    /// **order** that is safe to stop in and to retry: the mark comes first
    /// (from then on no local password can open a new session), the passkeys
    /// and certificates next, and the sessions and refresh tokens **last**, so
    /// that anything issued before the mark is swept by the final step. A
    /// failure partway returns the error (and writes a failure row); calling
    /// again with the account already linked to the same entry re-runs the
    /// revocations and nothing else.
    ///
    /// Audited (`directory.account_linked`) with counts and identifiers only.
    ///
    /// # Errors
    ///
    /// `NotFound` (no such account, or no single matching entry), `Conflict`
    /// (the entry or the account is linked elsewhere, or the tenant has no
    /// enabled directory), `Validation` (a deleted account) and
    /// `ServiceUnavailable` (no authenticator, or the directory cannot be
    /// reached or is misconfigured).
    #[allow(clippy::too_many_arguments)] // the five collaborators are the unit of work
    pub async fn link_local_account_to_directory<W, C>(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        actor_id: Uuid,
        ip_address: Option<String>,
        webauthn_repo: &W,
        certificate_repo: &C,
    ) -> AxiamResult<DirectoryLinkOutcome>
    where
        W: WebauthnCredentialRepository,
        C: CertificateRepository,
    {
        let authenticator = self.directory_authenticator.clone().ok_or_else(|| {
            AxiamError::ServiceUnavailable("directory sign-in is not available".into())
        })?;
        let user = self.user_repo.get_by_id(tenant_id, user_id).await?;
        if user.status == UserStatus::Deleted {
            return Err(AxiamError::Validation {
                message: "a deleted account cannot be linked to a directory".into(),
            });
        }

        let identity = match authenticator.lookup_entry(tenant_id, &user.username).await {
            Ok(identity) => identity,
            Err(DirectoryAuthError::InvalidCredentials) => {
                return Err(AxiamError::NotFound {
                    entity: "directory entry".into(),
                    id: format!("the entry for login name {}", user.username),
                });
            }
            Err(DirectoryAuthError::NotConfigured) => {
                return Err(AxiamError::Conflict {
                    reason: "the tenant has no enabled directory".into(),
                });
            }
            Err(other) => {
                tracing::warn!(
                    target: "axiam::directory",
                    %tenant_id,
                    outcome = ?other,
                    "linking refused: the directory could not answer"
                );
                return Err(AxiamError::ServiceUnavailable(
                    "the directory could not be queried".into(),
                ));
            }
        };

        let was_already_linked = match user.directory_external_id.as_deref() {
            Some(marker) if marker.eq_ignore_ascii_case(&identity.external_id) => true,
            Some(_) => {
                return Err(AxiamError::Conflict {
                    reason: "the account is already linked to a different directory entry".into(),
                });
            }
            None => false,
        };

        // 1. Mark. From here no local password opens a new session.
        let marked = if was_already_linked {
            user.clone()
        } else {
            match self
                .user_repo
                .mark_directory_account(tenant_id, user.id, &identity.external_id)
                .await
            {
                Ok(marked) => marked,
                Err(AxiamError::AlreadyExists { .. }) => {
                    return Err(AxiamError::Conflict {
                        reason: "that directory entry is already linked to another account".into(),
                    });
                }
                Err(other) => return Err(other),
            }
        };

        // 2-4. Retire what authenticates without the directory.
        let retired = self
            .retire_local_credentials(tenant_id, &marked, webauthn_repo, certificate_repo)
            .await;
        let (webauthn_credentials_deleted, certificates_revoked) = match retired {
            Ok(counts) => counts,
            Err((stage, error)) => {
                tracing::error!(
                    target: "axiam::directory",
                    %tenant_id,
                    user_id = %marked.id,
                    stage,
                    %error,
                    "linking is incomplete: the account is marked but a revocation failed; \
                     repeat the call"
                );
                self.audit_directory_raw(
                    tenant_id,
                    ip_address,
                    AUDIT_ACCOUNT_LINKED,
                    ActorType::User,
                    actor_id,
                    marked.id,
                    serde_json::json!({
                        "stage": stage,
                        "directory_external_id": identity.external_id,
                        "marked": true,
                    }),
                    AuditOutcome::Failure,
                )
                .await;
                return Err(error);
            }
        };

        self.audit_directory_raw(
            tenant_id,
            ip_address,
            AUDIT_ACCOUNT_LINKED,
            ActorType::User,
            actor_id,
            marked.id,
            serde_json::json!({
                "directory_external_id": identity.external_id,
                "webauthn_credentials_deleted": webauthn_credentials_deleted,
                "certificates_revoked": certificates_revoked,
                "sessions_and_refresh_tokens_revoked": true,
                "retry_of_interrupted_link": was_already_linked,
            }),
            AuditOutcome::Success,
        )
        .await;

        Ok(DirectoryLinkOutcome {
            user: marked,
            webauthn_credentials_deleted,
            certificates_revoked,
            was_already_linked,
        })
    }

    /// Steps 2–4 of linking, in the order that matters: the two credential
    /// kinds that outlive a session, then the sessions and refresh tokens last.
    /// The error names the stage that failed.
    async fn retire_local_credentials<W, C>(
        &self,
        tenant_id: Uuid,
        user: &User,
        webauthn_repo: &W,
        certificate_repo: &C,
    ) -> Result<(u64, u64), (&'static str, AxiamError)>
    where
        W: WebauthnCredentialRepository,
        C: CertificateRepository,
    {
        let passkeys = webauthn_repo
            .delete_by_user(tenant_id, user.id)
            .await
            .map_err(|error| ("webauthn_credentials", error))?;
        let certificates = certificate_repo
            .revoke_user_certificates(tenant_id, user.id, &user.username, &user.email)
            .await
            .map_err(|error| ("user_certificates", error))?;
        self.revoke_all_sessions(tenant_id, user.id)
            .await
            .map_err(|error| ("sessions_and_refresh_tokens", error))?;
        Ok((passkeys, certificates))
    }

    /// One audit row, written through the injected sink, if there is one.
    async fn audit_directory(
        &self,
        input: &LoginInput,
        action: &str,
        resource_id: Uuid,
        metadata: serde_json::Value,
        outcome: AuditOutcome,
    ) {
        self.audit_directory_as(
            input,
            action,
            ActorType::System,
            Uuid::nil(),
            resource_id,
            metadata,
            outcome,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)] // an audit row is this wide
    async fn audit_directory_as(
        &self,
        input: &LoginInput,
        action: &str,
        actor_type: ActorType,
        actor_id: Uuid,
        resource_id: Uuid,
        metadata: serde_json::Value,
        outcome: AuditOutcome,
    ) {
        self.audit_directory_raw(
            input.tenant_id,
            input.ip_address.clone(),
            action,
            actor_type,
            actor_id,
            resource_id,
            metadata,
            outcome,
        )
        .await;
    }

    #[allow(clippy::too_many_arguments)] // an audit row is this wide
    async fn audit_directory_raw(
        &self,
        tenant_id: Uuid,
        ip_address: Option<String>,
        action: &str,
        actor_type: ActorType,
        actor_id: Uuid,
        resource_id: Uuid,
        metadata: serde_json::Value,
        outcome: AuditOutcome,
    ) {
        let Some(sink) = &self.directory_audit else {
            return;
        };
        sink.record(CreateAuditLogEntry {
            tenant_id,
            actor_id,
            actor_type,
            action: action.to_string(),
            resource_id: (!resource_id.is_nil()).then_some(resource_id),
            outcome,
            ip_address,
            metadata: Some(metadata),
        })
        .await;
    }

    /// The directory half of [`Self::login_unknown_user`]: authenticate the
    /// typed name against the tenant's directory for provisioning, beside the
    /// equalising dummy verify. `None` is "answer as an unknown user"; `Some`
    /// is an entry the directory vouched for.
    pub(super) async fn authenticate_unknown_name_against_directory(
        &self,
        input: &LoginInput,
    ) -> AxiamResult<Option<DirectoryIdentity>> {
        let authenticator = match &self.directory_authenticator {
            Some(authenticator) if !input.password.is_empty() => {
                std::sync::Arc::clone(authenticator)
            }
            _ => {
                // Nothing to ask, or nobody to ask: the plain unknown-user cost.
                self.equalising_dummy_verify().await?;
                return Ok(None);
            }
        };
        // The same shape `login_directory_account` uses: a hash permit first,
        // so saturation answers `503` exactly where every other branch does and
        // before the directory is contacted, then the dummy verify and the
        // directory call side by side. A tenant with no directory (or without
        // `jit_provisioning`) is answered by the gate before any socket opens,
        // so for it the whole call costs one verify, as it always has.
        let permit = acquire_hash_permit(
            &self.crypto_semaphore,
            std::time::Duration::from_secs(self.config.hash_acquire_timeout_secs),
        )
        .await?;
        let ((), outcome) = tokio::join!(
            self.dummy_verify_holding(permit),
            authenticator.authenticate_for_provisioning(
                input.tenant_id,
                &input.username_or_email,
                &input.password,
            ),
        );
        match outcome {
            Ok(identity) => Ok(Some(identity)),
            Err(DirectoryAuthError::NotConfigured) => {
                tracing::debug!(
                    target: "axiam::directory",
                    tenant_id = %input.tenant_id,
                    "unknown login name: no directory provisioning for this tenant"
                );
                Ok(None)
            }
            Err(other) => {
                tracing::info!(
                    target: "axiam::directory",
                    tenant_id = %input.tenant_id,
                    outcome = ?other,
                    "unknown login name refused by the directory"
                );
                Ok(None)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(
        username: Option<&str>,
        email: Option<&str>,
        name: Option<&str>,
    ) -> DirectoryIdentity {
        DirectoryIdentity {
            external_id: "6f9619ff-8b86-d011-b42d-00c04fc964ff".into(),
            dn: "uid=a,dc=example,dc=com".into(),
            username: username.map(str::to_string),
            email: email.map(str::to_string),
            display_name: name.map(str::to_string),
        }
    }

    #[test]
    fn a_complete_entry_becomes_a_profile() {
        let profile = JitProfile::from_identity(
            &identity(
                Some(" alice "),
                Some("alice@example.com"),
                Some("Alice  Example"),
            ),
            "typed",
        )
        .unwrap();
        assert_eq!(profile.username, "alice");
        assert_eq!(profile.email, "alice@example.com");
        assert_eq!(profile.display_name.as_deref(), Some("Alice Example"));
    }

    #[test]
    fn the_typed_name_stands_in_for_a_missing_username_attribute() {
        let profile =
            JitProfile::from_identity(&identity(None, Some("a@example.com"), None), "typed")
                .unwrap();
        assert_eq!(profile.username, "typed");
        assert!(profile.display_name.is_none());
    }

    #[test]
    fn an_entry_without_a_usable_address_cannot_become_an_account() {
        for email in [
            None,
            Some(""),
            Some("no-at-sign"),
            Some("a@nodot"),
            Some("@x.test"),
            Some("a@@x.test"),
            Some("a b@x.test"),
            Some("a@x.test\n"),
        ] {
            let outcome = JitProfile::from_identity(&identity(Some("alice"), email, None), "t");
            // A trailing newline is trimmed, so only the others are refused.
            if email == Some("a@x.test\n") {
                assert!(outcome.is_some());
            } else {
                assert!(
                    outcome.is_none(),
                    "an unusable address must refuse the entry"
                );
            }
        }
    }

    #[test]
    fn identifiers_with_control_or_whitespace_or_overrides_are_refused_not_repaired() {
        for bad in ["al ice", "al\tice", "al\u{0}ice", "al\u{202E}ice", ""] {
            assert!(clean_identifier(bad, 255).is_none());
        }
        assert!(clean_identifier(&"a".repeat(256), 255).is_none());
        assert!(clean_identifier(&"a".repeat(255), 255).is_some());
    }

    #[test]
    fn a_display_name_loses_overrides_and_controls_and_is_bounded() {
        assert_eq!(
            clean_display_name("Al\u{202E}ice\u{0}\n Example").as_deref(),
            Some("Alice Example")
        );
        assert!(clean_display_name("\u{202E}\u{0}  ").is_none());
        assert_eq!(
            clean_display_name(&"x".repeat(1000)).map(|n| n.chars().count()),
            Some(255)
        );
    }
}

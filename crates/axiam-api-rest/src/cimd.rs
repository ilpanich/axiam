//! Materialising a client from a Client ID Metadata Document (T21.5).
//!
//! `axiam_oauth2::cimd` decides *whether* a URL-shaped `client_id` is a client
//! and *what* it becomes. This module is the half that needs state: the
//! tenant's settings, the document cache, the client table and the audit log.
//!
//! # Where it runs, and why nowhere else
//!
//! [`materialise_if_cimd`] is called at the top of the authorize, PAR and
//! token paths — the three places a `client_id` arrives — **before** the
//! existing client lookup. It is not a lookup itself and it returns nothing:
//! its whole effect is that, by the time the ordinary
//! `get_by_client_id` runs, a row either exists or does not, and everything
//! downstream (client authentication, the T21.2 loopback matcher, the D4
//! consent gate, the D3 resource allow-list, the FAPI refusals) is the code
//! that was already there, acting on a row like any other.
//!
//! That is the design decision worth stating plainly: **CIMD adds no branch to
//! any flow.** It adds one step in front of three of them, and that step's
//! only outputs are "a row now exists" or "nothing happened".
//!
//! # Every failure is "nothing happened"
//!
//! A `client_id` that is not a URL, a tenant with CIMD off, a URL the rules
//! refuse, a publisher that is down, a document that is malformed, a row that
//! belongs to somebody else, a settings read that failed — all of them return
//! without writing. The request then meets the client lookup it would have met
//! anyway and is refused as an unknown client, which is **byte for byte
//! today's answer** (I1). Nothing here can turn a request that used to succeed
//! into one that fails, because the only thing it can do is add a row that did
//! not exist.
//!
//! # The row it will not touch
//!
//! A client whose `managed_by` is not `cimd` is left exactly as it is, and the
//! request proceeds against the administrator's registration. An operator who
//! registered a client whose `client_id` happens to be a URL keeps that
//! client, its secret, its profile and its audiences, whatever any document at
//! that address says. The repository enforces this too — the refresh carries
//! `AND managed_by = 'cimd'` in its `WHERE` — so it is refused twice, once
//! where it can be explained and once where it cannot be bypassed.

use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::models::oauth2_client::ManagedBy;
use axiam_core::repository::{
    AuditLogRepository, OAuth2ClientRepository, SettingsRepository, TenantRepository,
};
use axiam_oauth2::cimd;
use surrealdb::Connection;
use uuid::Uuid;

use crate::state::AppState;

/// Resolve a URL-shaped `client_id` into a shadow client row, if this tenant
/// admits one.
///
/// Returns nothing on purpose: see the module header. The caller's next step
/// is the client lookup it was always going to make.
///
/// # Cost on the path that is not CIMD
///
/// Two `starts_with` calls. Every `client_id` AXIAM has ever issued is
/// `oa_` followed by hex, so the overwhelming majority of requests leave this
/// function having read no setting, taken no lock and touched no socket. The
/// settings read happens only for a `client_id` that is literally an
/// `http`/`https` URL — which, on a deployment that has not enabled CIMD, is a
/// request that was going to be refused anyway.
pub async fn materialise_if_cimd<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &actix_web::HttpRequest,
    tenant_id: Uuid,
    client_id: &str,
) {
    // 1. The I1 fast path.
    if !cimd::looks_like_url(client_id) {
        return;
    }

    // 2. The tenant's policy. A tenant that cannot be read, or whose
    //    organization cannot be resolved, is treated as having CIMD off: a
    //    settings read that failed must never be what opens an outbound fetch.
    let Ok(tenant) = state.tenant_repo.get_by_id(tenant_id).await else {
        return;
    };
    let Ok(settings) = SettingsRepository::get_effective_settings(
        &state.settings_repo,
        tenant.organization_id,
        tenant_id,
    )
    .await
    else {
        tracing::warn!(
            %tenant_id,
            "could not read a tenant's effective settings while resolving a URL-shaped \
             client_id; treating client ID metadata documents as disabled"
        );
        return;
    };
    if !settings.oidc.cimd.enabled {
        return;
    }

    // 3. The per-tenant ceiling, **before any fetch** — T21.8 / MCP-04.
    //
    // Asked here rather than after the resolve for two reasons. A tenant at
    // quota should not be an outbound amplifier either: refusing after the
    // fetch would mean a stranger at the ceiling still gets one outbound
    // request per distinct URL they can name. And the row lookup this needs is
    // one the function made anyway, a few lines down, to decide whether the
    // materialisation is a first appearance or a refresh — so moving it up
    // costs nothing and the count query runs only when there is no row.
    //
    // **A refresh never counts and never costs the query.** The quota bounds
    // how many distinct documents a tenant holds, not how often they are
    // presented.
    //
    // The ceiling is `dcr_max_clients`, counted separately for `cimd`, which
    // is what the repository's own comment on `count_by_managed_by` asks for:
    // "the quota is per mechanism, so … a CIMD shadow row materialised by a
    // legitimate client cannot exhaust the allowance for self-registration".
    // Two counts against one number honours that. Not a tenth CIMD field: the
    // precedent is T21.5 amendment 4, where `dcr_allowed_scopes` governs both
    // mechanisms and keeps its `dcr_` name because DCR defined it.
    let existing = state
        .oauth2_client_repo
        .get_by_client_id(tenant_id, client_id)
        .await
        .ok();
    if let Some(row) = &existing
        && row.managed_by != ManagedBy::Cimd
    {
        tracing::warn!(
            %tenant_id,
            client_id,
            managed_by = %row.managed_by,
            "a client ID metadata document names a client_id this tenant already registered by \
             another means; the existing registration stands and the document is ignored"
        );
        return;
    }
    if existing.is_none() {
        let limit = u64::from(settings.oidc.dcr_max_clients);
        let held = match state
            .oauth2_client_repo
            .count_by_managed_by(tenant_id, ManagedBy::Cimd)
            .await
        {
            Ok(held) => held,
            Err(e) => {
                // Fail closed: an unreadable count must not be read as room,
                // exactly as the DCR endpoint reads it.
                tracing::error!(
                    error = %e,
                    %tenant_id,
                    "could not count client ID metadata document rows; treating the tenant as \
                     at quota"
                );
                limit
            }
        };
        if held >= limit {
            // `debug`, not `warn`, for the reason the resolve failure below
            // gives: the input is chosen by an unauthenticated caller, so
            // anything louder is a log-flooding primitive handed to a
            // stranger. The audit row is the record an operator acts on.
            tracing::debug!(
                %tenant_id,
                client_id,
                held,
                limit,
                "a tenant is at its client ID metadata document ceiling; not fetching"
            );
            audit_quota_refusal(state, http_req, tenant_id).await;
            return;
        }
    }

    // 4-6. Validate the URL, fetch (cached, guarded, bounded) and validate the
    //      document.
    let validated = match cimd::resolve(
        &state.oauth2.cimd_cache,
        tenant_id,
        client_id,
        &settings.oidc,
    )
    .await
    {
        Ok(validated) => validated,
        Err(e) => {
            // `debug`, not `warn`: the input is chosen by an unauthenticated
            // caller, so anything louder is a log-flooding primitive handed to
            // a stranger. The audit event below records the refusals that
            // reached a fetch; this line is for the operator debugging their
            // own client.
            tracing::debug!(
                %tenant_id,
                client_id,
                error = %e,
                "a URL-shaped client_id did not resolve to a client ID metadata document"
            );
            return;
        }
    };

    // `existing` was read above, before the fetch, because the quota needed
    // it. It also decides whether anything is audited — a client materialising
    // for the first time is an event an operator wants to see, and a refresh
    // every five minutes for as long as the client is in use is not.
    match state
        .oauth2_client_repo
        .upsert_cimd_client(client_id, validated.create)
        .await
    {
        Ok(_) if existing.is_some() => {}
        Ok(_) => audit_materialisation(state, http_req, tenant_id, client_id).await,
        Err(e) => {
            tracing::error!(
                %tenant_id,
                client_id,
                error = %e,
                "a client ID metadata document validated but its shadow client could not be \
                 written; the request will be refused as an unknown client"
            );
        }
    }
}

/// Record a refusal because the tenant is at its CIMD ceiling (T21.8 / MCP-04).
///
/// The same shape as T21.4a's registration refusal — the action, the
/// `managed_by`, the error code, the caller's IP — so one audit filter shows
/// both mechanisms' refusals side by side. And the same discipline about what
/// it carries: **no client-supplied string**, not even the `client_id`, which
/// on this path is a URL a stranger chose and an audit viewer is a place where
/// attacker-controlled strings are read by people. The count and the ceiling
/// are AXIAM's own numbers and are what an operator needs to act on.
async fn audit_quota_refusal<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &actix_web::HttpRequest,
    tenant_id: Uuid,
) {
    if let Err(e) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: "oauth2.client_registration_refused".into(),
            resource_id: None,
            outcome: AuditOutcome::Failure,
            ip_address: crate::extractors::client_info::client_ip(http_req),
            metadata: Some(serde_json::json!({
                "managed_by": ManagedBy::Cimd.as_str(),
                "error": "client_quota_exhausted",
            })),
        })
        .await
    {
        tracing::error!(
            error = %e,
            %tenant_id,
            "could not record a refused client ID metadata document materialisation; the \
             request is unaffected"
        );
    }
}

/// Record the first time a document becomes a client in this tenant.
///
/// The same shape as T21.4's registration event, with `managed_by: cimd`, so
/// the audit viewer's existing filter shows both mechanisms side by side. A
/// failure to write it never fails the authorization: the client exists either
/// way, and refusing a sign-in because an audit row could not be appended
/// would make the log a single point of failure for the login page.
async fn audit_materialisation<C: Connection + Clone>(
    state: &AppState<C>,
    http_req: &actix_web::HttpRequest,
    tenant_id: Uuid,
    client_id: &str,
) {
    if let Err(e) = state
        .audit_repo
        .append(CreateAuditLogEntry {
            tenant_id,
            actor_id: Uuid::nil(),
            actor_type: ActorType::System,
            action: "oauth2.client_registered".into(),
            resource_id: None,
            outcome: AuditOutcome::Success,
            ip_address: crate::extractors::client_info::client_ip(http_req),
            metadata: Some(serde_json::json!({
                "managed_by": ManagedBy::Cimd.as_str(),
                "client_id": client_id,
            })),
        })
        .await
    {
        tracing::error!(
            error = %e,
            %tenant_id,
            "could not record a client ID metadata document materialisation; the request is \
             unaffected"
        );
    }
}

//! #613 (T-289) — the tenant's `dcr_allowed_scopes` as a **ceiling** on what an
//! externally registered client may obtain, applied where scopes are read.
//!
//! # The gap this closes
//!
//! `dcr_allowed_scopes` bounds what a self-registered client (`managed_by:
//! dcr`) or a client ID metadata document (`managed_by: cimd`) may *register*.
//! It was checked at registration, at an RFC 7592 `PUT` and at a CIMD fetch —
//! and nowhere else. A tenant that withdrew a scope from the list therefore
//! narrowed nothing already registered: the client row kept the scope, every
//! grant that reads `client.scopes` kept offering it, and the refresh grant's
//! `stored.scopes ∩ client.scopes` (#520) intersected against a row that still
//! held it. The withdrawal took effect only when the client itself chose to
//! re-register.
//!
//! # Enforcement at the read points, not a rewrite of rows
//!
//! The settings handler does not narrow client rows when the list changes.
//! Rewriting rows would be a second writer on `oauth2_client` racing RFC 7592
//! `PUT`s and CIMD re-materialisations, and it would make the *row* say
//! something the client never registered. Instead every point that decides
//! what a token may carry reads the client's scopes through
//! [`apply_to_client`], which intersects them with the tenant's **effective**
//! list (the organization baseline merged with the tenant override, exactly
//! what registration validates against). A withdrawn scope is gone at the
//! client's next request, whatever the row says; a scope put back is back at
//! the next request too, because nothing was deleted.
//!
//! The read points, each of which calls into this module:
//!
//! | Path | Where | What is narrowed |
//! |---|---|---|
//! | `/oauth2/authorize` (query, PAR `request_uri`) | `AuthorizeService::authorize` step 5 | the scopes a request may name |
//! | `authorization_code` | `TokenService::handle_authorization_code` | the code's scopes, before it is spent |
//! | `client_credentials` | `TokenService::handle_client_credentials` | requested / default scopes |
//! | `refresh_token` | `TokenService::handle_refresh_token` | `stored.scopes ∩ client.scopes` |
//! | CIBA token (`urn:openid:params:grant-type:ciba`) | `TokenService::exchange_ciba` | the approved request's scopes |
//! | `/oauth2/bc-authorize` | the REST handler, through `TokenService::apply_scope_ceiling` | the scopes a request may name |
//! | token exchange (RFC 8693) | the REST handler, through `TokenService::apply_scope_ceiling` | the client side of the narrowing |
//! | `/oauth2/device_authorization` | `DeviceAuthorizationService::authorize` | the scopes the device grant records |
//!
//! # Who pays for it
//!
//! Only an external client. [`applies_to`] is answered from the client row the
//! path already holds, so a client an administrator created — every client in
//! most deployments — costs no read and sees byte-identical behaviour. An
//! external client costs one effective-settings read per request on the paths
//! above, which is the read `materialise_if_cimd` already makes for every
//! URL-shaped `client_id`. Nothing is cached: a cache would be the staleness
//! this module exists to remove.
//!
//! # A read that fails refuses
//!
//! For an external client a failed policy read is a `server_error`, never a
//! fall-back to the row's scopes: the row is exactly the value this module
//! exists to distrust. An unwired policy ([`unwired`]) is the same refusal, so
//! a composition root that forgets the port fails loudly on the first DCR
//! request rather than silently restoring the gap.
//!
//! # What it does not do
//!
//! An access token already minted keeps its `scope` until it expires (15
//! minutes by default): it is a stateless JWT and nothing re-reads it. The
//! refresh token behind it is narrowed at its next use. A device code pending
//! when the list changes mints with the scopes recorded at
//! `/oauth2/device_authorization` (its poll never reads the client), and the
//! refresh token it yields is narrowed at its first use.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::oauth2_client::{ManagedBy, OAuth2Client};
use uuid::Uuid;

use crate::error::OAuth2Error;

/// Where the tenant's effective `dcr_allowed_scopes` is read from.
///
/// A port rather than a repository type parameter, for the reason
/// [`crate::mtls::IssuedCertificateLookup`] is one: the services that need it
/// keep their type parameters, and the composition root builds one value that
/// every service shares.
pub trait ExternalClientScopePolicy: Send + Sync {
    /// The tenant's **effective** `dcr_allowed_scopes` — the organization
    /// baseline merged with the tenant override, as registration reads it.
    ///
    /// An `Err` is a failed read, never "no ceiling": the caller refuses.
    fn allowed_scopes<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Vec<String>>> + Send + 'a>>;
}

/// The shared form every service holds.
pub type SharedScopePolicy = Arc<dyn ExternalClientScopePolicy>;

/// The policy a service holds until its composition root wires a real one.
///
/// Refuses every read, so an external client is refused with `server_error`
/// and an administrator's client — which never reads it — is unaffected.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnwiredScopePolicy;

impl ExternalClientScopePolicy for UnwiredScopePolicy {
    fn allowed_scopes<'a>(
        &'a self,
        _tenant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = AxiamResult<Vec<String>>> + Send + 'a>> {
        Box::pin(async {
            Err(AxiamError::Internal(
                "no external-client scope policy is wired into this service".into(),
            ))
        })
    }
}

/// A [`SharedScopePolicy`] that refuses — see [`UnwiredScopePolicy`].
pub fn unwired() -> SharedScopePolicy {
    Arc::new(UnwiredScopePolicy)
}

/// Whether the ceiling binds a client of this provenance.
///
/// Exhaustive on purpose: a new `ManagedBy` variant must decide here whether
/// the tenant's list bounds it.
pub const fn applies_to(managed_by: ManagedBy) -> bool {
    match managed_by {
        ManagedBy::Admin => false,
        ManagedBy::Dcr | ManagedBy::Cimd => true,
    }
}

/// Keep, in their order, only the scopes the ceiling names.
pub fn narrow(scopes: &mut Vec<String>, ceiling: &[String]) {
    scopes.retain(|s| ceiling.iter().any(|c| c == s));
}

/// The ceiling that binds `client`: `None` for an administrator's client (no
/// read is made), the tenant's effective list for an external one.
///
/// # Errors
///
/// `server_error` when the list cannot be read — fail closed, see the module
/// documentation.
pub async fn ceiling_for(
    policy: &dyn ExternalClientScopePolicy,
    client: &OAuth2Client,
) -> Result<Option<Vec<String>>, OAuth2Error> {
    if !applies_to(client.managed_by) {
        return Ok(None);
    }
    match policy.allowed_scopes(client.tenant_id).await {
        Ok(list) => Ok(Some(list)),
        Err(e) => {
            tracing::error!(
                error = %e,
                tenant_id = %client.tenant_id,
                client_id = %client.client_id,
                managed_by = %client.managed_by,
                "could not read the tenant's dcr_allowed_scopes for an externally registered \
                 client; refusing rather than trusting the client row"
            );
            Err(OAuth2Error::ServerError(
                "the tenant's scope policy could not be read".into(),
            ))
        }
    }
}

/// Narrow `client.scopes` to the tenant's current ceiling, in place, and
/// return the ceiling so a caller holding scopes granted *earlier* (a code, a
/// refresh token, an approved CIBA request) can narrow those with the same
/// list.
///
/// A no-op returning `Ok(None)` for an administrator's client.
///
/// # Errors
///
/// As [`ceiling_for`].
pub async fn apply_to_client(
    policy: &dyn ExternalClientScopePolicy,
    client: &mut OAuth2Client,
) -> Result<Option<Vec<String>>, OAuth2Error> {
    let ceiling = ceiling_for(policy, client).await?;
    if let Some(ceiling) = &ceiling {
        let before = client.scopes.len();
        narrow(&mut client.scopes, ceiling);
        if client.scopes.len() != before {
            tracing::debug!(
                tenant_id = %client.tenant_id,
                client_id = %client.client_id,
                kept = %client.scopes.join(" "),
                "an externally registered client holds scopes the tenant no longer offers; \
                 they are withheld"
            );
        }
    }
    Ok(ceiling)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| (*x).to_owned()).collect()
    }

    #[test]
    fn only_external_provenance_is_bound() {
        assert!(!applies_to(ManagedBy::Admin));
        assert!(applies_to(ManagedBy::Dcr));
        assert!(applies_to(ManagedBy::Cimd));
    }

    #[test]
    fn narrowing_keeps_order_and_drops_only_what_the_ceiling_lacks() {
        let mut scopes = s(&["profile", "openid", "email"]);
        narrow(&mut scopes, &s(&["openid", "profile"]));
        assert_eq!(scopes, s(&["profile", "openid"]));

        // An empty ceiling is "offer nothing", exactly as registration reads
        // it (`dcr::validate` refuses every scope under an empty list) — not
        // "no ceiling". Withdrawing the last scope must not restore the rest.
        let mut scopes = s(&["openid"]);
        narrow(&mut scopes, &[]);
        assert!(scopes.is_empty());

        // A scope the ceiling gained is never added.
        let mut scopes = s(&["openid"]);
        narrow(&mut scopes, &s(&["openid", "profile"]));
        assert_eq!(scopes, s(&["openid"]));
    }

    #[tokio::test]
    async fn an_unwired_policy_refuses_an_external_client_and_ignores_an_admin_one() {
        let policy = UnwiredScopePolicy;
        let mut client = OAuth2Client {
            scopes: s(&["openid"]),
            managed_by: ManagedBy::Admin,
            ..test_client()
        };
        assert_eq!(apply_to_client(&policy, &mut client).await.unwrap(), None);
        assert_eq!(client.scopes, s(&["openid"]));

        client.managed_by = ManagedBy::Dcr;
        let err = apply_to_client(&policy, &mut client).await.unwrap_err();
        assert_eq!(err.error_code(), "server_error");
        assert_eq!(client.scopes, s(&["openid"]), "a refusal narrows nothing");
    }

    fn test_client() -> OAuth2Client {
        use axiam_core::models::oauth2_client::{
            AuthnRequestParamsMode, ClientAuthMethod, ClientProfile,
        };
        OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "oa_test".into(),
            client_secret_hash: String::new(),
            name: "test".into(),
            redirect_uris: vec![],
            grant_types: vec!["authorization_code".into()],
            scopes: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: ClientAuthMethod::None,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            allowed_resources: Vec::new(),
            managed_by: ManagedBy::Admin,
            last_authorized_at: None,
            ciba: Default::default(),
        }
    }
}

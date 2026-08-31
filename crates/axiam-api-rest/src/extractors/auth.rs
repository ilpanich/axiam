//! JWT-based authentication extractor.
//!
//! [`AuthenticatedUser`] implements Actix-Web's `FromRequest` trait.
//! It extracts the JWT from the `axiam_access` httpOnly cookie (browser clients)
//! or falls back to `Authorization: Bearer <token>` header (service clients).

use axiam_authz::types::SubjectScope;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use actix_web::dev::Payload;
use actix_web::web;
use actix_web::{HttpMessage, HttpRequest};
use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    AUD_M2M, AUD_USER, CachedUserIdentity, ValidatedClaims, validate_access_token,
};
use axiam_core::error::AxiamError;
use axiam_core::models::role::{TenantReach, tenant_reach_of};
use axiam_db::SurrealSessionRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::error::AxiamApiError;

/// Object-safe per-request session-validity check (D-15 / REQ-7).
///
/// Access tokens are stateless JWTs, so revoking a session (deleting its row)
/// has no effect unless every authenticated request re-checks that the session
/// behind the token's `jti` (= `session.id`) is still active. This trait is the
/// object-safe seam that lets the connection-agnostic [`AuthenticatedUser`]
/// extractor perform that check without being generic over the DB `Connection`.
///
/// Mirrors the [`crate::authz::AuthzChecker`] boxed-future pattern because the
/// underlying repository methods are native `async fn` (RPITIT, not dyn-safe).
pub trait SessionValidator: Send + Sync {
    /// Returns `true` if a non-expired session with `session_id` exists for
    /// `tenant_id`. A revoked session (row deleted) or an expired one is
    /// considered inactive.
    fn is_session_active<'a>(
        &'a self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>>;
}

impl<C: Connection> SessionValidator for SurrealSessionRepository<C> {
    fn is_session_active<'a>(
        &'a self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
        // I6: delegate to the repository, which answers from its optional
        // short-TTL validity cache when one is attached and otherwise performs
        // exactly the read this used to inline. Keeping the logic there is what
        // guarantees the cache is invalidated by the same methods that delete
        // the rows — see `axiam_db::session_validation_cache`.
        Box::pin(self.is_session_active_checked(tenant_id, session_id))
    }
}

/// The header a client uses to say which tenant it is acting on.
///
/// Only meaningful for an organization-level principal, which is the only kind
/// that has more than one answer. Honoured for anyone else would be a request
/// asking to be treated as belonging to a tenant it does not belong to.
pub const ACTIVE_TENANT_HEADER: &str = "X-Axiam-Tenant";

/// What the authorization layer needs to know about a tenant to decide whether
/// a principal may act on it.
#[derive(Debug, Clone, Copy)]
pub struct TenantScope {
    pub organization_id: Uuid,
    /// Whether this is the organization's own reserved tenant.
    pub is_organization: bool,
}

/// Object-safe tenant lookup for the authentication extractor.
///
/// The same boxed-future seam as [`SessionValidator`], and for the same reason:
/// the extractor is not generic over the DB `Connection` and the repository
/// methods are native `async fn`.
///
/// # Why this cannot be answered from the token
///
/// The token says which tenant the principal *lives in*. Whether some **other**
/// tenant belongs to the same organization is a fact about that other tenant,
/// and a client that could assert it could name a tenant in an organization it
/// has nothing to do with. An organization-level principal's global grants
/// carry across tenant boundaries by design; without this check they would
/// carry across *organization* boundaries too, which is the one thing an
/// organization is.
pub trait TenantScopeResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Option<TenantScope>> + Send + 'a>>;
}

impl<C: Connection> TenantScopeResolver for axiam_db::SurrealTenantRepository<C> {
    fn resolve<'a>(
        &'a self,
        tenant_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Option<TenantScope>> + Send + 'a>> {
        Box::pin(async move {
            use axiam_core::repository::TenantRepository as _;
            self.get_by_id(tenant_id).await.ok().map(|t| TenantScope {
                organization_id: t.organization_id,
                is_organization: t.is_organization_scope(),
            })
        })
    }
}

/// Object-safe lookup of how far a principal's roles reach across the tenants
/// of its organization.
///
/// The same boxed-future seam as [`TenantScopeResolver`], for the same reason:
/// the extractor is not generic over the DB `Connection`.
///
/// # Why the extractor asks at all
///
/// `axiam_authz` is the authority here — it drops every assignment that does
/// not reach the tenant being acted on, so a principal that names a tenant
/// outside its reach is refused every single action inside it. That is correct
/// and it is unusable: the operator switches tenant, the switch appears to
/// work, and every page then fails one request at a time with a different
/// message.
///
/// Refusing the header itself turns that into one answer, at the moment the
/// caller asked for something it may not have.
///
/// # Why an absent resolver means "unrestricted"
///
/// [`TenantScopeResolver`] fails closed when unregistered, because it is the
/// only check that keeps organization scope inside an organization — nothing
/// else would catch it. This one is not that: the engine still enforces the
/// same restriction on every action, so an unregistered resolver costs the
/// clear early refusal and nothing else. Failing closed here would instead
/// break every organization-level tenant switch in any harness that did not
/// register it, which is a real outage in exchange for no security.
pub trait PrincipalReachResolver: Send + Sync {
    fn reach<'a>(
        &'a self,
        principal_tenant_id: Uuid,
        subject_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Option<TenantReach>> + Send + 'a>>;
}

impl<C: Connection> PrincipalReachResolver for axiam_db::SurrealRoleRepository<C> {
    fn reach<'a>(
        &'a self,
        principal_tenant_id: Uuid,
        subject_id: Uuid,
    ) -> Pin<Box<dyn Future<Output = Option<TenantReach>> + Send + 'a>> {
        Box::pin(async move {
            use axiam_core::repository::RoleRepository as _;
            self.get_user_role_assignments(principal_tenant_id, subject_id)
                .await
                .ok()
                .map(|assignments| tenant_reach_of(&assignments))
        })
    }
}

/// Authenticated user context extracted from a valid JWT.
///
/// Use this as a handler parameter to require authentication.
/// If the audit middleware has already validated the token, the cached
/// claims are reused to avoid double verification.
///
/// **Audience narrowing (D-19 / D-21):** only tokens with `aud = axiam:user`
/// are accepted on user-facing routes. M2M tokens are rejected with 401.
/// When `aud` is absent and `AuthConfig.allow_missing_aud_as_user` is `true`,
/// the token is accepted with a `WARN` log on every request. No in-process
/// rate limit is applied — operator-side log filtering (Loki dedup, fluent-bit
/// rewrite_tag, etc.) handles burst noise. This trade-off keeps the extractor
/// allocation-free and avoids shared mutable state.
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: Uuid,
    /// The tenant being **acted upon**.
    ///
    /// Equal to [`Self::principal_tenant_id`] for every ordinary principal,
    /// which is why the ~100 handlers that read this field did not change when
    /// organization scope arrived. For an organization-level principal it is
    /// whichever tenant the request named in [`ACTIVE_TENANT_HEADER`],
    /// validated to be in the caller's own organization.
    pub tenant_id: Uuid,
    /// The tenant the caller's own record and grants live in.
    ///
    /// The organization tenant for an organization-level principal, and the
    /// same as [`Self::tenant_id`] for everyone else.
    pub principal_tenant_id: Uuid,
    /// Whether [`Self::principal_tenant_id`] was **verified** to be the
    /// organization's reserved scope.
    ///
    /// Set only by [`resolve_active_tenant`], which reads the tenant record and
    /// checks its `kind`. `false` until then, so a request that never named
    /// another tenant is evaluated as an ordinary tenant principal — which it
    /// is, as far as this request is concerned.
    ///
    /// This is the flag that becomes
    /// [`axiam_authz::types::SubjectScope::Organization`], and it is the whole
    /// reason that claim is trustworthy: it cannot be reached without the
    /// lookup that justifies it.
    pub organization_level: bool,
    pub org_id: Uuid,
    /// The session ID — equals the JWT `jti` claim which is set to
    /// `session.id` for user-facing tokens (D-15). Use this for
    /// selective session invalidation on password change.
    pub session_id: Uuid,
    pub claims: ValidatedClaims,
}

impl AuthenticatedUser {
    /// How the authorization engine should read this caller's grants.
    ///
    /// [`SubjectScope::Organization`] only when
    /// [`Self::organization_level`] was set by the tenant lookup in
    /// [`resolve_active_tenant`], so the claim can never be made on the
    /// strength of request input alone.
    pub fn subject_scope(&self) -> SubjectScope {
        if self.organization_level {
            SubjectScope::Organization {
                tenant_id: self.principal_tenant_id,
            }
        } else {
            SubjectScope::Tenant
        }
    }
}

impl actix_web::FromRequest for AuthenticatedUser {
    type Error = AxiamApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        // Synchronous JWT/aud/jti extraction first (ends the `req` borrow before
        // the async block). Clone the optional session validator (an Arc) so the
        // returned future is `'static`.
        let user_result = extract_user(req);
        let validator = req
            .app_data::<web::Data<Arc<dyn SessionValidator>>>()
            .map(|d| d.get_ref().clone());
        let tenants = req
            .app_data::<web::Data<Arc<dyn TenantScopeResolver>>>()
            .map(|d| d.get_ref().clone());
        let reach = req
            .app_data::<web::Data<Arc<dyn PrincipalReachResolver>>>()
            .map(|d| d.get_ref().clone());
        // Read the header here, while `req` is still borrowed. A malformed
        // value is dropped rather than refused: it names a tenant that cannot
        // exist, so the request falls back to the caller's own tenant and is
        // then denied by RBAC like any other over-reach.
        let requested_tenant = req
            .headers()
            .get(ACTIVE_TENANT_HEADER)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| Uuid::parse_str(v.trim()).ok());

        Box::pin(async move {
            let mut user = user_result?;

            // REQ-7 / D-15: reject access tokens whose session has been revoked
            // (row deleted on password change/reset/MFA reset) or expired. The
            // validator is optional so non-session test harnesses are unaffected;
            // the production server (and session-security tests) always register it.
            //
            // Checked against the *principal's* tenant, which is where the
            // session row is. It is the same value as `tenant_id` at this point
            // — the header is applied below — but ordering matters: resolving
            // the active tenant first would look the session up in whichever
            // tenant the request asked to act on, and find none.
            if let Some(validator) = validator
                && !validator
                    .is_session_active(user.principal_tenant_id, user.session_id)
                    .await
            {
                return Err(AxiamError::AuthenticationFailed {
                    reason: "session revoked or expired".into(),
                }
                .into());
            }

            if let Some(target) = requested_tenant.filter(|t| *t != user.principal_tenant_id) {
                user.tenant_id = resolve_active_tenant(&user, target, tenants.as_ref()).await?;
                // ...and, for a principal whose roles name the tenants they
                // reach, that the tenant named is one of them. See
                // [`PrincipalReachResolver`] for why this is a courtesy refusal
                // rather than the enforcement.
                if let Some(reach) = reach
                    && let Some(reach) = reach.reach(user.principal_tenant_id, user.user_id).await
                    && !reach.includes(target)
                {
                    return Err(AxiamError::AuthorizationDenied {
                        reason: "this account's roles do not reach the requested tenant".into(),
                        action: None,
                        resource_id: None,
                    }
                    .into());
                }
                // Reached only when the resolution above confirmed the caller's
                // own tenant is the organization scope — it refuses otherwise.
                user.organization_level = true;
            }

            Ok(user)
        })
    }
}

/// Service-account context extracted from a valid M2M JWT.
///
/// Use this as a handler parameter to require M2M authentication.
/// Accepts only tokens with `aud = axiam:m2m`; user tokens are rejected.
#[derive(Debug, Clone)]
pub struct AuthenticatedServiceAccount {
    /// The token's `sub` claim — the **subject** of the machine token.
    ///
    /// **Its meaning depends on which principal obtained the token**, so do not
    /// treat it as an OAuth2 `client_id` without checking `claims.sub_kind`:
    ///
    /// * `sub_kind = oauth2_client` → the OAuth2 `client_id` (`oa_…`), because
    ///   `issue_client_credentials_token` stamps the client id as `sub`.
    /// * `sub_kind = service_account` → the service-account **UUID**, because a
    ///   service account's grants are resolved by subject id (§16.6). It is
    ///   *not* the `sa_…` client id.
    ///
    /// Named `subject` rather than `client_id` for exactly that reason
    /// (§17.2 residual 7): the old name was accurate for only one of the two
    /// principals and invited the first consumer to treat a UUID as a client
    /// id. No route consumes this extractor today, so the rename is free —
    /// which is why it happens now rather than after something depends on it.
    pub subject: String,
    pub tenant_id: Uuid,
    pub claims: ValidatedClaims,
}

impl actix_web::FromRequest for AuthenticatedServiceAccount {
    type Error = AxiamApiError;
    type Future = std::future::Ready<Result<Self, Self::Error>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        std::future::ready(extract_service_account(req))
    }
}

// ---------------------------------------------------------------------------
// Shared token extraction
// ---------------------------------------------------------------------------

/// Decode and validate the JWT from the request — shared between the
/// extractors. Does not apply audience narrowing.
pub(crate) fn parse_validated_claims(req: &HttpRequest) -> Result<ValidatedClaims, AxiamApiError> {
    let config = req
        .app_data::<web::Data<AuthConfig>>()
        .ok_or(AxiamError::Internal("missing auth config".into()))?;

    // Try cookie first (browser clients), then Authorization header (service clients).
    let token = if let Some(cookie) = req.cookie("axiam_access") {
        cookie.value().to_owned()
    } else {
        // Fall back to the Authorization header for non-browser clients.
        let header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AxiamError::AuthenticationFailed {
                reason: "missing authentication credentials".into(),
            })?;

        // Parse `Authorization` as a case-insensitive scheme with flexible
        // whitespace. `DPoP` joins `Bearer` here (X5.1, RFC 9449 §7.1): a
        // DPoP-bound token arrives under its own scheme, and a guard that only
        // ever splits on `Bearer ` would not find the token at all.
        let header = header.trim();
        let mut parts = header.splitn(2, char::is_whitespace);
        let scheme = parts.next().unwrap_or("");
        let credentials = parts.next().unwrap_or("").trim();

        let known_scheme =
            scheme.eq_ignore_ascii_case("bearer") || axiam_oauth2::dpop::is_dpop_scheme(scheme);
        if !known_scheme || credentials.is_empty() {
            return Err(AxiamError::AuthenticationFailed {
                reason: "invalid Authorization scheme, expected Bearer or DPoP".into(),
            }
            .into());
        }
        credentials.to_owned()
    };

    let validated = validate_access_token(&token, config).map_err(AxiamError::from)?;
    enforce_sender_constraint(req, &token, &validated.0)?;
    Ok(validated)
}

/// Enforce a token's `cnf` sender constraint against what this request actually
/// proved (X5.1; RFC 8705 §3.2 and RFC 9449 §7.1).
///
/// AXIAM's own API is a resource server for its own tokens, so it owes the same
/// obligation the SDK contract's §10.1 rule 9 places on every SDK: **a token
/// carrying `cnf` is not a bearer token, and a `cnf` naming a method this
/// validator cannot check is refused rather than read as unbound.**
///
/// # Ordinary callers are untouched
///
/// A token with no `cnf` — which is every token AXIAM issued before X5.1 and
/// every token it issues to a client that has not asked for binding — returns
/// `Ok` here without any evidence being gathered, and without either header
/// being read. That is the property `an_unbound_token_is_never_asked_for_a_proof`
/// pins, and it is the one this function is most likely to break.
///
/// # The replay caveat, stated rather than hidden
///
/// The proof's signature, `typ`, `alg`, `htm`, `htu`, `iat` freshness, `ath` and
/// `jkt` are all checked. Its `jti` is **not** recorded here, because actix
/// extractors are synchronous and the replay store is not. Within the 60-second
/// freshness window a captured proof for *this exact method and URI*, presented
/// with *the same token*, would therefore be accepted a second time on this
/// path. The token endpoint — which is async and does hold the repository —
/// does record it. This is exactly the limitation §21.7.2's row 8 requires an
/// implementation to document rather than paper over, and closing it means
/// moving this check into middleware that can await.
fn enforce_sender_constraint(
    req: &HttpRequest,
    token: &str,
    claims: &axiam_auth::token::AccessTokenClaims,
) -> Result<(), AxiamApiError> {
    use axiam_auth::token::{PresentedProofs, verify_token_binding};

    // The fast path, and the common one: nothing to enforce, nothing read.
    if claims.cnf.is_none() {
        return Ok(());
    }

    let certificate_thumbprint = req
        .conn_data::<crate::extractors::cert_auth::VerifiedClientCert>()
        .map(|v| axiam_oauth2::mtls::thumbprint_s256(&v.der));

    let dpop_thumbprint = verified_dpop_thumbprint(req, token);

    verify_token_binding(
        claims,
        PresentedProofs {
            certificate_thumbprint: certificate_thumbprint.as_deref(),
            dpop_thumbprint: dpop_thumbprint.as_deref(),
        },
    )
    .map_err(AxiamError::from)?;
    Ok(())
}

/// The `jkt` of a DPoP proof on this request that **verified**, or `None`.
///
/// `None` for "no proof", "malformed proof" and "proof that failed
/// verification" alike, which is the correct collapsing: every one of them means
/// the caller has not proved possession, and
/// [`axiam_auth::token::verify_token_binding`] refuses a `jkt`-bound token for
/// all three. Returning a thumbprint from an unverified proof — the obvious
/// shortcut, since the `jkt` is right there in the header — would turn DPoP
/// into a self-signed permission slip.
fn verified_dpop_thumbprint(req: &HttpRequest, token: &str) -> Option<String> {
    use axiam_oauth2::dpop::{DpopExpectation, verify_dpop_proof};

    let raw = req
        .headers()
        .get("DPoP")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|v| !v.is_empty())?;
    // RFC 9449 §4.3 step 2: more than one proof is a malformed request, not a
    // choice of proofs.
    if req.headers().get_all("DPoP").count() > 1 {
        return None;
    }

    // SEC-102: the authority comes from the configured issuer, never from the
    // request's `Forwarded` / `X-Forwarded-Host` / `Host` headers, which
    // `HttpRequest::full_url()` would prefer in that order and none of which a
    // trusted-proxy layer normalises here. Same reasoning as
    // `handlers::oauth2::dpop_htu`, at the resource-server end of the same
    // comparison: with a request-derived authority the caller chooses both
    // sides of RFC 9449 §4.3 step 9.
    //
    // A deployment with no `AuthConfig` in scope cannot compute the server's
    // own view of its URI, so no proof verifies — the fail-closed direction: a
    // `jkt`-bound token is then refused by `verify_token_binding` rather than
    // accepted against an attacker-chosen `htu`.
    let config = req.app_data::<web::Data<AuthConfig>>()?;
    let htu = format!("{}{}", config.effective_issuer(), req.path());
    let expect = DpopExpectation::at_resource_server(
        req.method().as_str(),
        &htu,
        token,
        chrono::Utc::now().timestamp(),
    );

    match verify_dpop_proof(raw, &expect) {
        Ok(proof) => Some(proof.jkt),
        Err(e) => {
            tracing::debug!(error = %e, "a DPoP proof on a resource request did not verify");
            None
        }
    }
}

// ---------------------------------------------------------------------------
// AuthenticatedUser extractor
// ---------------------------------------------------------------------------

/// Decide whether `target` may be this request's active tenant.
///
/// Two conditions, both required, and both refusals rather than silent
/// fallbacks — a caller that named a tenant it may not act on should be told
/// so, not served a different tenant's data under a header it thinks was
/// honoured.
///
/// 1. The caller must be **organization-level**: its own record lives in the
///    organization's reserved tenant. A tenant user has exactly one tenant it
///    can act on, and a request asking otherwise is asking to be somebody else.
/// 2. `target` must belong to the **caller's own organization**. This is the
///    check that keeps organization scope inside an organization: an
///    organization-level principal's global grants deliberately cross tenant
///    boundaries, so without it they would cross organization boundaries too.
///
/// With no resolver registered — the shape most test harnesses use — the header
/// is refused rather than trusted. Failing closed is the only safe default for
/// a check whose entire job is to say no.
async fn resolve_active_tenant(
    user: &AuthenticatedUser,
    target: Uuid,
    tenants: Option<&Arc<dyn TenantScopeResolver>>,
) -> Result<Uuid, AxiamApiError> {
    let deny = |reason: &str| -> AxiamApiError {
        AxiamError::AuthorizationDenied {
            reason: reason.to_string(),
            action: None,
            resource_id: None,
        }
        .into()
    };

    let Some(tenants) = tenants else {
        return Err(deny(
            "cannot verify the requested tenant: no tenant resolver is configured",
        ));
    };

    let Some(home) = tenants.resolve(user.principal_tenant_id).await else {
        return Err(deny("the caller's own tenant could not be resolved"));
    };
    if !home.is_organization {
        return Err(deny(
            "only organization-level principals may act on another tenant",
        ));
    }

    let Some(scope) = tenants.resolve(target).await else {
        return Err(deny("the requested tenant does not exist"));
    };
    // Compare against the *home tenant's* organization rather than the token's
    // `org_id` claim: both should agree, and if they ever do not, the one
    // backed by a row the caller cannot edit is the one to trust.
    if scope.organization_id != home.organization_id {
        return Err(deny(
            "the requested tenant belongs to a different organization",
        ));
    }

    Ok(target)
}

fn extract_user(req: &HttpRequest) -> Result<AuthenticatedUser, AxiamApiError> {
    // Try to reuse claims cached by the audit middleware.
    if let Some(cached) = req.extensions().get::<Arc<CachedUserIdentity>>() {
        let config = req
            .app_data::<web::Data<AuthConfig>>()
            .ok_or(AxiamError::Internal("missing auth config".into()))?;

        let session_id = check_user_aud_and_parse_jti(&cached.claims, config)?;
        return Ok(AuthenticatedUser {
            user_id: cached.user_id,
            tenant_id: cached.tenant_id,
            // The token's tenant is the home tenant until the header
            // resolution in `from_request` says otherwise.
            principal_tenant_id: cached.tenant_id,
            organization_level: false,
            org_id: cached.org_id,
            session_id,
            claims: cached.claims.clone(),
        });
    }

    let config = req
        .app_data::<web::Data<AuthConfig>>()
        .ok_or(AxiamError::Internal("missing auth config".into()))?;

    let validated = parse_validated_claims(req)?;

    let session_id = check_user_aud_and_parse_jti(&validated, config)?;

    let user_id =
        Uuid::parse_str(&validated.0.sub).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid sub claim".into(),
        })?;

    let tenant_id =
        Uuid::parse_str(&validated.0.tenant_id).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid tenant_id claim".into(),
        })?;

    let org_id =
        Uuid::parse_str(&validated.0.org_id).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid org_id claim".into(),
        })?;

    Ok(AuthenticatedUser {
        user_id,
        tenant_id,
        principal_tenant_id: tenant_id,
        organization_level: false,
        org_id,
        session_id,
        claims: validated,
    })
}

/// Enforce the audience narrowing policy for user-facing routes and
/// parse the `jti` claim as a `Uuid` (= session ID).
///
/// Audience rules (D-19, D-21):
/// - `aud = axiam:user` → accepted.
/// - `aud` absent AND `allow_missing_aud_as_user = true` → accepted; a
///   `WARN` is emitted on every such request. No in-process rate limiting is
///   applied here — operator-side log deduplication (Loki, fluent-bit, etc.)
///   handles burst noise, keeping this hot path allocation-free and
///   lock-free.
/// - `aud` absent AND `allow_missing_aud_as_user = false` → 401.
/// - `aud = axiam:m2m` → 401 (audience mismatch — wrong token type for
///   this route).
/// - Any other `aud` value → 401 (unknown audience).
fn check_user_aud_and_parse_jti(
    validated: &ValidatedClaims,
    config: &AuthConfig,
) -> Result<Uuid, AxiamApiError> {
    match validated.0.aud.as_deref() {
        Some(AUD_USER) => {
            // Expected audience — accept.
        }
        None => {
            if config.allow_missing_aud_as_user {
                // Back-compat window: treat as axiam:user, but warn unconditionally.
                // TRADE-OFF: no in-process rate limit on this warn. Operator-side
                // log filtering (e.g. Loki `rate()` alert, fluent-bit rewrite_tag
                // dedup) is the intended mechanism for suppressing burst noise
                // during the rollout window. Keeping this path lock-free is
                // intentional — auth hot paths must not contend on shared atomics.
                let jti = &validated.0.jti;
                tracing::warn!(
                    token_jti = %jti,
                    "accepted access token without aud — backward-compat window active"
                );
            } else {
                return Err(AxiamError::AuthenticationFailed {
                    reason: "aud required".into(),
                }
                .into());
            }
        }
        Some(AUD_M2M) => {
            return Err(AxiamError::AuthenticationFailed {
                reason: "audience mismatch — this route requires axiam:user audience".into(),
            }
            .into());
        }
        Some(_) => {
            return Err(AxiamError::AuthenticationFailed {
                reason: "unknown audience".into(),
            }
            .into());
        }
    }

    Uuid::parse_str(&validated.0.jti).map_err(|_| {
        AxiamError::AuthenticationFailed {
            reason: "invalid jti".into(),
        }
        .into()
    })
}

// ---------------------------------------------------------------------------
// AuthenticatedServiceAccount extractor
// ---------------------------------------------------------------------------

fn extract_service_account(
    req: &HttpRequest,
) -> Result<AuthenticatedServiceAccount, AxiamApiError> {
    let validated = parse_validated_claims(req)?;

    match validated.0.aud.as_deref() {
        Some(AUD_M2M) => {
            // Expected audience — accept.
        }
        Some(AUD_USER) => {
            return Err(AxiamError::AuthenticationFailed {
                reason: "audience mismatch — this route requires axiam:m2m audience".into(),
            }
            .into());
        }
        Some(_) | None => {
            return Err(AxiamError::AuthenticationFailed {
                reason: "audience mismatch — this route requires axiam:m2m audience".into(),
            }
            .into());
        }
    }

    let tenant_id =
        Uuid::parse_str(&validated.0.tenant_id).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid tenant_id claim".into(),
        })?;

    Ok(AuthenticatedServiceAccount {
        subject: validated.0.sub.clone(),
        tenant_id,
        claims: validated,
    })
}

// ---------------------------------------------------------------------------
// AuthenticatedPrincipal extractor — accepts either audience
// ---------------------------------------------------------------------------

/// An authenticated caller that may be **either** a human user
/// (`aud = axiam:user`) or a machine (`aud = axiam:m2m`).
///
/// This exists so the mTLS device path can carry the machine audience
/// (§17.2 residual 1) without losing the endpoints a device legitimately
/// needs. Before it, `axiam:m2m` reached **no** REST route at all — every
/// guarded handler takes [`AuthenticatedUser`], which rejects that audience —
/// so moving device tokens to `axiam:m2m` on its own would have replaced a
/// too-wide grant with no grant, which is an outage rather than a narrowing.
///
/// **What this deliberately is not:** a general-purpose relaxation. It is used
/// only on the authorization-check endpoints, which are the machine-facing
/// read-only surface. Every other route keeps [`AuthenticatedUser`] and so
/// keeps rejecting machine tokens outright. Widening its use is a security
/// decision, not a convenience one.
///
/// Two properties worth stating because they are easy to lose:
///
/// * **User tokens are not weakened.** A `axiam:user` token extracted this way
///   still goes through the same session-revocation check
///   [`AuthenticatedUser`] applies, so a revoked session cannot reach these
///   endpoints through the wider extractor. That check is skipped only for
///   machine tokens, which have no session row to check by construction.
/// * **`aud` must be present.** The `allow_missing_aud_as_user` back-compat
///   window is honoured for the user branch only, exactly as on the narrow
///   extractor — an absent `aud` is never silently treated as a machine.
#[derive(Debug, Clone)]
pub struct AuthenticatedPrincipal {
    /// The subject the authorization engine should evaluate: the user id for a
    /// user token, the service-account id for a machine token. Both are the
    /// token's `sub`, and both are what role assignments are keyed on.
    pub subject_id: Uuid,
    pub tenant_id: Uuid,
    pub org_id: Uuid,
    /// `true` when the caller authenticated as a machine (`aud = axiam:m2m`).
    /// Handlers use this for audit attribution, not for authorization — RBAC
    /// is applied identically to both kinds.
    pub is_machine: bool,
    pub claims: ValidatedClaims,
}

impl AuthenticatedPrincipal {
    /// Audit actor type matching how this principal authenticated.
    pub fn actor_type(&self) -> axiam_core::models::audit::ActorType {
        if self.is_machine {
            axiam_core::models::audit::ActorType::ServiceAccount
        } else {
            axiam_core::models::audit::ActorType::User
        }
    }
}

fn extract_principal(req: &HttpRequest) -> Result<AuthenticatedPrincipal, AxiamApiError> {
    let config = req
        .app_data::<web::Data<AuthConfig>>()
        .ok_or(AxiamError::Internal("missing auth config".into()))?;

    let validated = match req.extensions().get::<Arc<CachedUserIdentity>>() {
        Some(cached) => cached.claims.clone(),
        None => parse_validated_claims(req)?,
    };

    // Machine tokens take the m2m branch; everything else (including the
    // absent-`aud` back-compat window) is decided by the *same* function the
    // narrow user extractor uses, so the two cannot drift apart.
    let is_machine = validated.0.aud.as_deref() == Some(AUD_M2M);
    if !is_machine {
        check_user_aud_and_parse_jti(&validated, config)?;
    }

    // `sub` must be a UUID, which quietly makes this extractor reject one of
    // the two machine principal kinds — an asymmetry worth stating rather than
    // leaving to be rediscovered.
    //
    // A *service account*'s `sub` is its UUID, so it parses. An *OAuth2
    // client*'s `sub` is its `oa_…` client id, so it does not, and such a
    // caller gets 401 here even though its token carries `axiam:m2m` and is
    // accepted elsewhere.
    //
    // That is the correct outcome, not a gap to close: role assignments are
    // keyed on a subject UUID, and an OAuth2 client has no row in that graph.
    // Admitting one would produce a principal the authorization engine can
    // only ever evaluate to "no grants" — a caller that authenticates and then
    // fails every check, which is a worse experience than a clean 401 and
    // invites someone to "fix" it later by inventing a subject mapping. If
    // OAuth2 clients ever need to be RBAC subjects, that is a deliberate
    // modelling change, and this parse is where it would start.
    let subject_id =
        Uuid::parse_str(&validated.0.sub).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid sub claim".into(),
        })?;
    let tenant_id =
        Uuid::parse_str(&validated.0.tenant_id).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid tenant_id claim".into(),
        })?;
    let org_id =
        Uuid::parse_str(&validated.0.org_id).map_err(|_| AxiamError::AuthenticationFailed {
            reason: "invalid org_id claim".into(),
        })?;

    Ok(AuthenticatedPrincipal {
        subject_id,
        tenant_id,
        org_id,
        is_machine,
        claims: validated,
    })
}

impl actix_web::FromRequest for AuthenticatedPrincipal {
    type Error = AxiamApiError;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let principal_result = extract_principal(req);
        let validator = req
            .app_data::<web::Data<Arc<dyn SessionValidator>>>()
            .map(|d| d.get_ref().clone());

        Box::pin(async move {
            let principal = principal_result?;

            // A user token reaching these endpoints must satisfy exactly the
            // same session-revocation rule it would on any other route
            // (REQ-7 / D-15). Skipping it for machines is not a relaxation:
            // a machine token has no session row, so there is nothing to
            // revoke — revocation for machines is disabling the account,
            // which the token-issuing path checks.
            if !principal.is_machine
                && let Some(validator) = validator
            {
                let session_id = Uuid::parse_str(&principal.claims.0.jti).map_err(|_| {
                    AxiamError::AuthenticationFailed {
                        reason: "invalid jti".into(),
                    }
                })?;
                if !validator
                    .is_session_active(principal.tenant_id, session_id)
                    .await
                {
                    return Err(AxiamError::AuthenticationFailed {
                        reason: "session revoked or expired".into(),
                    }
                    .into());
                }
            }
            Ok(principal)
        })
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::test::TestRequest;
    use axiam_auth::token::{issue_access_token, issue_client_credentials_token};
    use uuid::Uuid;

    fn test_auth_config() -> AuthConfig {
        let private_key = "\
-----BEGIN PRIVATE KEY-----\n\
MC4CAQAwBQYDK2VwBCIEINvQFIZqeI5OX7TDEFKcYhLxO5R75FOv/nC4+o+HHPfM\n\
-----END PRIVATE KEY-----";
        let public_key = "\
-----BEGIN PUBLIC KEY-----\n\
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=\n\
-----END PUBLIC KEY-----";
        AuthConfig {
            jwt_private_key_pem: private_key.into(),
            jwt_public_key_pem: public_key.into(),
            access_token_lifetime_secs: 900,
            refresh_token_lifetime_secs: 2_592_000,
            jwt_issuer: "axiam-test".into(),
            pepper: None,
            pepper_previous: None,
            min_password_length: 12,
            mfa_encryption_key: None,
            opaque_session_key: None,
            opaque_setup_key: None,
            federation_encryption_key: None,
            allow_missing_aud_as_user: true,
            cookie_secure: true,
            mfa_challenge_lifetime_secs: 300,
            totp_issuer: "AXIAM-Test".into(),
            max_failed_login_attempts: 5,
            lockout_duration_secs: 300,
            lockout_backoff_multiplier: 2.0,
            max_lockout_duration_secs: 3600,
            auth_code_lifetime_secs: 600,
            oauth2_issuer_url: String::new(),
            sso_spa_origins: Vec::new(),
            email_verification_grace_period_hours: 24,
            password_reset_token_expiry_hours: 1,
            webauthn_rp_id: "localhost".into(),
            webauthn_rp_origin: "http://localhost:8090".into(),
            webauthn_rp_name: "AXIAM-Test".into(),
            jwt_encoding_key: None,
            jwt_decoding_key: None,
            hibp_breaker_threshold: 5,
            hibp_breaker_cooldown_secs: 30,
            max_concurrent_hashes: 0,
            hash_acquire_timeout_secs: 5,
            session_validation_cache_ttl_secs: 0,
        }
    }

    fn make_user_token(config: &AuthConfig, jti: Option<String>) -> String {
        let jti = jti.unwrap_or_else(|| Uuid::new_v4().to_string());
        issue_access_token(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            &[],
            config,
            jti,
            AUD_USER,
        )
        .unwrap()
    }

    fn make_m2m_token(config: &AuthConfig) -> String {
        issue_client_credentials_token("my-service", Uuid::new_v4(), Uuid::new_v4(), &[], config)
            .unwrap()
    }

    fn make_no_aud_token(config: &AuthConfig) -> String {
        // Manually craft via issue_access_token then patch — actually simpler to
        // issue a user token and strip aud. We don't have that API, so instead
        // we use the fact that decode_access_token does not require aud.
        // The simplest approach: issue with AUD_USER but override aud to None
        // by constructing claims manually.
        use axiam_auth::token::{AccessTokenClaims, SubjectKind};
        use chrono::Utc;
        use jsonwebtoken::{Algorithm, EncodingKey, Header};

        let now = Utc::now().timestamp();
        let claims = AccessTokenClaims {
            sub: Uuid::new_v4().to_string(),
            tenant_id: Uuid::new_v4().to_string(),
            org_id: Uuid::new_v4().to_string(),
            iss: "axiam-test".into(),
            iat: now,
            exp: now + 900,
            jti: Uuid::new_v4().to_string(),
            aud: None, // no audience
            scope: None,
            sub_kind: SubjectKind::User,
            act: None,
            permissions: None,
            ext_exchange: None,
            cnf: None,
            ext: None,
        };
        let key = EncodingKey::from_ed_pem(config.jwt_private_key_pem.as_bytes()).unwrap();
        let header = Header::new(Algorithm::EdDSA);
        jsonwebtoken::encode(&header, &claims, &key).unwrap()
    }

    fn req_with_config_and_bearer(config: AuthConfig, token: &str) -> actix_web::HttpRequest {
        TestRequest::default()
            .app_data(web::Data::new(config))
            .insert_header(("Authorization", format!("Bearer {token}")))
            .to_http_request()
    }

    // -----------------------------------------------------------------------
    // AuthenticatedUser tests
    // -----------------------------------------------------------------------

    #[test]
    fn accepts_axiam_user_audience() {
        let config = test_auth_config();
        let token = make_user_token(&config, None);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_user(&req);
        assert!(result.is_ok(), "expected Ok, got: {result:?}");
    }

    #[test]
    fn accepts_missing_aud_when_flag_true() {
        let mut config = test_auth_config();
        config.allow_missing_aud_as_user = true;
        let token = make_no_aud_token(&config);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_user(&req);
        assert!(
            result.is_ok(),
            "expected Ok with flag=true, got: {result:?}"
        );
    }

    #[test]
    fn rejects_missing_aud_when_flag_false() {
        let mut config = test_auth_config();
        config.allow_missing_aud_as_user = false;
        let token = make_no_aud_token(&config);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_user(&req);
        assert!(result.is_err(), "expected 401, got Ok when flag=false");
    }

    #[test]
    fn rejects_axiam_m2m_audience_on_user_route() {
        let config = test_auth_config();
        let token = make_m2m_token(&config);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_user(&req);
        assert!(
            result.is_err(),
            "expected rejection of m2m token on user route"
        );
    }

    #[test]
    fn session_id_matches_jti() {
        let config = test_auth_config();
        let jti = "11111111-1111-1111-1111-111111111111".to_string();
        let token = make_user_token(&config, Some(jti.clone()));
        let req = req_with_config_and_bearer(config, &token);
        let user = extract_user(&req).expect("should succeed");
        assert_eq!(user.session_id.to_string(), jti);
    }

    // -----------------------------------------------------------------------
    // AuthenticatedServiceAccount tests
    // -----------------------------------------------------------------------

    #[test]
    fn service_account_extractor_accepts_m2m() {
        let config = test_auth_config();
        let token = make_m2m_token(&config);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_service_account(&req);
        assert!(result.is_ok(), "expected Ok for m2m token, got: {result:?}");
    }

    #[test]
    fn service_account_extractor_rejects_user_token() {
        let config = test_auth_config();
        let token = make_user_token(&config, None);
        let req = req_with_config_and_bearer(config, &token);
        let result = extract_service_account(&req);
        assert!(
            result.is_err(),
            "expected rejection of user token on m2m route"
        );
    }

    // -----------------------------------------------------------------------
    // Audience-narrowing regression guard
    // (security-analysis-2026-08-02 §4 item 3 / backend residual §4.3)
    // -----------------------------------------------------------------------

    /// `axiam_auth::token::decode_access_token` deliberately accepts BOTH
    /// `axiam:user` and `axiam:m2m` (`token.rs`: `validation.set_audience(&[
    /// AUD_USER, AUD_M2M])`), deferring per-route audience separation to
    /// these extractors. That is only safe while the extractors really do
    /// narrow, so this test asserts the whole contract end to end in one
    /// place: **permissive at the token layer, strict at the route layer, in
    /// both directions.**
    ///
    /// If someone ever "simplifies" `check_user_aud_and_parse_jti` or
    /// `AuthenticatedServiceAccount`'s audience check away, the token layer's
    /// permissiveness silently becomes a cross-audience token-confusion bug
    /// (an M2M client-credentials token would be accepted as a user session,
    /// and vice-versa). This test is what stops that.
    #[test]
    fn token_layer_accepts_both_audiences_but_routes_narrow_in_both_directions() {
        let config = test_auth_config();
        let user_token = make_user_token(&config, None);
        let m2m_token = make_m2m_token(&config);

        // 1. The token layer is deliberately permissive: both audiences
        //    decode successfully, with the audience preserved in the claims.
        let decoded_user = axiam_auth::token::decode_access_token(&user_token, &config)
            .expect("a user token must decode at the token layer");
        let decoded_m2m = axiam_auth::token::decode_access_token(&m2m_token, &config)
            .expect("an m2m token must ALSO decode at the token layer (D-20/SEC-006)");
        assert_eq!(decoded_user.aud.as_deref(), Some(AUD_USER));
        assert_eq!(decoded_m2m.aud.as_deref(), Some(AUD_M2M));

        // 2. A user route accepts ONLY axiam:user.
        assert!(
            extract_user(&req_with_config_and_bearer(config.clone(), &user_token)).is_ok(),
            "axiam:user must be accepted on a user route"
        );
        assert!(
            extract_user(&req_with_config_and_bearer(config.clone(), &m2m_token)).is_err(),
            "axiam:m2m must be REJECTED on a user route — the token layer accepts it, so \
             this extractor is the only thing enforcing the separation"
        );

        // 3. An m2m route accepts ONLY axiam:m2m.
        assert!(
            extract_service_account(&req_with_config_and_bearer(config.clone(), &m2m_token))
                .is_ok(),
            "axiam:m2m must be accepted on an m2m route"
        );
        assert!(
            extract_service_account(&req_with_config_and_bearer(config, &user_token)).is_err(),
            "axiam:user must be REJECTED on an m2m route"
        );
    }

    /// The `allow_missing_aud_as_user` back-compat window must NOT leak into
    /// the m2m route: an `aud`-less legacy token is a *user* token by
    /// definition, never a service account, whatever the flag says.
    #[test]
    fn missing_aud_is_never_accepted_on_an_m2m_route() {
        for allow_missing in [true, false] {
            let mut config = test_auth_config();
            config.allow_missing_aud_as_user = allow_missing;
            let token = make_no_aud_token(&config);
            let req = req_with_config_and_bearer(config, &token);
            assert!(
                extract_service_account(&req).is_err(),
                "a token with no aud must be rejected on an m2m route \
                 (allow_missing_aud_as_user={allow_missing})"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Active-tenant resolution (organization scope)
    // -----------------------------------------------------------------------

    /// A resolver backed by a fixed table, so these tests exercise
    /// [`resolve_active_tenant`]'s decision rather than a database.
    struct FakeTenants(Vec<(Uuid, TenantScope)>);

    impl TenantScopeResolver for FakeTenants {
        fn resolve<'a>(
            &'a self,
            tenant_id: Uuid,
        ) -> Pin<Box<dyn Future<Output = Option<TenantScope>> + Send + 'a>> {
            let found = self
                .0
                .iter()
                .find(|(id, _)| *id == tenant_id)
                .map(|(_, scope)| *scope);
            Box::pin(async move { found })
        }
    }

    fn caller_in(tenant_id: Uuid, org_id: Uuid) -> AuthenticatedUser {
        use axiam_auth::token::{AccessTokenClaims, SubjectKind, ValidatedClaims};
        use chrono::Utc;

        let user_id = Uuid::new_v4();
        let now = Utc::now().timestamp();
        // `resolve_active_tenant` reads none of these — it decides from
        // `principal_tenant_id` and the resolver alone — but `AuthenticatedUser`
        // carries the claims it was built from, so they have to be real.
        let claims = ValidatedClaims(AccessTokenClaims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            org_id: org_id.to_string(),
            iss: "axiam-test".into(),
            iat: now,
            exp: now + 900,
            jti: Uuid::new_v4().to_string(),
            aud: Some("axiam:user".into()),
            scope: None,
            sub_kind: SubjectKind::User,
            act: None,
            permissions: None,
            ext_exchange: None,
            cnf: None,
            ext: None,
        });
        AuthenticatedUser {
            user_id,
            tenant_id,
            principal_tenant_id: tenant_id,
            organization_level: false,
            org_id,
            session_id: Uuid::new_v4(),
            claims,
        }
    }

    /// The whole point of the header: an organization-level principal names a
    /// tenant in its own organization and gets it.
    #[actix_rt::test]
    async fn an_organization_principal_may_act_on_a_tenant_of_its_organization() {
        let org = Uuid::new_v4();
        let org_scope = Uuid::new_v4();
        let tenant = Uuid::new_v4();
        let tenants = Arc::new(FakeTenants(vec![
            (
                org_scope,
                TenantScope {
                    organization_id: org,
                    is_organization: true,
                },
            ),
            (
                tenant,
                TenantScope {
                    organization_id: org,
                    is_organization: false,
                },
            ),
        ])) as Arc<dyn TenantScopeResolver>;

        let user = caller_in(org_scope, org);
        let resolved = resolve_active_tenant(&user, tenant, Some(&tenants))
            .await
            .expect("an organization principal may act on its own organization's tenant");
        assert_eq!(resolved, tenant);
    }

    /// A tenant principal has exactly one tenant. Asking for another is asking
    /// to be somebody else, and is refused rather than silently ignored.
    #[actix_rt::test]
    async fn a_tenant_principal_may_not_act_on_another_tenant() {
        let org = Uuid::new_v4();
        let home = Uuid::new_v4();
        let other = Uuid::new_v4();
        let tenants = Arc::new(FakeTenants(vec![
            (
                home,
                TenantScope {
                    organization_id: org,
                    is_organization: false,
                },
            ),
            (
                other,
                TenantScope {
                    organization_id: org,
                    is_organization: false,
                },
            ),
        ])) as Arc<dyn TenantScopeResolver>;

        let user = caller_in(home, org);
        assert!(
            resolve_active_tenant(&user, other, Some(&tenants))
                .await
                .is_err(),
            "a tenant principal must not reach another tenant through the header"
        );
    }

    /// Organization scope stays inside an organization. This is the check that
    /// keeps global grants — which deliberately cross tenant boundaries — from
    /// crossing organization boundaries too.
    #[actix_rt::test]
    async fn organization_scope_does_not_cross_organizations() {
        let mine = Uuid::new_v4();
        let theirs = Uuid::new_v4();
        let org_scope = Uuid::new_v4();
        let foreign_tenant = Uuid::new_v4();
        let tenants = Arc::new(FakeTenants(vec![
            (
                org_scope,
                TenantScope {
                    organization_id: mine,
                    is_organization: true,
                },
            ),
            (
                foreign_tenant,
                TenantScope {
                    organization_id: theirs,
                    is_organization: false,
                },
            ),
        ])) as Arc<dyn TenantScopeResolver>;

        let user = caller_in(org_scope, mine);
        assert!(
            resolve_active_tenant(&user, foreign_tenant, Some(&tenants))
                .await
                .is_err(),
            "an organization principal must not reach another organization's tenant"
        );
    }

    /// Failing closed with no resolver registered is what makes the header
    /// safe to add to the extractor at all: a deployment that forgot to wire
    /// one refuses every switch rather than trusting the request.
    #[actix_rt::test]
    async fn without_a_resolver_the_header_is_refused() {
        let user = caller_in(Uuid::new_v4(), Uuid::new_v4());
        assert!(
            resolve_active_tenant(&user, Uuid::new_v4(), None)
                .await
                .is_err(),
            "with no resolver the header must be refused, never trusted"
        );
    }

    /// A header naming a tenant that does not exist is refused too — not
    /// quietly downgraded to the caller's own tenant, which would serve one
    /// tenant's data under a header the caller believes was honoured.
    #[actix_rt::test]
    async fn an_unknown_tenant_is_refused() {
        let org = Uuid::new_v4();
        let org_scope = Uuid::new_v4();
        let tenants = Arc::new(FakeTenants(vec![(
            org_scope,
            TenantScope {
                organization_id: org,
                is_organization: true,
            },
        )])) as Arc<dyn TenantScopeResolver>;

        let user = caller_in(org_scope, org);
        assert!(
            resolve_active_tenant(&user, Uuid::new_v4(), Some(&tenants))
                .await
                .is_err(),
            "a tenant that does not exist must be refused"
        );
    }
}

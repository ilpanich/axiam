//! OAuth2 Token Exchange (RFC 8693) — B3.
//!
//! Design and rationale: `claude_dev/token-exchange-design.md`. The short
//! version, because it governs every function below:
//!
//! > **An exchange may only ever narrow.** There is no input, no
//! > configuration and no client grant that causes the issued token to permit
//! > something the subject token did not already permit.
//!
//! Each check here is that rule restated for one dimension — scopes,
//! audience, lifetime, actor identity — and each has a test named after the
//! thing it stops.
//!
//! Like the device grant, this is a **separate service** rather than another
//! arm of [`crate::token::TokenService`]: it needs different collaborators,
//! and the REST layer keeps the seam at one `match` on `grant_type`.

use std::future::Future;
use std::pin::Pin;

use axiam_auth::config::AuthConfig;
use axiam_auth::token::{
    AUD_M2M, AUD_USER, ActClaim, ExtExchangeClaim, MAX_ACT_CHAIN_DEPTH, SubjectKind,
    decode_access_token, issue_exchanged_token, unverified_issuer_of,
};
use axiam_core::models::oauth2_client::OAuth2Client;
use axiam_core::repository::TenantRepository;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::OAuth2Error;

/// The grant type this service handles.
pub const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The subject/actor token type for an AXIAM-issued access token.
///
/// Since X4 this is no longer the *only* admissible subject token type — see
/// [`TOKEN_TYPE_JWT`] — but it remains the only type an exchange **issues**,
/// and the only type an `actor_token` may be.
pub const TOKEN_TYPE_ACCESS_TOKEN: &str = "urn:ietf:params:oauth:token-type:access_token";

/// RFC 8693 §3 generic JWT subject-token type (X4).
///
/// Accepted only on the external path: a caller presenting a partner's token
/// rarely knows whether that IdP would call it an "access token" in AXIAM's
/// sense, and RFC 8693 provides this type for exactly that case. The token is
/// still shape-checked — an ID token labelled `…:jwt` is refused just as
/// firmly as one labelled `…:id_token`.
pub const TOKEN_TYPE_JWT: &str = "urn:ietf:params:oauth:token-type:jwt";

/// Token types a caller sometimes reaches for and never gets (X4).
///
/// Named individually rather than lumped into "unsupported" because a caller
/// who sent one has made a *specific* mistake, and "unsupported
/// subject_token_type" sends them looking for a config switch that does not
/// exist. Refusing these is a security property, not a gap: a refresh token is
/// a re-authentication credential and an ID token is an assertion to a client
/// about a login — neither is a bearer credential for an API, and both are
/// treated as lower-risk artefacts by the IdPs that issue them.
pub const TOKEN_TYPE_REFRESH_TOKEN: &str = "urn:ietf:params:oauth:token-type:refresh_token";
pub const TOKEN_TYPE_ID_TOKEN: &str = "urn:ietf:params:oauth:token-type:id_token";

/// Grant-list entry that permits impersonation.
///
/// Encoded as a grant-type entry rather than a new column: the client
/// registration already carries a list of what a client may do, adding to it
/// needs no migration, and an operator reading `grant_types` sees this
/// capability in the same place as every other one.
pub const MAY_IMPERSONATE_GRANT: &str = "urn:axiam:params:oauth:grant-type:may-impersonate";

/// `POST /oauth2/token` with `grant_type=…:token-exchange` (RFC 8693 §2.1).
#[derive(Debug, Clone, Deserialize, utoipa::ToSchema)]
pub struct TokenExchangeRequest {
    pub subject_token: String,
    pub subject_token_type: String,
    /// RFC 8693 §2.1. Optional, and the AS picks the default — but a client
    /// that *names* a type it does not get must be told, not handed an
    /// access token and left to discover the difference. v1 issues access
    /// tokens only, so any other explicit value is refused.
    pub requested_token_type: Option<String>,
    /// Presence of an actor token selects **delegation**; absence selects
    /// **impersonation**, which is off unless the client is granted it.
    pub actor_token: Option<String>,
    pub actor_token_type: Option<String>,
    /// Space-separated. Absent means "the subject's own scopes".
    pub scope: Option<String>,
    /// Target audience for the issued token. **The allow-list is the
    /// client's `redirect_uris`** (SEC-089): a target is accepted if it
    /// appears in the client's registered redirect URIs, or is one of
    /// AXIAM's own built-in audiences. There is no separate audience field
    /// in v1 — adding a redirect URI to a client also authorises it as a
    /// token audience for that client. This allow-list is checked at two
    /// call sites in this file (same-domain exchange, and the X4 external
    /// exchange) — both are tagged `SEC-089` and must be touched together
    /// (and together with this comment) if a future dedicated
    /// `allowed_token_targets` field replaces this reuse. Full write-up in
    /// `docs/api/token-exchange.md#audience`.
    pub audience: Option<String>,
    /// RFC 8707. Treated as a synonym of `audience`; if both are given they
    /// must agree, because silently preferring one would make the request
    /// mean something the caller did not write.
    pub resource: Option<String>,
}

/// RFC 8693 §2.2.1 response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TokenExchangeResponse {
    pub access_token: String,
    /// Mandatory per §2.2.1, and not decoration: a client that asked for one
    /// token type and got another must be able to tell.
    pub issued_token_type: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

// ---------------------------------------------------------------------------
// X4 ports
// ---------------------------------------------------------------------------

/// What verifying an external IdP's subject token established.
///
/// Mirrors `axiam_federation::token_exchange::ExternalSubject` without
/// importing it — `axiam-oauth2` does not depend on `axiam-federation`, and
/// `axiam-api-rest` is the composition root that owns both. Same seam UMA's
/// [`crate::uma::PermissionEvaluator`] uses, for the same reason.
#[derive(Debug, Clone)]
pub struct ResolvedExternalSubject {
    /// The foreign issuer, verbatim. Stamped into the issued token.
    pub issuer: String,
    pub provider_id: Uuid,
    pub provider_name: String,
    /// The partner-local `sub`. Audit only.
    pub external_subject: String,
    pub user_id: Uuid,
    pub newly_provisioned: bool,
    /// AXIAM scope names the provider's `scope_map` produced.
    ///
    /// A **candidate** set and nothing more. Names in here have been agreed by
    /// an AXIAM admin as things this provider's assertions *may* map onto —
    /// not as things this user holds. The client registration and the RBAC
    /// engine still have to agree, below.
    pub candidate_scopes: Vec<String>,
    /// The external token's `exp`, so the issued token cannot outlive it.
    pub subject_exp: i64,
    pub max_lifetime_secs: Option<i64>,
}

/// Why an external subject token was refused, in the shape this crate answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalSubjectRejection {
    /// No trusted, exchange-enabled provider claims the token's issuer.
    IssuerNotTrusted,
    /// Anything else about the token. The payload is for the audit record.
    Rejected(String),
    Server(String),
}

impl ExternalSubjectRejection {
    /// Stable label for the audit record and metrics.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::IssuerNotTrusted => "issuer_not_trusted",
            Self::Rejected(_) => "token_rejected",
            Self::Server(_) => "server_error",
        }
    }
}

/// Resolves an external IdP's token to an AXIAM subject (X4).
pub trait ExternalSubjectResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_token: &'a str,
    ) -> Pin<
        Box<
            dyn Future<Output = Result<ResolvedExternalSubject, ExternalSubjectRejection>>
                + Send
                + 'a,
        >,
    >;
}

/// Answers "which of these scope names does this subject actually hold" (X4).
///
/// The port exists because a partner's token proves *authentication* and
/// nothing else: what the resolved user may do is a question only the RBAC
/// engine can answer, and `axiam-oauth2` cannot see the engine. Implemented in
/// the composition root over `axiam-authz`.
///
/// The contract is one-directional and that is the whole point: an
/// implementation may return **fewer** names than it was given, never more and
/// never different ones. A caller treats the result as a filter, not as a
/// source of scopes.
pub trait SubjectScopeAuthority: Send + Sync {
    fn held_scopes<'a>(
        &'a self,
        tenant_id: Uuid,
        subject_id: Uuid,
        candidates: &'a [String],
    ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>;
}

/// What an exchange did, for the audit record.
///
/// Impersonation is the reason this type exists. A delegated token carries an
/// `act` claim naming who acted; an impersonated one deliberately does not, so
/// the audit entry is the *only* surviving evidence that the acting party was
/// not the subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExchangeKind {
    Delegation,
    Impersonation,
    /// X4 — the subject token came from a trusted external IdP.
    ///
    /// A third kind rather than a flavour of impersonation, even though the
    /// issued token also carries no `act` claim. The distinction is what the
    /// acting party's authority rests on: an impersonating client asserts on
    /// *its own* authority that it may be the user, while an external exchange
    /// presents a trusted IdP's signed assertion that the user authenticated,
    /// addressed to us. Different evidence, different gate (the per-provider
    /// trust block, not `may_impersonate`), and an audit reader must be able
    /// to tell them apart at a glance.
    External,
}

impl ExchangeKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Delegation => "delegation",
            Self::Impersonation => "impersonation",
            Self::External => "external",
        }
    }
}

/// Provenance of an [`ExchangeKind::External`] exchange, for the audit record.
#[derive(Debug, Clone)]
pub struct ExternalProvenance {
    pub issuer: String,
    pub provider_id: Uuid,
    pub provider_name: String,
    pub external_subject: String,
    pub newly_provisioned: bool,
}

/// The outcome the caller audits and returns.
///
/// `Debug` is hand-written rather than derived: it would otherwise print the
/// freshly-minted access token into whatever log line touched it, which is the
/// one thing in this struct that must never be logged. Same reasoning, and the
/// same `[REDACTED]` marker, as `FederationConfig`'s secret columns.
pub struct ExchangeOutcome {
    pub response: TokenExchangeResponse,
    pub kind: ExchangeKind,
    pub subject: String,
    pub actor: Option<String>,
    pub granted_scopes: Vec<String>,
    pub audience: String,
    /// Present exactly when `kind == External` (X4).
    pub external: Option<ExternalProvenance>,
}

impl std::fmt::Debug for ExchangeOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExchangeOutcome")
            .field("access_token", &"[REDACTED]")
            .field("issued_token_type", &self.response.issued_token_type)
            .field("expires_in", &self.response.expires_in)
            .field("kind", &self.kind)
            .field("subject", &self.subject)
            .field("actor", &self.actor)
            .field("granted_scopes", &self.granted_scopes)
            .field("audience", &self.audience)
            .field("external", &self.external)
            .finish()
    }
}

/// Intersect the three scope sets, preserving the caller's requested order.
///
/// A free function, not a method, because it is the single most important
/// thing in the feature and should be testable without a datastore, a client
/// or a token. `requested` is already defaulted to the subject's scopes by the
/// caller when the parameter was absent.
///
/// Returns `Err` naming the first requested scope that fails. **Refusing
/// rather than silently dropping** is deliberate: a quietly-narrowed token
/// works for some calls and not others, and the caller discovers that at the
/// second service with no idea why. An error at the exchange is actionable.
pub fn narrow_scopes(
    requested: &[String],
    subject_scopes: &[String],
    client_scopes: &[String],
) -> Result<Vec<String>, OAuth2Error> {
    let mut granted: Vec<String> = Vec::with_capacity(requested.len());
    for scope in requested {
        if !subject_scopes.contains(scope) {
            return Err(OAuth2Error::InvalidScope(format!(
                "the subject token does not hold scope '{scope}'"
            )));
        }
        // The client's own registration bounds the result even when the
        // subject token is broader. This is what stops a compromised
        // low-privilege service that has captured an admin's token from
        // minting an admin token: it can only ever reach its own ceiling.
        if !client_scopes.contains(scope) {
            return Err(OAuth2Error::InvalidScope(format!(
                "the exchanging client is not registered for scope '{scope}'"
            )));
        }
        if !granted.contains(scope) {
            granted.push(scope.clone());
        }
    }
    if granted.is_empty() {
        return Err(OAuth2Error::InvalidScope(
            "the exchange would grant no scopes at all".into(),
        ));
    }
    Ok(granted)
}

/// Whether a client may impersonate.
pub fn client_may_impersonate(client: &OAuth2Client) -> bool {
    client
        .grant_types
        .iter()
        .any(|g| g == MAY_IMPERSONATE_GRANT)
}

/// AXIAM's own two audiences are always addressable — they are not
/// third-party systems, and refusing them would make the common "narrow a
/// user token to an M2M token" case impossible to express.
fn is_builtin_audience(target: &str) -> bool {
    target == AUD_USER || target == AUD_M2M
}

fn parse_scopes(raw: Option<&str>) -> Option<Vec<String>> {
    raw.map(|s| s.split_whitespace().map(str::to_owned).collect())
}

/// Token-exchange service.
#[derive(Clone)]
pub struct TokenExchangeService<TR> {
    tenant_repo: TR,
    auth_config: AuthConfig,
    /// Independent ceiling on an exchanged token's lifetime, applied on top of
    /// "never outlives its subject".
    max_lifetime_secs: i64,
    /// X4 — resolves external subject tokens. `None` disables the external
    /// path entirely: a deployment that never wires this in cannot accept a
    /// foreign token no matter how a provider row is configured, which is the
    /// behaviour every pre-X4 test asserts and must keep asserting.
    external_resolver: Option<std::sync::Arc<dyn ExternalSubjectResolver>>,
    /// X4 — the RBAC engine's answer for the resolved user.
    ///
    /// Paired with `external_resolver` and checked as a pair: an external
    /// exchange with no way to consult the engine would have to either fail or
    /// skip the check, and skipping it is how `scope_map` output becomes an
    /// authority in its own right.
    scope_authority: Option<std::sync::Arc<dyn SubjectScopeAuthority>>,
}

impl<TR> TokenExchangeService<TR>
where
    TR: TenantRepository,
{
    pub fn new(tenant_repo: TR, auth_config: AuthConfig, max_lifetime_secs: i64) -> Self {
        Self {
            tenant_repo,
            auth_config,
            max_lifetime_secs,
            external_resolver: None,
            scope_authority: None,
        }
    }

    /// Enable the X4 external path (both collaborators, together).
    ///
    /// Taken as a pair on purpose. There is no useful configuration in which
    /// external subject tokens are accepted but the engine is not consulted,
    /// and a builder that let the two be set independently would make that
    /// configuration expressible.
    pub fn with_external_subjects(
        mut self,
        resolver: std::sync::Arc<dyn ExternalSubjectResolver>,
        authority: std::sync::Arc<dyn SubjectScopeAuthority>,
    ) -> Self {
        self.external_resolver = Some(resolver);
        self.scope_authority = Some(authority);
        self
    }

    /// Perform an exchange.
    ///
    /// The exchanging client is assumed already authenticated by the caller —
    /// the token endpoint does that for every grant — and `client` is the row
    /// that authentication produced.
    ///
    /// `cnf` is the confirmation claim the *exchanging client* earned on this
    /// request, produced by `TokenService::certificate_binding_for` from the
    /// certificate or DPoP proof it actually presented (SEC-096). It is
    /// threaded in rather than computed here because the transport context
    /// belongs to the HTTP layer and this service must not learn about it.
    /// `None` — every client that registered no binding — issues exactly the
    /// bytes this grant issued before SEC-096.
    pub async fn exchange(
        &self,
        tenant_id: Uuid,
        client: &OAuth2Client,
        req: TokenExchangeRequest,
        cnf: Option<axiam_auth::token::CnfClaim>,
    ) -> Result<ExchangeOutcome, OAuth2Error> {
        if !client
            .grant_types
            .iter()
            .any(|g| g == TOKEN_EXCHANGE_GRANT_TYPE)
        {
            return Err(OAuth2Error::UnauthorizedClient(
                "client is not registered for the token-exchange grant".into(),
            ));
        }

        // Checked before anything is decoded: a client asking for a refresh
        // token wants a different thing entirely, and answering it with an
        // access token would satisfy the request shape while defeating the
        // lifetime cap the whole grant is built around.
        if let Some(want) = req.requested_token_type.as_deref()
            && want != TOKEN_TYPE_ACCESS_TOKEN
        {
            return Err(OAuth2Error::InvalidRequest(format!(
                "unsupported requested_token_type '{want}'; \
                 v1 issues only {TOKEN_TYPE_ACCESS_TOKEN}"
            )));
        }

        // Named refusals first (X4). A caller who sent a refresh or ID token
        // type has made a specific mistake, and "unsupported
        // subject_token_type" would send them hunting for a config switch that
        // does not and will not exist.
        match req.subject_token_type.as_str() {
            TOKEN_TYPE_REFRESH_TOKEN => {
                return Err(OAuth2Error::InvalidRequest(
                    "a refresh token is a re-authentication credential, not a subject \
                     token; present an access token"
                        .into(),
                ));
            }
            TOKEN_TYPE_ID_TOKEN => {
                return Err(OAuth2Error::InvalidRequest(
                    "an ID token asserts a login to a client, not authority at an API; \
                     present an access token"
                        .into(),
                ));
            }
            TOKEN_TYPE_ACCESS_TOKEN | TOKEN_TYPE_JWT => {}
            other => {
                return Err(OAuth2Error::InvalidRequest(format!(
                    "unsupported subject_token_type '{other}'; \
                     accepted types are {TOKEN_TYPE_ACCESS_TOKEN} and {TOKEN_TYPE_JWT}"
                )));
            }
        }

        // --- internal or external? (X4) --------------------------------------
        //
        // Routed on the subject token's UNVERIFIED `iss`, which is safe
        // precisely because neither destination trusts it: a token claiming to
        // be ours is checked against our signing key, and a token claiming a
        // partner's issuer is checked against that partner's JWKS. The claim
        // chooses which key the token faces, never whether it faces one.
        //
        // A token with no readable `iss` takes the internal path, where
        // `decode_access_token` refuses it — that is the same answer this grant
        // gave before X4 existed, and it keeps "malformed" a single failure
        // rather than two that differ by which branch noticed.
        let claimed_issuer = unverified_issuer_of(&req.subject_token);
        let is_external = match claimed_issuer.as_deref() {
            Some(iss) => iss != self.auth_config.effective_issuer(),
            None => false,
        };

        if is_external {
            return self.exchange_external(tenant_id, client, req, cnf).await;
        }

        // From here down is B3, unchanged except for the transitivity check.
        if req.subject_token_type == TOKEN_TYPE_JWT {
            return Err(OAuth2Error::InvalidRequest(format!(
                "subject_token_type {TOKEN_TYPE_JWT} is for tokens from external \
                 issuers; an AXIAM-issued token must be presented as \
                 {TOKEN_TYPE_ACCESS_TOKEN}"
            )));
        }

        // --- the subject ---------------------------------------------------
        let subject = decode_access_token(&req.subject_token, &self.auth_config)
            .map_err(|_| OAuth2Error::InvalidGrant("subject token is not valid".into()))?;

        // No re-exchange of a cross-domain token (X4), on this path too. The
        // external path refuses the claim on the way in; this refuses it on
        // the way back round. Without both, trust composes silently: a
        // partner's token buys an AXIAM token, and that token buys another one
        // whose provenance nobody can see.
        if subject.ext_exchange.is_some() {
            return Err(OAuth2Error::InvalidRequest(
                "the subject token is already the product of a cross-domain exchange; \
                 exchanges do not compose"
                    .into(),
            ));
        }

        // Cross-tenant is `invalid_grant`, not a distinct error: a caller
        // learning that their token is valid SOMEWHERE ELSE is a
        // tenant-enumeration signal.
        if subject.tenant_id != tenant_id.to_string() {
            return Err(OAuth2Error::InvalidGrant(
                "subject token is not valid".into(),
            ));
        }

        // No unbounded re-exchange. A token already carrying a full `act`
        // chain cannot be exchanged again — otherwise the chain, and the
        // token, grows one re-exchange at a time.
        if let Some(act) = subject.act.as_ref()
            && act.depth() >= MAX_ACT_CHAIN_DEPTH
        {
            return Err(OAuth2Error::InvalidRequest(format!(
                "subject token already names {MAX_ACT_CHAIN_DEPTH} actors; \
                 it cannot be exchanged again"
            )));
        }

        // --- delegation or impersonation ------------------------------------
        let (kind, actor_sub) = match req.actor_token.as_deref() {
            Some(actor_token) => {
                match req.actor_token_type.as_deref() {
                    Some(t) if t == TOKEN_TYPE_ACCESS_TOKEN => {}
                    _ => {
                        return Err(OAuth2Error::InvalidRequest(
                            "actor_token_type must be supplied and must be an access token".into(),
                        ));
                    }
                }
                let actor = decode_access_token(actor_token, &self.auth_config)
                    .map_err(|_| OAuth2Error::InvalidGrant("actor token is not valid".into()))?;
                if actor.tenant_id != tenant_id.to_string() {
                    return Err(OAuth2Error::InvalidGrant("actor token is not valid".into()));
                }
                (ExchangeKind::Delegation, Some(actor.sub))
            }
            None => {
                // Impersonation. The resulting token is indistinguishable from
                // one the subject obtained directly, so it is off unless the
                // client was explicitly granted it — and a client without the
                // grant is REFUSED rather than silently downgraded to
                // delegation, which would hand back a token that is not the
                // one they asked for.
                if !client_may_impersonate(client) {
                    return Err(OAuth2Error::UnauthorizedClient(
                        "impersonation requires the may_impersonate grant; \
                         supply an actor_token to delegate instead"
                            .into(),
                    ));
                }
                (ExchangeKind::Impersonation, None)
            }
        };

        // --- scopes ----------------------------------------------------------
        let subject_scopes: Vec<String> = subject
            .scope
            .as_deref()
            .map(|s| s.split_whitespace().map(str::to_owned).collect())
            .unwrap_or_default();
        let requested =
            parse_scopes(req.scope.as_deref()).unwrap_or_else(|| subject_scopes.clone());
        let granted = narrow_scopes(&requested, &subject_scopes, &client.scopes)?;

        // --- audience ---------------------------------------------------------
        let target = match (req.audience.as_deref(), req.resource.as_deref()) {
            (Some(a), Some(r)) if a != r => {
                return Err(OAuth2Error::InvalidRequest(
                    "audience and resource disagree; supply one or make them equal".into(),
                ));
            }
            (Some(a), _) => Some(a),
            (None, Some(r)) => Some(r),
            (None, None) => None,
        };
        let audience = match target {
            Some(t) => {
                // An unconstrained `aud` would let a service mint tokens
                // addressed at systems it has no relationship with — the mesh
                // equivalent of an open redirect. The client's registered URIs
                // are its declared relationships.
                //
                // SEC-089: the allow-list *is* `client.redirect_uris` — there
                // is no separate audience field in v1, so adding a redirect
                // URI also authorises it as a token audience. Documented on
                // `TokenExchangeRequest::audience` above and in
                // `docs/api/token-exchange.md#audience`. The same check is
                // repeated at the X4 external-exchange call site further
                // down this file; a future `allowed_token_targets` field
                // must replace both together.
                if !is_builtin_audience(t) && !client.redirect_uris.iter().any(|u| u == t) {
                    return Err(OAuth2Error::InvalidTarget(format!(
                        "'{t}' is not a registered target for this client"
                    )));
                }
                t.to_owned()
            }
            // Inherit. `aud` is optional on pre-Phase-4 tokens, which
            // `decode_access_token` treats as user tokens.
            None => subject.aud.clone().unwrap_or_else(|| AUD_USER.to_string()),
        };

        // --- lifetime ----------------------------------------------------------
        let now = Utc::now().timestamp();
        let subject_remaining = subject.exp - now;
        if subject_remaining <= 0 {
            return Err(OAuth2Error::InvalidGrant(
                "subject token has expired".into(),
            ));
        }
        // Never outlives its subject. Without this an exchange launders
        // lifetime: hold a token for thirty seconds, exchange it, hold the
        // result for the full access-token lifetime.
        let lifetime = subject_remaining.min(self.max_lifetime_secs);
        let expires_at = now + lifetime;

        // --- issue --------------------------------------------------------------
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        let act = actor_sub.as_ref().map(|actor| ActClaim {
            sub: actor.clone(),
            act: subject.act.clone().map(Box::new),
        });

        // The subject kind is carried through UNCHANGED, including when the
        // target is the machine audience (SEC-088).
        //
        // An earlier revision rewrote it to `OAuth2Client` whenever
        // `audience == AUD_M2M`, while `sub` stayed the subject's own id. That
        // produced the one combination the extractor contract says cannot
        // occur — see `AuthenticatedServiceAccount::subject` in
        // `axiam-api-rest`, which documents `sub_kind = oauth2_client` as
        // meaning `sub` IS an OAuth2 client id (`oa_…`). A user UUID wearing
        // that label is a type confusion aimed squarely at whoever writes the
        // first consumer of that extractor.
        //
        // The audience change is the real and intended effect of narrowing a
        // user token for a machine API. Relabelling the *subject* to match the
        // audience answers a different question, and answers it wrongly: who
        // the principal is did not change. A consumer that needs to know the
        // token arrived by exchange has `act` and the audit record, which the
        // impersonation path already relies on as its only evidence.
        let access_token = issue_exchanged_token(
            &subject.sub,
            subject.sub_kind,
            tenant_id,
            tenant.organization_id,
            &granted,
            &self.auth_config,
            Uuid::new_v4().to_string(),
            &audience,
            expires_at,
            act,
            // Same-domain: no foreign provenance to record.
            None,
            cnf.clone(),
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        Ok(ExchangeOutcome {
            response: TokenExchangeResponse {
                access_token,
                issued_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
                // RFC 9449 §5: a DPoP-bound token is announced as such.
                // Certificate-bound tokens stay `Bearer` (RFC 8705 leaves the
                // HTTP scheme alone), so this is `Bearer` for every client
                // that did not ask for DPoP binding.
                token_type: crate::dpop::token_type_for(cnf.as_ref()),
                expires_in: lifetime as u64,
                scope: Some(granted.join(" ")),
                // No refresh token, ever. One would let the holder outlive the
                // subject token indefinitely — the lifetime cap above,
                // defeated. Re-run the exchange.
            },
            kind,
            subject: subject.sub,
            actor: actor_sub,
            granted_scopes: granted,
            audience,
            external: None,
        })
    }

    /// X4 — the external branch of [`Self::exchange`].
    ///
    /// Separate function, not a `match` arm, because it shares almost nothing
    /// with the internal path: the subject is resolved by a different
    /// authority, the scopes come from a different source, and the answer to
    /// "what may this token do" is decided by the RBAC engine rather than by
    /// another token. Splicing the two would produce a function where every
    /// line needs a "…but not on the external path" qualifier, which is the
    /// shape mistakes hide in.
    ///
    /// The **order** of the checks below is the design doc's §"Validation
    /// pipeline" and is normative.
    async fn exchange_external(
        &self,
        tenant_id: Uuid,
        client: &OAuth2Client,
        req: TokenExchangeRequest,
        cnf: Option<axiam_auth::token::CnfClaim>,
    ) -> Result<ExchangeOutcome, OAuth2Error> {
        // Not configured ⇒ the external path does not exist. Deliberately the
        // same answer as "no provider trusts this issuer": whether a
        // deployment has X4 wired in at all is not something an authenticated
        // client needs to distinguish from a provider it did not configure.
        let (Some(resolver), Some(authority)) = (
            self.external_resolver.as_ref(),
            self.scope_authority.as_ref(),
        ) else {
            return Err(OAuth2Error::InvalidGrant(ISSUER_NOT_TRUSTED.into()));
        };

        // Delegation across a trust boundary needs a second trust decision —
        // "may this actor act for a subject *this IdP* vouched for" — that X4
        // does not make. Refused before the token is verified so the answer
        // does not depend on whether the subject token happened to be good.
        if req.actor_token.is_some() || req.actor_token_type.is_some() {
            return Err(OAuth2Error::InvalidRequest(
                "actor_token is not supported for subject tokens from external \
                 issuers in v1"
                    .into(),
            ));
        }

        let external = resolver
            .resolve(tenant_id, &req.subject_token)
            .await
            .map_err(|e| match e {
                ExternalSubjectRejection::IssuerNotTrusted => {
                    OAuth2Error::InvalidGrant(ISSUER_NOT_TRUSTED.into())
                }
                // The precise reason goes to the audit record, not to the
                // wire: which of a dozen checks refused a token is a map of
                // our validation order, drawn one request at a time.
                ExternalSubjectRejection::Rejected(_) => {
                    OAuth2Error::InvalidGrant("subject token is not valid".into())
                }
                ExternalSubjectRejection::Server(m) => OAuth2Error::ServerError(m),
            })?;

        // --- scopes: four gates, and the partner's token is not one of them --
        //
        // `candidate_scopes` is what an AXIAM admin agreed this provider's
        // assertions may map onto. It is not what the user holds, and it is
        // certainly not what the partner said — deny-by-default mapping has
        // already dropped everything unmapped.
        let requested_explicitly = req.scope.is_some();
        let requested =
            parse_scopes(req.scope.as_deref()).unwrap_or_else(|| external.candidate_scopes.clone());

        // Gate 1 + 2: the map's output and the exchanging client's ceiling.
        // Reusing `narrow_scopes` is deliberate — the client-ceiling rule that
        // stops a low-privilege service minting an admin token is exactly the
        // same rule here, and a second implementation of it would be a second
        // thing to keep correct.
        let mapped_and_registered = if requested_explicitly {
            narrow_scopes(&requested, &external.candidate_scopes, &client.scopes)?
        } else {
            // The default drops rather than refuses — see the design doc. A
            // provider's `scope_map` is written for a provider, not a user, so
            // a no-`scope` call that refused on the first name the caller
            // could not have would fail for everyone but the most privileged
            // user in the tenant.
            let kept: Vec<String> = requested
                .into_iter()
                .filter(|s| external.candidate_scopes.contains(s) && client.scopes.contains(s))
                .collect();
            if kept.is_empty() {
                return Err(OAuth2Error::InvalidScope(
                    "no scope this provider maps to is registered for this client".into(),
                ));
            }
            kept
        };

        // Gate 3: the RBAC engine, at mint time. Deny-override (B1) applies —
        // see the authority's implementation. This is the check that makes an
        // external token evidence of authentication rather than a grant of
        // authorization: without it, an admin's `scope_map` would be an
        // authority in its own right and every user the provider vouches for
        // would hold the same scopes.
        let held = authority
            .held_scopes(tenant_id, external.user_id, &mapped_and_registered)
            .await
            .map_err(OAuth2Error::ServerError)?;

        let granted: Vec<String> = if requested_explicitly {
            if let Some(missing) = mapped_and_registered.iter().find(|s| !held.contains(s)) {
                return Err(OAuth2Error::InvalidScope(format!(
                    "the resolved user does not hold scope '{missing}'"
                )));
            }
            mapped_and_registered
        } else {
            mapped_and_registered
                .into_iter()
                .filter(|s| held.contains(s))
                .collect()
        };
        if granted.is_empty() {
            return Err(OAuth2Error::InvalidScope(
                "the exchange would grant no scopes at all".into(),
            ));
        }

        // --- audience --------------------------------------------------------
        //
        // B3's rule, with one change that matters: when the request names no
        // target the issued token gets AXIAM's own user audience. It never
        // inherits the external token's `aud`, which names the *partner's*
        // resource server and would be meaningless here — or, worse,
        // coincidentally meaningful.
        let target = match (req.audience.as_deref(), req.resource.as_deref()) {
            (Some(a), Some(r)) if a != r => {
                return Err(OAuth2Error::InvalidRequest(
                    "audience and resource disagree; supply one or make them equal".into(),
                ));
            }
            (Some(a), _) => Some(a),
            (None, Some(r)) => Some(r),
            (None, None) => None,
        };
        let audience = match target {
            Some(t) => {
                // SEC-089: same allow-list reuse as the same-domain exchange
                // path above in this file — `client.redirect_uris` doubles
                // as the audience allow-list, so adding a redirect URI also
                // authorises it as a token audience. Documented on
                // `TokenExchangeRequest::audience` and in
                // `docs/api/token-exchange.md#audience`. Keep this check and
                // the same-domain one in sync; a future
                // `allowed_token_targets` field must replace both together.
                if !is_builtin_audience(t) && !client.redirect_uris.iter().any(|u| u == t) {
                    return Err(OAuth2Error::InvalidTarget(format!(
                        "'{t}' is not a registered target for this client"
                    )));
                }
                t.to_owned()
            }
            None => AUD_USER.to_string(),
        };

        // --- lifetime ---------------------------------------------------------
        let now = Utc::now().timestamp();
        let subject_remaining = external.subject_exp - now;
        if subject_remaining <= 0 {
            return Err(OAuth2Error::InvalidGrant(
                "subject token has expired".into(),
            ));
        }
        let mut lifetime = subject_remaining.min(self.max_lifetime_secs);
        if let Some(provider_max) = external.max_lifetime_secs {
            lifetime = lifetime.min(provider_max);
        }
        if lifetime <= 0 {
            return Err(OAuth2Error::InvalidGrant(
                "subject token has expired".into(),
            ));
        }

        // --- issue --------------------------------------------------------------
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        let access_token = issue_exchanged_token(
            &external.user_id.to_string(),
            // The subject is an AXIAM user — resolved through the federation
            // link, which is what a federated login resolves through too.
            SubjectKind::User,
            tenant_id,
            tenant.organization_id,
            &granted,
            &self.auth_config,
            Uuid::new_v4().to_string(),
            &audience,
            now + lifetime,
            // No `act`: nobody acted *for* the user. The IdP asserted that the
            // user authenticated, which is a different statement, and the one
            // `ext_exchange` records.
            None,
            Some(ExtExchangeClaim {
                iss: external.issuer.clone(),
            }),
            cnf.clone(),
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        Ok(ExchangeOutcome {
            response: TokenExchangeResponse {
                access_token,
                issued_token_type: TOKEN_TYPE_ACCESS_TOKEN.to_string(),
                // SEC-096, as on the same-domain path above.
                token_type: crate::dpop::token_type_for(cnf.as_ref()),
                expires_in: lifetime as u64,
                scope: Some(granted.join(" ")),
            },
            kind: ExchangeKind::External,
            subject: external.user_id.to_string(),
            actor: None,
            granted_scopes: granted,
            audience,
            external: Some(ExternalProvenance {
                issuer: external.issuer,
                provider_id: external.provider_id,
                provider_name: external.provider_name,
                external_subject: external.external_subject,
                newly_provisioned: external.newly_provisioned,
            }),
        })
    }
}

/// The one X4 refusal given a distinguishable description.
///
/// The exchanging client is an authenticated confidential client of this
/// tenant, not an anonymous prober: telling it that an issuer it named is not
/// configured leaks nothing it could not get by asking the admin, and without
/// it an SDK cannot tell "fix your trust configuration" from "fix your token".
/// Pinned as a constant because the SDK contract's §15 addendum quotes it.
pub const ISSUER_NOT_TRUSTED: &str =
    "the subject token's issuer is not configured for token exchange";

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn narrowing_keeps_only_what_all_three_sets_hold() {
        let granted = narrow_scopes(
            &v(&["read", "write"]),
            &v(&["read", "write", "admin"]),
            &v(&["read", "write", "delete"]),
        )
        .unwrap();
        assert_eq!(granted, v(&["read", "write"]));
    }

    #[test]
    fn a_scope_the_subject_lacks_is_refused_not_dropped() {
        let err = narrow_scopes(
            &v(&["read", "admin"]),
            &v(&["read"]),
            &v(&["read", "admin"]),
        )
        .unwrap_err();
        assert_eq!(err.error_code(), "invalid_scope");
        assert!(
            err.error_description().contains("admin"),
            "the error should name the offending scope: {err}"
        );
    }

    #[test]
    fn the_clients_own_ceiling_bounds_a_broader_subject_token() {
        // The headline case: a low-privilege service holding an admin's token
        // must not be able to mint an admin token.
        let err = narrow_scopes(&v(&["admin"]), &v(&["admin", "read"]), &v(&["read"])).unwrap_err();
        assert_eq!(err.error_code(), "invalid_scope");
        assert!(err.error_description().contains("client"));
    }

    #[test]
    fn an_empty_result_is_an_error_rather_than_a_scopeless_token() {
        let err = narrow_scopes(&[], &v(&["read"]), &v(&["read"])).unwrap_err();
        assert_eq!(err.error_code(), "invalid_scope");
    }

    #[test]
    fn duplicate_requested_scopes_collapse() {
        let granted = narrow_scopes(&v(&["read", "read"]), &v(&["read"]), &v(&["read"])).unwrap();
        assert_eq!(granted, v(&["read"]));
    }

    /// The property the whole feature exists to preserve, over every
    /// combination of three scope sets: whatever comes out is a subset of all
    /// three inputs. Exhaustive rather than randomised — the universe is four
    /// scopes, so every case can simply be enumerated.
    #[test]
    fn granted_is_always_a_subset_of_all_three_inputs() {
        let universe = ["a", "b", "c", "d"];
        let subsets: Vec<Vec<String>> = (0u8..16)
            .map(|mask| {
                universe
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| mask & (1 << i) != 0)
                    .map(|(_, s)| (*s).to_string())
                    .collect()
            })
            .collect();

        for requested in &subsets {
            for subject in &subsets {
                for client in &subsets {
                    match narrow_scopes(requested, subject, client) {
                        Ok(granted) => {
                            assert!(!granted.is_empty(), "an Ok result is never empty");
                            for s in &granted {
                                assert!(requested.contains(s), "widened past requested");
                                assert!(subject.contains(s), "widened past the subject token");
                                assert!(client.contains(s), "widened past the client");
                            }
                        }
                        Err(e) => assert_eq!(e.error_code(), "invalid_scope"),
                    }
                }
            }
        }
    }

    #[test]
    fn act_chain_depth_counts_every_actor() {
        let one = ActClaim {
            sub: "a".into(),
            act: None,
        };
        assert_eq!(one.depth(), 1);
        let two = ActClaim {
            sub: "b".into(),
            act: Some(Box::new(one)),
        };
        assert_eq!(two.depth(), 2);
        let three = ActClaim {
            sub: "c".into(),
            act: Some(Box::new(two)),
        };
        assert_eq!(three.depth(), MAX_ACT_CHAIN_DEPTH);
    }

    #[test]
    fn impersonation_is_off_unless_the_grant_is_present() {
        let mut client = OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "oa_x".into(),
            client_secret_hash: String::new(),
            name: "svc".into(),
            redirect_uris: vec![],
            grant_types: vec![TOKEN_EXCHANGE_GRANT_TYPE.into()],
            scopes: v(&["read"]),
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
            token_endpoint_auth_method:
                axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(
            !client_may_impersonate(&client),
            "a client registered only for the exchange grant must not impersonate"
        );
        client.grant_types.push(MAY_IMPERSONATE_GRANT.into());
        assert!(client_may_impersonate(&client));
    }

    // =================================================================
    // X4 — the external branch
    // =================================================================

    mod external {
        use super::*;
        use axiam_core::error::AxiamResult;
        use axiam_core::models::tenant::{CreateTenant, Tenant, TenantStatus, UpdateTenant};
        use axiam_core::repository::{PaginatedResult, Pagination};
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        // ---- collaborators ------------------------------------------

        #[derive(Clone)]
        struct StubTenantRepo {
            org_id: Uuid,
        }

        impl TenantRepository for StubTenantRepo {
            async fn get_organization_tenant(
                &self,
                _organization_id: uuid::Uuid,
            ) -> axiam_core::error::AxiamResult<Tenant> {
                unimplemented!("this stub has no organization scope")
            }

            async fn create(&self, _input: CreateTenant) -> AxiamResult<Tenant> {
                unimplemented!()
            }
            async fn get_by_id(&self, id: Uuid) -> AxiamResult<Tenant> {
                Ok(Tenant {
                    kind: axiam_core::models::tenant::TenantKind::Standard,
                    id,
                    organization_id: self.org_id,
                    name: "t".into(),
                    slug: "t".into(),
                    status: TenantStatus::Active,
                    metadata: serde_json::json!({}),
                    created_at: Utc::now(),
                    updated_at: Utc::now(),
                })
            }
            async fn get_by_slug(&self, _o: Uuid, _s: &str) -> AxiamResult<Tenant> {
                unimplemented!()
            }
            async fn update(&self, _id: Uuid, _i: UpdateTenant) -> AxiamResult<Tenant> {
                unimplemented!()
            }
            async fn delete(&self, _id: Uuid) -> AxiamResult<()> {
                unimplemented!()
            }
            async fn list_by_organization(
                &self,
                _o: Uuid,
                _p: Pagination,
            ) -> AxiamResult<PaginatedResult<Tenant>> {
                unimplemented!()
            }
        }

        struct StubResolver {
            outcome: Result<ResolvedExternalSubject, ExternalSubjectRejection>,
            called: AtomicBool,
        }

        impl StubResolver {
            fn ok(subject: ResolvedExternalSubject) -> Arc<Self> {
                Arc::new(Self {
                    outcome: Ok(subject),
                    called: AtomicBool::new(false),
                })
            }
            fn err(e: ExternalSubjectRejection) -> Arc<Self> {
                Arc::new(Self {
                    outcome: Err(e),
                    called: AtomicBool::new(false),
                })
            }
        }

        impl ExternalSubjectResolver for StubResolver {
            fn resolve<'a>(
                &'a self,
                _tenant_id: Uuid,
                _subject_token: &'a str,
            ) -> Pin<
                Box<
                    dyn Future<Output = Result<ResolvedExternalSubject, ExternalSubjectRejection>>
                        + Send
                        + 'a,
                >,
            > {
                self.called.store(true, Ordering::SeqCst);
                let outcome = self.outcome.clone();
                Box::pin(async move { outcome })
            }
        }

        /// An authority that holds exactly the scopes it was told to.
        ///
        /// Mirrors the real contract deliberately — a **filter**, never a
        /// source. A stub that could return a name it was not given would let
        /// a test pass that the real port makes impossible.
        struct StubAuthority(Vec<String>);

        impl SubjectScopeAuthority for StubAuthority {
            fn held_scopes<'a>(
                &'a self,
                _tenant_id: Uuid,
                _subject_id: Uuid,
                candidates: &'a [String],
            ) -> Pin<Box<dyn Future<Output = Result<Vec<String>, String>> + Send + 'a>>
            {
                let held: Vec<String> = candidates
                    .iter()
                    .filter(|c| self.0.contains(c))
                    .cloned()
                    .collect();
                Box::pin(async move { Ok(held) })
            }
        }

        // ---- fixtures ------------------------------------------------

        const EXT_ISS: &str = "https://partner.example";

        fn auth_config() -> AuthConfig {
            let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
            AuthConfig {
                jwt_private_key_pem: kp.serialize_pem(),
                jwt_public_key_pem: kp.public_key_pem(),
                access_token_lifetime_secs: 900,
                jwt_issuer: "axiam-test".into(),
                oauth2_issuer_url: "https://id.axiam.test".into(),
                sso_spa_origins: Vec::new(),
                ..AuthConfig::default()
            }
        }

        fn subject(candidates: &[&str]) -> ResolvedExternalSubject {
            ResolvedExternalSubject {
                issuer: EXT_ISS.into(),
                provider_id: Uuid::new_v4(),
                provider_name: "PartnerIdP".into(),
                external_subject: "partner-user-1".into(),
                user_id: Uuid::new_v4(),
                newly_provisioned: false,
                candidate_scopes: candidates.iter().map(|s| (*s).to_string()).collect(),
                subject_exp: Utc::now().timestamp() + 600,
                max_lifetime_secs: None,
            }
        }

        fn client(scopes: &[&str]) -> OAuth2Client {
            OAuth2Client {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                client_id: "oa_gateway".into(),
                client_secret_hash: String::new(),
                name: "gateway".into(),
                redirect_uris: vec![],
                grant_types: vec![TOKEN_EXCHANGE_GRANT_TYPE.into()],
                scopes: scopes.iter().map(|s| (*s).to_string()).collect(),
                post_logout_redirect_uris: Vec::new(),
                backchannel_logout_uri: None,
                require_par: false,
                profile: axiam_core::models::oauth2_client::ClientProfile::Standard,
                token_endpoint_auth_method:
                    axiam_core::models::oauth2_client::ClientAuthMethod::ClientSecretPost,
                tls_client_auth_subject_dn: None,
                tls_client_auth_san_dns: None,
                tls_client_auth_san_uri: None,
                self_signed_tls_client_auth_thumbprints: vec![],
                tls_client_certificate_bound_access_tokens: false,
                jwks: None,
                jwks_uri: None,
                dpop_bound_access_tokens: false,
                dpop_require_nonce: false,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }
        }

        /// A syntactically well-formed JWT whose payload names `iss`.
        ///
        /// Never verified by anything in these tests — the resolver is stubbed
        /// — so the signature segment is a placeholder. What it exercises is
        /// the *routing* decision, which is the only thing the unverified
        /// payload is allowed to influence.
        fn foreign_token(iss: &str) -> String {
            use base64::Engine;
            let b64 = |v: &serde_json::Value| {
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(serde_json::to_vec(v).unwrap())
            };
            format!(
                "{}.{}.{}",
                b64(&serde_json::json!({ "alg": "RS256", "typ": "at+jwt" })),
                b64(&serde_json::json!({ "iss": iss, "sub": "partner-user-1" })),
                "c2ln"
            )
        }

        fn service(
            cfg: &AuthConfig,
            resolver: Arc<dyn ExternalSubjectResolver>,
            authority: Arc<dyn SubjectScopeAuthority>,
        ) -> TokenExchangeService<StubTenantRepo> {
            TokenExchangeService::new(
                StubTenantRepo {
                    org_id: Uuid::new_v4(),
                },
                cfg.clone(),
                900,
            )
            .with_external_subjects(resolver, authority)
        }

        fn request(token: String, scope: Option<&str>) -> TokenExchangeRequest {
            TokenExchangeRequest {
                subject_token: token,
                subject_token_type: TOKEN_TYPE_JWT.into(),
                requested_token_type: None,
                actor_token: None,
                actor_token_type: None,
                scope: scope.map(str::to_owned),
                audience: None,
                resource: None,
            }
        }

        // ---- the happy path, and what it proves ----------------------

        #[tokio::test]
        async fn a_trusted_partner_token_mints_a_narrowed_axiam_token() {
            let cfg = auth_config();
            let subj = subject(&["read:orders"]);
            let user_id = subj.user_id;
            let svc = service(
                &cfg,
                StubResolver::ok(subj),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let outcome = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders", "write:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .expect("a fully-permitted exchange must succeed");

            assert_eq!(outcome.kind, ExchangeKind::External);
            assert_eq!(outcome.granted_scopes, vec!["read:orders".to_string()]);
            assert_eq!(outcome.subject, user_id.to_string());
            assert_eq!(
                outcome.external.as_ref().unwrap().issuer,
                EXT_ISS,
                "the audit record must name the foreign issuer"
            );

            let claims = decode_access_token(&outcome.response.access_token, &cfg).unwrap();
            assert_eq!(
                claims.ext_exchange.map(|e| e.iss),
                Some(EXT_ISS.to_string()),
                "the issued token must carry its provenance"
            );
            assert!(
                claims.act.is_none(),
                "nobody acted FOR the user; the IdP asserted the user authenticated"
            );
            assert_eq!(claims.sub, user_id.to_string());
        }

        /// The headline invariant: the partner's token never widens anything.
        /// A scope the map produces but the engine refuses does not come out.
        #[tokio::test]
        async fn the_engine_bounds_the_result_even_when_the_map_is_generous() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["read:orders", "admin"])),
                // The user holds `read:orders` and nothing else.
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let outcome = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders", "admin"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap();

            assert_eq!(
                outcome.granted_scopes,
                vec!["read:orders".to_string()],
                "an admin-configured scope_map is not an authority; the engine is"
            );
        }

        #[tokio::test]
        async fn an_explicitly_requested_scope_the_user_lacks_is_refused_not_dropped() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["read:orders", "admin"])),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let err = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders", "admin"]),
                    request(foreign_token(EXT_ISS), Some("read:orders admin")),
                    None,
                )
                .await
                .unwrap_err();

            assert_eq!(err.error_code(), "invalid_scope");
            assert!(
                err.error_description().contains("admin"),
                "the error must name the offending scope: {err}"
            );
        }

        /// SEC-096. The exchanging client's own confirmation claim reaches
        /// the issued token, and the response announces `DPoP` for it.
        ///
        /// Before SEC-096 the token-exchange grant `return`ed from
        /// `handlers::token` above `dpop_from_request`, so no proof was ever
        /// verified on this path and `issue_exchanged_token` had no `cnf`
        /// parameter to give one to: a `cnf.jkt`-bound token could be
        /// exchanged for a plain bearer token with the same subject and a
        /// subset of the same scopes.
        #[tokio::test]
        async fn an_exchange_carries_the_exchanging_clients_binding() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["read:orders"])),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let jkt = "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I";
            let outcome = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    Some(axiam_auth::token::CnfClaim::from_dpop_thumbprint(jkt)),
                )
                .await
                .expect("a fully-permitted exchange must succeed");

            assert_eq!(
                outcome.response.token_type, "DPoP",
                "RFC 9449 §5: a DPoP-bound token is announced as such"
            );
            let claims = decode_access_token(&outcome.response.access_token, &cfg).unwrap();
            assert_eq!(
                claims
                    .cnf
                    .as_ref()
                    .and_then(axiam_auth::token::CnfClaim::dpop_thumbprint),
                Some(jkt),
                "the exchanged token must be sender-constrained to the exchanging \
                 client's key, not laundered into a bearer token"
            );
        }

        /// The same property in the other direction: a client that registered
        /// no binding gets byte-for-byte what it got before SEC-096.
        #[tokio::test]
        async fn an_unbound_exchange_is_unchanged_by_sec_096() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["read:orders"])),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let outcome = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap();

            assert_eq!(outcome.response.token_type, "Bearer");
            assert!(
                decode_access_token(&outcome.response.access_token, &cfg)
                    .unwrap()
                    .cnf
                    .is_none()
            );
        }

        #[tokio::test]
        async fn the_exchanging_clients_own_ceiling_still_applies() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["admin"])),
                Arc::new(StubAuthority(vec!["admin".into()])),
            );

            // Everything else says yes; the client is not registered for it.
            let err = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), Some("admin")),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.error_code(), "invalid_scope");
        }

        #[tokio::test]
        async fn an_unmapped_partner_token_yields_no_token_at_all() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&[])),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let err = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.error_code(), "invalid_scope");
        }

        // ---- routing --------------------------------------------------

        /// A deployment that never wired X4 in cannot accept a foreign token,
        /// whatever a provider row says — and answers the same way as "no
        /// provider trusts this issuer".
        #[tokio::test]
        async fn without_the_external_collaborators_a_foreign_token_is_untrusted() {
            let cfg = auth_config();
            let svc = TokenExchangeService::new(
                StubTenantRepo {
                    org_id: Uuid::new_v4(),
                },
                cfg.clone(),
                900,
            );

            let err = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.error_code(), "invalid_grant");
            assert_eq!(err.error_description(), ISSUER_NOT_TRUSTED);
        }

        #[tokio::test]
        async fn an_untrusted_issuer_says_so_distinguishably() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::err(ExternalSubjectRejection::IssuerNotTrusted),
                Arc::new(StubAuthority(vec![])),
            );

            let err = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token("https://nobody.example"), None),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.error_description(), ISSUER_NOT_TRUSTED);
        }

        /// Every *other* refusal is generic: which of a dozen checks refused a
        /// token is a map of our validation order, drawn one request at a time.
        #[tokio::test]
        async fn every_other_rejection_reason_stays_off_the_wire() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::err(ExternalSubjectRejection::Rejected(
                    "signature is invalid".into(),
                )),
                Arc::new(StubAuthority(vec![])),
            );

            let err = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.error_code(), "invalid_grant");
            assert_eq!(err.error_description(), "subject token is not valid");
            assert!(!err.error_description().contains("signature"));
        }

        /// A token claiming AXIAM's own issuer takes the internal path, where
        /// it faces AXIAM's signing key — the routing claim is unverified, and
        /// choosing a branch is all it can do.
        #[tokio::test]
        async fn a_token_claiming_our_issuer_is_verified_against_our_key() {
            let cfg = auth_config();
            let resolver = StubResolver::ok(subject(&["read:orders"]));
            let svc = service(
                &cfg,
                resolver.clone(),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let mut req = request(foreign_token(cfg.effective_issuer()), None);
            req.subject_token_type = TOKEN_TYPE_ACCESS_TOKEN.into();
            let err = svc
                .exchange(Uuid::new_v4(), &client(&["read:orders"]), req, None)
                .await
                .unwrap_err();

            assert_eq!(err.error_code(), "invalid_grant");
            assert!(
                !resolver.called.load(Ordering::SeqCst),
                "a token claiming our issuer must never reach the external resolver"
            );
        }

        // ---- the invariants X4 exists to hold ------------------------

        #[tokio::test]
        async fn an_actor_token_is_refused_across_a_trust_boundary() {
            let cfg = auth_config();
            let resolver = StubResolver::ok(subject(&["read:orders"]));
            let svc = service(
                &cfg,
                resolver.clone(),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let mut req = request(foreign_token(EXT_ISS), None);
            req.actor_token = Some("whatever".into());
            req.actor_token_type = Some(TOKEN_TYPE_ACCESS_TOKEN.into());

            let err = svc
                .exchange(Uuid::new_v4(), &client(&["read:orders"]), req, None)
                .await
                .unwrap_err();
            assert_eq!(err.error_code(), "invalid_request");
            assert!(
                !resolver.called.load(Ordering::SeqCst),
                "refused before the token is verified, so the answer cannot \
                 depend on whether the subject token happened to be good"
            );
        }

        #[tokio::test]
        async fn refresh_and_id_subject_token_types_are_refused_by_name() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["read:orders"])),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            for (ty, needle) in [
                (TOKEN_TYPE_REFRESH_TOKEN, "re-authentication"),
                (TOKEN_TYPE_ID_TOKEN, "asserts a login"),
            ] {
                let mut req = request(foreign_token(EXT_ISS), None);
                req.subject_token_type = ty.into();
                let err = svc
                    .exchange(Uuid::new_v4(), &client(&["read:orders"]), req, None)
                    .await
                    .unwrap_err();
                assert_eq!(err.error_code(), "invalid_request");
                assert!(
                    err.error_description().contains(needle),
                    "{ty} should be refused by name, got: {err}"
                );
            }
        }

        /// The transitivity ban, in the direction only this crate can test:
        /// an AXIAM token that itself came from a cross-domain exchange cannot
        /// buy another one.
        #[tokio::test]
        async fn a_token_minted_by_an_external_exchange_cannot_be_exchanged_again() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["read:orders"])),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let first = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap();

            // Present the result back as a subject token — same issuer as us,
            // so it takes the internal path and is cryptographically valid.
            let mut req = request(first.response.access_token, None);
            req.subject_token_type = TOKEN_TYPE_ACCESS_TOKEN.into();
            let err = svc
                .exchange(Uuid::new_v4(), &client(&["read:orders"]), req, None)
                .await
                .unwrap_err();

            assert_eq!(err.error_code(), "invalid_request");
            assert!(
                err.error_description().contains("do not compose"),
                "got: {err}"
            );
        }

        #[tokio::test]
        async fn the_issued_token_never_outlives_the_partners_token() {
            let cfg = auth_config();
            let mut subj = subject(&["read:orders"]);
            // The partner's token has 30 seconds left; the server-wide cap is
            // 900. Without the min(), an exchange would launder lifetime.
            subj.subject_exp = Utc::now().timestamp() + 30;
            let svc = service(
                &cfg,
                StubResolver::ok(subj),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let outcome = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap();
            assert!(
                outcome.response.expires_in <= 30,
                "expires_in was {}",
                outcome.response.expires_in
            );
        }

        #[tokio::test]
        async fn a_per_provider_lifetime_ceiling_is_honoured() {
            let cfg = auth_config();
            let mut subj = subject(&["read:orders"]);
            subj.max_lifetime_secs = Some(60);
            let svc = service(
                &cfg,
                StubResolver::ok(subj),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let outcome = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap();
            assert!(outcome.response.expires_in <= 60);
        }

        #[tokio::test]
        async fn an_expired_partner_token_buys_nothing() {
            let cfg = auth_config();
            let mut subj = subject(&["read:orders"]);
            subj.subject_exp = Utc::now().timestamp() - 1;
            let svc = service(
                &cfg,
                StubResolver::ok(subj),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let err = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.error_code(), "invalid_grant");
        }

        /// The issued `aud` is AXIAM's, never the partner's — the external
        /// token's audience names *their* resource server.
        #[tokio::test]
        async fn the_partners_audience_is_never_inherited() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["read:orders"])),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let outcome = svc
                .exchange(
                    Uuid::new_v4(),
                    &client(&["read:orders"]),
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap();
            assert_eq!(outcome.audience, AUD_USER);
        }

        #[tokio::test]
        async fn an_unregistered_audience_is_invalid_target() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["read:orders"])),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let mut req = request(foreign_token(EXT_ISS), None);
            req.audience = Some("https://not-registered.example".into());
            let err = svc
                .exchange(Uuid::new_v4(), &client(&["read:orders"]), req, None)
                .await
                .unwrap_err();
            assert_eq!(err.error_code(), "invalid_target");
        }

        #[tokio::test]
        async fn a_client_without_the_exchange_grant_gets_nowhere_near_the_resolver() {
            let cfg = auth_config();
            let resolver = StubResolver::ok(subject(&["read:orders"]));
            let svc = service(
                &cfg,
                resolver.clone(),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let mut c = client(&["read:orders"]);
            c.grant_types.clear();
            let err = svc
                .exchange(
                    Uuid::new_v4(),
                    &c,
                    request(foreign_token(EXT_ISS), None),
                    None,
                )
                .await
                .unwrap_err();
            assert_eq!(err.error_code(), "unauthorized_client");
            assert!(!resolver.called.load(Ordering::SeqCst));
        }

        /// `may_impersonate` is deliberately NOT the gate here — the evidence
        /// is a trusted IdP's signed assertion, not the client's own say-so.
        #[tokio::test]
        async fn the_external_path_does_not_require_the_impersonation_grant() {
            let cfg = auth_config();
            let svc = service(
                &cfg,
                StubResolver::ok(subject(&["read:orders"])),
                Arc::new(StubAuthority(vec!["read:orders".into()])),
            );

            let c = client(&["read:orders"]);
            assert!(!client_may_impersonate(&c));
            assert!(
                svc.exchange(
                    Uuid::new_v4(),
                    &c,
                    request(foreign_token(EXT_ISS), None),
                    None
                )
                .await
                .is_ok()
            );
        }

        /// Exhaustive over the three gates the request itself does not set:
        /// whatever comes out is a subset of every one of them. The single
        /// most valuable test in the feature, mirroring B3's own property test
        /// one layer up.
        #[tokio::test]
        async fn granted_is_always_a_subset_of_map_client_and_engine() {
            let universe = ["a", "b", "c"];
            let subsets: Vec<Vec<String>> = (0u8..8)
                .map(|mask| {
                    universe
                        .iter()
                        .enumerate()
                        .filter(|(i, _)| mask & (1 << i) != 0)
                        .map(|(_, s)| (*s).to_string())
                        .collect()
                })
                .collect();
            let cfg = auth_config();

            for candidates in &subsets {
                for client_scopes in &subsets {
                    for held in &subsets {
                        let mut subj = subject(&[]);
                        subj.candidate_scopes = candidates.clone();
                        let svc = service(
                            &cfg,
                            StubResolver::ok(subj),
                            Arc::new(StubAuthority(held.clone())),
                        );
                        let mut c = client(&[]);
                        c.scopes = client_scopes.clone();

                        match svc
                            .exchange(
                                Uuid::new_v4(),
                                &c,
                                request(foreign_token(EXT_ISS), None),
                                None,
                            )
                            .await
                        {
                            Ok(outcome) => {
                                assert!(!outcome.granted_scopes.is_empty());
                                for s in &outcome.granted_scopes {
                                    assert!(candidates.contains(s), "escaped the scope map");
                                    assert!(client_scopes.contains(s), "escaped the client");
                                    assert!(held.contains(s), "escaped the engine");
                                }
                            }
                            Err(e) => assert_eq!(e.error_code(), "invalid_scope"),
                        }
                    }
                }
            }
        }
    }
}

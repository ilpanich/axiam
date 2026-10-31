//! G-A — native sign-in with a provider ID token: the grant (W2.3).
//!
//! Design: `claude_dev/social-login-gap-plan-2026-10-30.md` §3.1, D-N1, D-N6.
//! The rule the whole feature applies:
//!
//! > **An ID token is accepted as a sign-in only when it was issued to us.**
//!
//! `axiam-federation`'s `native_login` decides *whether* a provider ID token
//! proves a sign-in and *who* signed in (§3.1 steps 2–7). This module turns
//! that answer into the client's ordinary sign-in token set (step 8) and owns
//! the gate in front of it (step 1). The token endpoint dispatches here and
//! writes the audit record (step 9).
//!
//! # The wire
//!
//! `POST /oauth2/token` with
//! `grant_type=`[`PROVIDER_ID_TOKEN_GRANT_TYPE`], `provider` (the federation
//! provider's UUID or `provider_slug`), `id_token`, `nonce` (the raw nonce the
//! app generated; the provider's SDK was given its SHA-256 hex, which is what
//! the token carries — D-N16), optional `scope` and RFC 8707 `resource`, and
//! the client's usual authentication — a public (mobile) client sends
//! `client_id` only.
//!
//! # Why a vendor URN, and this one
//!
//! The grant is AXIAM's own: no IETF or OIDF registry defines "sign in with a
//! third party's ID token" as a grant, and RFC 8693 is the wrong shape (X4
//! refuses ID tokens by design; §3.1). RFC 6749 §4.5 extension grants are
//! named by absolute URI, and the tree already has exactly one vendor grant
//! URN, `urn:axiam:params:oauth:grant-type:may-impersonate`
//! (`crate::token_exchange::MAY_IMPERSONATE_GRANT`). This one follows it
//! segment for segment, so the two read as one family and no new namespace is
//! opened. Nothing else in the tree, the SDK contract or the discovery
//! document spells `provider-id-token`.
//!
//! # Order, and what each step may write
//!
//! 1. **The client** is read and authenticates by its registered method — a
//!    public client by presenting nothing, a confidential one by its
//!    credential ([`TokenService::authenticate_provider_id_token_client`]).
//!    The profile's request-time rules run (`fapi::enforce_token_request`),
//!    the registration must list the grant (`unauthorized_client`
//!    otherwise), and the binding the registration asks for (`cnf`: DPoP,
//!    certificate) is decided — refused, not downgraded, when the request
//!    cannot satisfy it. The REST layer then applies the
//!    `oauth2_provider_id_token` bucket. Nothing has been written.
//! 2. **The request**: `provider`, `id_token` and `nonce` present; `scope`
//!    within the client's registered set (after the external-client ceiling);
//!    `resource` one the client may address
//!    ([`TokenService::prepare_provider_id_token_grant`]). Still nothing
//!    written, so a malformed request does not spend the token.
//! 3. **Steps 2–7** run in `axiam-federation` (the provider, the signature,
//!    the claims, the shape, the replay record, the user). Every refusal is
//!    one `invalid_grant` on the wire ([`refusal_for`]). The token endpoint
//!    then fires `login.post_auth` for the resolved user (CONTRACT §22,
//!    F4-W2-01) — the gate every interactive sign-in passes — and a veto is
//!    the same `invalid_grant`.
//! 4. **Consent** (D-N6): a scope that would need a consent ceremony is
//!    `consent_required` ([`decide_consent`]) — there is nobody to ask on
//!    this request, so it is answered as `prompt=none` is at `/authorize`.
//! 5. **Issue** ([`TokenService::issue_provider_id_token_grant`]): a session
//!    recording the federated authentication, the access token, a refresh
//!    token when the client holds `refresh_token`, and an ID token carrying
//!    the request's nonce when `openid` was granted.
//!
//! # The session, and what it records
//!
//! A federated *browser* sign-in creates a session whose evidence is
//! `AuthenticationEvidence::upstream(auth_time, now, [fed])`, and a code
//! issued from it carries that session in `sid` and that evidence onward.
//! The native sign-in records the same: one session row with the provider's
//! `auth_time` (clamped to now) and `amr = [fed]`, no browser cookie, and a
//! console refresh credential nobody is given. The access token names it in
//! `sid`, so UserInfo and the session-validated API admit the token, ending
//! the session (logout, password reset, an administrator's revocation) ends
//! the tokens, and the user's session list shows the device. No claim is new.

use axiam_auth::token::{
    CnfClaim, IdTokenEvidence, generate_refresh_token, hash_refresh_token, issue_id_token,
};
use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::{CreateRefreshToken, OAuth2Client};
use axiam_core::models::session::{Amr, AuthenticationEvidence, CreateSession};
use axiam_core::repository::{
    AuditLogRepository, AuthorizationCodeRepository, OAuth2ClientRepository,
    RefreshTokenRepository, ServiceAccountRepository, SessionRepository, TenantRepository,
    UserRepository,
};
use axiam_federation::native_login::{
    NativeIdTokenRequest, NativeLoginError, NativeLoginRefusal, NativeSubject,
};

/// The one `invalid_grant` description every refusal of §3.1 steps 2–7
/// carries, re-exported so the token endpoint answers with the federation
/// module's own wording.
pub use axiam_federation::native_login::PUBLIC_REFUSAL_DESCRIPTION;
use chrono::Utc;
use uuid::Uuid;

use super::{
    CLIENT_AUTH_FAILED, TokenRequest, TokenRequestContext, TokenResponse, TokenService,
    resolve_client_id, spend_one_verify,
};
use crate::error::OAuth2Error;

/// The grant type of a native sign-in with a provider ID token.
pub const PROVIDER_ID_TOKEN_GRANT_TYPE: &str =
    "urn:axiam:params:oauth:grant-type:provider-id-token";

/// The audit action every native sign-in attempt that reached the grant is
/// recorded under, accepted or refused. Never carries the token or the nonce.
pub const NATIVE_LOGIN_AUDIT_ACTION: &str = "federation.native_login";

/// The `server_error` description for a refusal that is the datastore's
/// fault. As generic as [`PUBLIC_REFUSAL_DESCRIPTION`], for the same reason.
pub const SERVER_REFUSAL_DESCRIPTION: &str = "the sign-in could not be completed; retry shortly";

/// Whether a client's registration lists this grant.
pub fn holds_provider_id_token_grant(grant_types: &[String]) -> bool {
    grant_types
        .iter()
        .any(|g| g == PROVIDER_ID_TOKEN_GRANT_TYPE)
}

/// The three grant parameters, borrowed from the request, or
/// `invalid_request` naming the first one that is missing or empty.
///
/// # Errors
///
/// `invalid_request` when `provider`, `id_token` or `nonce` is absent or
/// empty.
pub fn native_request(req: &TokenRequest) -> Result<NativeIdTokenRequest<'_>, OAuth2Error> {
    fn required<'a>(value: Option<&'a String>, name: &str) -> Result<&'a str, OAuth2Error> {
        value
            .map(String::as_str)
            .filter(|v| !v.trim().is_empty())
            .ok_or_else(|| {
                OAuth2Error::InvalidRequest(format!(
                    "{name} is required for the provider-id-token grant"
                ))
            })
    }
    Ok(NativeIdTokenRequest {
        provider: required(req.provider.as_ref(), "provider")?,
        id_token: required(req.id_token.as_ref(), "id_token")?,
        nonce: required(req.nonce.as_ref(), "nonce")?,
    })
}

/// The scopes this grant issues: the requested ones, each of which must be
/// in the client's registered set.
///
/// The result is the intersection of the request with the registration, and
/// a requested scope outside it is **refused** (`invalid_scope`) rather than
/// dropped — the rule `/oauth2/authorize` applies to the same registration,
/// so a scope that would be refused there is not quietly narrowed away here.
/// An absent or empty `scope` is the empty set, as at `/authorize`: no
/// `openid`, so no ID token. Order is the request's; duplicates collapse.
///
/// `registered` is the client's set after the external-client ceiling.
///
/// # Errors
///
/// `invalid_scope` naming every requested scope the client is not registered
/// for.
pub fn requested_scopes(
    raw: Option<&str>,
    registered: &[String],
) -> Result<Vec<String>, OAuth2Error> {
    let mut scopes: Vec<String> = Vec::new();
    for scope in raw.unwrap_or("").split_whitespace() {
        if !scopes.iter().any(|s| s == scope) {
            scopes.push(scope.to_owned());
        }
    }
    let unregistered: Vec<&str> = scopes
        .iter()
        .filter(|s| !registered.contains(s))
        .map(String::as_str)
        .collect();
    if !unregistered.is_empty() {
        return Err(OAuth2Error::InvalidScope(format!(
            "unregistered scopes: {}",
            unregistered.join(", ")
        )));
    }
    Ok(scopes)
}

/// What the REST layer resolved about the consent this sign-in's scopes need,
/// for the user [`NativeSubject`] named.
///
/// The same two questions `/oauth2/authorize` asks, resolved by the same
/// functions over the same records — this crate decides, it does not fetch.
/// The default is the state of a request from an administrator's client
/// asking for nothing sensitive.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ConsentState {
    /// W7: the GDPR-sensitive scopes (`address`, `phone`).
    pub sensitive: crate::sensitive::Requested,
    /// W7: the tenant's effective settings have the sensitive scopes off.
    pub sensitive_switch_off: bool,
    /// T21.4 / D4: an externally registered client acting as the user.
    pub external: crate::external_consent::Requested,
}

/// D-N6: refuse any scope that would need a consent ceremony.
///
/// This grant has no interaction to offer — no browser, no consent screen —
/// so it is decided exactly as an `/authorize` request carrying `prompt=none`
/// on its first leg: what is consented (or needs no consent, which the
/// client's registration decides as it does today) proceeds, and what would
/// need the screen is `consent_required`. There is no implicit-consent switch
/// for first-party clients; that is a separate decision (D-N6).
///
/// # Errors
///
/// `invalid_scope` when the sensitive scopes are switched off for the tenant;
/// `consent_required` when a consent record is missing.
pub fn decide_consent(state: ConsentState) -> Result<(), OAuth2Error> {
    use crate::external_consent as external;
    use crate::sensitive;

    match sensitive::decide(state.sensitive, state.sensitive_switch_off, false, true) {
        sensitive::Decision::Proceed => {}
        sensitive::Decision::Refuse(sensitive::Refusal::Disabled) => {
            return Err(OAuth2Error::InvalidScope(
                "the address and phone scopes are not enabled for this tenant".into(),
            ));
        }
        // `AskForConsent` cannot come back with `prompt_none`, and `Declined`
        // cannot without a consent leg; both are answered as what they would
        // need — a ceremony this grant cannot hold.
        sensitive::Decision::AskForConsent
        | sensitive::Decision::Refuse(
            sensitive::Refusal::ConsentRequired | sensitive::Refusal::Declined,
        ) => {
            return Err(OAuth2Error::ConsentRequired(
                "releasing the requested scopes needs the end user's consent, which this grant \
                 cannot ask for; obtain it through an authorization request first"
                    .into(),
            ));
        }
    }
    match external::decide(state.external, false, true) {
        external::Decision::Proceed => Ok(()),
        external::Decision::AskForConsent | external::Decision::Refuse(_) => {
            Err(OAuth2Error::ConsentRequired(
                "this client was not registered by an administrator of this tenant, so the end \
                 user must consent before it may act as them, which this grant cannot ask for; \
                 obtain it through an authorization request first"
                    .into(),
            ))
        }
    }
}

/// What the wire sees for a refusal of §3.1 steps 2–7.
///
/// One `invalid_grant` with [`PUBLIC_REFUSAL_DESCRIPTION`] for every refusal
/// about the token or the configuration — a wrong token and a wrong
/// configuration are told apart only in the server log and the audit record
/// ([`NativeLoginError::reason_code`]) — and one generic `server_error` for a
/// datastore failure, the replay store's included.
pub fn refusal_for(e: &NativeLoginError) -> OAuth2Error {
    match e.refusal() {
        NativeLoginRefusal::InvalidGrant => {
            OAuth2Error::InvalidGrant(PUBLIC_REFUSAL_DESCRIPTION.into())
        }
        NativeLoginRefusal::ServerError => {
            OAuth2Error::ServerError(SERVER_REFUSAL_DESCRIPTION.into())
        }
    }
}

/// A client that passed step 1: authenticated, on a live tenant, within its
/// profile's rules, holding the grant, with its token binding decided.
#[derive(Debug, Clone)]
pub struct ProviderIdTokenClient {
    client: OAuth2Client,
    organization_id: Uuid,
    cnf: Option<CnfClaim>,
}

impl ProviderIdTokenClient {
    /// The authenticated client's registration.
    pub fn client(&self) -> &OAuth2Client {
        &self.client
    }
}

/// A request that passed step 2 as well: its scopes and target are decided.
#[derive(Debug, Clone)]
pub struct ProviderIdTokenGrant {
    client: ProviderIdTokenClient,
    scopes: Vec<String>,
    resource: Option<String>,
}

impl ProviderIdTokenGrant {
    /// The authenticated client's registration.
    pub fn client(&self) -> &OAuth2Client {
        &self.client.client
    }

    /// The scopes this sign-in will be granted, in request order.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// The organization of the requesting tenant, as the client
    /// authentication read it — what `login.post_auth` is told (F4-W2-01).
    pub fn organization_id(&self) -> Uuid {
        self.client.organization_id
    }
}

/// Where the sign-in came from, for the session row. Both values are already
/// bounded by the REST layer's extractors.
#[derive(Debug, Clone, Default)]
pub struct SignInOrigin {
    /// The caller's address, as the login paths record it.
    pub ip_address: Option<String>,
    /// The caller's `User-Agent`.
    pub user_agent: Option<String>,
}

impl<OC, AC, TR, RT, UR, SA, SR, AR> TokenService<OC, AC, TR, RT, UR, SA, SR, AR>
where
    OC: OAuth2ClientRepository,
    SA: ServiceAccountRepository,
    AC: AuthorizationCodeRepository,
    TR: TenantRepository,
    RT: RefreshTokenRepository,
    UR: UserRepository,
    SR: SessionRepository,
    AR: AuditLogRepository,
{
    /// Step 1: authenticate the client of a provider-id-token request and
    /// decide its token binding.
    ///
    /// A public client authenticates by presenting nothing and is refused if
    /// it presents a credential; a confidential one by the method its
    /// registration names (SEC-093). After authentication, and only then, the
    /// profile's request-time rules run and the grant must be registered —
    /// so `unauthorized_client` is learnt only by the credential's holder
    /// (SEC-086's ordering). The binding is decided last: a client registered
    /// for DPoP- or certificate-bound tokens whose request carries no proof
    /// is refused here, before the provider token is looked at.
    ///
    /// # Errors
    ///
    /// `invalid_request` without a `client_id`; `invalid_client` for an
    /// unknown client, a failed credential, a tombstoned tenant or an
    /// unsatisfiable binding; the codes of `fapi::enforce_token_request`;
    /// `unauthorized_client` for a client not registered for the grant.
    pub async fn authenticate_provider_id_token_client(
        &self,
        tenant_id: Uuid,
        req: &TokenRequest,
        ctx: &TokenRequestContext,
    ) -> Result<ProviderIdTokenClient, OAuth2Error> {
        let client_id = resolve_client_id(req.client_id.as_deref(), ctx)?;
        let client_secret = req.client_secret.as_deref();
        let refused = || OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into());
        let client = match self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
        {
            Ok(client) => client,
            Err(AxiamError::NotFound { .. }) => {
                // #679: a refusal costs the verify a wrong secret costs.
                spend_one_verify(client_secret, ctx);
                return Err(refused());
            }
            // QUAL-03/D-11: a datastore fault is not bad client credentials.
            Err(other) => return Err(OAuth2Error::ServerError(other.to_string())),
        };
        // Defence in depth: the lookup is tenant-scoped in SQL.
        if client.tenant_id != tenant_id {
            spend_one_verify(client_secret, ctx);
            return Err(refused());
        }
        // The public arm inside refuses a credential presented by a public
        // client; a confidential client with none is refused as a wrong one.
        let tenant = self
            .authenticate_client_credential(tenant_id, &client, client_secret, ctx)
            .await?;
        crate::fapi::enforce_token_request(&client, ctx.evidence())?;
        if !holds_provider_id_token_grant(&client.grant_types) {
            return Err(OAuth2Error::UnauthorizedClient(
                "client is not registered for the provider-id-token grant".into(),
            ));
        }
        let cnf = self.certificate_binding_for(&client, ctx)?;
        Ok(ProviderIdTokenClient {
            client,
            organization_id: tenant.organization_id,
            cnf,
        })
    }

    /// Step 2: the request's own parameters, decided before the provider token
    /// is verified — so a malformed request does not spend it.
    ///
    /// The scopes are checked against the client's registered set after the
    /// tenant's external-client ceiling (#613), and the RFC 8707 `resource`
    /// against its `allowed_resources`, exactly as `/oauth2/authorize` checks
    /// both.
    ///
    /// # Errors
    ///
    /// `invalid_request` for a missing grant parameter; `invalid_scope`;
    /// `invalid_target`; `server_error` when an external client's ceiling
    /// cannot be read.
    pub async fn prepare_provider_id_token_grant(
        &self,
        client: ProviderIdTokenClient,
        req: &TokenRequest,
    ) -> Result<ProviderIdTokenGrant, OAuth2Error> {
        native_request(req)?;
        let mut client = client;
        crate::scope_ceiling::apply_to_client(self.scope_policy.as_ref(), &mut client.client)
            .await?;
        let scopes = requested_scopes(req.scope.as_deref(), &client.client.scopes)?;
        let resource = crate::resource::resolve_requested(
            &client.client.allowed_resources,
            req.resource.as_deref(),
        )?;
        Ok(ProviderIdTokenGrant {
            client,
            scopes,
            resource,
        })
    }

    /// Steps 4 and 5 (§3.1 step 8): decide consent, then issue the client's
    /// ordinary sign-in token set for the user the provider token signed in.
    ///
    /// `nonce` is the request's raw nonce, which the AXIAM ID token carries
    /// back when `openid` was granted. Evidence (`auth_time`, `amr = [fed]`,
    /// and the class it earns) is recorded on the session and the refresh
    /// token whatever the client's lane, and released in the ID token only to
    /// a client on the lane that emits it — the code flow's rule.
    ///
    /// # Errors
    ///
    /// `invalid_scope` / `consent_required` from [`decide_consent`];
    /// `invalid_grant` when a reactor vetoes issuance; `server_error` for a
    /// datastore or signing failure.
    #[allow(clippy::too_many_arguments)]
    pub async fn issue_provider_id_token_grant(
        &self,
        tenant_id: Uuid,
        grant: &ProviderIdTokenGrant,
        subject: &NativeSubject,
        nonce: &str,
        consent: ConsentState,
        origin: SignInOrigin,
        ctx: &TokenRequestContext,
    ) -> Result<TokenResponse, OAuth2Error> {
        decide_consent(consent)?;
        if subject.tenant_id != tenant_id {
            // The federation service resolves users in the requesting tenant
            // only; a subject from anywhere else is an inconsistency, refused.
            return Err(OAuth2Error::ServerError(
                "native sign-in resolved a subject outside the requesting tenant".into(),
            ));
        }
        let client = &grant.client.client;
        let user_id = subject.user_id;

        // X1 — the `token.pre_issue` hook, before anything is written, so a
        // veto leaves no session behind.
        let ext = self
            .pre_issue_ext_claims(
                tenant_id,
                &user_id.to_string(),
                "user",
                &client.client_id,
                &grant.scopes,
            )
            .await?;

        // The session the federated browser sign-in would have created, with
        // the same evidence: the provider's `auth_time` clamped to now (D-10)
        // and `fed` alone (X7.2).
        let now = Utc::now();
        let evidence =
            AuthenticationEvidence::upstream(subject.upstream_auth_time, now, vec![Amr::Fed]);
        let session = self
            .session_repo
            .create(CreateSession {
                tenant_id,
                user_id,
                // The console refresh credential of this session, which nobody
                // is given: the client refreshes through its OAuth2 refresh
                // token, and `/auth/refresh` can never rotate this row.
                token_hash: hash_refresh_token(&generate_refresh_token()),
                ip_address: origin.ip_address,
                user_agent: origin.user_agent,
                expires_at: now + chrono::Duration::seconds(self.refresh_token_lifetime_secs),
                authenticated_at: evidence.authenticated_at,
                amr: evidence.amr.clone(),
                // No browser, so no `axiam_op_session` cookie to match.
                browser_token_hash: None,
            })
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        // W4 — the class this evidence earns, recorded only for a client on
        // the honour lane, as the authorization code records it.
        let acr = crate::fapi::honours_authn_params(client)
            .then(|| crate::acr::acr_for(&evidence.amr).as_str().to_owned());

        let cnf = grant.client.cnf.clone();
        let token_type = crate::dpop::token_type_for(cnf.as_ref());
        // #681 — a public DPoP client's refresh token is bound to its key.
        let refresh_jkt = crate::dpop::refresh_token_binding(client, cnf.as_ref());
        let audience = grant
            .resource
            .as_deref()
            .unwrap_or(axiam_auth::token::AUD_USER)
            .to_owned();
        let minting = self.minting_config(ctx.issuer.as_deref());
        let access_token = axiam_auth::token::AccessTokenSpec::user(
            user_id,
            tenant_id,
            grant.client.organization_id,
            Uuid::new_v4().to_string(),
        )
        .aud(&audience)
        .scopes(&grant.scopes)
        .cnf(cnf)
        .ext(ext)
        .client_id(Some(&client.client_id))
        .session(Some(session.id))
        .issue(&minting)
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        let refresh_token = if client.grant_types.iter().any(|g| g == "refresh_token") {
            let raw_refresh = generate_refresh_token();
            self.refresh_token_repo
                .create(CreateRefreshToken {
                    tenant_id,
                    token_hash: hash_refresh_token(&raw_refresh),
                    client_id: client.client_id.clone(),
                    user_id: Some(user_id),
                    scopes: grant.scopes.clone(),
                    session_id: Some(session.id),
                    requested_userinfo_claims: Vec::new(),
                    // RFC 8707 — the target travels with the grant.
                    resource: grant.resource.clone(),
                    // D-9 — the authentication this grant descends from, so a
                    // refreshed ID token reports the original.
                    auth_time: Some(evidence.authenticated_at),
                    acr: acr.clone(),
                    amr: evidence.amr.clone(),
                    dpop_jkt: refresh_jkt,
                    expires_at: now + chrono::Duration::seconds(self.refresh_token_lifetime_secs),
                })
                .await
                .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
            Some(raw_refresh)
        } else {
            None
        };

        let id_token = if grant.scopes.iter().any(|s| s == "openid") {
            let user = self
                .user_repo
                .get_by_id(tenant_id, user_id)
                .await
                .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
            let claims_evidence = if crate::fapi::emits_session_evidence(client) {
                super::evidence_from_snapshot(
                    Some(evidence.authenticated_at),
                    acr.as_deref(),
                    &evidence.amr,
                )
            } else {
                IdTokenEvidence::NONE
            };
            Some(
                issue_id_token(
                    user_id,
                    &client.client_id,
                    Some(nonce),
                    Some(&user.username),
                    &grant.scopes,
                    &minting,
                    Some(session.id),
                    &claims_evidence,
                )
                .map_err(|e| OAuth2Error::ServerError(e.to_string()))?,
            )
        } else {
            None
        };

        Ok(TokenResponse {
            access_token,
            token_type,
            expires_in: self.auth_config.access_token_lifetime_secs,
            refresh_token,
            scope: (!grant.scopes.is_empty()).then(|| grant.scopes.join(" ")),
            id_token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_consent::Requested as External;
    use crate::sensitive::Requested as Sensitive;

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    fn request(grant: &str) -> TokenRequest {
        serde_json::from_value(serde_json::json!({ "grant_type": grant })).unwrap()
    }

    /// The URN is the vendor family's, and distinct from every grant X4 owns.
    #[test]
    fn the_grant_urn_follows_the_vendor_family() {
        assert_eq!(
            PROVIDER_ID_TOKEN_GRANT_TYPE,
            "urn:axiam:params:oauth:grant-type:provider-id-token"
        );
        let family = crate::token_exchange::MAY_IMPERSONATE_GRANT
            .rsplit_once(':')
            .unwrap()
            .0;
        assert_eq!(
            PROVIDER_ID_TOKEN_GRANT_TYPE.rsplit_once(':').unwrap().0,
            family
        );
        assert_ne!(
            PROVIDER_ID_TOKEN_GRANT_TYPE,
            crate::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE
        );
    }

    /// The gate is the registration's list and nothing else — no default set,
    /// and no near-miss spelling.
    #[test]
    fn the_gate_is_an_exact_entry_in_the_registration() {
        assert!(holds_provider_id_token_grant(&strings(&[
            "authorization_code",
            PROVIDER_ID_TOKEN_GRANT_TYPE,
        ])));
        assert!(!holds_provider_id_token_grant(&strings(&[
            "authorization_code",
            "refresh_token",
        ])));
        assert!(!holds_provider_id_token_grant(&strings(&[
            crate::token_exchange::TOKEN_EXCHANGE_GRANT_TYPE,
            crate::token_exchange::MAY_IMPERSONATE_GRANT,
        ])));
        assert!(!holds_provider_id_token_grant(&strings(&[
            "urn:axiam:params:oauth:grant-type:provider-id-token ",
            "provider-id-token",
        ])));
        assert!(!holds_provider_id_token_grant(&[]));
    }

    /// Each parameter is required by name, and an empty one is absent.
    #[test]
    fn the_three_parameters_are_required() {
        let mut r = request(PROVIDER_ID_TOKEN_GRANT_TYPE);
        r.provider = Some("google".into());
        r.id_token = Some("a.b.c".into());
        r.nonce = Some("n-0S6_WzA2Mj".into());
        let ok = native_request(&r).unwrap();
        assert_eq!(
            (ok.provider, ok.id_token, ok.nonce),
            ("google", "a.b.c", "n-0S6_WzA2Mj")
        );

        for (name, clear) in [("provider", 0usize), ("id_token", 1), ("nonce", 2)] {
            for value in [None, Some(String::new()), Some("  ".to_owned())] {
                let mut r = r.clone_for_test();
                match clear {
                    0 => r.provider = value.clone(),
                    1 => r.id_token = value.clone(),
                    _ => r.nonce = value.clone(),
                }
                match native_request(&r) {
                    Err(OAuth2Error::InvalidRequest(m)) => assert!(m.starts_with(name), "{m}"),
                    other => panic!("{name} = {value:?}: {other:?}"),
                }
            }
        }
    }

    /// The issued scopes are the request within the registration; a scope
    /// outside it is refused by name, never silently dropped.
    #[test]
    fn scopes_are_the_request_within_the_registration() {
        let registered = strings(&["openid", "profile", "email", "read:orders"]);
        assert_eq!(
            requested_scopes(Some("openid profile openid"), &registered).unwrap(),
            strings(&["openid", "profile"])
        );
        assert!(requested_scopes(None, &registered).unwrap().is_empty());
        assert!(
            requested_scopes(Some("   "), &registered)
                .unwrap()
                .is_empty()
        );
        match requested_scopes(Some("openid admin:all phone"), &registered) {
            Err(OAuth2Error::InvalidScope(m)) => {
                assert_eq!(m, "unregistered scopes: admin:all, phone");
            }
            other => panic!("{other:?}"),
        }
    }

    /// An administrator's client asking for nothing sensitive proceeds, and
    /// so does a recorded consent.
    #[test]
    fn what_needs_no_ceremony_proceeds() {
        assert!(decide_consent(ConsentState::default()).is_ok());
        assert!(
            decide_consent(ConsentState {
                sensitive: Sensitive::Consented,
                sensitive_switch_off: false,
                external: External::Consented,
            })
            .is_ok()
        );
    }

    /// D-N6: whatever would need the consent screen is `consent_required`.
    #[test]
    fn a_scope_that_needs_a_ceremony_is_consent_required() {
        for state in [
            ConsentState {
                sensitive: Sensitive::ConsentMissing,
                ..ConsentState::default()
            },
            ConsentState {
                external: External::ConsentMissing,
                ..ConsentState::default()
            },
            ConsentState {
                sensitive: Sensitive::Consented,
                sensitive_switch_off: false,
                external: External::ConsentMissing,
            },
        ] {
            let e = decide_consent(state).unwrap_err();
            assert_eq!(e.error_code(), "consent_required", "{state:?}");
        }
    }

    /// The operator's switch outranks consent, here as at `/authorize`.
    #[test]
    fn the_sensitive_switch_outranks_everything() {
        for sensitive in [Sensitive::Disabled, Sensitive::Consented] {
            let e = decide_consent(ConsentState {
                sensitive,
                sensitive_switch_off: true,
                external: External::NotApplicable,
            })
            .unwrap_err();
            assert_eq!(e.error_code(), "invalid_scope", "{sensitive:?}");
        }
    }

    /// Every refusal about the token or the configuration is one wire answer;
    /// only a datastore failure differs, and it names nothing either.
    #[test]
    fn every_token_refusal_is_one_generic_invalid_grant() {
        let token_or_config = [
            NativeLoginError::ProviderNotFound,
            NativeLoginError::ProviderUnavailable("dns".into()),
            NativeLoginError::AlgorithmRefused,
            NativeLoginError::UnknownKey,
            NativeLoginError::KeysUnavailable("timeout".into()),
            NativeLoginError::BadSignature,
            NativeLoginError::WrongIssuer,
            NativeLoginError::WrongAudience,
            NativeLoginError::AuthorizedPartyRefused,
            NativeLoginError::Expired,
            NativeLoginError::TooOld,
            NativeLoginError::IssuedInFuture,
            NativeLoginError::ClaimRejected("sub".into()),
            NativeLoginError::WrongTokenShape("at+jwt".into()),
            NativeLoginError::NonceMissing,
            NativeLoginError::NonceMismatch,
            NativeLoginError::Replayed,
            NativeLoginError::SubjectUnmapped,
            NativeLoginError::AccountRefused("locked".into()),
        ];
        for e in &token_or_config {
            match refusal_for(e) {
                OAuth2Error::InvalidGrant(m) => assert_eq!(m, PUBLIC_REFUSAL_DESCRIPTION, "{e:?}"),
                other => panic!("{e:?} -> {other:?}"),
            }
        }
        for e in [
            NativeLoginError::ReplayGuardUnavailable("db down".into()),
            NativeLoginError::Server("db down".into()),
        ] {
            match refusal_for(&e) {
                OAuth2Error::ServerError(m) => {
                    assert_eq!(m, SERVER_REFUSAL_DESCRIPTION);
                    assert!(!m.contains("db down"), "the detail stays in the log");
                }
                other => panic!("{e:?} -> {other:?}"),
            }
        }
    }

    /// The audit action is in the `federation.` family and within the action
    /// grammar the audit ingestion enforces.
    #[test]
    fn the_audit_action_is_a_federation_action() {
        assert_eq!(NATIVE_LOGIN_AUDIT_ACTION, "federation.native_login");
        assert!(axiam_core::models::audit::is_valid_audit_action(
            NATIVE_LOGIN_AUDIT_ACTION
        ));
        assert!(
            axiam_core::models::audit::reserved_action_namespace(NATIVE_LOGIN_AUDIT_ACTION)
                .is_none()
        );
    }

    impl TokenRequest {
        fn clone_for_test(&self) -> Self {
            let mut r = request(&self.grant_type);
            r.provider = self.provider.clone();
            r.id_token = self.id_token.clone();
            r.nonce = self.nonce.clone();
            r
        }
    }
}

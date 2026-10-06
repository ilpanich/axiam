//! The CIBA grant at the token endpoint (G-7, CIBA Core §10–11).
//!
//! A child module of [`crate::token`] so that it issues through exactly the
//! private machinery the other user grants use — client authentication by the
//! registered method, the profile's request-time rules, sender-constraining,
//! the `token.pre_issue` reactor hook, the refresh-token snapshot — rather
//! than through a copy of it. The pending-request store is a parameter, not a
//! ninth type parameter on `TokenService`, because only this grant reads it.
//!
//! # Order, and what each step may write
//!
//! 1. `auth_req_id` present — decidable from the request alone.
//! 2. **The client authenticates**, by its registered method, and the
//!    profile's request-time rules run (`enforce_token_request`, D-17). The
//!    client must hold the grant.
//! 3. The request is looked up **in this tenant, for this client**. Another
//!    client's (or tenant's) `auth_req_id` is `invalid_grant`, exactly like an
//!    unknown one — and nothing has been written for it.
//! 4. Only now is the poll recorded (T-404's lesson: nothing is written for a
//!    request before the request carrying it is validated), as a
//!    compare-and-set on the `last_polled_at` read in step 3, and the back-off
//!    decided: inside the interval is `slow_down`, whatever the state.
//! 5. Expired → `expired_token` (and the row marked, conditionally).
//!    Pending → `authorization_pending`, denied → `access_denied`, redeemed →
//!    `invalid_grant`.
//! 6. Approved → redeemed on the X6 two-layer arbiter, conditional on the
//!    client; a lost race is `invalid_grant`.
//! 7. The subject is re-read **after** redemption (so a refused account burns
//!    the approval): an account that may no longer act, or is under
//!    brute-force lockout, is `invalid_grant`.
//! 8. Tokens are minted with the approval's evidence: the access token names
//!    the approving session in `sid` (ending that session ends them), the ID
//!    token carries `auth_time`, `acr` (the reported class, `report_acr`) and
//!    `amr`, and a refresh token — only for a client holding `refresh_token` —
//!    carries the same snapshot (D-9).

use axiam_auth::token::{
    IdTokenEvidence, generate_refresh_token, hash_refresh_token, issue_id_token,
};
use axiam_core::error::AxiamError;
use axiam_core::models::ciba::{CIBA_GRANT_TYPE, CibaRequestStatus};
use axiam_core::models::oauth2_client::CreateRefreshToken;
use axiam_core::repository::{
    AuditLogRepository, AuthorizationCodeRepository, CibaRequestRepository, OAuth2ClientRepository,
    RefreshTokenRepository, ServiceAccountRepository, TenantRepository, UserRepository,
};
use chrono::Utc;
use uuid::Uuid;

use super::{CLIENT_AUTH_FAILED, TokenRequest, TokenRequestContext, TokenResponse, TokenService};
use crate::acr::{Acr, report_acr};
use crate::ciba::{hash_auth_req_id, holds_ciba_grant, poll_backoff, user_may_be_subject};
use crate::error::OAuth2Error;

impl<OC, AC, TR, RT, UR, SA, SR, AR> TokenService<OC, AC, TR, RT, UR, SA, SR, AR>
where
    OC: OAuth2ClientRepository,
    SA: ServiceAccountRepository,
    AC: AuthorizationCodeRepository,
    TR: TenantRepository,
    RT: RefreshTokenRepository,
    UR: UserRepository,
    SR: axiam_core::repository::SessionRepository,
    AR: AuditLogRepository,
{
    /// `grant_type=urn:openid:params:grant-type:ciba` (CIBA Core §10.1).
    ///
    /// See the module documentation for the order of checks and what each
    /// may write.
    ///
    /// # Errors
    ///
    /// The CIBA Core §11 / RFC 6749 §5.2 code for each refusal.
    pub async fn exchange_ciba<CR: CibaRequestRepository>(
        &self,
        tenant_id: Uuid,
        req: TokenRequest,
        ctx: &TokenRequestContext,
        requests: &CR,
    ) -> Result<TokenResponse, OAuth2Error> {
        // --- 1. the parameter --------------------------------------------
        let auth_req_id = req
            .auth_req_id
            .as_deref()
            .filter(|v| !v.is_empty())
            .ok_or_else(|| {
                OAuth2Error::InvalidRequest("auth_req_id is required for the CIBA grant".into())
            })?;
        let client_id = super::resolve_client_id(req.client_id.as_deref(), ctx)?;

        // --- 2. the client -------------------------------------------------
        //
        // A CIBA client is never public (`ciba::validate_client_registration`),
        // so a request carrying no credential is refused before the lookup —
        // one answer whether or not the client exists (SEC-086's ordering).
        let client_secret = req.client_secret.as_deref();
        if ctx.carries_no_client_credential(client_secret) {
            return Err(OAuth2Error::InvalidClient(
                "client authentication is required".into(),
            ));
        }
        let client = self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => {
                    OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into())
                }
                other => OAuth2Error::ServerError(other.to_string()),
            })?;
        if client.tenant_id != tenant_id {
            return Err(OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into()));
        }
        self.authenticate_client_credential(tenant_id, &client, client_secret, ctx)
            .await?;
        crate::fapi::enforce_token_request(&client, ctx.evidence())?;
        if !holds_ciba_grant(&client.grant_types) {
            return Err(OAuth2Error::UnauthorizedClient(
                "client not authorized for the CIBA grant".into(),
            ));
        }

        // --- 3. the request, for this client -------------------------------
        let hash = hash_auth_req_id(auth_req_id);
        let unknown = || OAuth2Error::InvalidGrant("auth_req_id is invalid".into());
        let row = requests
            .get_by_hash(tenant_id, &hash)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
            .filter(|r| r.client_id == client.client_id && r.tenant_id == tenant_id)
            .ok_or_else(unknown)?;

        // --- 4. the poll, recorded only now --------------------------------
        let now = Utc::now();
        let (too_fast, next_interval) = poll_backoff(row.interval_secs, row.last_polled_at, now);
        let recorded = requests
            .record_poll(tenant_id, row.id, row.last_polled_at, now, next_interval)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
        if too_fast || !recorded {
            // A lost compare-and-set is another token request for the same
            // `auth_req_id` landing in between: polling too fast by definition.
            return Err(OAuth2Error::SlowDown);
        }

        // --- 5. the state --------------------------------------------------
        if row.status == CibaRequestStatus::Expired || row.is_expired_at(now) {
            if matches!(
                row.status,
                CibaRequestStatus::Pending | CibaRequestStatus::Approved
            ) && let Err(e) = requests.mark_expired(tenant_id, row.id, row.version).await
            {
                // Best effort: the sweep marks it too, and the answer below
                // does not depend on the mark.
                tracing::debug!(error = %e, "could not mark an expired CIBA request");
            }
            return Err(OAuth2Error::ExpiredToken);
        }
        // RFC 8707 — the target was decided at `bc-authorize`; a token request
        // may repeat it, never change it. Checked before the state so a client
        // mis-sending it learns on its first poll.
        let resource =
            crate::resource::resolve_bound(row.resource.as_deref(), req.resource.as_deref())?;
        match row.status {
            CibaRequestStatus::Pending => return Err(OAuth2Error::AuthorizationPending),
            CibaRequestStatus::Denied => {
                return Err(OAuth2Error::AccessDenied(
                    "the user denied the request".into(),
                ));
            }
            CibaRequestStatus::Redeemed => {
                return Err(OAuth2Error::InvalidGrant(
                    "auth_req_id has already been used".into(),
                ));
            }
            CibaRequestStatus::Expired => return Err(OAuth2Error::ExpiredToken),
            CibaRequestStatus::Approved => {}
        }

        // --- 6. single use, on the X6 arbiter ------------------------------
        let redeemed = requests
            .redeem(tenant_id, &hash, &client.client_id)
            .await
            .map_err(|e| OAuth2Error::ServerError(e.to_string()))?
            .ok_or_else(|| OAuth2Error::InvalidGrant("auth_req_id has already been used".into()))?;
        let (Some(user_id), Some(approval)) = (redeemed.user_id, redeemed.approval.clone()) else {
            // An approved request with no subject or no evidence is a datastore
            // inconsistency: refuse rather than mint a token for nobody.
            return Err(OAuth2Error::ServerError(
                "approved CIBA request carries no subject".into(),
            ));
        };

        // --- 7. the subject, re-read after the approval is spent ------------
        let refused = || {
            OAuth2Error::InvalidGrant(
                "the account this grant was issued for can no longer sign in".into(),
            )
        };
        let user = match self.user_repo.get_by_id(tenant_id, user_id).await {
            Ok(user) => user,
            Err(AxiamError::NotFound { .. }) => return Err(refused()),
            Err(e) => return Err(OAuth2Error::ServerError(e.to_string())),
        };
        if !user_may_be_subject(&user) {
            tracing::info!(
                %tenant_id,
                %user_id,
                "refusing a CIBA redemption: the account may no longer sign in or is locked out"
            );
            return Err(refused());
        }

        // --- 8. issuance ---------------------------------------------------
        let tenant = self
            .tenant_repo
            .get_by_id(tenant_id)
            .await
            .map_err(|e| match e {
                AxiamError::NotFound { .. } => OAuth2Error::InvalidRequest("unknown tenant".into()),
                other => OAuth2Error::ServerError(other.to_string()),
            })?;
        let cnf = self.certificate_binding_for(&client, ctx)?;
        let token_type = crate::dpop::token_type_for(cnf.as_ref());
        let ext = self
            .pre_issue_ext_claims(
                tenant_id,
                &user_id.to_string(),
                "user",
                &client.client_id,
                &redeemed.scopes,
            )
            .await?;
        let audience = resource
            .as_deref()
            .unwrap_or(axiam_auth::token::AUD_USER)
            .to_owned();
        let minting = self.minting_config(ctx.issuer.as_deref());
        let access_token = axiam_auth::token::AccessTokenSpec::user(
            user_id,
            tenant_id,
            tenant.organization_id,
            Uuid::new_v4().to_string(),
        )
        .aud(&audience)
        .scopes(&redeemed.scopes)
        .cnf(cnf)
        .ext(ext)
        .client_id(Some(&client.client_id))
        .session(Some(approval.session_id))
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
                    scopes: redeemed.scopes.clone(),
                    session_id: Some(approval.session_id),
                    requested_userinfo_claims: Vec::new(),
                    resource: resource.clone(),
                    // D-9 — the approval's evidence travels with the grant, so
                    // a refreshed ID token reports the original authentication.
                    auth_time: Some(approval.auth_time),
                    acr: Some(approval.acr.clone()),
                    amr: approval.amr.clone(),
                    expires_at: Utc::now()
                        + chrono::Duration::seconds(self.refresh_token_lifetime_secs),
                })
                .await
                .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;
            Some(raw_refresh)
        } else {
            None
        };

        // CIBA Core §10.1.1: an ID token is always returned (the scope always
        // carries `openid`). It reports the approval: what was achieved, in the
        // class the request asked for when the achievement satisfies it.
        let achieved = Acr::from_wire(&approval.acr).unwrap_or(Acr::SingleFactor);
        let evidence = IdTokenEvidence {
            auth_time: Some(approval.auth_time.timestamp()),
            acr: Some(report_acr(achieved, &redeemed.acr_values).to_owned()),
            amr: axiam_core::models::session::Amr::encode_list(&approval.amr),
        };
        let id_token = issue_id_token(
            user_id,
            &client.client_id,
            None,
            Some(&user.username),
            &redeemed.scopes,
            &minting,
            Some(approval.session_id),
            &evidence,
        )
        .map_err(|e| OAuth2Error::ServerError(e.to_string()))?;

        tracing::debug!(
            client_id = %client.client_id,
            grant_type = CIBA_GRANT_TYPE,
            "CIBA request redeemed"
        );

        Ok(TokenResponse {
            access_token,
            token_type,
            expires_in: self.auth_config.access_token_lifetime_secs,
            refresh_token,
            scope: Some(redeemed.scopes.join(" ")),
            id_token: Some(id_token),
        })
    }
}

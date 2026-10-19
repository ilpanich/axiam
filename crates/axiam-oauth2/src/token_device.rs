//! The device grant's client authentication (#635, R101W3-01).
//!
//! A child module of [`crate::token`] so that the device grant authenticates
//! its client through exactly the private machinery every other grant uses —
//! the credential the **registration** names (SEC-093), the tenant's liveness
//! (R1W1-03), the profile's request-time rules (D-17) and the token binding
//! (X5.1, RFC 9449) — rather than through a copy of it. The grant itself (the
//! device code, the user code, the poll's state machine) stays in
//! [`crate::device_service`], which accepts only the [`DeviceClient`] these
//! methods return.
//!
//! # Why the device grant authenticates a client at all
//!
//! It used to authenticate none: the poll was dispatched before the token
//! endpoint built its request context and found the grant by the device
//! code's hash alone. That reading of RFC 8628 holds for public clients only.
//! RFC 8628 §3.4's token request is an RFC 6749 token request — `client_id` is
//! required of a client that does not authenticate — and RFC 6749 §3.2.1 has
//! a confidential client authenticate at the token endpoint; RFC 8628 §3.1
//! applies the same rule at the device authorization endpoint. An
//! administrator may register the grant on any client (the admin API admits
//! it whatever the method or profile), so without this a leaked device code
//! was a bearer credential, anyone knowing a confidential client's id could
//! run a device flow in its name, a DPoP-, mTLS-bound or `fapi2` client got an
//! unbound bearer token, and an approved grant redeemed after the client lost
//! the grant or rotated its secret.
//!
//! # Order, and what each refusal costs
//!
//! 1. The client is read. An unknown one is `invalid_client`
//!    ([`CLIENT_AUTH_FAILED`]), and — when the caller presented a secret —
//!    costs the one HMAC verify a wrong secret costs, against a hash no
//!    secret produces (§10: every refusal of a credential check costs one
//!    verify). A public client that presented a credential is refused the
//!    same way and at the same cost.
//! 2. The client authenticates by its registered method
//!    (`authenticate_client_credential`), which also finds its tenant live: a
//!    tombstoned tenant's client is the same `invalid_client` (#641 (a)).
//! 3. The profile's request-time rule: the whole of
//!    [`crate::fapi::enforce_token_request`] at the poll, its
//!    client-authentication rule alone at `/oauth2/device_authorization`,
//!    whose request carries no DPoP proof to judge (as at PAR and
//!    `bc-authorize`).
//! 4. The client must hold the grant: `unauthorized_client` at the start, as
//!    before; `invalid_client` at the poll, where a client that lost the grant
//!    after its user approved is refused the approval.
//! 5. At the poll, the binding: `cnf.x5t#S256` and/or `cnf.jkt` as the client
//!    registered, refused rather than downgraded when the request does not
//!    carry the certificate or proof.
//!
//! Nothing here reads or writes a device grant, so a caller who fails any of
//! these steps — a caller holding only a leaked device code among them — has
//! not touched the grant: it is not spent, its poll is not recorded, and its
//! state is not revealed.

use axiam_core::error::AxiamError;
use axiam_core::models::oauth2_client::OAuth2Client;
use axiam_core::models::tenant::Tenant;
use axiam_core::repository::{
    AuditLogRepository, AuthorizationCodeRepository, OAuth2ClientRepository,
    RefreshTokenRepository, ServiceAccountRepository, TenantRepository, UserRepository,
};
use uuid::Uuid;

use super::{
    CLIENT_AUTH_FAILED, TokenRequest, TokenRequestContext, TokenService, resolve_client_id,
    spend_one_verify,
};
use crate::device_service::{DeviceClient, holds_device_grant};
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
    /// Authenticate the client of a `POST /oauth2/device_authorization`
    /// (RFC 8628 §3.1).
    ///
    /// See the module documentation for the order. A public client
    /// authenticates by presenting nothing, exactly as before; a confidential
    /// one now needs its credential here too.
    ///
    /// # Errors
    ///
    /// `invalid_client` for an unknown client, a wrong or missing credential,
    /// a credential presented by a public client, a tombstoned tenant or a
    /// `fapi2` row on a shared-secret method; `unauthorized_client` for a
    /// client that does not hold the grant; `server_error` for a datastore
    /// fault.
    pub async fn authenticate_device_authorization(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        client_secret: Option<&str>,
        ctx: &TokenRequestContext,
    ) -> Result<DeviceClient, OAuth2Error> {
        let (client, tenant) = self
            .authenticate_device_client(tenant_id, client_id, client_secret, ctx)
            .await?;
        crate::fapi::enforce_client_authentication(&client)?;
        if !holds_device_grant(&client.grant_types) {
            return Err(OAuth2Error::UnauthorizedClient(
                "client is not registered for the device authorization grant".into(),
            ));
        }
        Ok(DeviceClient::new(client, tenant.organization_id, None))
    }

    /// Authenticate the client of a device-code token request (RFC 8628 §3.4)
    /// and decide the binding of the token it may receive.
    ///
    /// `client_id` is required: from the body, or from the `Authorization:
    /// Basic` header or the client assertion of a client authenticating that
    /// way (`resolve_client_id`). The grant is not read here; the caller hands
    /// the returned [`DeviceClient`] to
    /// [`crate::device_service::DeviceAuthorizationService::poll_at`], which
    /// refuses a grant issued to any other client as an unknown one.
    ///
    /// # Errors
    ///
    /// `invalid_request` without a `client_id`; `invalid_client` for an
    /// unknown client, a failed credential, a tombstoned tenant, a client that
    /// no longer holds the grant, or a binding the request cannot satisfy;
    /// the codes of [`crate::fapi::enforce_token_request`] for a `fapi2`
    /// client.
    pub async fn authenticate_device_poll(
        &self,
        tenant_id: Uuid,
        req: &TokenRequest,
        ctx: &TokenRequestContext,
    ) -> Result<DeviceClient, OAuth2Error> {
        let client_id = resolve_client_id(req.client_id.as_deref(), ctx)?;
        let (client, tenant) = self
            .authenticate_device_client(tenant_id, client_id, req.client_secret.as_deref(), ctx)
            .await?;
        // After authentication, as at every grant: the refusal reports a fact
        // about the registration, which only the credential's holder may learn.
        crate::fapi::enforce_token_request(&client, ctx.evidence())?;
        if !holds_device_grant(&client.grant_types) {
            // `invalid_client` rather than the `unauthorized_client` the start
            // endpoint answers: the poll treats a client whose registration no
            // longer admits the grant as it treats a client that is gone — the
            // registration the user approved no longer exists in that form.
            // Either way the grant is not touched.
            return Err(OAuth2Error::InvalidClient(
                "client is no longer registered for the device authorization grant".into(),
            ));
        }
        let cnf = self.certificate_binding_for(&client, ctx)?;
        Ok(DeviceClient::new(client, tenant.organization_id, cnf))
    }

    /// Steps 1 and 2 of the module documentation, shared by both endpoints.
    async fn authenticate_device_client(
        &self,
        tenant_id: Uuid,
        client_id: &str,
        client_secret: Option<&str>,
        ctx: &TokenRequestContext,
    ) -> Result<(OAuth2Client, Tenant), OAuth2Error> {
        let refused = || OAuth2Error::InvalidClient(CLIENT_AUTH_FAILED.into());
        let client = match self
            .client_repo
            .get_by_client_id(tenant_id, client_id)
            .await
        {
            Ok(client) => client,
            Err(AxiamError::NotFound { .. }) => {
                spend_one_verify(client_secret, ctx);
                return Err(refused());
            }
            // QUAL-03/D-11: a datastore fault is not bad client credentials.
            Err(other) => return Err(OAuth2Error::ServerError(other.to_string())),
        };
        // Defence in depth, as in `authenticate_client`: the lookup is
        // tenant-scoped in SQL.
        if client.tenant_id != tenant_id {
            spend_one_verify(client_secret, ctx);
            return Err(refused());
        }
        // A credential presented for a public client is refused inside
        // `authenticate_client_credential`, which spends the verify for it.
        let tenant = self
            .authenticate_client_credential(tenant_id, &client, client_secret, ctx)
            .await?;
        Ok((client, tenant))
    }
}

#[cfg(test)]
mod tests {
    use crate::token::UNKNOWN_CLIENT_SECRET_HASH;
    use axiam_auth::client_secret;

    /// The equalising hash is a well-formed current-scheme hash, so the
    /// verify it is fed takes the same branch, and costs the same, as a
    /// verify against a real client's row.
    #[test]
    fn the_unknown_client_hash_is_a_well_formed_v2_hash() {
        assert_eq!(
            UNKNOWN_CLIENT_SECRET_HASH.len(),
            axiam_auth::client_secret::V2_HASH_LEN
        );
        assert!(UNKNOWN_CLIENT_SECRET_HASH.starts_with(axiam_auth::client_secret::V2_PREFIX));
        let hasher = client_secret::global().unwrap();
        assert!(
            !hasher
                .verify("anything", UNKNOWN_CLIENT_SECRET_HASH)
                .is_match()
        );
        assert!(!hasher.verify("", UNKNOWN_CLIENT_SECRET_HASH).is_match());
    }
}

//! What removing an OAuth2 client revokes (#517).
//!
//! Three paths remove a client row: an administrator's
//! `DELETE /api/v1/oauth2-clients/{id}`, RFC 7592's
//! `DELETE /oauth2/register/{client_id}` and the unused-client sweep. Each
//! calls [`ClientGrantStores::revoke`], so they cannot disagree about what a
//! removed client leaves behind.
//!
//! # Why anything needs revoking
//!
//! With the row gone every grant fails at client authentication — but only
//! while the `client_id` names nothing. A `managed_by: cimd` client's
//! `client_id` is its metadata document's URL, and `materialise_if_cimd`
//! writes the row back on the client's next request. Whatever the old row's
//! client still held would then work again. Before #517 nothing was revoked,
//! and every refresh token issued before an administrator's delete refreshed
//! against the re-materialised row.
//!
//! # What is revoked, and what is not
//!
//! * **Refresh tokens** — marked revoked (`revoke_all_for_client`).
//! * **Authorization codes** — deleted, redeemed or not. Deleted rather than
//!   marked used, because a used code presented again is answered as a replay
//!   (the session it came from is revoked), and a voided code is not evidence
//!   of theft.
//! * **Pushed authorization requests** — deleted, spent or not.
//! * **Device grants** (RFC 8628) — deleted in every status. An *approved*
//!   grant is the dangerous one: the device holds the device code and is
//!   polling, and the poll authenticated no client (R101W3-01), so the grant
//!   redeemed whether or not its client still existed (#610 (d)). (This module
//!   used to give a re-materialised CIMD client as the reason. That was wrong:
//!   a CIMD client registers only the code grants and can hold neither this
//!   grant nor CIBA, #642 (a). The poll now authenticates the client, #635, and
//!   refuses `invalid_client` while no row names the `client_id`; deleting the
//!   grant is what refuses a row that names it again.) A poll in flight when
//!   the delete lands is safe in the same way: `redeem` is one guarded
//!   `UPDATE … WHERE status = 'approved'`, so once the row is gone it matches
//!   nothing, however recently the poll read the grant. A poll whose redeem
//!   committed *before* the delete has already minted for the old client and
//!   holds a refresh token the second revoke pass (run by every caller after
//!   the row is gone) voids, unless it was written after that pass too — the
//!   window every flow shares, bounded by the access-token lifetime.
//! * **CIBA requests** (OpenID CIBA) — deleted in every status: an approved
//!   one would otherwise outlive its client, and a pending one would stay on
//!   the user's approval surface naming a client that no longer exists.
//!   `redeem` is guarded the same way.
//! * **Access tokens** — self-contained JWTs, revoked by nothing in AXIAM;
//!   they expire within the access-token lifetime.
//! * **The end user's AXIAM sessions** — not the client's to end: they are
//!   shared with every other relying party, and ending them because one client
//!   went away would be a forced logout a stranger could trigger through
//!   RFC 7592.
//! * **D4 consent records** — left to the users who gave them. A `dcr` or
//!   `admin` identifier is never reissued, and a re-materialised CIMD client is
//!   the same document at the same URL the user consented to.

use axiam_core::error::AxiamResult;
use axiam_core::repository::{
    AuthorizationCodeRepository, CibaRequestRepository, DeviceGrantRepository,
    PushedAuthRequestRepository, RefreshTokenRepository,
};
use uuid::Uuid;

/// The stores holding what a client was granted, revoked together when the
/// client is removed. See the [module documentation](self).
#[derive(Debug, Clone)]
pub struct ClientGrantStores<RT, AC, PR, DG, CB> {
    refresh_tokens: RT,
    codes: AC,
    pushed_requests: PR,
    device_grants: DG,
    ciba_requests: CB,
}

impl<RT, AC, PR, DG, CB> ClientGrantStores<RT, AC, PR, DG, CB>
where
    RT: RefreshTokenRepository,
    AC: AuthorizationCodeRepository,
    PR: PushedAuthRequestRepository,
    DG: DeviceGrantRepository,
    CB: CibaRequestRepository,
{
    /// Group the five stores.
    pub fn new(
        refresh_tokens: RT,
        codes: AC,
        pushed_requests: PR,
        device_grants: DG,
        ciba_requests: CB,
    ) -> Self {
        Self {
            refresh_tokens,
            codes,
            pushed_requests,
            device_grants,
            ciba_requests,
        }
    }

    /// Revoke every refresh token, and delete every authorization code,
    /// pushed request, device grant and CIBA request, issued to `client_id` in
    /// `tenant_id`.
    ///
    /// Idempotent, so a caller may run it before and again after removing the
    /// row. The stores are visited in a fixed order (refresh tokens, codes,
    /// pushed requests, device grants, CIBA requests) and the first failure is
    /// returned without visiting the rest — the ones already done stay done,
    /// the ones after it are retried by the next call. A caller that has not
    /// yet removed the row should then keep it, so the removal can be retried
    /// rather than leave a row-less client whose grants are still live.
    pub async fn revoke(&self, tenant_id: Uuid, client_id: &str) -> AxiamResult<()> {
        self.refresh_tokens
            .revoke_all_for_client(tenant_id, client_id)
            .await?;
        self.codes
            .delete_all_for_client(tenant_id, client_id)
            .await?;
        self.pushed_requests
            .delete_all_for_client(tenant_id, client_id)
            .await?;
        self.device_grants
            .delete_all_for_client(tenant_id, client_id)
            .await?;
        self.ciba_requests
            .delete_all_for_client(tenant_id, client_id)
            .await?;
        Ok(())
    }
}

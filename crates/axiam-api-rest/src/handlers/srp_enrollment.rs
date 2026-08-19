//! Recording an SRP verifier at the moments a plaintext password legitimately
//! exists.
//!
//! There are exactly three such moments — user creation, an authenticated
//! password change, and password-reset completion — and this module is the one
//! place that handles all three, so the validation and the policy checks cannot
//! drift between them.
//!
//! # Why enrolment has to be client-driven
//!
//! The server cannot compute a verifier. `v = g^x mod N` where
//! `x = KDF(identity ":" password, salt)`, and the whole point of SRP is that
//! the server never sees the password. So the client computes `v` and posts it;
//! the server's job is to check that what arrived is well-formed, meets the
//! tenant's policy, and is attributed to the right account — never to trust the
//! client about *whose* account it is. That is why [`SrpEnrollment`] carries no
//! user id: the tenant, user and canonical identity are all taken from the
//! authenticated server-side context.
//!
//! # Why a missing verifier is sometimes an error
//!
//! Under [`SrpMode::Required`] a password set without a verifier produces an
//! account that cannot authenticate at all: password login is refused
//! tenant-wide, and there is nothing for `/auth/srp/challenge` to answer with.
//! Accepting it silently would mean an admin creating a user, seeing `201`, and
//! discovering only later that the account was born unusable. So it is rejected
//! at the point of creation, where the message can say what to do about it.

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::settings::{SrpPolicy, srp_kdf_is_at_least};
use axiam_core::models::srp::{CreateSrpCredential, SrpEnrollment, SrpMode};
use axiam_core::repository::SrpCredentialRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::state::AppState;

/// Validate and store a client-computed verifier for `user_id`.
///
/// `identity` must be the user's canonical `username` — the same string the
/// challenge endpoint will hand back to clients, and the same one the client
/// must have used inside the KDF. Passing anything else here produces a
/// verifier that can never be satisfied.
///
/// A `None` enrolment is accepted under `disabled` and `optional`, and refused
/// under `required`.
pub(crate) async fn record_verifier<C: Connection + Clone>(
    state: &AppState<C>,
    policy: &SrpPolicy,
    tenant_id: Uuid,
    user_id: Uuid,
    identity: &str,
    enrollment: Option<&SrpEnrollment>,
) -> AxiamResult<()> {
    match (policy.srp_mode, enrollment) {
        // Nothing offered, nothing expected.
        (SrpMode::Disabled, None) => Ok(()),

        // A verifier for a tenant that does not do SRP is refused rather than
        // dropped on the floor: storing it would be dead weight, and silently
        // discarding it would let a client believe SRP is active when the very
        // next login will be a password login.
        (SrpMode::Disabled, Some(_)) => Err(AxiamError::Validation {
            message: "SRP is not enabled for this tenant".into(),
        }),

        // The migration state: clients that can do SRP enrol, clients that
        // cannot keep working.
        (SrpMode::Optional, None) => Ok(()),

        (SrpMode::Required, None) => Err(AxiamError::Validation {
            message: "this tenant requires Secure Remote Password: the request must \
                      include an `srp` verifier, or the account will be unable to \
                      authenticate"
                .into(),
        }),

        (SrpMode::Optional | SrpMode::Required, Some(enrollment)) => {
            let (group, params, salt, verifier) = enrollment.parse()?;

            // Policy is a floor, not an exact match. A client that enrols with
            // a *stronger* group or KDF than the tenant asks for is doing
            // nothing wrong, and refusing it would block a client that had
            // already moved ahead of a tenant's configuration.
            if group.bits() < policy.srp_group.bits() {
                return Err(AxiamError::Validation {
                    message: format!(
                        "srp group {} is weaker than the tenant minimum {}",
                        group, policy.srp_group
                    ),
                });
            }
            if !srp_kdf_is_at_least(params.kdf(), policy.srp_kdf) {
                return Err(AxiamError::Validation {
                    message: format!(
                        "srp kdf {} is weaker than the tenant minimum {}",
                        params.kdf(),
                        policy.srp_kdf
                    ),
                });
            }

            state
                .srp_credential_repo
                .upsert(CreateSrpCredential {
                    tenant_id,
                    user_id,
                    identity: identity.to_string(),
                    group,
                    kdf_params: params,
                    salt,
                    verifier,
                })
                .await?;
            Ok(())
        }
    }
}

/// Drop a user's verifier because the identity it was bound to no longer
/// exists.
///
/// `x` is derived over `identity ":" password`, so renaming a user
/// invalidates their verifier as surely as changing their password would — but
/// silently, and only at their next login attempt, which is the worst possible
/// time to discover it. Deleting it here converts a baffling "invalid
/// credentials" into the honest state: this user has no verifier and must
/// re-enrol via a password change.
///
/// Deliberately best-effort at the call site: a rename must not fail because
/// of this.
pub(crate) async fn invalidate_on_rename<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    user_id: Uuid,
) {
    if let Err(e) = state
        .srp_credential_repo
        .delete_for_user(tenant_id, user_id)
        .await
    {
        tracing::warn!(
            target: "axiam::auth",
            tenant_id = %tenant_id,
            user_id = %user_id,
            error = %e,
            "failed to drop an SRP verifier after a username change; the user \
             will see 'invalid credentials' on the SRP path until it is replaced"
        );
    }
}

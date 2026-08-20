//! Recording an OPAQUE registration record at the moments a plaintext password
//! legitimately exists.
//!
//! There are exactly four such moments — user creation, an authenticated
//! password change, password-reset completion, and first-run bootstrap — and
//! this module is the one place that handles all of them, so the validation
//! and the policy checks cannot drift between them.
//!
//! # Why enrolment has to be client-driven
//!
//! The server cannot compute a record. The envelope is sealed under a key
//! derived from the password by way of the OPRF, and the whole point of OPAQUE
//! is that the server never sees the password. So the client builds the record
//! and posts it; the server's job is to check that what arrived is well-formed,
//! meets the tenant's policy, and is attributed to the right account — never to
//! trust the client about *whose* account it is. That is why [`OpaqueEnrollment`]
//! carries no user id: the tenant and the user are taken from the authenticated
//! server-side context, and the credential identifier from the sealed session
//! the server itself minted.
//!
//! # Why a missing record is sometimes an error
//!
//! Under [`OpaqueMode::Required`] a password set without a record produces an
//! account that cannot authenticate at all: password login is refused
//! tenant-wide, and there is nothing for `/auth/opaque/login/start` to answer
//! with. Accepting it silently would mean an admin creating a user, seeing
//! `201`, and discovering only later that the account was born unusable. So it
//! is rejected at the point of creation, where the message can say what to do
//! about it.
//!
//! # What is *not* here any more
//!
//! The SRP version of this module had an `invalidate_on_rename` that
//! `PUT /api/v1/users/{id}` called on every username change. SRP derived its
//! private key over `username ":" password`, so a rename silently produced a
//! verifier no client could satisfy — an entirely correct password reported as
//! "invalid credentials", discovered at the worst possible moment. OPAQUE binds
//! to a random server-chosen credential identifier that has no relationship to
//! any name, so there is nothing to invalidate and the function is gone rather
//! than ported.

use axiam_auth::OpaqueEnrolled;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::opaque::{
    CreateOpaqueCredential, OpaqueEnrollment, OpaqueMode, opaque_ksf_is_at_least,
    opaque_suite_is_at_least,
};
use axiam_core::models::settings::OpaquePolicy;
use axiam_core::repository::OpaqueCredentialRepository;
use surrealdb::Connection;
use uuid::Uuid;

use crate::handlers::opaque::opaque_server;
use crate::state::AppState;

/// Validate a client-built registration record against tenant policy, without
/// writing anything.
///
/// Split from [`store_credential`] on purpose. Every call site has to validate
/// *before* it moves the password and store *after*, because doing both
/// afterwards leaves a window in which the Argon2id hash has advanced while
/// the OPAQUE record still answers to the old password — a user mid-migration
/// could then log in with two different passwords depending on which endpoint
/// they used. Making that ordering expressible is what the split is for.
///
/// A `None` enrolment is accepted under `disabled` and `optional`, and refused
/// under `required`.
pub(crate) fn validate_enrollment<C: Connection + Clone>(
    state: &AppState<C>,
    policy: &OpaquePolicy,
    tenant_id: Uuid,
    enrollment: Option<&OpaqueEnrollment>,
) -> AxiamResult<Option<OpaqueEnrolled>> {
    match (policy.opaque_mode, enrollment) {
        // Nothing offered, nothing expected.
        (OpaqueMode::Disabled, None) => Ok(None),

        // A record for a tenant that does not do OPAQUE is refused rather than
        // dropped on the floor: storing it would be dead weight, and silently
        // discarding it would let a client believe OPAQUE is active when the
        // very next login will be a password login.
        (OpaqueMode::Disabled, Some(_)) => Err(AxiamError::Validation {
            message: "OPAQUE is not enabled for this tenant".into(),
        }),

        // The migration state: clients that can do OPAQUE enrol, clients that
        // cannot keep working.
        (OpaqueMode::Optional, None) => Ok(None),

        (OpaqueMode::Required, None) => Err(AxiamError::Validation {
            message: "this tenant requires OPAQUE: the request must include an \
                      `opaque` registration record, or the account will be unable \
                      to authenticate"
                .into(),
        }),

        (OpaqueMode::Optional | OpaqueMode::Required, Some(enrollment)) => {
            let opaque = opaque_server(state).map_err(|e| e.0)?;

            // Opening the sealed session is what binds the record to a
            // credential identifier the *server* chose, and to the suite and
            // KSF parameters it dictated. A client cannot substitute any of
            // them, because it never held them in the clear.
            let enrolled = opaque
                .register_finish(&enrollment.opaque_session, &enrollment.registration_record)
                .map_err(AxiamError::from)?;

            // The session is tenant-scoped, and the caller's tenant comes from
            // its own authenticated context. A mismatch means a session minted
            // for one tenant is being redeemed against another.
            if enrolled.tenant_id != tenant_id {
                return Err(AxiamError::Validation {
                    message: "the OPAQUE session was issued for a different tenant".into(),
                });
            }

            // Policy is a floor, not an exact match. A client that enrols with
            // a *stronger* suite or KSF than the tenant asks for is doing
            // nothing wrong, and refusing it would block a client that had
            // already moved ahead of a tenant's configuration.
            //
            // In practice both values came from the server's own
            // register/start response, so this can only fire if the tenant's
            // policy was tightened in the seconds between the two calls. It is
            // kept because "the server told the client what to use" is an
            // invariant worth enforcing rather than assuming.
            if !opaque_suite_is_at_least(enrolled.suite, policy.opaque_suite) {
                return Err(AxiamError::Validation {
                    message: format!(
                        "opaque suite {} is weaker than the tenant minimum {}",
                        enrolled.suite, policy.opaque_suite
                    ),
                });
            }
            if !opaque_ksf_is_at_least(enrolled.ksf_params.ksf(), policy.opaque_ksf) {
                return Err(AxiamError::Validation {
                    message: format!(
                        "opaque ksf {} is weaker than the tenant minimum {}",
                        enrolled.ksf_params.ksf(),
                        policy.opaque_ksf
                    ),
                });
            }

            Ok(Some(enrolled))
        }
    }
}

/// Persist a validated record against `user_id`.
///
/// `None` is a no-op, which is what the `disabled` and `optional`-without-a-
/// record cases resolve to.
pub(crate) async fn store_credential<C: Connection + Clone>(
    state: &AppState<C>,
    tenant_id: Uuid,
    user_id: Uuid,
    enrolled: Option<OpaqueEnrolled>,
) -> AxiamResult<()> {
    let Some(enrolled) = enrolled else {
        return Ok(());
    };
    state
        .opaque_credential_repo
        .upsert(CreateOpaqueCredential {
            tenant_id,
            user_id,
            credential_identifier: enrolled.credential_identifier,
            suite: enrolled.suite,
            ksf_params: enrolled.ksf_params,
            record: enrolled.record,
        })
        .await?;
    Ok(())
}

//! The persistent, pairwise `NameID` (D-22).
//!
//! A persistent `NameID` is what a service provider keys its account on, for as
//! long as the account lives. Pairwise means each SP sees a different value for
//! the same person, so two SPs comparing notes cannot tell they share a user.
//! The value is
//!
//! ```text
//! hex( HMAC-SHA256( saml_pairwise_key,
//!        "axiam/saml-pairwise/v1" ‖ 0x00
//!        ‖ tenant_id (16 bytes) ‖ user_id (16 bytes)
//!        ‖ len(sp_entity_id) as u32 big-endian ‖ sp_entity_id ) )
//! ```
//!
//! — 64 lower-case hex characters, within SAML Core §8.3.7's 256-character
//! bound. What each property rests on:
//!
//! * **Stable** per (tenant, SP entity id, user): a pure function of the three
//!   and a key that does not rotate. Deleting and re-registering an SP under the
//!   same entity id gives its users their old identifiers back.
//! * **Unlinkable** across SPs and tenants: different inputs to a PRF under a
//!   key no SP holds.
//! * **Not reversible** to the user id: HMAC is one-way; recovering the user
//!   would need the key and a search over the tenant's users.
//! * **Independent of the signing credential** (T23.2.1, D-21): the key is a
//!   separate deployment secret, so rotating, retiring or re-issuing the
//!   tenant's SAML signing certificate changes no identifier.
//!
//! The input encoding is injective — fixed-width ids, a length-prefixed entity
//! id and a versioned label — so no two (tenant, user, entity id) triples can
//! collide by concatenation, and a later derivation under the same key with a
//! different label cannot produce these values.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use uuid::Uuid;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

/// Domain-separation label, versioned so that a second scheme can coexist.
const LABEL: &[u8] = b"axiam/saml-pairwise/v1";

/// The deployment's pairwise-identifier key (`saml_pairwise_key`, D-22).
///
/// Held in a zeroizing buffer; `Debug` prints no key material.
pub struct PairwiseKey(Zeroizing<[u8; 32]>);

impl PairwiseKey {
    /// Wrap the 256-bit key the secret provider returned for
    /// [`axiam_core::secrets::SAML_PAIRWISE_KEY`].
    #[must_use]
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
}

impl std::fmt::Debug for PairwiseKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairwiseKey([REDACTED])")
    }
}

/// The persistent pairwise `NameID` of `user_id` at the SP `sp_entity_id` of
/// tenant `tenant_id`. See the module docs for the construction.
#[must_use]
pub fn pairwise_name_id(
    pairwise_key: &PairwiseKey,
    tenant_id: Uuid,
    sp_entity_id: &str,
    user_id: Uuid,
) -> String {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(pairwise_key.0.as_slice())
        .expect("HMAC accepts a 32-byte key");
    mac.update(LABEL);
    mac.update(&[0]);
    mac.update(tenant_id.as_bytes());
    mac.update(user_id.as_bytes());
    // An entity id is bounded at 1 KiB by the registry validator, so the
    // length always fits; saturating keeps the function total regardless.
    let len = u32::try_from(sp_entity_id.len()).unwrap_or(u32::MAX);
    mac.update(&len.to_be_bytes());
    mac.update(sp_entity_id.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

//! The session-revocation feed (T-39, T-143).
//!
//! # The gap this narrows
//!
//! An AXIAM access token is self-contained and valid for up to fifteen
//! minutes, and an SDK route guard verifies it locally. A role removal, an
//! account disable or a logout therefore does not reach a token already in a
//! caller's hands: the two threats are the server-side and client-side faces
//! of one trade, and both recorded the same remedy — call gRPC introspection
//! instead of verifying locally. That remedy is real and costs a network round
//! trip **per request**, which is why integrators demonstrably do not adopt it.
//!
//! The feed is the cheaper shape of the same answer: a small, bounded,
//! unlinkable list of revoked sessions, published beside the JWKS, polled on an
//! interval rather than per request. A guard that polls it rejects a revoked
//! session within one poll interval instead of within one token lifetime.
//!
//! # Five properties, each load-bearing
//!
//! 1. **Hashes, never identifiers.** An entry is
//!    [`revocation_hash`] of the session id — base64url-unpadded SHA-256, the
//!    same encoding `cnf.x5t#S256` and `jkt` already use, so no SDK needs a new
//!    primitive. A `sid` is a session id and not a subject, so the feed
//!    discloses neither who was revoked nor how many distinct users are behind
//!    the entries. This is not a privacy *guarantee* — it is a
//!    non-enumerability argument, and it holds because a `sid` is a UUIDv4 and
//!    the preimage space is not walkable, not because a hash is magic.
//! 2. **Bounded.** An entry lives exactly one access-token lifetime past the
//!    revocation. After that every token naming that session has expired on its
//!    own `exp` and the entry proves nothing. So the document's size tracks the
//!    revocation rate over fifteen minutes, never the deployment's history.
//! 3. **Rate-limited and cacheable**, like the JWKS beside it.
//! 4. **Never fail closed on the feed.** A guard that cannot fetch it, or that
//!    fetches something malformed, MUST behave exactly as it does today. This
//!    is the rule that makes the feature safe to ship at all: a revocation feed
//!    that can deny requests when it is unreachable turns a network blip into
//!    an outage, and would be a worse control than the window it narrows. The
//!    feed can only ever turn an accept into a reject, never the reverse.
//! 5. **Additive to the token.** Nothing about the JWT changes. `sid` has been
//!    there since T-249.
//!
//! Off by default, per deployment. A deployment that does not enable it writes
//! no row, serves no route, and is byte-identical to one built before this
//! module existed.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The digest algorithm the feed publishes, and the only value a client may
/// accept in the document's `alg` member.
///
/// Published so a client can refuse a document it cannot interpret rather than
/// silently matching nothing — which is the failure mode that would make a
/// guard *appear* to honour revocations while honouring none.
pub const REVOCATION_HASH_ALG: &str = "SHA-256";

/// The feed entry for a session id.
///
/// Base64url without padding, over the session id's **canonical hyphenated
/// lowercase text form** — the same bytes that appear in the token's `sid`
/// claim. Hashing the UUID's raw 16 bytes instead would be equally secure and
/// would not interoperate, because a guard computes this from the string it
/// read out of a JWT.
#[must_use]
pub fn revocation_hash(session_id: Uuid) -> String {
    revocation_hash_of(&session_id.to_string())
}

/// [`revocation_hash`] for a `sid` that has already been read as text.
///
/// What an SDK guard calls: it holds the claim, not a parsed UUID, and
/// requiring it to parse first would make a guard's answer depend on its UUID
/// parser's strictness rather than on the feed.
#[must_use]
pub fn revocation_hash_of(sid: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sid.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The wire format, pinned. Eleven SDKs compute this independently, and a
    /// change here is a change every one of them silently stops matching —
    /// which presents as "revocation stopped working" with nothing failing.
    #[test]
    fn the_hash_is_base64url_unpadded_sha256_of_the_canonical_text_form() {
        let sid = Uuid::parse_str("6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b").unwrap();
        let hash = revocation_hash(sid);

        // 32 bytes base64url-unpadded is 43 characters, and none of them may be
        // `+`, `/` or `=` — a standard-alphabet encoding here would be a subtle
        // mismatch that only shows up for some inputs.
        assert_eq!(hash.len(), 43);
        assert!(!hash.contains('+') && !hash.contains('/') && !hash.contains('='));

        // Computed over the hyphenated lowercase text, which is what the `sid`
        // claim carries.
        assert_eq!(
            hash,
            revocation_hash_of("6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b")
        );
        assert_eq!(hash, "i9N2lYMTV4FhA0husWjGYCqJXXTb7_fMBuomhWjSsgQ");
    }

    /// A guard reads the claim as text and must reach the same entry as the
    /// server, which parsed a UUID. An uppercase or braced rendering is a
    /// *different* string and hashes differently — which is correct, and is
    /// why the contract says the canonical form.
    #[test]
    fn the_text_form_is_the_canonical_one_and_nothing_else() {
        let sid = Uuid::parse_str("6F3E0A5C-1B2D-4E8F-9A7B-0C1D2E3F4A5B").unwrap();
        // `Uuid::to_string` normalises, so the server's entry is the lowercase
        // one whatever case the id was written in.
        assert_eq!(
            revocation_hash(sid),
            revocation_hash_of("6f3e0a5c-1b2d-4e8f-9a7b-0c1d2e3f4a5b")
        );
        assert_ne!(
            revocation_hash(sid),
            revocation_hash_of("6F3E0A5C-1B2D-4E8F-9A7B-0C1D2E3F4A5B")
        );
    }

    /// Distinct sessions produce distinct entries, and the same session
    /// produces the same one — so a session revoked twice is one row, not two.
    #[test]
    fn the_hash_is_deterministic_and_distinguishing() {
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        assert_eq!(revocation_hash(a), revocation_hash(a));
        assert_ne!(revocation_hash(a), revocation_hash(b));
    }

    /// The entry must not be the id. Stated as a test because the cheap
    /// "optimisation" — publish the `sid` and skip the hashing on both sides —
    /// is exactly what turns a public document into a disclosure.
    #[test]
    fn the_entry_never_contains_the_session_id() {
        let sid = Uuid::new_v4();
        let text = sid.to_string();
        let hash = revocation_hash(sid);
        assert!(!hash.contains(&text));
        for window in text
            .as_bytes()
            .windows(4)
            .map(|w| std::str::from_utf8(w).unwrap())
        {
            assert!(!hash.contains(window), "the entry leaks {window:?}");
        }
    }
}

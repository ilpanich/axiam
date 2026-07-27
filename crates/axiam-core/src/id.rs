//! Identifier generation for persisted entities.
//!
//! # Why v7 and not v4
//!
//! Every repository in `axiam-db` writes its rows as
//! `CREATE type::record('<table>', $id)`, where `$id` is the hyphenated string
//! form of a [`Uuid`]. SurrealDB stores records in an ordered key-value engine
//! (`surrealkv:` in dev/prod compose, `file:`/RocksDB in the k8s StatefulSet),
//! so the record id *is* the primary key and its ordering determines physical
//! layout.
//!
//! With v4 the key is uniformly random, so consecutive inserts scatter across
//! the whole keyspace: every insert dirties a different page, the working set
//! for a write burst is the entire index rather than its tail, and LSM
//! compaction rewrites overlapping ranges repeatedly. UUIDv7 (RFC 9562) puts a
//! 48-bit big-endian Unix-millisecond timestamp in the high bits, so ids
//! generated close in time sort close together and inserts append to the tail
//! of the keyspace instead of scattering.
//!
//! Two properties this depends on are verified by the tests below rather than
//! assumed:
//!
//! 1. **The string form sorts like the byte form.** We store ids as
//!    hyphenated strings, so the ordering benefit would be lost if the textual
//!    encoding permuted it. Lowercase hex is order-preserving here, and the
//!    hyphens sit at fixed offsets, so it holds — but it is asserted, because
//!    the whole rationale collapses without it.
//! 2. **Ids are monotonic within a single millisecond.** `uuid`'s
//!    [`Uuid::now_v7`] carries a per-millisecond counter (RFC 9562 §6.2
//!    "monotonic random"), so a burst of inserts inside one millisecond is
//!    still ordered rather than randomly permuted inside that millisecond's
//!    bucket.
//!
//! # When NOT to use this
//!
//! [`new_id`] must not be used for anything whose security depends on being
//! unguessable — session tokens, download/cancel tokens, reset tokens,
//! passwords, or any other bearer capability.
//!
//! v4 spends 122 bits on randomness. v7 spends 48 on the timestamp and, because
//! of the monotonic counter, ids minted in the *same* millisecond share a long
//! common prefix and differ only in the low counter bits. Two adjacent same-ms
//! ids can therefore share ~90 of their 128 bits, which is ample for collision
//! resistance but nowhere near enough for secrecy.
//!
//! That distinction is the rule this module encodes: **v7 for identifiers, CSPRNG
//! for secrets.** Identifiers in AXIAM are not capabilities — every repository
//! read is tenant-scoped and every route is checked by the authz engine, so
//! knowing another entity's id grants nothing. Secrets are generated separately
//! (see `generate_cancel_token` in the GDPR handlers, which uses a 256-bit
//! `rand` draw for exactly this reason).
//!
//! # Disclosure trade-off
//!
//! A v7 id discloses its own creation time to anyone who can see it. For AXIAM
//! entities this reveals nothing new: `created_at` is already part of the
//! public representation of every entity that carries one, and JWTs already
//! carry `iat` alongside the `jti`/`sub` claims.

use uuid::Uuid;

/// Generate the identifier for a newly created, persisted entity.
///
/// Use this for anything that becomes a SurrealDB record id or a foreign key.
/// See the module docs for why this is v7 and for the cases that must keep
/// using a CSPRNG instead.
#[inline]
#[must_use]
pub fn new_id() -> Uuid {
    Uuid::now_v7()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn is_version_7() {
        let id = new_id();
        assert_eq!(id.get_version_num(), 7, "new_id must mint UUIDv7");
        assert_eq!(id.get_variant(), uuid::Variant::RFC4122);
    }

    /// The ordering guarantee must survive the hyphenated-string encoding,
    /// because that is the form actually handed to `type::record(...)`.
    #[test]
    fn string_form_sorts_in_generation_order() {
        let ids: Vec<Uuid> = (0..10_000).map(|_| new_id()).collect();

        let generated: Vec<String> = ids.iter().map(Uuid::to_string).collect();
        let mut sorted = generated.clone();
        sorted.sort();

        assert_eq!(
            sorted, generated,
            "hyphenated string ordering must match generation order, otherwise \
             storing ids as strings discards the v7 locality benefit"
        );
    }

    /// A burst inside one millisecond must stay ordered, not shuffle within
    /// that millisecond's bucket.
    #[test]
    fn monotonic_within_a_single_millisecond() {
        let ids: Vec<Uuid> = (0..5_000).map(|_| new_id()).collect();

        // Confirm the burst really did share milliseconds, so this test is
        // exercising the counter rather than trivially passing on distinct
        // timestamps.
        let distinct_ms: HashSet<&[u8]> = ids.iter().map(|u| &u.as_bytes()[0..6]).collect();
        assert!(
            distinct_ms.len() < ids.len(),
            "expected several ids per millisecond in a tight burst"
        );

        for pair in ids.windows(2) {
            assert!(
                pair[0] < pair[1],
                "v7 ids must increase monotonically: {} !< {}",
                pair[0],
                pair[1]
            );
        }
    }

    #[test]
    fn ids_are_unique() {
        let ids: HashSet<Uuid> = (0..50_000).map(|_| new_id()).collect();
        assert_eq!(ids.len(), 50_000);
    }

    /// The embedded timestamp must track wall-clock time, since ordering
    /// across processes and restarts relies on it.
    #[test]
    fn embeds_current_unix_millis() {
        let before = chrono::Utc::now().timestamp_millis();
        let id = new_id();
        let after = chrono::Utc::now().timestamp_millis();

        let b = id.as_bytes();
        let ms = i64::from(u32::from_be_bytes([b[0], b[1], b[2], b[3]])) << 16
            | i64::from(u16::from_be_bytes([b[4], b[5]]));

        assert!(
            (before..=after).contains(&ms),
            "embedded timestamp {ms} outside [{before}, {after}]"
        );
    }
}

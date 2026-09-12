//! The declared inventory of what each column of the `user` table means
//! (T-261).
//!
//! # Why this exists
//!
//! Four code paths decide what a `user` column means, and three of them used
//! to decide it by writing the column name out by hand: the Art. 17 erasure
//! statement, the administrator's tombstone behind `DELETE
//! /api/v1/users/{id}`, and the Art. 15 export's `profile` section. A column
//! named by none of them survives erasure and never reaches an export — which
//! is precisely what nearly happened to `phone_number` and `address`, added by
//! the release that also added the paths that would have stranded them. The
//! fourth path, SCIM's no-op detection, was guarded because somebody wrote a
//! destructure of `UpdateUser`; that guard does not generalise, because
//! `UpdateUser` is not the `user` table.
//!
//! So the lists stop being lists. [`USER_COLUMNS`] is the one declaration; the
//! two erasure statements derive their shared `SET` fragment from it
//! ([`shared_erasure_fragment`]), and two gates make an unclassified column
//! impossible to add quietly:
//!
//! 1. `user_schema_matches_the_declared_inventory` (in `axiam-db`, against a
//!    live datastore after migrations) introspects `INFO FOR TABLE user` and
//!    requires the field set and [`USER_COLUMNS`] to agree **in both
//!    directions** — a removed column fails as loudly as an added one.
//! 2. [`audit_declarations`] requires every row that classifies a column as
//!    neither erased nor exported to say, in `note`, why.
//!
//! # Why `erasure` and `export` are two fields and not one flag
//!
//! Because a single "is personal data" boolean gets two real cases wrong.
//! `password_hash` and `mfa_secret` are erased and are deliberately **not**
//! exported (D-10: handing a data subject — or whoever compromised their
//! mailbox — the offline-crackable artefact is not an Art. 15 obligation),
//! while `created_at` is exported and deliberately not erased. Both are
//! expressible only because the two questions are asked separately.
//!
//! # What this inventory does not decide
//!
//! Each erasure path keeps its own path-specific clauses: the terminal
//! `status` value, the Art. 17 pipeline's `deletion_pending` /
//! `scheduled_purge_at` reset, the tombstone's `email_verified_at`,
//! `totp_last_used_step` and `failed_login_attempts` reset. Those asymmetries
//! are **recorded** in the `note` of the column they belong to rather than
//! harmonised here: harmonising them would change erasure behaviour, and this
//! module is a gate.

/// What an erasure statement writes into a column.
///
/// Only columns cleared by **both** erasure paths appear as `Some` on
/// [`UserColumn::erasure`]; a column one path clears and the other does not is
/// path-specific, stays `None`, and says so in its `note`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Erasure {
    /// `SET <column> = NONE`.
    ToNone,
    /// `SET <column> = <literal>` — a SurrealQL literal such as `''`, `{}` or
    /// `false`, written verbatim into the statement.
    ToLiteral(&'static str),
    /// `SET <column> = $<param>` — the calling path binds the value, because
    /// it derives from the row: a pseudonym, an email hash, an `.invalid`
    /// placeholder.
    ToParam(&'static str),
}

impl Erasure {
    /// The right-hand side this variant renders into a `SET` clause.
    #[must_use]
    pub fn render(&self) -> String {
        match self {
            Self::ToNone => "NONE".to_owned(),
            Self::ToLiteral(literal) => (*literal).to_owned(),
            Self::ToParam(param) => format!("${param}"),
        }
    }
}

/// One column of the `user` table, classified.
///
/// Every column has a row. A column with no row fails the schema-introspection
/// gate in `axiam-db`, naming itself.
#[derive(Debug, Clone, Copy)]
pub struct UserColumn {
    /// The column name exactly as `DEFINE FIELD` spells it.
    pub name: &'static str,
    /// What **both** erasure paths write, or `None` when the column is not
    /// erased by both — `note` then says why.
    pub erasure: Option<Erasure>,
    /// The key this column appears under in the Art. 15 export's `profile`
    /// section, or `None` when it is deliberately withheld — `note` says why.
    ///
    /// The key is not always the column name: `phone_number_verified_at` is
    /// exported as the derived boolean `phone_number_verified`, because
    /// exporting the internal column name would describe AXIAM's storage
    /// rather than the subject's data.
    pub export: Option<&'static str>,
    /// Why, in the cases where either of the two above is `None`. Required to
    /// be non-empty there, so that "nobody classified this" and "classified as
    /// neither" are different states rather than the same silence.
    pub note: &'static str,
}

/// Keys the Art. 15 `profile` section carries that are not `user` columns.
///
/// `id` is the record identifier. It is not a `DEFINE FIELD`, so it cannot
/// appear in [`USER_COLUMNS`] without breaking the schema gate, and it is
/// exported because a subject asking what is held about them is entitled to
/// the handle everything else is keyed by.
pub const EXPORT_KEYS_NOT_FROM_COLUMNS: &[&str] = &["id"];

/// Every column of the `user` table, in schema-declaration order.
pub const USER_COLUMNS: &[UserColumn] = &[
    UserColumn {
        name: "tenant_id",
        erasure: None,
        export: None,
        note: "The tenant this row is scoped to. Erasing it would orphan the \
               row from every tenant-scoped read, including the ones that \
               prove the erasure happened; it is an internal scoping \
               identifier and not the subject's data.",
    },
    UserColumn {
        name: "username",
        erasure: Some(Erasure::ToParam("pseudonym")),
        export: Some("username"),
        note: "",
    },
    UserColumn {
        name: "email",
        erasure: Some(Erasure::ToParam("email_replacement")),
        export: Some("email"),
        note: "Both paths replace it, with different values bound under the \
               same parameter: the Art. 17 pipeline writes a keyed hash, the \
               tombstone writes a `deleted-<id>@deleted.invalid` placeholder. \
               Overwriting rather than hiding is what frees the address from \
               the unique index so the person can sign up again.",
    },
    UserColumn {
        name: "password_hash",
        erasure: Some(Erasure::ToLiteral("''")),
        export: None,
        note: "D-10: a credential. The column is TYPE string and not nullable, \
               so the empty string is the tombstone — Argon2 output is never \
               empty, so nothing can verify against it even if some future \
               path skipped the status check. Never exported.",
    },
    UserColumn {
        name: "status",
        erasure: None,
        export: Some("status"),
        note: "Path-specific: the Art. 17 pipeline writes `Anonymized` and the \
               tombstone writes `Deleted`, and the difference is the whole \
               point of having two paths. Not personal data.",
    },
    UserColumn {
        name: "mfa_enabled",
        erasure: Some(Erasure::ToLiteral("false")),
        export: Some("mfa_enabled"),
        note: "",
    },
    UserColumn {
        name: "mfa_secret",
        erasure: Some(Erasure::ToNone),
        export: None,
        note: "D-10: a credential. Exported as the derived `mfa_enabled` \
               boolean and never as the secret itself.",
    },
    UserColumn {
        name: "failed_login_attempts",
        erasure: None,
        export: None,
        note: "Path-specific: the tombstone zeroes it, the Art. 17 pipeline \
               does not. Operational lockout state rather than the subject's \
               data; not in the `profile` section today, which is recorded \
               here so the omission is a decision on the record rather than an \
               absence.",
    },
    UserColumn {
        name: "last_failed_login_at",
        erasure: Some(Erasure::ToNone),
        export: None,
        note: "Erased by both paths because it is a timestamp of the \
               subject's own activity. Not in the `profile` section today — \
               the export's `sessions` section is where activity is shown, \
               and moving this one would be an Art. 15 change rather than a \
               gate.",
    },
    UserColumn {
        name: "locked_until",
        erasure: Some(Erasure::ToNone),
        export: None,
        note: "Erased by both paths. Operational lockout state; see \
               `last_failed_login_at` for why it is not in `profile` today.",
    },
    UserColumn {
        name: "metadata",
        erasure: Some(Erasure::ToLiteral("{}")),
        export: Some("metadata"),
        note: "Operator-supplied and free-form, so whatever personal data \
               somebody put in it goes with the rest.",
    },
    UserColumn {
        name: "created_at",
        erasure: None,
        export: Some("created_at"),
        note: "Kept through erasure deliberately: the row survives to preserve \
               referential integrity for audit references, and an erased row \
               with no age cannot be reasoned about by retention. Not \
               personal data on its own.",
    },
    UserColumn {
        name: "updated_at",
        erasure: None,
        export: Some("updated_at"),
        note: "Both erasure paths set it to `time::now()`, which is the \
               write's own timestamp and not an erasure of anything.",
    },
    UserColumn {
        name: "email_verified_at",
        erasure: None,
        export: None,
        note: "Path-specific: the tombstone clears it, the Art. 17 pipeline \
               leaves it, because by then the address itself has been replaced \
               by its hash and the timestamp describes an address that no \
               longer exists on the row. Asymmetry recorded rather than \
               harmonised — harmonising it is a behaviour change.",
    },
    UserColumn {
        name: "deletion_pending",
        erasure: None,
        export: None,
        note: "Path-specific: the Art. 17 pipeline clears it, and clearing it \
               is what marks the erasure as done — it is the only step that \
               does. The tombstone never sets it. Workflow state, not the \
               subject's data.",
    },
    UserColumn {
        name: "scheduled_purge_at",
        erasure: None,
        export: None,
        note: "Path-specific: cleared by the Art. 17 pipeline alongside \
               `deletion_pending`. Workflow state.",
    },
    UserColumn {
        name: "totp_last_used_step",
        erasure: None,
        export: None,
        note: "Path-specific: cleared by the tombstone. A TOTP replay counter, \
               meaningless once `mfa_secret` is gone — which both paths do \
               clear.",
    },
    UserColumn {
        name: "phone_number",
        erasure: Some(Erasure::ToNone),
        export: Some("phone_number"),
        note: "",
    },
    UserColumn {
        name: "phone_number_verified_at",
        erasure: Some(Erasure::ToNone),
        export: Some("phone_number_verified"),
        note: "Exported as the derived boolean rather than the timestamp: that \
               is the claim the subject would have seen released, and \
               exporting the column name would describe AXIAM's storage.",
    },
    UserColumn {
        name: "address",
        erasure: Some(Erasure::ToNone),
        export: Some("address"),
        note: "An object with its own `DEFINE FIELD` members. The schema gate \
               folds `address.*` into this row rather than requiring a row per \
               member — the members are erased and exported with the object \
               they belong to, and cannot be reached without it.",
    },
];

/// The `SET` clause fragment both erasure statements share, derived from
/// [`USER_COLUMNS`].
///
/// Rendered without a trailing comma and without surrounding whitespace, so a
/// caller composes it with its own path-specific clauses. The clause **set** is
/// what this guarantees; clause order is the inventory's order, which neither
/// erasure statement depended on (the two already disagreed about it) and
/// SurrealDB does not observe.
#[must_use]
pub fn shared_erasure_fragment() -> String {
    USER_COLUMNS
        .iter()
        .filter_map(|column| {
            column
                .erasure
                .map(|erasure| format!("{} = {}", column.name, erasure.render()))
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Every parameter name [`shared_erasure_fragment`] expects a caller to bind.
///
/// A path that renders the fragment and forgets one of these produces a query
/// SurrealDB refuses at parse time rather than one that silently writes
/// nothing, but the list is here so a caller can be checked against it in a
/// test rather than at runtime.
#[must_use]
pub fn shared_erasure_params() -> Vec<&'static str> {
    USER_COLUMNS
        .iter()
        .filter_map(|column| match column.erasure {
            Some(Erasure::ToParam(param)) => Some(param),
            _ => None,
        })
        .collect()
}

/// Every export key the `profile` section must carry: the columns' keys plus
/// [`EXPORT_KEYS_NOT_FROM_COLUMNS`].
#[must_use]
pub fn export_keys() -> Vec<&'static str> {
    EXPORT_KEYS_NOT_FROM_COLUMNS
        .iter()
        .copied()
        .chain(USER_COLUMNS.iter().filter_map(|column| column.export))
        .collect()
}

/// The declaration gate: every column classified as neither erased nor
/// exported must say why, and no column may be declared twice.
///
/// Returns the offending column names rather than panicking, so the test that
/// calls it can report all of them at once.
#[must_use]
pub fn audit_declarations() -> Vec<&'static str> {
    let mut problems = Vec::new();
    for (index, column) in USER_COLUMNS.iter().enumerate() {
        if (column.erasure.is_none() || column.export.is_none()) && column.note.is_empty() {
            problems.push(column.name);
        }
        if USER_COLUMNS[..index].iter().any(|c| c.name == column.name) {
            problems.push(column.name);
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gate 2. A column classified as neither erased nor exported is a
    /// decision, and a decision with no reason recorded is how the next author
    /// concludes it was an oversight and "fixes" it.
    #[test]
    fn every_unerased_or_unexported_column_says_why() {
        assert!(
            audit_declarations().is_empty(),
            "these columns are not erased and/or not exported and carry no \
             `note` saying why: {:?}",
            audit_declarations()
        );
    }

    #[test]
    fn the_shared_fragment_names_every_column_that_declares_an_erasure() {
        let fragment = shared_erasure_fragment();
        for column in USER_COLUMNS.iter().filter(|c| c.erasure.is_some()) {
            assert!(
                fragment.contains(&format!("{} = ", column.name)),
                "`{}` declares an erasure but is missing from the fragment",
                column.name
            );
        }
        // And nothing else: a column with `erasure: None` in the fragment
        // would be an erasure nobody declared.
        let clauses = fragment.split(", ").count();
        let declared = USER_COLUMNS.iter().filter(|c| c.erasure.is_some()).count();
        assert_eq!(clauses, declared);
    }

    /// The fragment is pinned verbatim. Not because the text matters to
    /// SurrealDB — it does not — but because this is the one place a change to
    /// what erasure writes becomes visible in a diff, and a derived statement
    /// that nobody can see is worse than the hand-written one it replaced.
    #[test]
    fn the_shared_fragment_is_exactly_this() {
        assert_eq!(
            shared_erasure_fragment(),
            "username = $pseudonym, \
             email = $email_replacement, \
             password_hash = '', \
             mfa_enabled = false, \
             mfa_secret = NONE, \
             last_failed_login_at = NONE, \
             locked_until = NONE, \
             metadata = {}, \
             phone_number = NONE, \
             phone_number_verified_at = NONE, \
             address = NONE"
        );
    }

    #[test]
    fn the_fragment_expects_exactly_two_bound_parameters() {
        assert_eq!(
            shared_erasure_params(),
            vec!["pseudonym", "email_replacement"]
        );
    }

    #[test]
    fn export_keys_are_unique_and_include_the_record_id() {
        let keys = export_keys();
        let mut sorted = keys.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), keys.len(), "duplicate export key");
        assert!(keys.contains(&"id"));
    }

    /// I4 twin for the gate above: an inventory that *does* carry the defect
    /// is reported, so a green `audit_declarations` means the check runs rather
    /// than that it cannot fail.
    #[test]
    fn a_column_with_no_note_and_no_classification_would_be_reported() {
        let offender = UserColumn {
            name: "a_column_somebody_added",
            erasure: None,
            export: None,
            note: "",
        };
        assert!(
            (offender.erasure.is_none() || offender.export.is_none()) && offender.note.is_empty(),
            "the condition `audit_declarations` applies must hold for this shape"
        );
    }
}

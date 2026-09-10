//! User domain model.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, utoipa::ToSchema)]
pub enum UserStatus {
    Active,
    Inactive,
    Locked,
    PendingVerification,
    /// User has been anonymized in-place following Art. 17 erasure (D-05).
    Anonymized,
    /// Removed by an administrator through `DELETE /api/v1/users/{id}`.
    ///
    /// An anonymised tombstone, not a row deletion. The audit trail is
    /// append-only and references actors by id, so hard-deleting the row would
    /// leave every entry the user ever produced pointing at nothing — and an
    /// audit log you cannot resolve to a person is not an audit log.
    ///
    /// What the row keeps is its id. `username` and `email` are overwritten
    /// with values derived from that id, `metadata` is emptied, every
    /// credential is cleared, and (since W7) [`User::phone_number`] and
    /// [`User::address`] are cleared too, so the tombstone holds no personal
    /// data: keeping someone's address on it indefinitely would be retention
    /// with the UI hidden, not erasure. That last clause was written before
    /// there was an address column to keep; there is one now, and it is
    /// cleared here and in the Art. 17 pipeline both. Overwriting rather than hiding is also what frees
    /// the identifiers from their unique indexes, so the person can register
    /// again — which erasure has to leave them able to do.
    ///
    /// Distinct from [`Self::Inactive`], the reversible "suspended" state an
    /// administrator sets from the edit dialog. Reusing that for deletion is
    /// what made `DELETE` look like it did nothing: the user stayed in the
    /// list, in their groups, holding their roles, with live sessions.
    ///
    /// Distinct from [`Self::Anonymized`] in evidence rather than in effect.
    /// That is the scheduled Art. 17 pipeline, which does everything this does
    /// AND pseudonymises the audit log's actor references with a keyed HMAC
    /// before writing a signed erasure proof. This is the immediate operational
    /// removal an administrator performs; that is the certified one a data
    /// subject requests.
    Deleted,
}

/// The OIDC Core §5.1.1 `address` claim, stored as a typed record (X7 G8).
///
/// Every member is optional, exactly as §5.1.1 defines them, and the set is
/// **closed**: the six members below are the whole of the claim, and the
/// database column is SCHEMAFULL with one sub-field each. That is the data
/// minimisation argument made structural rather than written down — there is
/// no shape in which an integration could park a passport number, a date of
/// birth or a free-form note on the user row and have it released under the
/// `address` scope.
///
/// `formatted` is the multi-line rendering §5.1.1 says a display surface should
/// use; the other five are its components. AXIAM never derives one from the
/// other: what a provisioning client wrote is what a relying party is released,
/// because inventing a `formatted` from components would put words AXIAM chose
/// into a claim the user consented to release.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Address {
    /// Full mailing address, formatted for display or use on a mailing label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formatted: Option<String>,
    /// House number, street name and unit, possibly on multiple lines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub street_address: Option<String>,
    /// City or locality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<String>,
    /// State, province, prefecture or region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    /// Zip or postal code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<String>,
    /// Country name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl Address {
    /// Whether every member is absent.
    ///
    /// An address with nothing in it is not an address: the write paths store
    /// `None` rather than an empty record, so "the user has an address" and
    /// "the address has content" cannot disagree, and the userinfo release
    /// omits the claim rather than emitting `{}`.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct User {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub status: UserStatus,
    pub mfa_enabled: bool,
    /// AES-256-GCM encrypted TOTP secret (if MFA is enrolled).
    pub mfa_secret: Option<String>,
    /// The TOTP time-step counter value last successfully verified.
    ///
    /// Used to prevent replay attacks: a code whose step ≤ this value is
    /// rejected even if the HMAC is correct (SEC-008).
    pub totp_last_used_step: Option<u64>,
    pub failed_login_attempts: u32,
    pub last_failed_login_at: Option<DateTime<Utc>>,
    pub locked_until: Option<DateTime<Utc>>,
    pub email_verified_at: Option<DateTime<Utc>>,
    /// GDPR Art. 17 — set when user requests account deletion (D-08).
    pub deletion_pending: bool,
    /// Scheduled purge date when `deletion_pending` is true (D-08).
    pub scheduled_purge_at: Option<DateTime<Utc>>,
    /// E.164 telephone number, released under the OIDC `phone` scope (X7 G8).
    ///
    /// Personal data with no operational use inside AXIAM: nothing
    /// authenticates against it, no notification is sent to it, and no lookup
    /// is keyed by it. It exists so that a relying party the user has
    /// consented to can be told it, which is why it is written only by the
    /// admin API and by SCIM and read only by the UserInfo endpoint.
    #[serde(default)]
    pub phone_number: Option<String>,
    /// When this number was verified, feeding the `phone_number_verified`
    /// claim (OIDC Core §5.1).
    ///
    /// AXIAM ships no telephone verification ceremony, so this is written only
    /// by an administrator asserting an out-of-band check. `None` means the
    /// claim is released as `false` — never omitted and never assumed true:
    /// §5.1 makes `phone_number_verified` a statement the OP is answerable
    /// for, and the honest default for a verification that never happened is
    /// "no".
    #[serde(default)]
    pub phone_number_verified_at: Option<DateTime<Utc>>,
    /// Postal address, released under the OIDC `address` scope (X7 G8).
    ///
    /// Same posture as [`Self::phone_number`]: stored to be released under
    /// consent, read by nothing else.
    #[serde(default)]
    pub address: Option<Address>,
    pub metadata: serde_json::Value,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CreateUser {
    pub tenant_id: Uuid,
    pub username: String,
    pub email: String,
    /// Raw password (will be hashed with Argon2id before storage).
    pub password: String,
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, utoipa::ToSchema)]
pub struct UpdateUser {
    pub username: Option<String>,
    pub email: Option<String>,
    /// Internal-only field set programmatically after Argon2id hashing.
    /// Never accepted from or exposed to API consumers.
    #[serde(skip)]
    #[schema(ignore = true)]
    pub password_hash: Option<String>,
    pub status: Option<UserStatus>,
    pub metadata: Option<serde_json::Value>,
    pub mfa_enabled: Option<bool>,
    /// `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub mfa_secret: Option<Option<String>>,
    /// `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub totp_last_used_step: Option<Option<u64>>,
    pub failed_login_attempts: Option<u32>,
    pub last_failed_login_at: Option<Option<DateTime<Utc>>>,
    pub locked_until: Option<Option<DateTime<Utc>>>,
    /// `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub email_verified_at: Option<Option<DateTime<Utc>>>,
    /// X7 G8. `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub phone_number: Option<Option<String>>,
    /// X7 G8. `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub phone_number_verified_at: Option<Option<DateTime<Utc>>>,
    /// X7 G8. `Some(Some(val))` = set, `Some(None)` = clear, `None` = no change.
    pub address: Option<Option<Address>>,
}

// ---------------------------------------------------------------------------
// Debug — the two X7 G8 columns are redacted
// ---------------------------------------------------------------------------

/// `User` prints its GDPR-sensitive columns as markers, never as values.
///
/// A manual impl rather than `#[derive(Debug)]` for the reason
/// `axiam_db`'s `UserRow` has one (SEC-043): the most natural diagnostic line
/// anybody writes is `?user`, and a telephone number or a postal address that
/// reaches a log has been disclosed to whoever can read logs — a population
/// that is not the population the data subject consented to.
///
/// What is printed instead is *presence*: `Some(<redacted>)` or `None`. That
/// is what a person debugging "why did userinfo omit the claim" needs, and it
/// is all they need.
///
/// Only the two new columns are redacted. `password_hash` and `mfa_secret`
/// print as they did before this wave; widening the redaction would be a
/// change to output every existing operator's tooling reads, and it is not
/// what this wave was asked to decide.
impl std::fmt::Debug for User {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("User")
            .field("id", &self.id)
            .field("tenant_id", &self.tenant_id)
            .field("username", &self.username)
            .field("email", &self.email)
            .field("password_hash", &self.password_hash)
            .field("status", &self.status)
            .field("mfa_enabled", &self.mfa_enabled)
            .field("mfa_secret", &self.mfa_secret)
            .field("totp_last_used_step", &self.totp_last_used_step)
            .field("failed_login_attempts", &self.failed_login_attempts)
            .field("last_failed_login_at", &self.last_failed_login_at)
            .field("locked_until", &self.locked_until)
            .field("email_verified_at", &self.email_verified_at)
            .field("deletion_pending", &self.deletion_pending)
            .field("scheduled_purge_at", &self.scheduled_purge_at)
            .field(
                "phone_number",
                &self.phone_number.as_ref().map(|_| "<redacted>"),
            )
            .field("phone_number_verified_at", &self.phone_number_verified_at)
            .field("address", &self.address.as_ref().map(|_| "<redacted>"))
            .field("metadata", &self.metadata)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{OIDC_METADATA_KEY, ProfileClaims, SCIM_METADATA_KEY};
    use serde_json::json;

    /// All twelve, from the two buckets, in one go — because the failure this
    /// guards against is a claim silently not wired, and a test per claim is a
    /// test somebody forgets to add the thirteenth time.
    #[test]
    fn every_profile_claim_is_read_from_the_bucket_that_holds_it() {
        let metadata = json!({
            SCIM_METADATA_KEY: {
                "formatted": "Ada Lovelace",
                "givenName": "Ada",
                "familyName": "Lovelace",
                "middleName": "Byron",
                "nickName": "Ada",
                "profileUrl": "https://example.test/ada",
                "photos": [{ "value": "https://example.test/ada.png", "type": "photo" }],
                "timezone": "Europe/London",
                "locale": "en-GB",
            },
            OIDC_METADATA_KEY: {
                "website": "https://example.test/",
                "gender": "female",
                "birthdate": "1815-12-10",
            },
        });
        let c = ProfileClaims::from_metadata(&metadata);
        assert_eq!(c.name.as_deref(), Some("Ada Lovelace"));
        assert_eq!(c.given_name.as_deref(), Some("Ada"));
        assert_eq!(c.family_name.as_deref(), Some("Lovelace"));
        assert_eq!(c.middle_name.as_deref(), Some("Byron"));
        assert_eq!(c.nickname.as_deref(), Some("Ada"));
        assert_eq!(c.profile.as_deref(), Some("https://example.test/ada"));
        assert_eq!(c.picture.as_deref(), Some("https://example.test/ada.png"));
        assert_eq!(c.website.as_deref(), Some("https://example.test/"));
        assert_eq!(c.gender.as_deref(), Some("female"));
        assert_eq!(c.birthdate.as_deref(), Some("1815-12-10"));
        assert_eq!(c.zoneinfo.as_deref(), Some("Europe/London"));
        assert_eq!(c.locale.as_deref(), Some("en-GB"));
        assert!(!c.is_empty());
    }

    /// A deployment that does not run SCIM can still hold a complete profile.
    #[test]
    fn the_oidc_bucket_alone_fills_every_claim_scim_would_have() {
        let metadata = json!({
            OIDC_METADATA_KEY: {
                "name": "Ada Lovelace",
                "given_name": "Ada",
                "family_name": "Lovelace",
                "middle_name": "Byron",
                "nickname": "Ada",
                "profile": "https://example.test/ada",
                "picture": "https://example.test/ada.png",
                "zoneinfo": "Europe/London",
                "locale": "en-GB",
            },
        });
        let c = ProfileClaims::from_metadata(&metadata);
        for (claim, got) in [
            ("name", c.name.as_deref()),
            ("given_name", c.given_name.as_deref()),
            ("family_name", c.family_name.as_deref()),
            ("middle_name", c.middle_name.as_deref()),
            ("nickname", c.nickname.as_deref()),
            ("profile", c.profile.as_deref()),
            ("picture", c.picture.as_deref()),
            ("zoneinfo", c.zoneinfo.as_deref()),
            ("locale", c.locale.as_deref()),
        ] {
            assert!(got.is_some(), "{claim} must fall back to the oidc bucket");
        }
    }

    /// The precedence is one way round and must stay that way: SCIM is what a
    /// directory synchronises, so a value it overwrote must not be shadowed by
    /// an older one somebody wrote by hand.
    #[test]
    fn scim_wins_over_the_oidc_bucket_where_both_hold_a_claim() {
        let metadata = json!({
            SCIM_METADATA_KEY: { "nickName": "from-scim", "locale": "en-GB" },
            OIDC_METADATA_KEY: { "nickname": "from-oidc", "locale": "it-IT" },
        });
        let c = ProfileClaims::from_metadata(&metadata);
        assert_eq!(c.nickname.as_deref(), Some("from-scim"));
        assert_eq!(c.locale.as_deref(), Some("en-GB"));
    }

    /// A subject AXIAM knows nothing about yields nothing — not empty strings,
    /// which UserInfo would then emit as claims it cannot assert.
    #[test]
    fn an_unprovisioned_subject_yields_no_claims_at_all() {
        assert!(ProfileClaims::from_metadata(&json!({})).is_empty());
        assert!(ProfileClaims::from_metadata(&json!(null)).is_empty());
        assert!(ProfileClaims::from_metadata(&json!({"scim": {}})).is_empty());
    }

    /// `photos` is multi-valued in SCIM; a client that wrote a bare string is
    /// still understood, because refusing it would drop a picture AXIAM holds.
    #[test]
    fn a_picture_is_read_from_either_shape_scim_allows() {
        let array = json!({ SCIM_METADATA_KEY: { "photos": [{"value": "https://a.test/p"}] } });
        let flat = json!({ SCIM_METADATA_KEY: { "photos": "https://a.test/p" } });
        assert_eq!(
            ProfileClaims::from_metadata(&array).picture.as_deref(),
            Some("https://a.test/p")
        );
        assert_eq!(
            ProfileClaims::from_metadata(&flat).picture.as_deref(),
            Some("https://a.test/p")
        );
    }

    /// The composed fallback, kept from `ProfileNames`: a provisioning client
    /// is not obliged to send `name.formatted`.
    #[test]
    fn name_is_composed_from_the_parts_when_no_formatted_whole_was_stored() {
        let m = json!({ SCIM_METADATA_KEY: { "givenName": "Ada", "familyName": "Lovelace" } });
        assert_eq!(
            ProfileClaims::from_metadata(&m).name.as_deref(),
            Some("Ada Lovelace")
        );
    }

    use super::*;

    fn a_user() -> User {
        User {
            id: uuid::Uuid::nil(),
            tenant_id: uuid::Uuid::nil(),
            username: "u".into(),
            email: "u@example.test".into(),
            password_hash: String::new(),
            status: UserStatus::Active,
            mfa_enabled: false,
            mfa_secret: None,
            totp_last_used_step: None,
            failed_login_attempts: 0,
            last_failed_login_at: None,
            locked_until: None,
            email_verified_at: None,
            deletion_pending: false,
            scheduled_purge_at: None,
            phone_number: Some("+390212345678".into()),
            phone_number_verified_at: None,
            address: Some(Address {
                street_address: Some("Via Roma 1".into()),
                locality: Some("Milano".into()),
                ..Address::default()
            }),
            metadata: serde_json::Value::Null,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// X7 G8 — neither value reaches `Debug`, and presence still does.
    #[test]
    fn debug_redacts_the_sensitive_columns_but_still_shows_presence() {
        let printed = format!("{:?}", a_user());
        assert!(
            !printed.contains("+390212345678"),
            "the telephone number must not appear in Debug output: {printed}"
        );
        assert!(
            !printed.contains("Via Roma"),
            "the postal address must not appear in Debug output: {printed}"
        );
        assert!(
            printed.contains("phone_number: Some(\"<redacted>\")"),
            "presence must still be visible: {printed}"
        );
        assert!(
            printed.contains("address: Some(\"<redacted>\")"),
            "presence must still be visible: {printed}"
        );
    }

    /// An absent value prints as absent — the diagnostic the redaction exists
    /// to preserve is "was there anything there at all".
    #[test]
    fn debug_distinguishes_absent_from_redacted() {
        let mut user = a_user();
        user.phone_number = None;
        user.address = None;
        let printed = format!("{:?}", user);
        assert!(printed.contains("phone_number: None"), "{printed}");
        assert!(printed.contains("address: None"), "{printed}");
    }

    /// The `address` claim serialises with absent members omitted, so a
    /// UserInfo response never carries `"region": null` — OIDC Core §5.1
    /// asks for absent claims to be omitted, not nulled.
    #[test]
    fn address_omits_absent_members() {
        let addr = Address {
            locality: Some("Milano".into()),
            ..Address::default()
        };
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, r#"{"locality":"Milano"}"#);
    }

    /// An address with no members is empty, which is what makes "store `None`
    /// rather than an empty record" checkable at the write paths.
    #[test]
    fn an_address_with_no_members_is_empty() {
        assert!(Address::default().is_empty());
        assert!(
            !Address {
                country: Some("IT".into()),
                ..Address::default()
            }
            .is_empty()
        );
    }
}

// ---------------------------------------------------------------------------
// The names a provisioning client stores, read where a token is answered
// ---------------------------------------------------------------------------

/// The single `metadata` key everything SCIM writes lives under.
///
/// SCIM stores `externalId` and `name.*` inside the generic `metadata` column
/// rather than in new schema, all under one top-level key so it can never
/// collide with what another feature writes there.
///
/// The constant lives in `axiam-core` (layer 0) rather than in `axiam-scim`
/// because it has two readers on opposite sides of the crate graph: the SCIM
/// surface writes it (layer 7) and the OIDC UserInfo endpoint reads it (layer
/// 6). A layer-6 crate cannot depend on a layer-7 one —
/// `scripts/check-crate-layering.py` fails CI on it — so a second copy of the
/// string was the only alternative, and a second copy of a storage key is the
/// kind of duplicate that stops being equal quietly.
pub const SCIM_METADATA_KEY: &str = "scim";

/// Read `metadata.scim.<field>` as a string.
///
/// `None` when the key is absent, when `metadata` is not an object, or when
/// the value is not a string — a provisioning client that wrote a number where
/// a name belongs has written no name.
#[must_use]
pub fn scim_metadata_str(metadata: &serde_json::Value, field: &str) -> Option<String> {
    metadata
        .get(SCIM_METADATA_KEY)?
        .get(field)?
        .as_str()
        .map(str::to_owned)
}

/// The key `metadata` sub-object holding OIDC standard claims SCIM has no
/// field for.
///
/// SCIM 2.0's core `User` schema covers most of OIDC Core §5.1 — `nickName`,
/// `profileUrl`, `photos`, `locale`, `timezone`, `name.middleName` all have
/// homes — but defines nothing for `website`, `gender` or `birthdate`.
/// Rather than bend SCIM attributes into meaning something they do not, those
/// live here, under a bucket named for the specification that defines them.
pub const OIDC_METADATA_KEY: &str = "oidc";

/// Read `metadata.oidc.<field>` as a string.
#[must_use]
pub fn oidc_metadata_str(metadata: &serde_json::Value, field: &str) -> Option<String> {
    metadata
        .get(OIDC_METADATA_KEY)?
        .get(field)?
        .as_str()
        .map(str::to_owned)
}

/// SCIM `photos` — multi-valued, so the first entry's `value` — falling back
/// to a plain string for a provisioning client that wrote one.
fn scim_photo(metadata: &serde_json::Value) -> Option<String> {
    let photos = metadata.get(SCIM_METADATA_KEY)?.get("photos")?;
    if let Some(s) = photos.as_str() {
        return Some(s.to_owned());
    }
    photos
        .as_array()?
        .first()?
        .get("value")?
        .as_str()
        .map(str::to_owned)
}

/// The OIDC Core §5.1 claims the `profile` scope promises, as AXIAM holds them.
///
/// # Where each one comes from
///
/// SCIM is the system of record wherever SCIM defines a field, because SCIM is
/// how users are provisioned and a second source would be a second answer:
///
/// | claim         | source                        |
/// |---------------|-------------------------------|
/// | `name`        | SCIM `name.formatted`         |
/// | `given_name`  | SCIM `name.givenName`         |
/// | `family_name` | SCIM `name.familyName`        |
/// | `middle_name` | SCIM `name.middleName`        |
/// | `nickname`    | SCIM `nickName`               |
/// | `profile`     | SCIM `profileUrl`             |
/// | `picture`     | SCIM `photos[0].value`        |
/// | `zoneinfo`    | SCIM `timezone`               |
/// | `locale`      | SCIM `locale`                 |
/// | `website`     | `metadata.oidc.website`       |
/// | `gender`      | `metadata.oidc.gender`        |
/// | `birthdate`   | `metadata.oidc.birthdate`     |
///
/// The last three have no SCIM equivalent — see [`OIDC_METADATA_KEY`].
/// `updated_at` is deliberately absent: it is `User::updated_at`, a column,
/// and reading it from metadata would let a provisioning client assert when
/// AXIAM last changed its own row.
///
/// # SCIM wins, `metadata.oidc` fills in
///
/// Every claim above also reads from `metadata.oidc.<claim>` when SCIM has
/// nothing, so a deployment that does not run SCIM at all can still hold a
/// complete profile through the admin API. The precedence is one way round and
/// stays that way: where SCIM defines the attribute SCIM is the system of
/// record, because SCIM is what a directory synchronises and a value it
/// overwrote must not be shadowed by an older one somebody wrote by hand.
///
/// # Absent, never invented
///
/// Every field is `Option` and an absent one is omitted from UserInfo rather
/// than emitted as `null`. OIDC Core §5.3.2 is explicit that a claim the OP
/// cannot assert is simply not there, and a `null` would be AXIAM asserting it
/// knows the subject has no name.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProfileClaims {
    /// OIDC `name` — SCIM `name.formatted`.
    pub name: Option<String>,
    /// OIDC `given_name` — SCIM `name.givenName`.
    pub given_name: Option<String>,
    /// OIDC `family_name` — SCIM `name.familyName`.
    pub family_name: Option<String>,
    /// OIDC `middle_name` — SCIM `name.middleName`.
    pub middle_name: Option<String>,
    /// OIDC `nickname` — SCIM `nickName`.
    pub nickname: Option<String>,
    /// OIDC `profile` — SCIM `profileUrl`.
    pub profile: Option<String>,
    /// OIDC `picture` — SCIM `photos`.
    pub picture: Option<String>,
    /// OIDC `website` — `metadata.oidc.website`.
    pub website: Option<String>,
    /// OIDC `gender` — `metadata.oidc.gender`.
    pub gender: Option<String>,
    /// OIDC `birthdate` — `metadata.oidc.birthdate`, an ISO 8601 `YYYY-MM-DD`.
    pub birthdate: Option<String>,
    /// OIDC `zoneinfo` — SCIM `timezone`, an IANA zone such as `Europe/Rome`.
    pub zoneinfo: Option<String>,
    /// OIDC `locale` — SCIM `locale`, a BCP 47 tag such as `en-GB`.
    pub locale: Option<String>,
}

impl ProfileClaims {
    /// Read them out of a user's `metadata`.
    ///
    /// `name` falls back to "given family" when SCIM stored the parts without
    /// a formatted whole. A provisioning client is not obliged to send
    /// `name.formatted`, and a relying party asking for `name` should not be
    /// told AXIAM knows nothing about a subject whose first and last names it
    /// is holding. Composed only when at least one part exists, so a user with
    /// no name at all still yields `None` rather than an empty string.
    #[must_use]
    pub fn from_metadata(metadata: &serde_json::Value) -> Self {
        let given_name = scim_metadata_str(metadata, "givenName");
        let family_name = scim_metadata_str(metadata, "familyName");
        let name = scim_metadata_str(metadata, "formatted").or_else(|| {
            let joined = [given_name.as_deref(), family_name.as_deref()]
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
                .join(" ");
            (!joined.is_empty()).then_some(joined)
        });
        Self {
            name: name.or_else(|| oidc_metadata_str(metadata, "name")),
            given_name: given_name.or_else(|| oidc_metadata_str(metadata, "given_name")),
            family_name: family_name.or_else(|| oidc_metadata_str(metadata, "family_name")),
            middle_name: scim_metadata_str(metadata, "middleName")
                .or_else(|| oidc_metadata_str(metadata, "middle_name")),
            nickname: scim_metadata_str(metadata, "nickName")
                .or_else(|| oidc_metadata_str(metadata, "nickname")),
            profile: scim_metadata_str(metadata, "profileUrl")
                .or_else(|| oidc_metadata_str(metadata, "profile")),
            picture: scim_photo(metadata).or_else(|| oidc_metadata_str(metadata, "picture")),
            // No SCIM equivalent at all — see `OIDC_METADATA_KEY`.
            website: oidc_metadata_str(metadata, "website"),
            gender: oidc_metadata_str(metadata, "gender"),
            birthdate: oidc_metadata_str(metadata, "birthdate"),
            zoneinfo: scim_metadata_str(metadata, "timezone")
                .or_else(|| oidc_metadata_str(metadata, "zoneinfo")),
            locale: scim_metadata_str(metadata, "locale")
                .or_else(|| oidc_metadata_str(metadata, "locale")),
        }
    }

    /// Whether nothing at all was stored.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

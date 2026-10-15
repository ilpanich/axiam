//! The RADIUS reply-profile dictionary `axiam-radius-reply/1` and the typed
//! profile built from it (RADIUS D4, `claude_dev/radius-reply-profile-design.md`
//! §3).
//!
//! # A typed record, not an attribute list
//!
//! A reply profile is the set of RADIUS attributes AXIAM would put in an
//! Access-Accept for a device placed on one network segment. There is **no
//! field in which a writer names an attribute**: every attribute a profile can
//! produce is a named, bounded field of [`ReplyProfileInput`], and the
//! dictionary below ([`DICTIONARY_V1`]) is the closed set of them. A vendor
//! attribute, an unknown attribute number or a free-form string attribute
//! cannot be expressed, so it cannot be validated wrongly (§3.1).
//!
//! **The VLAN is not a profile field.** The three tunnel attributes are
//! derived from the owning segment's `vlan_id`
//! ([`crate::models::network::NetworkSegment::vlan_id`]); a profile cannot name
//! one, so the only way to put a device on VLAN 99 is to write the profile of
//! the segment that owns VLAN 99 (§3.1).
//!
//! # The dictionary is code
//!
//! It is a compile-time table in this layer-0 crate, each entry citing its RFC
//! section. A dictionary change is a code change with review; no API adds an
//! entry. Every stored profile records the version it was validated against
//! and an unknown version is refused, never ignored (§3.4).
//!
//! # Bounds
//!
//! The tenant's `Session-Timeout` cap is read from
//! [`crate::models::network::NetworkPolicy`]. A value above the cap is refused
//! at write time ([`ReplyProfileInput::validate`]) and clamped down at read
//! time ([`clamp_session_timeout`]): lowering the cap afterwards only narrows
//! (§3.4, §5.2).

use serde::{Deserialize, Serialize};

use crate::error::{AxiamError, AxiamResult};

/// The dictionary version a profile is validated against.
pub const REPLY_DICTIONARY_V1: &str = "axiam-radius-reply/1";

/// The lowest `Session-Timeout` a profile may carry, in seconds.
///
/// Follows from RFC 3580 §3.17: with `Termination-Action = RADIUS-Request`, a
/// `Session-Timeout` of zero means "re-authenticate immediately", which is a
/// re-authentication loop. The floor also keeps a fleet's re-authentication
/// rate inside the power-restore budget of the spike's §6.1.
pub const SESSION_TIMEOUT_FLOOR_SECS: u32 = 300;

/// The tenant cap on `Session-Timeout` when the tenant has not set one.
pub const DEFAULT_SESSION_TIMEOUT_MAX_SECS: u32 = 3600;

/// The highest value a tenant may set its cap to, in seconds (24 hours).
pub const SESSION_TIMEOUT_CAP_CEILING_SECS: u32 = 86_400;

/// The lowest `Idle-Timeout` a profile may carry, in seconds.
pub const IDLE_TIMEOUT_FLOOR_SECS: u32 = 60;

/// The most `Filter-Id` names one segment may declare.
pub const MAX_FILTER_IDS: usize = 32;

/// The lowest VLAN id (RFC 3580 §3.31: 12 bits, 1 to 4094).
pub const VLAN_MIN: u16 = 1;

/// The highest VLAN id (RFC 3580 §3.31).
pub const VLAN_MAX: u16 = 4094;

/// Where an attribute's value comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeSource {
    /// Derived from the owning segment; a profile cannot set it.
    DerivedFromSegment,
    /// A named field of the profile.
    ProfileField(&'static str),
}

/// One row of the dictionary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DictionaryEntry {
    /// The attribute's name in FreeRADIUS's dictionary.
    pub name: &'static str,
    /// The attribute number.
    pub number: u8,
    /// `integer` or `string`, as FreeRADIUS's dictionary spells it.
    pub data_type: &'static str,
    /// Whether the attribute carries an RFC 2868 tag octet (always `0x00` here).
    pub tagged: bool,
    /// The RFC sections that define it.
    pub rfc: &'static str,
    /// Where its value comes from.
    pub source: AttributeSource,
}

/// The `axiam-radius-reply/1` dictionary (design note §3.2). Eight attributes;
/// nothing else can appear in a reply AXIAM renders.
pub const DICTIONARY_V1: &[DictionaryEntry] = &[
    DictionaryEntry {
        name: "Tunnel-Type",
        number: 64,
        data_type: "integer",
        tagged: true,
        rfc: "RFC 2868 §3.1; RFC 3580 §3.31",
        source: AttributeSource::DerivedFromSegment,
    },
    DictionaryEntry {
        name: "Tunnel-Medium-Type",
        number: 65,
        data_type: "integer",
        tagged: true,
        rfc: "RFC 2868 §3.2; RFC 3580 §3.31",
        source: AttributeSource::DerivedFromSegment,
    },
    DictionaryEntry {
        name: "Tunnel-Private-Group-Id",
        number: 81,
        data_type: "string",
        tagged: true,
        rfc: "RFC 2868 §3.6; RFC 3580 §3.31",
        source: AttributeSource::DerivedFromSegment,
    },
    DictionaryEntry {
        name: "Session-Timeout",
        number: 27,
        data_type: "integer",
        tagged: false,
        rfc: "RFC 2865 §5.27; RFC 3580 §3.17",
        source: AttributeSource::ProfileField("session_timeout_secs"),
    },
    DictionaryEntry {
        name: "Termination-Action",
        number: 29,
        data_type: "integer",
        tagged: false,
        rfc: "RFC 2865 §5.29; RFC 3580 §3.17",
        source: AttributeSource::ProfileField("termination_action"),
    },
    DictionaryEntry {
        name: "Idle-Timeout",
        number: 28,
        data_type: "integer",
        tagged: false,
        rfc: "RFC 2865 §5.28",
        source: AttributeSource::ProfileField("idle_timeout_secs"),
    },
    DictionaryEntry {
        name: "Filter-Id",
        number: 11,
        data_type: "string",
        tagged: false,
        rfc: "RFC 2865 §5.11",
        source: AttributeSource::ProfileField("filter_id"),
    },
    DictionaryEntry {
        name: "Service-Type",
        number: 6,
        data_type: "integer",
        tagged: false,
        rfc: "RFC 2865 §5.6",
        source: AttributeSource::ProfileField("service_type"),
    },
];

/// The dictionary a version string names, or `None` for a version this server
/// does not know.
#[must_use]
pub fn dictionary(version: &str) -> Option<&'static [DictionaryEntry]> {
    (version == REPLY_DICTIONARY_V1).then_some(DICTIONARY_V1)
}

/// `Termination-Action` (RFC 2865 §5.29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum TerminationAction {
    /// 0, `Default`: the NAS ends the session when `Session-Timeout` expires.
    Default,
    /// 1, `RADIUS-Request`: the NAS re-authenticates. The default, and the
    /// value that bounds how long a quarantine or a revocation waits (RFC 3580
    /// §3.17).
    #[default]
    RadiusRequest,
}

impl TerminationAction {
    /// The RADIUS integer value.
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            Self::Default => 0,
            Self::RadiusRequest => 1,
        }
    }

    /// The stored and wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::RadiusRequest => "radius_request",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "default" => Some(Self::Default),
            "radius_request" => Some(Self::RadiusRequest),
            _ => None,
        }
    }
}

/// `Service-Type` (RFC 2865 §5.6), the values the dictionary admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServiceType {
    /// 2, `Framed-User`: the only value option B accepts.
    FramedUser,
    /// 6, `Administrative-User`: the admin class (administrative login to the
    /// NAS). In the table, **disabled for option B** (design note §3.3).
    AdministrativeUser,
    /// 7, `NAS-Prompt-User`: the admin class. Disabled for option B.
    NasPromptUser,
}

impl ServiceType {
    /// The RADIUS integer value.
    #[must_use]
    pub const fn value(self) -> u32 {
        match self {
            Self::FramedUser => 2,
            Self::AdministrativeUser => 6,
            Self::NasPromptUser => 7,
        }
    }

    /// Whether the value grants administrative login to the NAS (`admin_class`).
    #[must_use]
    pub const fn is_admin_class(self) -> bool {
        matches!(self, Self::AdministrativeUser | Self::NasPromptUser)
    }

    /// The stored and wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FramedUser => "framed_user",
            Self::AdministrativeUser => "administrative_user",
            Self::NasPromptUser => "nas_prompt_user",
        }
    }

    /// Parse the stored spelling.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "framed_user" => Some(Self::FramedUser),
            "administrative_user" => Some(Self::AdministrativeUser),
            "nas_prompt_user" => Some(Self::NasPromptUser),
            _ => None,
        }
    }
}

/// Whether `name` is an acceptable `Filter-Id` / segment-name identifier:
/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$` (design note §3.2).
///
/// Written by hand rather than with a regular expression: the alphabet is the
/// whole point, and it keeps this layer-0 crate free of a dependency.
#[must_use]
pub fn is_valid_identifier(name: &str) -> bool {
    let bytes = name.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return false;
    }
    bytes[0].is_ascii_alphanumeric()
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether `vlan` is a valid VLAN id.
#[must_use]
pub const fn is_valid_vlan(vlan: u16) -> bool {
    vlan >= VLAN_MIN && vlan <= VLAN_MAX
}

/// The `Session-Timeout` a reply may carry: the stored value, lowered to the
/// tenant's cap. Only ever narrows (design note §3.4).
#[must_use]
pub const fn clamp_session_timeout(stored: u32, cap: u32) -> u32 {
    if stored > cap { cap } else { stored }
}

fn default_dictionary() -> String {
    REPLY_DICTIONARY_V1.to_owned()
}

/// What a writer supplies for a profile. Closed: an unknown key is a refusal
/// naming it, never ignored (design note §3.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(deny_unknown_fields)]
pub struct ReplyProfileInput {
    /// The dictionary version the profile is written against; defaults to
    /// [`REPLY_DICTIONARY_V1`]. An unknown version is refused.
    #[serde(default = "default_dictionary")]
    pub dictionary: String,
    /// `Session-Timeout`, seconds: [`SESSION_TIMEOUT_FLOOR_SECS`] up to the
    /// tenant cap. Never zero.
    pub session_timeout_secs: u32,
    /// `Termination-Action`; defaults to `RADIUS-Request`.
    #[serde(default)]
    pub termination_action: TerminationAction,
    /// `Idle-Timeout`, seconds: [`IDLE_TIMEOUT_FLOOR_SECS`] up to
    /// `session_timeout_secs`.
    #[serde(default)]
    pub idle_timeout_secs: Option<u32>,
    /// `Filter-Id`: one of the owning segment's declared `filter_ids`.
    #[serde(default)]
    pub filter_id: Option<String>,
    /// `Service-Type`: `framed_user` or absent under option B.
    #[serde(default)]
    pub service_type: Option<ServiceType>,
}

impl ReplyProfileInput {
    /// Check the profile against its dictionary and the owning segment's
    /// envelope, at write time (design note §3.4 and §5.2 H3).
    ///
    /// * `segment_filter_ids` is the owning segment's declared `Filter-Id`
    ///   names; `filter_id` must be one of them.
    /// * `cap` is the tenant's `Session-Timeout` cap.
    ///
    /// Every refusal is `Validation`. This is the **value** half of H3; who may
    /// write the profile (H1, H2, H4 to H6) is the authorization function's.
    pub fn validate(&self, segment_filter_ids: &[String], cap: u32) -> AxiamResult<()> {
        if dictionary(&self.dictionary).is_none() {
            return Err(invalid("unknown reply dictionary version"));
        }
        if self.session_timeout_secs < SESSION_TIMEOUT_FLOOR_SECS {
            return Err(invalid(format!(
                "session_timeout_secs must be at least {SESSION_TIMEOUT_FLOOR_SECS}"
            )));
        }
        if self.session_timeout_secs > cap {
            return Err(invalid(format!(
                "session_timeout_secs exceeds the tenant cap of {cap}"
            )));
        }
        if let Some(idle) = self.idle_timeout_secs
            && !(IDLE_TIMEOUT_FLOOR_SECS..=self.session_timeout_secs).contains(&idle)
        {
            return Err(invalid(format!(
                "idle_timeout_secs must be between {IDLE_TIMEOUT_FLOOR_SECS} and \
                 session_timeout_secs"
            )));
        }
        if let Some(filter) = &self.filter_id {
            if !is_valid_identifier(filter) {
                return Err(invalid("filter_id is not a valid Filter-Id name"));
            }
            if !segment_filter_ids.iter().any(|f| f == filter) {
                return Err(invalid(
                    "filter_id is outside the segment's declared filter_ids",
                ));
            }
        }
        if self.service_type.is_some_and(ServiceType::is_admin_class) {
            return Err(invalid(
                "the administrative Service-Type values are disabled",
            ));
        }
        Ok(())
    }
}

fn invalid(message: impl Into<String>) -> AxiamError {
    AxiamError::Validation {
        message: message.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> ReplyProfileInput {
        ReplyProfileInput {
            dictionary: REPLY_DICTIONARY_V1.into(),
            session_timeout_secs: 900,
            termination_action: TerminationAction::RadiusRequest,
            idle_timeout_secs: Some(120),
            filter_id: Some("corp-acl".into()),
            service_type: Some(ServiceType::FramedUser),
        }
    }

    fn filters() -> Vec<String> {
        vec!["corp-acl".into(), "other".into()]
    }

    #[test]
    fn the_dictionary_is_the_eight_attributes_of_the_note() {
        let names: Vec<_> = DICTIONARY_V1.iter().map(|e| (e.name, e.number)).collect();
        assert_eq!(
            names,
            [
                ("Tunnel-Type", 64),
                ("Tunnel-Medium-Type", 65),
                ("Tunnel-Private-Group-Id", 81),
                ("Session-Timeout", 27),
                ("Termination-Action", 29),
                ("Idle-Timeout", 28),
                ("Filter-Id", 11),
                ("Service-Type", 6),
            ]
        );
        // No vendor-specific attribute, no protocol-owned one (§3.3).
        for excluded in [26u8, 18, 25, 69, 80, 79, 24, 33] {
            assert!(DICTIONARY_V1.iter().all(|e| e.number != excluded));
        }
        // The three tunnel attributes are the segment's, never the profile's.
        assert_eq!(
            DICTIONARY_V1
                .iter()
                .filter(|e| e.source == AttributeSource::DerivedFromSegment)
                .count(),
            3
        );
        assert!(dictionary("axiam-radius-reply/2").is_none());
    }

    #[test]
    fn a_profile_inside_its_envelope_is_valid() {
        input().validate(&filters(), 3600).unwrap();
    }

    #[test]
    fn a_filter_id_outside_the_envelope_is_refused() {
        let mut p = input();
        p.filter_id = Some("admin-acl".into());
        assert!(matches!(
            p.validate(&filters(), 3600),
            Err(AxiamError::Validation { .. })
        ));
    }

    #[test]
    fn the_session_timeout_is_bounded_both_ways() {
        let mut p = input();
        p.session_timeout_secs = 0;
        assert!(p.validate(&filters(), 3600).is_err());
        p.session_timeout_secs = 299;
        assert!(p.validate(&filters(), 3600).is_err());
        p.session_timeout_secs = 3601;
        assert!(p.validate(&filters(), 3600).is_err());
        p.session_timeout_secs = 3600;
        p.idle_timeout_secs = Some(3601);
        assert!(p.validate(&filters(), 3600).is_err());
        p.idle_timeout_secs = Some(59);
        assert!(p.validate(&filters(), 3600).is_err());
    }

    #[test]
    fn the_admin_class_and_unknown_versions_are_refused() {
        let mut p = input();
        p.service_type = Some(ServiceType::AdministrativeUser);
        assert!(p.validate(&filters(), 3600).is_err());
        p.service_type = Some(ServiceType::NasPromptUser);
        assert!(p.validate(&filters(), 3600).is_err());
        let mut p = input();
        p.dictionary = "axiam-radius-reply/2".into();
        assert!(p.validate(&filters(), 3600).is_err());
    }

    #[test]
    fn an_unknown_key_is_refused_by_name() {
        let err = serde_json::from_str::<ReplyProfileInput>(
            r#"{"session_timeout_secs": 600, "vendor_attribute": "Cisco-AVPair=priv-lvl=15"}"#,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("vendor_attribute"), "{err}");
    }

    #[test]
    fn the_wire_defaults_are_the_dictionary_and_radius_request() {
        let p: ReplyProfileInput =
            serde_json::from_str(r#"{"session_timeout_secs": 600}"#).unwrap();
        assert_eq!(p.dictionary, REPLY_DICTIONARY_V1);
        assert_eq!(p.termination_action, TerminationAction::RadiusRequest);
        assert!(p.filter_id.is_none() && p.service_type.is_none());
    }

    #[test]
    fn identifiers_follow_the_pattern() {
        for ok in ["a", "corp-acl", "A.b_c-9", &"a".repeat(63)] {
            assert!(is_valid_identifier(ok), "{ok}");
        }
        for bad in ["", "-a", ".a", "a b", "a/b", "é", &"a".repeat(64)] {
            assert!(!is_valid_identifier(bad), "{bad}");
        }
    }

    #[test]
    fn the_clamp_only_narrows() {
        assert_eq!(clamp_session_timeout(7200, 3600), 3600);
        assert_eq!(clamp_session_timeout(600, 3600), 600);
        assert!(is_valid_vlan(1) && is_valid_vlan(4094));
        assert!(!is_valid_vlan(0) && !is_valid_vlan(4095));
    }

    #[test]
    fn enum_spellings_round_trip() {
        for a in [TerminationAction::Default, TerminationAction::RadiusRequest] {
            assert_eq!(TerminationAction::parse(a.as_str()), Some(a));
        }
        for s in [
            ServiceType::FramedUser,
            ServiceType::AdministrativeUser,
            ServiceType::NasPromptUser,
        ] {
            assert_eq!(ServiceType::parse(s.as_str()), Some(s));
        }
        assert_eq!(ServiceType::FramedUser.value(), 2);
        assert_eq!(TerminationAction::RadiusRequest.value(), 1);
    }
}

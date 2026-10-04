//! SAML 2.0 service-provider registry (G-2, T23.2.1).
//!
//! AXIAM as a SAML identity provider issues assertions only to service
//! providers a tenant administrator has registered. This module is the plain
//! data of that registry. The write-time rules live in
//! `axiam_federation::saml_sp` — they need URL and X.509 parsing, which layer 0
//! does not carry — and the storage is `SamlServiceProviderRepository`.
//!
//! # What is deliberately *not* a field
//!
//! There is **no `sign_assertions` switch**. The design (plan §4 G-2) says
//! "assertions are signed always": an unsigned assertion is a bearer claim any
//! party on the path can forge, so a field for it could only ever be a way to
//! turn a security rule off. Signing the *response* envelope is a different
//! matter, because the assertion already carries its own signature, so that is
//! a policy ([`SamlServiceProvider::sign_responses`], default `true`).
//!
//! There is no private key here either. The SP's certificates are public
//! material used to verify a signed `AuthnRequest` and to encrypt an assertion
//! to the SP; the validator refuses anything that is not exactly one
//! `CERTIFICATE` PEM block.
//!
//! # Tenant scope
//!
//! Every row belongs to one tenant and `entity_id` is unique **per tenant**, so
//! two tenants may register the same SP without seeing each other.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Most ACS endpoints one service provider may register.
pub const MAX_ACS_ENDPOINTS: usize = 32;
/// Most attribute mappings one service provider may carry.
pub const MAX_ATTRIBUTE_MAPPINGS: usize = 64;
/// Most groups one `allowed_groups` list may name.
pub const MAX_ALLOWED_GROUPS: usize = 256;
/// Longest `entity_id`, in bytes (the pinned design bound).
pub const MAX_ENTITY_ID_BYTES: usize = 1024;
/// Longest `display_name`, in bytes.
pub const MAX_DISPLAY_NAME_BYTES: usize = 256;
/// Longest attribute `saml_name`, in bytes.
pub const MAX_ATTRIBUTE_NAME_BYTES: usize = 256;
/// Longest PEM text accepted for an SP certificate, in bytes.
pub const MAX_SP_CERT_PEM_BYTES: usize = 16 * 1024;

/// A SAML 2.0 protocol binding (SAML Bindings §3).
///
/// The response binding for Web Browser SSO is always [`Self::HttpPost`], but
/// the enum keeps both because SP metadata carries both, and an `slo_url` may
/// use either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum SamlBinding {
    /// `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST`.
    HttpPost,
    /// `urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect`.
    HttpRedirect,
}

impl SamlBinding {
    /// The spelling stored in the database column and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HttpPost => "http_post",
            Self::HttpRedirect => "http_redirect",
        }
    }

    /// Parse the stored spelling. Anything else is `None`.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "http_post" => Some(Self::HttpPost),
            "http_redirect" => Some(Self::HttpRedirect),
            _ => None,
        }
    }

    /// The SAML metadata `Binding` URN.
    #[must_use]
    pub const fn urn(self) -> &'static str {
        match self {
            Self::HttpPost => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Self::HttpRedirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
        }
    }
}

/// How the assertion's `NameID` is formed (per service provider).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum NameIdFormat {
    /// A persistent **pairwise** identifier: different for each service
    /// provider, so two SPs cannot correlate a user by `NameID`. The default.
    #[default]
    Persistent,
    /// The user's email address, on request.
    EmailAddress,
}

impl NameIdFormat {
    /// The spelling stored in the database column and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Persistent => "persistent",
            Self::EmailAddress => "email_address",
        }
    }

    /// Parse the stored spelling. Anything else is `None`.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "persistent" => Some(Self::Persistent),
            "email_address" => Some(Self::EmailAddress),
            _ => None,
        }
    }

    /// The SAML `NameIDFormat` URN.
    #[must_use]
    pub const fn urn(self) -> &'static str {
        match self {
            Self::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            Self::EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
        }
    }
}

/// Where an attribute's value comes from.
///
/// Every variant has a real source today; a variant with none (a telephone
/// number the OIDC `phone` scope gates behind its own consent, say) is
/// deliberately absent rather than mapped to an empty value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AttributeSource {
    /// `User::username`.
    Username,
    /// `User::email`.
    Email,
    /// The user's formatted name, `ProfileClaims::name` read from
    /// `User::metadata` (SCIM `name.formatted`, or "given family").
    DisplayName,
    /// `ProfileClaims::given_name` read from `User::metadata`.
    GivenName,
    /// `ProfileClaims::family_name` read from `User::metadata`.
    FamilyName,
    /// The names of the groups the user belongs to (multi-valued).
    Groups,
    /// The names of the roles the user holds (multi-valued).
    Roles,
}

impl AttributeSource {
    /// The spelling stored in the database and used on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Username => "username",
            Self::Email => "email",
            Self::DisplayName => "display_name",
            Self::GivenName => "given_name",
            Self::FamilyName => "family_name",
            Self::Groups => "groups",
            Self::Roles => "roles",
        }
    }

    /// Parse the stored spelling. Anything else is `None`.
    #[must_use]
    pub fn from_wire(raw: &str) -> Option<Self> {
        match raw {
            "username" => Some(Self::Username),
            "email" => Some(Self::Email),
            "display_name" => Some(Self::DisplayName),
            "given_name" => Some(Self::GivenName),
            "family_name" => Some(Self::FamilyName),
            "groups" => Some(Self::Groups),
            "roles" => Some(Self::Roles),
            _ => None,
        }
    }
}

/// `NameFormat` URNs an attribute mapping may name (SAML Core §8.2).
pub const ATTRIBUTE_NAME_FORMATS: [&str; 3] = [
    "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
    "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
    "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
];

/// One entry of an SP's attribute mapping table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AttributeMapping {
    /// The `Name` of the emitted `<saml:Attribute>`. Unique within one SP,
    /// compared exactly (SAML attribute names are case-sensitive).
    pub saml_name: String,
    /// The `NameFormat`, one of [`ATTRIBUTE_NAME_FORMATS`]. `None` leaves the
    /// attribute unqualified (`unspecified`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name_format: Option<String>,
    /// Where the value comes from.
    pub source: AttributeSource,
}

/// One `AssertionConsumerService` endpoint of a service provider.
///
/// The list of these is an **allow-list**, checked the way OAuth2 redirect
/// URIs are: an `AuthnRequest` naming an ACS URL is honoured only when the URL
/// equals one registered here, byte for byte. No globs, no prefix match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct AcsEndpoint {
    /// The endpoint URL.
    pub url: String,
    /// The binding the endpoint accepts.
    pub binding: SamlBinding,
    /// The `index` an `AuthnRequest` may use instead of a URL. Unique per SP.
    // An unsigned 16-bit integer (contract §29.2), and the published schema says
    // so (F4 W4 P23W4-05).
    #[schema(minimum = 0, maximum = 65535)]
    pub index: u16,
    /// Whether this is the SP's default endpoint. At most one is; when none is
    /// marked, the first listed is the default (SAML Metadata §2.4.4.1).
    #[serde(default)]
    pub is_default: bool,
}

fn default_true() -> bool {
    true
}

/// Everything an administrator supplies when registering or replacing a
/// service provider (`create` and `update` both take it; `update` is a full
/// replacement).
///
/// Every field but `entity_id`, `display_name` and `acs_urls` has a default, so
/// a client written against a later revision of this struct keeps working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SamlServiceProviderInput {
    /// Whether the SP may sign in at all. A disabled SP stays registered but
    /// every SSO request for it is refused.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Human-readable name for the console.
    pub display_name: String,
    /// The SP's `entityID`, unique per tenant. At most [`MAX_ENTITY_ID_BYTES`].
    pub entity_id: String,
    /// The ACS allow-list. At least one, at most one default.
    pub acs_urls: Vec<AcsEndpoint>,
    /// Single-logout endpoint, if the SP supports it.
    #[serde(default)]
    pub slo_url: Option<String>,
    /// The binding `slo_url` accepts. Set together with `slo_url`.
    #[serde(default)]
    pub slo_binding: Option<SamlBinding>,
    /// `NameID` policy. Default: persistent, pairwise.
    #[serde(default)]
    pub name_id_format: NameIdFormat,
    /// Sign the `<samlp:Response>` envelope as well as the assertion (which is
    /// signed always). Default **`true`**: it costs nothing and many SPs
    /// require it.
    #[serde(default = "default_true")]
    pub sign_responses: bool,
    /// Encrypt assertions to the SP's encryption certificate (D-2). Off by
    /// default; requires [`Self::sp_encryption_cert_pem`].
    #[serde(default)]
    pub encrypt_assertions: bool,
    /// PEM certificate the SP signs its `AuthnRequest`s with.
    #[serde(default)]
    pub sp_signing_cert_pem: Option<String>,
    /// PEM certificate assertions are encrypted to. Required when
    /// `encrypt_assertions` is set.
    #[serde(default)]
    pub sp_encryption_cert_pem: Option<String>,
    /// Refuse an `AuthnRequest` that is not signed by `sp_signing_cert_pem`.
    /// Requires that certificate.
    #[serde(default)]
    pub want_authn_requests_signed: bool,
    /// Whether IdP-initiated SSO is allowed for this SP (D-3). A per-SP
    /// opt-in, off by default: an unsolicited assertion has no `InResponseTo`
    /// to bind it to a request the SP made.
    #[serde(default)]
    pub allow_idp_initiated: bool,
    /// Attribute mapping table, at most [`MAX_ATTRIBUTE_MAPPINGS`] entries.
    #[serde(default)]
    pub attribute_mappings: Vec<AttributeMapping>,
    /// Groups whose members may sign in to this SP. **Empty means every active
    /// user of the tenant may.** Evaluated by the SSO endpoint (T23.2.3).
    #[serde(default)]
    pub allowed_groups: Vec<Uuid>,
}

/// A registered service provider, as stored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct SamlServiceProvider {
    /// Record id.
    pub id: Uuid,
    /// The owning tenant.
    pub tenant_id: Uuid,
    /// See [`SamlServiceProviderInput::enabled`].
    pub enabled: bool,
    /// See [`SamlServiceProviderInput::display_name`].
    pub display_name: String,
    /// See [`SamlServiceProviderInput::entity_id`].
    pub entity_id: String,
    /// See [`SamlServiceProviderInput::acs_urls`].
    pub acs_urls: Vec<AcsEndpoint>,
    /// See [`SamlServiceProviderInput::slo_url`].
    pub slo_url: Option<String>,
    /// See [`SamlServiceProviderInput::slo_binding`].
    pub slo_binding: Option<SamlBinding>,
    /// See [`SamlServiceProviderInput::name_id_format`].
    pub name_id_format: NameIdFormat,
    /// See [`SamlServiceProviderInput::sign_responses`].
    pub sign_responses: bool,
    /// See [`SamlServiceProviderInput::encrypt_assertions`].
    pub encrypt_assertions: bool,
    /// See [`SamlServiceProviderInput::sp_signing_cert_pem`].
    pub sp_signing_cert_pem: Option<String>,
    /// See [`SamlServiceProviderInput::sp_encryption_cert_pem`].
    pub sp_encryption_cert_pem: Option<String>,
    /// See [`SamlServiceProviderInput::want_authn_requests_signed`].
    pub want_authn_requests_signed: bool,
    /// See [`SamlServiceProviderInput::allow_idp_initiated`].
    pub allow_idp_initiated: bool,
    /// See [`SamlServiceProviderInput::attribute_mappings`].
    pub attribute_mappings: Vec<AttributeMapping>,
    /// See [`SamlServiceProviderInput::allowed_groups`].
    pub allowed_groups: Vec<Uuid>,
    /// When the SP was registered.
    pub created_at: DateTime<Utc>,
    /// When it was last replaced.
    pub updated_at: DateTime<Utc>,
}

impl SamlServiceProvider {
    /// The endpoint an `AuthnRequest` with no ACS hint is answered at: the
    /// one marked default, otherwise the first listed.
    #[must_use]
    pub fn default_acs(&self) -> Option<&AcsEndpoint> {
        self.acs_urls
            .iter()
            .find(|e| e.is_default)
            .or_else(|| self.acs_urls.first())
    }

    /// The registered endpoint whose URL equals `url` exactly, if any. This is
    /// the only way a requested ACS URL becomes a destination: exact string
    /// equality, no normalisation, no globs.
    #[must_use]
    pub fn acs_by_url(&self, url: &str) -> Option<&AcsEndpoint> {
        self.acs_urls.iter().find(|e| e.url == url)
    }

    /// The registered endpoint with this `index`, if any.
    #[must_use]
    pub fn acs_by_index(&self, index: u16) -> Option<&AcsEndpoint> {
        self.acs_urls.iter().find(|e| e.index == index)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn endpoint(url: &str, index: u16, is_default: bool) -> AcsEndpoint {
        AcsEndpoint {
            url: url.into(),
            binding: SamlBinding::HttpPost,
            index,
            is_default,
        }
    }

    fn sp(acs: Vec<AcsEndpoint>) -> SamlServiceProvider {
        SamlServiceProvider {
            id: Uuid::nil(),
            tenant_id: Uuid::nil(),
            enabled: true,
            display_name: "SP".into(),
            entity_id: "https://sp.example.com/metadata".into(),
            acs_urls: acs,
            slo_url: None,
            slo_binding: None,
            name_id_format: NameIdFormat::default(),
            sign_responses: true,
            encrypt_assertions: false,
            sp_signing_cert_pem: None,
            sp_encryption_cert_pem: None,
            want_authn_requests_signed: false,
            allow_idp_initiated: false,
            attribute_mappings: Vec::new(),
            allowed_groups: Vec::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn the_wire_spellings_round_trip_and_refuse_anything_else() {
        for b in [SamlBinding::HttpPost, SamlBinding::HttpRedirect] {
            assert_eq!(SamlBinding::from_wire(b.as_str()), Some(b));
        }
        for f in [NameIdFormat::Persistent, NameIdFormat::EmailAddress] {
            assert_eq!(NameIdFormat::from_wire(f.as_str()), Some(f));
        }
        for s in [
            AttributeSource::Username,
            AttributeSource::Email,
            AttributeSource::DisplayName,
            AttributeSource::GivenName,
            AttributeSource::FamilyName,
            AttributeSource::Groups,
            AttributeSource::Roles,
        ] {
            assert_eq!(AttributeSource::from_wire(s.as_str()), Some(s));
        }
        assert_eq!(SamlBinding::from_wire("HTTP-POST"), None);
        assert_eq!(NameIdFormat::from_wire("transient"), None);
        assert_eq!(AttributeSource::from_wire("password_hash"), None);
    }

    #[test]
    fn the_input_defaults_are_the_pinned_ones() {
        let input: SamlServiceProviderInput = serde_json::from_value(serde_json::json!({
            "display_name": "SP",
            "entity_id": "https://sp.example.com/metadata",
            "acs_urls": [{
                "url": "https://sp.example.com/acs",
                "binding": "http_post",
                "index": 0
            }]
        }))
        .expect("only the three required fields");
        assert!(input.enabled);
        assert_eq!(input.name_id_format, NameIdFormat::Persistent);
        assert!(input.sign_responses, "responses are signed by default");
        assert!(
            !input.encrypt_assertions,
            "D-2: encryption is off by default"
        );
        assert!(!input.want_authn_requests_signed);
        assert!(!input.allow_idp_initiated, "D-3: IdP-initiated is opt-in");
        assert!(input.allowed_groups.is_empty());
        assert!(input.attribute_mappings.is_empty());
        assert!(!input.acs_urls[0].is_default);
    }

    #[test]
    fn there_is_no_switch_to_turn_assertion_signing_off() {
        // A payload that tries to send one is simply not a field: it is
        // ignored on the way in, and the type has nowhere to store it.
        let value = serde_json::to_value(sp(vec![endpoint("https://a.example/acs", 0, false)]))
            .expect("serialise");
        assert!(value.get("sign_assertions").is_none());
    }

    #[test]
    fn the_default_endpoint_is_the_marked_one_else_the_first() {
        let marked = sp(vec![
            endpoint("https://a.example/acs", 0, false),
            endpoint("https://b.example/acs", 1, true),
        ]);
        assert_eq!(
            marked.default_acs().map(|e| e.url.as_str()),
            Some("https://b.example/acs")
        );
        let unmarked = sp(vec![
            endpoint("https://a.example/acs", 0, false),
            endpoint("https://b.example/acs", 1, false),
        ]);
        assert_eq!(
            unmarked.default_acs().map(|e| e.url.as_str()),
            Some("https://a.example/acs")
        );
        assert!(sp(Vec::new()).default_acs().is_none());
    }

    #[test]
    fn an_acs_url_is_found_by_exact_equality_only() {
        let provider = sp(vec![endpoint("https://a.example/acs", 3, false)]);
        assert!(provider.acs_by_url("https://a.example/acs").is_some());
        for near_miss in [
            "https://a.example/acs/",
            "https://A.example/acs",
            "https://a.example/acs?x=1",
            "https://a.example/ac",
            "https://a.example/acs ",
        ] {
            assert!(
                provider.acs_by_url(near_miss).is_none(),
                "{near_miss} must not match"
            );
        }
        assert!(provider.acs_by_index(3).is_some());
        assert!(provider.acs_by_index(4).is_none());
    }
}

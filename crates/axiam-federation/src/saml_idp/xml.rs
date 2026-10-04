//! The issuer's XML text primitives: escaping, identifiers and instants.
//!
//! The assertion is written as text rather than through a serializer, so that
//! what is signed is exactly what is read here. That makes escaping the whole
//! defence against markup injection: every value that did not originate in this
//! module — a user's display name, a group name, an SP entity id, a request id —
//! passes through [`escape`] on its way in, in element text and in attribute
//! values alike.

use chrono::{DateTime, SecondsFormat, Utc};
use rand::Rng;

/// Bytes of CSPRNG output in an `ID`. 160 bits: SAML Core §1.3.4 asks for an
/// identifier whose chance of a collision is "less than 2^-128", which wants at
/// least 128 bits; 160 is what the specification's own example uses.
const ID_RANDOM_BYTES: usize = 20;

/// Longest `InResponseTo` this issuer will echo, in bytes.
///
/// SAML Core types it as `xs:NCName` with no upper bound. The value comes from an
/// `AuthnRequest` anyone can send, and it is copied into a signed assertion, so
/// it is bounded rather than taken at any length. 256 bytes is several times
/// the length of the 128- to 160-bit random ids SAML Core §1.3.4 recommends,
/// however they are encoded.
pub const MAX_REQUEST_ID_BYTES: usize = 256;

/// Escape a value for XML element text **and** attribute values.
///
/// One function for both, so a call site cannot pick the weaker one:
///
/// * `&`, `<`, `>`, `"` and `'` become entity references, so no value can open
///   or close an element, end an attribute, or spell `]]>`;
/// * tab, line feed and carriage return become character references, so an
///   attribute value survives the parser's attribute-value normalisation (XML
///   1.0 §3.3.3) and a text value keeps a `\r` the parser would fold;
/// * a character XML 1.0 cannot carry at all, even escaped (the C0 controls
///   other than the three above, `U+FFFE`, `U+FFFF`), becomes `U+FFFD`. The
///   alternative, refusing the whole sign-in because a SCIM client stored a
///   control character in a display name, punishes the user for the
///   provisioner.
#[must_use]
pub fn escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + input.len() / 8);
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' => out.push_str("&#9;"),
            '\n' => out.push_str("&#10;"),
            '\r' => out.push_str("&#13;"),
            c if is_xml_char(c) => out.push(c),
            _ => out.push('\u{FFFD}'),
        }
    }
    out
}

/// XML 1.0 `Char` (§2.2), less the three whitespace controls [`escape`]
/// handles itself.
fn is_xml_char(c: char) -> bool {
    matches!(
        c,
        '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
    )
}

/// A fresh protocol identifier: `_` followed by 40 lower-case hex digits of
/// CSPRNG output.
///
/// The leading underscore is what makes it a valid `xs:ID` (an `NCName` may not
/// start with a digit, and hex often does); the 160 random bits are what make
/// it unique and unguessable. Never derived from a counter, a clock or a
/// database id, so an `ID` says nothing about how many assertions were issued
/// or when.
#[must_use]
pub fn new_id() -> String {
    let mut bytes = [0u8; ID_RANDOM_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    format!("_{}", hex::encode(bytes))
}

/// Whether `id` may be echoed as an `InResponseTo`.
///
/// The ASCII subset of `xs:NCName` — a letter or `_`, then letters, digits,
/// `.`, `-` and `_` — at most [`MAX_REQUEST_ID_BYTES`] long. Stricter than the
/// schema (which admits non-ASCII letters) and as permissive as every SP
/// implementation the e2e harness covers. Escaping would make any value safe to
/// write; this check is about not putting an arbitrary caller-chosen string
/// under the tenant's signature at all.
#[must_use]
pub fn is_request_id(id: &str) -> bool {
    let bytes = id.as_bytes();
    let Some((&first, rest)) = bytes.split_first() else {
        return false;
    };
    bytes.len() <= MAX_REQUEST_ID_BYTES
        && (first.is_ascii_alphabetic() || first == b'_')
        && rest
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

/// An `xs:dateTime` in UTC with whole seconds, `2026-10-03T12:00:00Z`.
///
/// Whole seconds because some service providers still parse the instant with a
/// fixed pattern that has no fraction; the builder truncates its clock reading
/// once, so every instant it writes is exactly representable.
#[must_use]
pub fn instant(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Secs, true)
}

/// Strip a leading `<?xml …?>` declaration, as libxml writes one on every
/// serialized document and an assertion embedded in a response must not carry
/// one.
#[must_use]
pub fn strip_declaration(xml: &str) -> &str {
    let trimmed = xml.trim_start();
    let body = if trimmed.starts_with("<?xml") {
        trimmed
            .find("?>")
            .map_or(trimmed, |end| &trimmed[end + 2..])
    } else {
        trimmed
    };
    body.trim()
}

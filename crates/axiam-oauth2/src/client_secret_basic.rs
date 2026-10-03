//! W8 / RFC 6749 §2.3.1 — the `Authorization: Basic` spelling of a client's
//! shared secret.
//!
//! # Why this module is separate from the header that carries it
//!
//! Everything here is a pure function over a `&str`. The REST layer reads the
//! `Authorization` header off an `HttpRequest` and hands the value in; this
//! crate never sees actix, and the RFC's decoding rules — which are where the
//! bugs live — are unit-testable without a running server. That is the same
//! division [`crate::dpop`] and [`crate::mtls`] already use: the transport
//! layer produces the raw material, this crate decides what it means, and
//! [`crate::token::TokenRequestContext`] carries the *conclusion*.
//!
//! # The decoding, and the step everybody skips
//!
//! RFC 6749 §2.3.1 does **not** say "base64 of `client_id:client_secret`". It
//! says the client id and secret are each encoded with the
//! `application/x-www-form-urlencoded` encoding algorithm *first*, joined with
//! a single colon, and the result base64-encoded. So the server must:
//!
//! 1. base64-decode the credentials blob;
//! 2. split it on the **first** colon (RFC 7617 §2: a user-id may not contain
//!    one, a password may — splitting on the last would truncate any secret
//!    containing a colon);
//! 3. `application/x-www-form-urlencoded`-**decode each half**.
//!
//! Step 3 is the classic omission, and it is invisible in testing unless the
//! secret contains a character the encoding touches — which AXIAM's own
//! server-generated secrets never do. A third-party relying party with a
//! secret containing `%`, `+` or `:` would simply fail to authenticate, with
//! an `invalid_client` that says nothing about why. `T9.1` in
//! `crates/axiam-oauth2/tests/client_secret_basic.rs` exists for exactly that
//! secret.
//!
//! # What this module deliberately does not do
//!
//! It does not decide whether the credentials it decoded are *the* credentials
//! for this request. Only the registration decides that
//! (`TokenService::authenticate_client_credential`, SEC-093): a
//! `client_secret_post` client presenting a Basic header is authenticated by
//! its body secret and the header is ignored. Parsing a header is not
//! accepting it.

use base64::Engine as _;

/// The scheme name, matched case-insensitively per RFC 9110 §11.1.
const BASIC_SCHEME: &str = "basic";

/// The `WWW-Authenticate` challenge a malformed or rejected Basic credential
/// is answered with (RFC 6749 §5.2: the challenge must name the scheme the
/// client actually used).
pub const BASIC_CHALLENGE: &str = "Basic realm=\"axiam\"";

/// A `client_id`/`client_secret` pair decoded out of an `Authorization: Basic`
/// header.
///
/// Holding the two halves separately rather than the raw header is what lets
/// the rest of the server treat this as a credential rather than as a string:
/// there is no method on this type that returns the base64 blob, so no log
/// site can accidentally emit it.
#[derive(Clone, PartialEq, Eq)]
pub struct BasicCredentials {
    client_id: String,
    client_secret: String,
}

impl BasicCredentials {
    /// The client identifier the header named.
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The shared secret the header carried.
    ///
    /// The only accessor for it, and it is called from exactly one place:
    /// [`crate::token::TokenService::authenticate_client_credential`]'s
    /// `ClientSecretBasic` arm.
    pub fn client_secret(&self) -> &str {
        &self.client_secret
    }
}

/// Redacted, unconditionally.
///
/// `TokenRequestContext` derives `Debug`, and a `TokenRequestContext` reaches
/// `tracing::error!(?ctx, …)` the first time somebody debugs a token-endpoint
/// failure. A derived `Debug` here would put a live client secret in the log
/// at that moment, which is the leak this whole wave is supposed to prevent —
/// so the derive is refused rather than trusted not to be used.
impl std::fmt::Debug for BasicCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BasicCredentials")
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .finish()
    }
}

/// Why an `Authorization: Basic` header could not be turned into credentials.
///
/// One flat error rather than a `bool`, because the REST layer answers all of
/// them with the same `invalid_client` + challenge and the *reason* is only
/// ever a `tracing::debug!` — but a caller reading this code should be able to
/// see that all four are distinguishable server-side without being
/// distinguishable to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BasicAuthError {
    /// The credentials blob is not valid base64.
    NotBase64,
    /// The decoded blob has no colon, so it names no client.
    NoSeparator,
    /// A half is not valid `application/x-www-form-urlencoded` — a truncated
    /// or non-hex `%` escape, or bytes that are not UTF-8 once decoded.
    BadEncoding,
    /// A half decoded to the empty string. An empty `client_id` names no
    /// client and an empty secret can match no stored hash, so both are
    /// refused here rather than sent on to fail obscurely later.
    EmptyHalf,
}

/// Read the `Authorization` header value.
///
/// `None` means "this request is not attempting Basic authentication" — no
/// header, or a header naming another scheme (`Bearer`, `DPoP`). That is not
/// an error: the token endpoint accepts four other client-authentication
/// methods, three of which put nothing in this header and one of which
/// (`private_key_jwt`) puts nothing there either.
///
/// `Some(Err(_))` means "this request *is* attempting Basic authentication and
/// got it wrong", which the REST layer answers with a challenge. The
/// distinction matters: collapsing it to `Option` would make a corrupt Basic
/// header silently equivalent to sending none, and a client whose secret
/// contained a stray byte would see `invalid_client` with no `WWW-Authenticate`
/// telling it which scheme failed.
pub fn parse_authorization_header(raw: &str) -> Option<Result<BasicCredentials, BasicAuthError>> {
    let credentials = basic_credentials_of(raw)?;
    Some(decode_credentials(credentials))
}

/// Whether this `Authorization` value names the `Basic` scheme, without
/// decoding anything.
///
/// The REST layer asks twice about one header — once to decode it and once,
/// before the handler runs, to fix the RFC 6749 §5.2 challenge — and the
/// second question needs only the scheme. Sharing this rather than re-writing
/// `split_once(' ')` at the call site is what keeps "what counts as Basic"
/// in one place: two copies would eventually disagree about a tab, a case, or
/// a missing credential, and the failure mode is a Basic attempt answered with
/// a `Bearer` challenge.
pub fn names_basic_scheme(raw: &str) -> bool {
    basic_credentials_of(raw).is_some()
}

/// The credentials portion of an `Authorization: Basic …` value, or `None` for
/// any other scheme.
fn basic_credentials_of(raw: &str) -> Option<&str> {
    let (scheme, credentials) = raw.trim().split_once(' ')?;
    scheme
        .eq_ignore_ascii_case(BASIC_SCHEME)
        .then(|| credentials.trim())
}

/// The RFC 6749 §2.3.1 credentials blob, decoded.
///
/// Split out from [`parse_authorization_header`] so the three-step decoding
/// can be tested against RFC vectors without constructing a header around
/// them.
pub fn decode_credentials(blob: &str) -> Result<BasicCredentials, BasicAuthError> {
    // RFC 4648 §4 with padding — what every Basic client emits. The
    // no-padding alphabet is deliberately not accepted as a fallback: a blob
    // that needs it was not produced by a conforming client, and quietly
    // accepting two encodings is how a request ends up meaning two things.
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .map_err(|_| BasicAuthError::NotBase64)?;
    let decoded = String::from_utf8(decoded).map_err(|_| BasicAuthError::BadEncoding)?;

    // RFC 7617 §2 — the FIRST colon. A user-id may not contain one; a
    // password may, and a client is not obliged to percent-encode it (`:` is
    // legal in the password half either way). Splitting on the last colon
    // truncates every such secret to its final segment, and does so silently.
    let (raw_id, raw_secret) = decoded.split_once(':').ok_or(BasicAuthError::NoSeparator)?;

    let client_id = form_urldecode(raw_id).ok_or(BasicAuthError::BadEncoding)?;
    let client_secret = form_urldecode(raw_secret).ok_or(BasicAuthError::BadEncoding)?;

    if client_id.is_empty() || client_secret.is_empty() {
        return Err(BasicAuthError::EmptyHalf);
    }

    Ok(BasicCredentials {
        client_id,
        client_secret,
    })
}

/// `application/x-www-form-urlencoded` decoding of one half (WHATWG URL
/// §5.1, the algorithm RFC 6749 §2.3.1 names).
///
/// Hand-written rather than routed through `url::form_urlencoded::parse`,
/// which is a *query string* parser: it also splits on `&` and `=`, so a
/// secret containing either would be silently truncated by the very function
/// meant to preserve it. Twenty lines that do only the one thing are cheaper
/// than a comment explaining why the library call is safe, and they are what
/// the RFC actually specifies.
///
/// `None` for a truncated or non-hex `%` escape, or for a byte sequence that
/// is not UTF-8 once the escapes are resolved.
fn form_urldecode(raw: &str) -> Option<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // `+` means space, and ONLY in this encoding. A client whose
            // secret contains a literal `+` must send `%2B`; one that sends a
            // raw `+` has said "space" and gets a space. That is the RFC's
            // answer, not a convenience, and it is pinned by a test.
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                let hi = (*bytes.get(i + 1)? as char).to_digit(16)?;
                let lo = (*bytes.get(i + 2)? as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
                i += 3;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(blob: &str) -> String {
        format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode(blob)
        )
    }

    #[test]
    fn a_plain_credential_pair_round_trips() {
        let c = parse_authorization_header(&header("oa_abc:s3cret"))
            .expect("scheme is basic")
            .expect("well-formed");
        assert_eq!(c.client_id(), "oa_abc");
        assert_eq!(c.client_secret(), "s3cret");
    }

    #[test]
    fn the_scheme_is_matched_case_insensitively() {
        let raw = header("oa_abc:s3cret").replace("Basic", "bAsIc");
        assert!(parse_authorization_header(&raw).is_some());
    }

    #[test]
    fn the_scheme_test_agrees_with_the_parser() {
        // The two must never disagree: `names_basic_scheme` decides the
        // challenge and `parse_authorization_header` decides the credential,
        // and a header that is Basic for one and not for the other is a Basic
        // attempt answered with a Bearer challenge.
        for raw in [
            "Basic YWJjOmRlZg==",
            "  bAsIc   YWJjOmRlZg==  ",
            "Basic !!!", // Basic, and malformed — still Basic
            "Bearer abc",
            "DPoP abc",
            "Basic",
            "",
        ] {
            assert_eq!(
                names_basic_scheme(raw),
                parse_authorization_header(raw).is_some(),
                "raw = {raw:?}"
            );
        }
    }

    #[test]
    fn another_scheme_is_not_an_error() {
        // A DPoP-bound client sends `Authorization: DPoP …` to the resource
        // server, and a token request may legitimately carry nothing at all.
        assert!(parse_authorization_header("Bearer abcdef").is_none());
        assert!(parse_authorization_header("").is_none());
        assert!(parse_authorization_header("Basic").is_none());
    }

    #[test]
    fn each_half_is_form_urldecoded_after_the_split() {
        // T9.1's vector: `%`, `+` and `:` all present in the secret. Skipping
        // the form-urlencoded decode yields `p%25a%2Bs%3As`, which matches no
        // stored hash.
        let c = decode_credentials(
            &base64::engine::general_purpose::STANDARD.encode("oa_abc:p%25a%2Bs%3As"),
        )
        .expect("well-formed");
        assert_eq!(c.client_secret(), "p%a+s:s");
    }

    #[test]
    fn the_split_is_on_the_first_colon() {
        // RFC 7617 §2 permits a raw colon in the password half. Splitting on
        // the last would hand back `b` and authenticate nobody.
        let c = decode_credentials(&base64::engine::general_purpose::STANDARD.encode("oa_abc:a:b"))
            .expect("well-formed");
        assert_eq!(c.client_id(), "oa_abc");
        assert_eq!(c.client_secret(), "a:b");
    }

    #[test]
    fn a_raw_plus_decodes_to_a_space() {
        let c = decode_credentials(&base64::engine::general_purpose::STANDARD.encode("oa_abc:a+b"))
            .expect("well-formed");
        assert_eq!(c.client_secret(), "a b");
    }

    #[test]
    fn the_client_id_half_is_decoded_too() {
        let c = decode_credentials(
            &base64::engine::general_purpose::STANDARD.encode("oa%5Fabc:secret"),
        )
        .expect("well-formed");
        assert_eq!(c.client_id(), "oa_abc");
    }

    #[test]
    fn malformed_blobs_are_classified_rather_than_guessed_at() {
        assert_eq!(
            decode_credentials("not base64!!"),
            Err(BasicAuthError::NotBase64)
        );
        assert_eq!(
            decode_credentials(&base64::engine::general_purpose::STANDARD.encode("no-colon-here")),
            Err(BasicAuthError::NoSeparator)
        );
        assert_eq!(
            decode_credentials(&base64::engine::general_purpose::STANDARD.encode("oa_abc:tru%")),
            Err(BasicAuthError::BadEncoding)
        );
        assert_eq!(
            decode_credentials(&base64::engine::general_purpose::STANDARD.encode("oa_abc:%zz")),
            Err(BasicAuthError::BadEncoding)
        );
        assert_eq!(
            decode_credentials(&base64::engine::general_purpose::STANDARD.encode(":secret")),
            Err(BasicAuthError::EmptyHalf)
        );
        assert_eq!(
            decode_credentials(&base64::engine::general_purpose::STANDARD.encode("oa_abc:")),
            Err(BasicAuthError::EmptyHalf)
        );
    }

    // -----------------------------------------------------------------
    // T23.1.5 — the RFC 6749 §2.3.1 / RFC 7617 edge cases an audit of the
    // module against its specification found without a pinning test. No
    // secret below is a real credential, and no assertion formats one: the
    // cases are named instead.
    // -----------------------------------------------------------------

    fn blob(raw: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(raw)
    }

    #[test]
    fn a_percent_encoded_colon_in_the_id_is_a_colon_in_the_id() {
        // `%3A` is the form-urlencoding of the one character the Basic
        // user-id may not carry raw. The split happens on the raw colon
        // FIRST, so an encoded one survives into the decoded id.
        let c = decode_credentials(&blob("oa%3Aabc:secret")).expect("well-formed");
        assert_eq!(c.client_id(), "oa:abc");
        assert_eq!(c.client_secret(), "secret");
    }

    #[test]
    fn plus_and_percent_two_b_are_different_characters_in_the_secret() {
        // Raw `+` is a space; `%2B` and `%2b` are a plus. Lower-case hex is
        // as valid as upper-case.
        for (encoded, expected, case) in [
            ("a+b", "a b", "raw plus"),
            ("a%2Bb", "a+b", "upper-case %2B"),
            ("a%2bb", "a+b", "lower-case %2b"),
            ("a%20b", "a b", "%20"),
            ("a%25b", "a%b", "%25"),
        ] {
            let c = decode_credentials(&blob(&format!("oa_abc:{encoded}"))).expect("well-formed");
            assert_eq!(c.client_secret(), expected, "case: {case}");
        }
    }

    #[test]
    fn ampersand_and_equals_in_the_secret_survive() {
        // The reason the decoder is hand-written: a query-string parser
        // splits on both and would truncate the secret silently.
        let c = decode_credentials(&blob("oa_abc:a&b=c")).expect("well-formed");
        assert_eq!(c.client_secret(), "a&b=c");
    }

    #[test]
    fn non_ascii_is_accepted_raw_or_percent_encoded_and_must_be_utf8() {
        // A client following RFC 6749 §2.3.1 percent-encodes the UTF-8
        // bytes; a client that does not sends them raw. Both decode to the
        // same string. Bytes that are not UTF-8 either way are refused.
        let raw = decode_credentials(&blob("oa_abc:p\u{e4}ss\u{20ac}")).expect("raw UTF-8");
        let encoded =
            decode_credentials(&blob("oa_abc:p%C3%A4ss%E2%82%AC")).expect("percent-encoded UTF-8");
        assert_eq!(raw.client_secret(), encoded.client_secret());
        assert_eq!(encoded.client_secret(), "p\u{e4}ss\u{20ac}");

        assert_eq!(
            decode_credentials(&blob("oa_abc:%FF%FE")),
            Err(BasicAuthError::BadEncoding),
            "percent-encoded bytes that are not UTF-8"
        );
        let not_utf8 = base64::engine::general_purpose::STANDARD.encode([b'o', b':', 0xFF, 0xFE]);
        assert_eq!(
            decode_credentials(&not_utf8),
            Err(BasicAuthError::BadEncoding),
            "raw bytes that are not UTF-8"
        );
    }

    #[test]
    fn only_canonical_padded_standard_base64_is_accepted() {
        // 'oa_abc:s3cret' is 13 bytes, so its canonical encoding needs one
        // `=`. Neither the unpadded form nor the URL-safe alphabet is a
        // second spelling of the same credential.
        let padded = blob("oa_abc:s3cret");
        assert!(padded.ends_with('='), "fixture needs a padded blob");
        assert!(decode_credentials(&padded).is_ok());

        let unpadded = padded.trim_end_matches('=');
        assert_eq!(
            decode_credentials(unpadded),
            Err(BasicAuthError::NotBase64),
            "unpadded"
        );

        // A value whose standard encoding uses `+` or `/` has a different
        // URL-safe spelling.
        let standard = base64::engine::general_purpose::STANDARD.encode([0xFB, 0xFF, 0xBF, b':']);
        let url_safe = base64::engine::general_purpose::URL_SAFE.encode([0xFB, 0xFF, 0xBF, b':']);
        assert_ne!(standard, url_safe, "fixture needs a character that differs");
        assert_eq!(
            decode_credentials(&url_safe),
            Err(BasicAuthError::NotBase64),
            "URL-safe alphabet"
        );
    }

    #[test]
    fn whitespace_around_the_scheme_and_credentials_is_tolerated_but_only_spaces_separate() {
        let blob = blob("oa_abc:s3cret");
        for (raw, case) in [
            (format!("Basic {blob}"), "one space"),
            (format!("Basic    {blob}"), "several spaces"),
            (format!("  Basic {blob}  "), "leading and trailing spaces"),
            (format!("BASIC {blob}"), "upper-case scheme"),
            (format!("basic {blob}"), "lower-case scheme"),
        ] {
            let parsed = parse_authorization_header(&raw)
                .unwrap_or_else(|| panic!("case {case}: not recognised as Basic"))
                .unwrap_or_else(|_| panic!("case {case}: not decoded"));
            assert_eq!(parsed.client_id(), "oa_abc", "case: {case}");
        }

        // RFC 9110 §11.1 separates scheme and credentials with 1*SP. A tab is
        // not that, and what `names_basic_scheme` says must agree with the
        // parser either way.
        let tabbed = format!("Basic\t{blob}");
        assert_eq!(
            names_basic_scheme(&tabbed),
            parse_authorization_header(&tabbed).is_some()
        );
        assert!(!names_basic_scheme(&tabbed), "a tab is not a separator");
    }

    #[test]
    fn an_empty_half_is_refused_whichever_half_it_is() {
        for (raw, case) in [
            ("oa_abc:", "empty secret"),
            (":secret", "empty id"),
            (":", "both empty"),
            (
                "oa_abc:%",
                "a lone percent sign is a bad escape, not an empty secret",
            ),
        ] {
            let expected = if case.starts_with("a lone") {
                BasicAuthError::BadEncoding
            } else {
                BasicAuthError::EmptyHalf
            };
            assert_eq!(
                decode_credentials(&blob(raw)),
                Err(expected),
                "case: {case}"
            );
        }
    }

    #[test]
    fn the_secret_never_reaches_a_debug_rendering() {
        // The one property this type exists to hold. `TokenRequestContext`
        // derives `Debug`; the day somebody adds `?ctx` to a tracing call at
        // the token endpoint, this is what stops it being an incident.
        let c = decode_credentials(
            &base64::engine::general_purpose::STANDARD.encode("oa_abc:super-secret-value"),
        )
        .expect("well-formed");
        let rendered = format!("{c:?}");
        assert!(!rendered.contains("super-secret-value"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("oa_abc"), "{rendered}");
    }
}

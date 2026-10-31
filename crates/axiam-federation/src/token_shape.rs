//! What kind of JWT a provider-issued token is, judged by its shape.
//!
//! One definition, read by two checks that point in opposite directions:
//!
//! * X4 ([`crate::token_exchange`]) accepts an **access token** as an RFC 8693
//!   subject token and refuses anything carrying an ID-token marker or a
//!   refresh/logout type.
//! * Native sign-in ([`crate::native_login`]) accepts **only an ID token** and
//!   refuses an access-token-shaped JWT.
//!
//! Were the marker list written twice, a marker added to one side and not the
//! other would open exactly the hole each check closes: an ID token buying an
//! API credential through X4, or an access token buying a sign-in here. So the
//! lists live here and both modules read them.

/// Claims that are legal only in an OIDC ID token: `nonce` (OIDC Core
/// §3.1.3.7) and the hashes of §3.3.2.11 / §3.2.2.9.
///
/// The order is the order X4 reports them in, and is part of its behaviour.
pub(crate) const ID_TOKEN_ONLY_CLAIMS: [&str; 4] = ["nonce", "at_hash", "c_hash", "s_hash"];

/// `typ` values (JOSE header or claim, after [`normalize_typ`]) that name an ID
/// token.
pub(crate) const ID_TOKEN_TYPES: [&str; 2] = ["id_token", "id+jwt"];

/// `typ` values that name a token which is neither an access token nor an ID
/// token: a refresh token, an offline token, a logout token. Neither path
/// accepts one.
pub(crate) const NEITHER_ACCESS_NOR_ID_TYPES: [&str; 4] =
    ["refresh", "refresh_token", "offline", "logout+jwt"];

/// `typ` values that name an access token (RFC 9068 §2.1). Native sign-in
/// refuses them; X4 has no need to name them, because it refuses by marker
/// rather than requiring one.
pub(crate) const ACCESS_TOKEN_TYPES: [&str; 1] = ["at+jwt"];

/// A `typ` as compared: trimmed, ASCII-lowercased, an `application/` media-type
/// prefix removed (RFC 7515 §4.1.9 allows it to be omitted).
pub(crate) fn normalize_typ(typ: &str) -> String {
    let lowered = typ.trim().to_ascii_lowercase();
    match lowered.strip_prefix("application/") {
        Some(rest) => rest.to_owned(),
        None => lowered,
    }
}

/// Whether X4 refuses a token whose (normalized) `typ` is this: an ID token
/// type, or one that is neither an access nor an ID token.
pub(crate) fn refused_as_subject_token(normalized: &str) -> bool {
    ID_TOKEN_TYPES.contains(&normalized) || NEITHER_ACCESS_NOR_ID_TYPES.contains(&normalized)
}

/// Whether native sign-in refuses a token whose (normalized) `typ` is this: an
/// access token type, or one that is neither an access nor an ID token.
pub(crate) fn refused_as_native_id_token(normalized: &str) -> bool {
    ACCESS_TOKEN_TYPES.contains(&normalized) || NEITHER_ACCESS_NOR_ID_TYPES.contains(&normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two refusals partition the named types: no `typ` is acceptable to
    /// both paths, and an ID-token type is refused by exactly one of them.
    #[test]
    fn no_named_type_is_accepted_by_both_paths() {
        for t in ID_TOKEN_TYPES
            .iter()
            .chain(&NEITHER_ACCESS_NOR_ID_TYPES)
            .chain(&ACCESS_TOKEN_TYPES)
        {
            assert!(
                refused_as_subject_token(t) || refused_as_native_id_token(t),
                "{t} is refused by at least one path"
            );
        }
        for t in ID_TOKEN_TYPES {
            assert!(refused_as_subject_token(t) && !refused_as_native_id_token(t));
        }
        for t in ACCESS_TOKEN_TYPES {
            assert!(!refused_as_subject_token(t) && refused_as_native_id_token(t));
        }
    }

    #[test]
    fn a_typ_is_compared_without_case_whitespace_or_media_type_prefix() {
        assert_eq!(normalize_typ(" Application/ID+JWT "), "id+jwt");
        assert_eq!(normalize_typ("at+jwt"), "at+jwt");
        assert_eq!(normalize_typ("JWT"), "jwt");
    }
}

//! OpenID Connect Discovery, JWKS, and UserInfo types.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Discovery Document (RFC 8414 / OpenID Connect Discovery 1.0)
// ---------------------------------------------------------------------------

/// RFC 8705 §5 `mtls_endpoint_aliases` — the endpoints re-based on the host
/// that performs the mutual-TLS handshake.
///
/// Present only when the deployment configured a separate mTLS host
/// (`AXIAM__AUTH__OAUTH2_MTLS_BASE_URL`); a client doing mTLS MUST prefer an
/// alias over the top-level endpoint of the same name.
//
// The rest of the rationale is deliberately NOT a doc comment: utoipa lifts a
// doc block verbatim into the OpenAPI `description`, and eleven SDK repos
// vendor `sdks/openapi.json` byte-for-byte. A design argument belongs in the
// source, where it is read by whoever changes this; a two-kilobyte markdown
// table belongs in neither a generated client nor eleven re-vendor rounds.
// Same reasoning as the F3 note on `handlers::oauth2::jwks`.
//
// # What is aliased, and what deliberately is not
//
// An endpoint belongs here exactly when reaching it over mTLS is meaningful —
// either the authorization server authenticates the client there (§2), or the
// caller presents a certificate-bound token there (§3.2):
//
// | Endpoint | Why it is aliased |
// |---|---|
// | `token_endpoint` | client authentication, and where a bound token is minted |
// | `revocation_endpoint` | client authentication (RFC 7009 §2.1) |
// | `introspection_endpoint` | client authentication (RFC 7662 §2.1) |
// | `device_authorization_endpoint` | client authentication (RFC 8628 §3.1) |
// | `pushed_authorization_request_endpoint` | client authentication (RFC 9126 §2) |
// | `userinfo_endpoint` | a `cnf`-bound access token is refused unless presented on the connection it is bound to |
//
// Three endpoints AXIAM publishes are absent, and their absence is the design
// rather than an omission:
//
// - `authorization_endpoint` and `end_session_endpoint` are front-channel: the
//   visitor is a browser, the authorization server authenticates the *user*
//   there and never the client, and prompting a browser for a client
//   certificate produces a native chooser dialog most users cannot answer.
// - `jwks_uri` is unauthenticated public key material. Putting it behind a
//   handshake gains nothing and costs every client that only wanted to verify a
//   signature.
//
// `issuer` is absent for a different reason again: it is an identifier, not an
// endpoint. OIDC Core §2 requires it to match the `iss` of every token exactly,
// so a per-transport `issuer` would break token validation on the transport
// that got the alias.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct MtlsEndpointAliases {
    /// RFC 8705 §2 and §3 — client authentication and the mint of a
    /// certificate-bound token.
    pub token_endpoint: String,
    /// OIDC Core §5.3, reached with an access token that may carry `cnf`.
    pub userinfo_endpoint: String,
    /// RFC 7009 §2.1 — authenticates the client.
    pub revocation_endpoint: String,
    /// RFC 7662 §2.1 — authenticates the caller.
    pub introspection_endpoint: String,
    /// RFC 8628 §3.1 — authenticates the client.
    pub device_authorization_endpoint: String,
    /// RFC 9126 §2 — authenticates the client.
    pub pushed_authorization_request_endpoint: String,
}

/// OpenID Connect Discovery 1.0 metadata document.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks_uri: String,
    pub revocation_endpoint: String,
    pub introspection_endpoint: String,
    /// RFC 8628 §4 — B2. Advertised unconditionally because the grant is
    /// always mounted; a device that reads discovery is exactly the client
    /// that cannot be told the URL out of band.
    pub device_authorization_endpoint: String,
    /// RFC 9126 §5 — B5. Advertised unconditionally because the endpoint is
    /// always mounted.
    pub pushed_authorization_request_endpoint: String,
    /// The **server-wide** default, which is `false`: PAR is available to
    /// every client but demanded of none. Per-client enforcement is
    /// `require_par` on the registration and is deliberately not discoverable
    /// — RFC 9126 §5 scopes this metadata to the server, and publishing a
    /// per-client answer here would leak one client's posture to every other
    /// reader of the document.
    pub require_pushed_authorization_requests: bool,
    /// OIDC RP-Initiated Logout 1.0 §3 — B5.
    pub end_session_endpoint: String,
    /// Back-Channel Logout 1.0 §3.
    pub backchannel_logout_supported: bool,
    /// The claim that AXIAM puts `sid` in its logout tokens — which it does,
    /// unconditionally. An RP reads this to know it can match a logout token
    /// to one session rather than having to end every session for the subject.
    pub backchannel_logout_session_supported: bool,
    pub response_types_supported: Vec<String>,
    pub subject_types_supported: Vec<String>,
    pub id_token_signing_alg_values_supported: Vec<String>,
    pub scopes_supported: Vec<String>,
    pub token_endpoint_auth_methods_supported: Vec<String>,
    pub claims_supported: Vec<String>,
    pub grant_types_supported: Vec<String>,
    /// RFC 9207 §3 — X5.1. AXIAM emits `iss` on **every** authorization
    /// response, success and error alike, for every client, so this is
    /// unconditionally true. See `handlers::oauth2::append_issuer` for why it
    /// is not made conditional.
    pub authorization_response_iss_parameter_supported: bool,
    /// RFC 8705 §3.3 — X5.1. Certificate-bound access tokens are available;
    /// whether a given client *gets* them is that client's
    /// `tls_client_certificate_bound_access_tokens` registration, which is
    /// deliberately not discoverable for the same reason `require_par` is not:
    /// this document is scoped to the server, and a per-client answer here
    /// would leak one client's posture to every reader.
    pub tls_client_certificate_bound_access_tokens: bool,
    /// RFC 9449 §5.1 — X5.1 second half. The JWS algorithms AXIAM accepts on a
    /// DPoP proof.
    ///
    /// Its **presence** is what tells a client DPoP is supported at all; RFC
    /// 9449 defines no separate boolean. The list is the profile's three, and
    /// notably excludes `RS256` — the omission a client library defaulting to
    /// RSA will hit first, and the reason advertising the list matters rather
    /// than merely advertising support.
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// RFC 8705 §5 — the mTLS-specific endpoint URLs, when this deployment
    /// terminates mutual TLS somewhere other than the issuer's own host.
    /// Absent (not `null`) when it does not.
    //
    // The `skip_serializing_if` is load-bearing, not cosmetic: a *present*
    // member tells a conforming client it MUST switch hosts. Serialising
    // `"mtls_endpoint_aliases": null` on the single-listener deployment would
    // hand every mTLS client a member to interpret where the RFC wants none.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtls_endpoint_aliases: Option<MtlsEndpointAliases>,
}

/// Build the endpoint paths for a base URL.
///
/// The single place the endpoint *paths* are written down, so a top-level
/// endpoint and its RFC 8705 §5 alias cannot drift apart. They did in the first
/// draft of this change — a `/oauth2/device_authorization` alias against a
/// `/oauth2/device_authorization` top-level is easy to keep in step by hand
/// right up until one of them is renamed.
macro_rules! endpoint {
    ($base:expr, $path:literal) => {
        format!("{}{}", $base, $path)
    };
}

/// Build the RFC 8705 §5 aliases for a base URL, or `None` when there is no
/// separate mTLS host.
///
/// `Err` when `mtls_base_url` is `Some` but not an absolute URL. That is a
/// deliberate refusal rather than a silent `None`: the whole point of the
/// member is to stop an mTLS client using the conventional endpoints, so
/// dropping it on a typo would produce exactly the failure the operator
/// configured it to prevent — and would do so invisibly, since a client cannot
/// tell an absent alias from one the server meant to send.
fn build_mtls_aliases(mtls_base_url: Option<&str>) -> Result<Option<MtlsEndpointAliases>, String> {
    let Some(base) = mtls_base_url else {
        return Ok(None);
    };
    let base = base.trim_end_matches('/');

    // `Url::parse` accepts only absolute URLs, which is the property wanted
    // here: a relative alias is not resolvable against anything a client holds.
    let parsed = url::Url::parse(base).map_err(|e| format!("not a valid absolute URL: {e}"))?;
    if !matches!(parsed.scheme(), "https" | "http") {
        // `http` is tolerated for the same reason the rest of the test and
        // compose topology tolerates it, and for no other; mutual TLS over
        // cleartext is a contradiction, so a deployment reaching this with
        // `http` has a configuration error the operator needs to see rather
        // than a document to serve.
        return Err(format!(
            "scheme must be https (or http for local development), got {:?}",
            parsed.scheme()
        ));
    }
    // A base URL is concatenated with an endpoint path, so a query or fragment
    // on it lands in the middle of the result:
    // `https://mtls.example.com?x=1` + `/oauth2/token` is a URL that parses and
    // points nowhere. Refusing is the same fail-closed call as the scheme
    // check — a malformed alias is worse than no alias, because a client will
    // dutifully try it.
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(
            "must be a bare base URL: a query string or fragment cannot carry an endpoint path"
                .to_owned(),
        );
    }

    Ok(Some(MtlsEndpointAliases {
        token_endpoint: endpoint!(base, "/oauth2/token"),
        userinfo_endpoint: endpoint!(base, "/oauth2/userinfo"),
        revocation_endpoint: endpoint!(base, "/oauth2/revoke"),
        introspection_endpoint: endpoint!(base, "/oauth2/introspect"),
        device_authorization_endpoint: endpoint!(base, "/oauth2/device_authorization"),
        pushed_authorization_request_endpoint: endpoint!(base, "/oauth2/par"),
    }))
}

/// Build a fully-populated OIDC discovery document for the given issuer URL.
///
/// `mtls_base_url` is the deployment's separate mutual-TLS host, when it has
/// one; `None` omits RFC 8705 §5 `mtls_endpoint_aliases` from the document.
///
/// # Errors
///
/// Only when `mtls_base_url` is `Some` and not a usable absolute URL. Every
/// other field is derived from `issuer`, whose validation is the caller's —
/// the discovery handler parses it before calling and answers `500` itself, and
/// that check predates this one.
pub fn build_discovery_document(
    issuer: &str,
    mtls_base_url: Option<&str>,
) -> Result<OidcDiscoveryDocument, String> {
    let issuer = issuer.trim_end_matches('/');
    let mtls_endpoint_aliases = build_mtls_aliases(mtls_base_url)?;
    Ok(OidcDiscoveryDocument {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{issuer}/oauth2/authorize"),
        token_endpoint: endpoint!(issuer, "/oauth2/token"),
        userinfo_endpoint: endpoint!(issuer, "/oauth2/userinfo"),
        jwks_uri: format!("{issuer}/oauth2/jwks"),
        revocation_endpoint: endpoint!(issuer, "/oauth2/revoke"),
        introspection_endpoint: endpoint!(issuer, "/oauth2/introspect"),
        device_authorization_endpoint: endpoint!(issuer, "/oauth2/device_authorization"),
        pushed_authorization_request_endpoint: endpoint!(issuer, "/oauth2/par"),
        require_pushed_authorization_requests: false,
        end_session_endpoint: format!("{issuer}/oauth2/end_session"),
        backchannel_logout_supported: true,
        backchannel_logout_session_supported: true,
        response_types_supported: vec!["code".into()],
        subject_types_supported: vec!["public".into()],
        id_token_signing_alg_values_supported: vec!["EdDSA".into()],
        scopes_supported: vec!["openid".into(), "profile".into(), "email".into()],
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post".into(),
            // X5.1 / RFC 8705 §2. Advertised unconditionally: whether a mTLS
            // handshake is actually available is a deployment's listener
            // configuration (the p3 profile), and a client that cannot reach
            // an mTLS listener discovers that at connect time rather than by
            // reading a metadata field that would have to lie one way or the
            // other on a multi-listener deployment.
            "tls_client_auth".into(),
            "self_signed_tls_client_auth".into(),
            // X5.1 second half / RFC 7523 §2.2. Unlike the two mTLS methods
            // this one needs nothing from the deployment's listeners at all,
            // so advertising it carries no caveat: every AXIAM deployment can
            // serve it.
            "private_key_jwt".into(),
        ],
        claims_supported: vec![
            "sub".into(),
            "iss".into(),
            "aud".into(),
            "exp".into(),
            "iat".into(),
            "nonce".into(),
            "email".into(),
            "preferred_username".into(),
            "tenant_id".into(),
            "org_id".into(),
        ],
        grant_types_supported: vec![
            "authorization_code".into(),
            "client_credentials".into(),
            "refresh_token".into(),
            // B2: the URN is the grant's identifier on the wire; a device
            // matches on this exact string, so it is spelled out rather than
            // referenced, and the constant it must equal
            // (`device_service::DEVICE_CODE_GRANT_TYPE`) is asserted against
            // it in this module's tests.
            "urn:ietf:params:oauth:grant-type:device_code".into(),
            // B3 / RFC 8693. Advertised so a mesh service can discover that
            // narrowing a token is possible here rather than being told out
            // of band; whether a given client MAY exchange is still its own
            // registration's business.
            "urn:ietf:params:oauth:grant-type:token-exchange".into(),
        ],
        authorization_response_iss_parameter_supported: true,
        tls_client_certificate_bound_access_tokens: true,
        dpop_signing_alg_values_supported: vec!["PS256".into(), "ES256".into(), "EdDSA".into()],
        mtls_endpoint_aliases,
    })
}

// ---------------------------------------------------------------------------
// JWKS (RFC 7517)
// ---------------------------------------------------------------------------

/// JSON Web Key per RFC 7517.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct Jwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub kid: String,
    #[serde(rename = "use")]
    pub use_: String,
    pub alg: String,
}

/// JSON Web Key Set document.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct JwksDocument {
    pub keys: Vec<Jwk>,
}

/// Build a JWKS document from an Ed25519 public key in PEM format.
///
/// The PEM must contain a SubjectPublicKeyInfo structure (44 bytes
/// when DER-decoded: 12-byte OID header + 32-byte raw Ed25519 key).
/// The `kid` is derived deterministically as the first 16 hex
/// characters (64 bits) of the SHA-256 hash of the raw public key bytes.
pub fn build_jwks(public_key_pem: &str) -> Result<JwksDocument, String> {
    // Strip PEM headers, trim whitespace (handles CRLF / trailing
    // spaces from env vars or Windows-formatted PEMs), and decode.
    let b64: String = public_key_pem
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with("-----"))
        .collect();
    let der = STANDARD
        .decode(&b64)
        .map_err(|e| format!("PEM decode: {e}"))?;

    // Ed25519 SubjectPublicKeyInfo is exactly 44 bytes:
    // 12-byte ASN.1/OID header + 32-byte raw public key.
    if der.len() != 44 {
        return Err(format!("expected 44-byte Ed25519 SPKI, got {}", der.len()));
    }
    let raw_key = &der[12..44];

    // Base64url-encode the raw key bytes for the JWK `x` parameter.
    let x = URL_SAFE_NO_PAD.encode(raw_key);

    // Deterministic kid: first 16 hex chars of SHA-256(raw_key).
    let kid = {
        let mut h = Sha256::new();
        h.update(raw_key);
        hex::encode(h.finalize())[..16].to_string()
    };

    Ok(JwksDocument {
        keys: vec![Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            x,
            kid,
            use_: "sig".into(),
            alg: "EdDSA".into(),
        }],
    })
}

// ---------------------------------------------------------------------------
// UserInfo Response (OIDC Core 5.3)
// ---------------------------------------------------------------------------

/// OIDC UserInfo response.
#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    pub tenant_id: String,
    pub org_id: String,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const ISSUER: &str = "https://auth.example.com";
    const MTLS: &str = "https://mtls.auth.example.com";

    fn doc(mtls: Option<&str>) -> OidcDiscoveryDocument {
        build_discovery_document(ISSUER, mtls).expect("valid inputs build a document")
    }

    #[test]
    fn discovery_document_has_required_fields() {
        let doc = doc(None);
        assert_eq!(doc.issuer, ISSUER);
        assert_eq!(
            doc.authorization_endpoint,
            "https://auth.example.com/oauth2/authorize"
        );
        assert!(doc.response_types_supported.contains(&"code".into()));
        assert!(doc.scopes_supported.contains(&"openid".into()));
    }

    /// RFC 8705 §5 makes the member OPTIONAL, and a *present* one is an
    /// instruction to switch hosts. A deployment with one listener must
    /// therefore emit no member at all — not an empty object, and not `null`,
    /// either of which a strict client is entitled to reject.
    #[test]
    fn no_mtls_host_omits_the_member_entirely() {
        let doc = doc(None);
        assert!(doc.mtls_endpoint_aliases.is_none());

        let json = serde_json::to_value(&doc).expect("document serialises");
        assert!(
            json.get("mtls_endpoint_aliases").is_none(),
            "the key must be absent, not null: {json}"
        );
    }

    #[test]
    fn mtls_host_aliases_every_endpoint_that_authenticates_a_client() {
        let aliases = doc(Some(MTLS))
            .mtls_endpoint_aliases
            .expect("a configured mTLS host produces aliases");

        assert_eq!(
            aliases.token_endpoint,
            "https://mtls.auth.example.com/oauth2/token"
        );
        assert_eq!(
            aliases.userinfo_endpoint,
            "https://mtls.auth.example.com/oauth2/userinfo"
        );
        assert_eq!(
            aliases.revocation_endpoint,
            "https://mtls.auth.example.com/oauth2/revoke"
        );
        assert_eq!(
            aliases.introspection_endpoint,
            "https://mtls.auth.example.com/oauth2/introspect"
        );
        assert_eq!(
            aliases.device_authorization_endpoint,
            "https://mtls.auth.example.com/oauth2/device_authorization"
        );
        assert_eq!(
            aliases.pushed_authorization_request_endpoint,
            "https://mtls.auth.example.com/oauth2/par"
        );
    }

    /// The front-channel and public endpoints are absent by construction — the
    /// type has no field for them. This pins the *serialised* shape, which is
    /// what a client actually reads, so adding a field later is a deliberate
    /// act rather than a silent one.
    #[test]
    fn aliases_carry_exactly_the_six_intended_keys() {
        let doc = doc(Some(MTLS));
        let json = serde_json::to_value(&doc).expect("document serialises");
        let aliases = json["mtls_endpoint_aliases"]
            .as_object()
            .expect("aliases serialise as an object");

        let mut keys: Vec<&str> = aliases.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "device_authorization_endpoint",
                "introspection_endpoint",
                "pushed_authorization_request_endpoint",
                "revocation_endpoint",
                "token_endpoint",
                "userinfo_endpoint",
            ]
        );

        for forbidden in [
            "authorization_endpoint",
            "end_session_endpoint",
            "jwks_uri",
            "issuer",
        ] {
            assert!(
                !aliases.contains_key(forbidden),
                "{forbidden} must not be aliased: see MtlsEndpointAliases' docs"
            );
        }
    }

    /// An alias must name the *same* endpoint as the top-level entry, only
    /// re-based. Deriving both from one macro is what guarantees it; this is
    /// the test that would fail if somebody inlined one of them again.
    #[test]
    fn each_alias_is_its_top_level_endpoint_re_based() {
        let doc = doc(Some(MTLS));
        let aliases = doc.mtls_endpoint_aliases.as_ref().expect("aliases present");

        for (top, alias) in [
            (&doc.token_endpoint, &aliases.token_endpoint),
            (&doc.userinfo_endpoint, &aliases.userinfo_endpoint),
            (&doc.revocation_endpoint, &aliases.revocation_endpoint),
            (&doc.introspection_endpoint, &aliases.introspection_endpoint),
            (
                &doc.device_authorization_endpoint,
                &aliases.device_authorization_endpoint,
            ),
            (
                &doc.pushed_authorization_request_endpoint,
                &aliases.pushed_authorization_request_endpoint,
            ),
        ] {
            let top_path = top
                .strip_prefix(ISSUER)
                .expect("top-level endpoint is under the issuer");
            let alias_path = alias
                .strip_prefix(MTLS)
                .expect("alias is under the mTLS host");
            assert_eq!(top_path, alias_path, "alias path diverged from {top}");
        }
    }

    /// The issuer keeps its own value even when aliases are present: OIDC Core
    /// §2 requires it to equal every token's `iss` exactly, and a token minted
    /// at the alias endpoint still carries the issuer.
    #[test]
    fn aliases_never_move_the_issuer_or_the_front_channel() {
        let doc = doc(Some(MTLS));
        assert_eq!(doc.issuer, ISSUER);
        assert_eq!(
            doc.authorization_endpoint,
            "https://auth.example.com/oauth2/authorize"
        );
        assert_eq!(
            doc.end_session_endpoint,
            "https://auth.example.com/oauth2/end_session"
        );
        assert_eq!(doc.jwks_uri, "https://auth.example.com/oauth2/jwks");
    }

    #[test]
    fn trailing_slashes_do_not_double_up() {
        let aliases = build_discovery_document(ISSUER, Some("https://mtls.auth.example.com///"))
            .expect("trailing slashes are tolerated")
            .mtls_endpoint_aliases
            .expect("aliases present");
        assert_eq!(
            aliases.token_endpoint,
            "https://mtls.auth.example.com/oauth2/token"
        );
    }

    /// A typo must not degrade into "no aliases" — see `build_mtls_aliases`.
    #[test]
    fn an_unusable_mtls_base_url_is_an_error_not_a_silent_omission() {
        for bad in [
            "mtls.auth.example.com",  // no scheme: not absolute
            "/oauth2",                // relative
            "ftp://mtls.example.com", // wrong scheme
            "not a url at all",
            // A base URL is concatenated with an endpoint path, so a query or
            // fragment would land in the middle of every alias.
            "https://mtls.example.com?tenant=acme",
            "https://mtls.example.com#frag",
        ] {
            assert!(
                build_discovery_document(ISSUER, Some(bad)).is_err(),
                "{bad:?} should have been refused"
            );
        }
    }

    #[test]
    fn jwks_parses_ed25519_pem() {
        let pem = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
        let jwks = build_jwks(pem).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        assert_eq!(jwks.keys[0].kty, "OKP");
        assert_eq!(jwks.keys[0].crv, "Ed25519");
        assert_eq!(jwks.keys[0].alg, "EdDSA");
        assert_eq!(jwks.keys[0].use_, "sig");
        assert!(!jwks.keys[0].x.is_empty());
        assert!(!jwks.keys[0].kid.is_empty());
    }

    #[test]
    fn jwk_kid_is_deterministic() {
        let pem = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
        let jwks1 = build_jwks(pem).unwrap();
        let jwks2 = build_jwks(pem).unwrap();
        assert_eq!(jwks1.keys[0].kid, jwks2.keys[0].kid);
    }
}

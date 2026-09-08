//! OpenID Connect Discovery, JWKS, and UserInfo types.

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Serialize;

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

/// The authentication context class reference for a single-factor login
/// (X7 G3/G4).
///
/// An AXIAM URN rather than one of the several competing registries because
/// the value must mean exactly one thing across every deployment: an operator
/// who can configure the string can configure it to say `mfa` for a password
/// login, and an `acr` an RP cannot trust is worse than none.
pub const ACR_SINGLE_FACTOR: &str = "urn:axiam:acr:1fa";

/// The authentication context class reference for a login that completed a
/// second factor (X7 G3/G4). See [`ACR_SINGLE_FACTOR`].
pub const ACR_MULTI_FACTOR: &str = "urn:axiam:acr:mfa";

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
    /// OIDC Discovery §3 — X7 G12. `false`, and truthfully so: AXIAM accepts
    /// no request object by value (see `authorize::RequestObject` for why it
    /// never will).
    ///
    /// `request_uri_parameter_supported` is deliberately **absent** rather
    /// than `false`: its default is `true`, and that is the truthful answer —
    /// AXIAM does accept `request_uri`, for the PAR handles RFC 9126 defines.
    /// Publishing `false` would tell a conforming client not to use PAR.
    pub request_parameter_supported: bool,
    /// OIDC Discovery §3 — X7. `false`: of the `claims` document AXIAM reads
    /// exactly one member, `id_token.acr`, and a partially-honoured `claims`
    /// is worse than an unsupported one because a relying party cannot tell
    /// which members were read.
    pub claims_parameter_supported: bool,
    /// OIDC Discovery §3 — X7 G3/G4. The authentication context class
    /// references AXIAM can assert.
    ///
    /// A capability statement, not a promise about any particular client: a
    /// client on the `ignore` lane (every client today) receives no `acr`
    /// claim at all. Two fixed URNs rather than operator-defined strings so
    /// that an ACR cannot be configured to mean whatever an echo of the
    /// request said it meant.
    pub acr_values_supported: Vec<String>,
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
    build_discovery_document_for(issuer, mtls_base_url, false)
}

/// [`build_discovery_document`], told whether the tenant this document
/// describes has the X7 G8 sensitive scopes enabled (W7, plan §6).
///
/// # The plan assumed a tenant-scoped document; there is not one
///
/// Plan §6 heads its table "tenant-scoped discovery document" and gates two
/// rows on the tenant switch. `GET /.well-known/openid-configuration` takes no
/// tenant: it is registered at the host root, reads only `AuthConfig`, and
/// describes the deployment. So the gate had to be built rather than used, and
/// `false` — omit the two scopes — is what a caller that names no tenant gets.
///
/// That default is the honest answer rather than a cautious one. Discovery
/// says what a relying party may ask for, and with no tenant named the server
/// genuinely does not know: one tenant may have the capability on and the next
/// may not. Advertising it unconditionally would tell every relying party in
/// every tenant that `address` is available, and most of them would be refused
/// `invalid_scope` on the first request.
///
/// Note the contrast with `auth_time`/`acr`/`amr`, added to `claims_supported`
/// by W1 *unconditionally* with the argument that "discovery describes the
/// server's capabilities, not any one client's grant". That argument holds
/// there and not here, and the difference is who decides: those three are a
/// per-**client** registration, and this is a per-**tenant** switch. A document
/// that cannot name the client is still truthful about what the server can do
/// for some client; a document that cannot name the tenant cannot say whether
/// the capability exists at all in the deployment the caller is talking to.
pub fn build_discovery_document_for(
    issuer: &str,
    mtls_base_url: Option<&str>,
    sensitive_scopes_enabled: bool,
) -> Result<OidcDiscoveryDocument, String> {
    let issuer = issuer.trim_end_matches('/');
    let mtls_endpoint_aliases = build_mtls_aliases(mtls_base_url)?;
    let mut doc = OidcDiscoveryDocument {
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
        scopes_supported: {
            let mut scopes = vec!["openid".into(), "profile".into(), "email".into()];
            if sensitive_scopes_enabled {
                scopes.extend(crate::sensitive::SENSITIVE_SCOPES.map(String::from));
            }
            scopes
        },
        token_endpoint_auth_methods_supported: vec![
            "client_secret_post".into(),
            // W8 / RFC 6749 §2.3.1. Advertised unconditionally, like the two
            // mTLS methods and for a narrower version of the same reason:
            // whether a *particular* client may use it is decided by its
            // registration, and this document describes the deployment's
            // capabilities rather than any one client's. A `fapi2` client
            // reading this list still cannot register for the method —
            // `validate_registration` refuses it — which is the intended
            // shape: the server can speak Basic, and the FAPI profile will
            // not let a client that must not, do so.
            //
            // Listed second rather than first: the order is the operator's
            // recommendation, and `client_secret_post` remains it (the header
            // channel is the one intermediaries log). SDKs are forbidden from
            // sending Basic at all — `sdks/CONTRACT.md` §5 rule 3.
            "client_secret_basic".into(),
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
            // X7 — the three authentication-evidence claims. Advertised as
            // claims AXIAM *can* assert; which clients receive them is their
            // own `authn_request_params` registration, and in this wave the
            // answer is none of them. Discovery describes the server's
            // capabilities, not any one client's grant — the same distinction
            // `require_pushed_authorization_requests` above draws.
            "auth_time".into(),
            "acr".into(),
            "amr".into(),
        ],
        // X7 G8 (W7). Appended after the closing bracket above rather than
        // inside it because these three are conditional and the ten are not —
        // and a `Vec` built by one expression with an `if` in the middle of it
        // is a `Vec` whose unconditional members are hard to read off.
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
        request_parameter_supported: false,
        claims_parameter_supported: false,
        acr_values_supported: vec![ACR_SINGLE_FACTOR.into(), ACR_MULTI_FACTOR.into()],
        tls_client_certificate_bound_access_tokens: true,
        dpop_signing_alg_values_supported: vec!["PS256".into(), "ES256".into(), "EdDSA".into()],
        mtls_endpoint_aliases,
    };
    if sensitive_scopes_enabled {
        doc.claims_supported
            .extend(["phone_number", "phone_number_verified", "address"].map(String::from));
    }
    Ok(doc)
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
    //
    // X7 §1.3 — derived by `axiam_auth::token::ed25519_jwk_kid`, which is also
    // what stamps the `kid` into every signed header. One definition, because
    // a JWKS advertising one `kid` while the tokens name another is worse than
    // no `kid` at all: the relying party looks up a key that is not there and
    // rejects a good signature. The PEM has already been validated above, so
    // the `None` arm is unreachable in practice and is answered with the same
    // message the length check would have given.
    let kid = axiam_auth::token::ed25519_jwk_kid(public_key_pem)
        .ok_or_else(|| "expected a 44-byte Ed25519 SPKI".to_owned())?;

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
///
/// # The three W7 claims are absent unless four gates all said yes
///
/// `phone_number`, `phone_number_verified` and `address` (X7 G8) are the only
/// members of this type that are not derivable from the token alone. They are
/// present only when the tenant switch is on, the access token carries the
/// scope, the relying party the token names holds a live consent record, and
/// that relying party is not on the `fapi2` profile — see
/// `crate::sensitive` for why each of the four exists and who closes it.
///
/// `Debug` is manual so that neither value can reach a log line through the
/// most natural diagnostic anybody writes, the same rule
/// `axiam_core::models::user::User` follows.
#[derive(Serialize, utoipa::ToSchema)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    /// OIDC Core §5.1, released under the `phone` scope (X7 G8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number: Option<String>,
    /// Whether [`Self::phone_number`] has been verified out of band.
    ///
    /// Emitted **only alongside** the number, per OIDC Core §5.1: a
    /// `phone_number_verified` with no `phone_number` asserts something about
    /// a value the relying party was not given. `false` rather than omitted
    /// when the number is present and unverified — that is a statement AXIAM
    /// is answerable for, and the honest one for a verification that never
    /// happened.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone_number_verified: Option<bool>,
    /// OIDC Core §5.1.1, released under the `address` scope (X7 G8).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<axiam_core::models::user::Address>,
    pub tenant_id: String,
    pub org_id: String,
}

impl std::fmt::Debug for UserInfoResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UserInfoResponse")
            .field("sub", &self.sub)
            .field("email", &self.email)
            .field("preferred_username", &self.preferred_username)
            .field(
                "phone_number",
                &self.phone_number.as_ref().map(|_| "<redacted>"),
            )
            .field("phone_number_verified", &self.phone_number_verified)
            .field("address", &self.address.as_ref().map(|_| "<redacted>"))
            .field("tenant_id", &self.tenant_id)
            .field("org_id", &self.org_id)
            .finish()
    }
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

    // -- X7: discovery statics --------------------------------------------

    /// The three new capability statements, and the one that is deliberately
    /// **absent**. `request_uri_parameter_supported` defaults to `true`, which
    /// is the truthful answer — AXIAM does accept `request_uri`, for the PAR
    /// handles RFC 9126 defines — so publishing `false` would tell a
    /// conforming client not to use PAR, which FAPI 2.0 requires of it.
    #[test]
    fn discovery_tells_the_truth_about_request_objects_and_claims() {
        let doc = doc(None);
        assert!(!doc.request_parameter_supported);
        assert!(!doc.claims_parameter_supported);

        let json = serde_json::to_value(&doc).expect("the document serialises");
        assert_eq!(
            json["request_parameter_supported"],
            serde_json::json!(false)
        );
        assert_eq!(json["claims_parameter_supported"], serde_json::json!(false));
        assert!(
            json.get("request_uri_parameter_supported").is_none(),
            "request_uri_parameter_supported must be omitted, not published false: \
             AXIAM accepts request_uri for PAR handles"
        );
        assert!(
            json.get("request_object_signing_alg_values_supported")
                .is_none(),
            "advertising request-object algorithms would claim support that does not exist"
        );
    }

    #[test]
    fn discovery_advertises_the_two_axiam_acr_urns() {
        let doc = doc(None);
        assert_eq!(
            doc.acr_values_supported,
            [ACR_SINGLE_FACTOR, ACR_MULTI_FACTOR]
        );
        // A fixed vocabulary, not an operator-configurable one: an ACR whose
        // meaning a deployment can edit is one a relying party cannot trust.
        assert!(
            doc.acr_values_supported
                .iter()
                .all(|v| v.starts_with("urn:axiam:acr:"))
        );
    }

    #[test]
    fn discovery_advertises_the_three_authentication_evidence_claims() {
        let doc = doc(None);
        for claim in ["auth_time", "acr", "amr"] {
            assert!(
                doc.claims_supported.iter().any(|c| c == claim),
                "{claim} must be advertised"
            );
        }
        // ...without disturbing the claims that were already there.
        for claim in ["sub", "iss", "aud", "exp", "iat", "nonce", "email"] {
            assert!(
                doc.claims_supported.iter().any(|c| c == claim),
                "{claim} lost"
            );
        }
    }

    /// Escalation B was answered **no**: no RSA key enters the JWKS, and this
    /// wave must not be the thing that widens the list. Pinned next to the new
    /// statics because that is where a well-meaning "while we are here" edit
    /// would land.
    #[test]
    fn the_id_token_algorithm_list_is_still_eddsa_only() {
        assert_eq!(doc(None).id_token_signing_alg_values_supported, ["EdDSA"]);
    }

    /// X7 §1.3 — the JWKS `kid` and the `kid` stamped into every signed header
    /// come from **one** derivation. A JWKS publishing one `kid` while the
    /// tokens name another is worse than no `kid` at all: the relying party
    /// looks up a key that is not there and rejects a good signature.
    #[test]
    fn the_published_kid_is_the_one_the_signer_stamps() {
        let pem = "\
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAcweT2rPwpUxadO56wIhW1XBoMF63aWOE2UMAVsRudhs=
-----END PUBLIC KEY-----";
        let published = build_jwks(pem).unwrap().keys[0].kid.clone();
        let stamped =
            axiam_auth::token::ed25519_jwk_kid(pem).expect("a valid Ed25519 SPKI yields a kid");
        assert_eq!(published, stamped);
        // 64 bits of SHA-256, hex-encoded.
        assert_eq!(published.len(), 16);
        assert!(published.chars().all(|c| c.is_ascii_hexdigit()));
    }

    /// A PEM the signer cannot derive a `kid` from is not an outage: the
    /// header simply goes unnamed, exactly as it did before X7. It is the
    /// JWKS endpoint's job to complain about the key.
    #[test]
    fn an_unusable_pem_yields_no_kid_rather_than_an_error() {
        for bad in [
            "",
            "not a pem",
            "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
        ] {
            assert_eq!(axiam_auth::token::ed25519_jwk_kid(bad), None, "{bad:?}");
            assert!(
                build_jwks(bad).is_err(),
                "{bad:?} must still fail at the JWKS endpoint"
            );
        }
    }
}

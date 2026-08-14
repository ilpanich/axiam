//! Mutual-TLS client authentication and certificate-bound tokens
//! (RFC 8705) — X5.1.
//!
//! Two mechanisms live here, and RFC 8705 keeps them deliberately separate
//! because they answer different questions:
//!
//! - **§2, client authentication.** *Who is this client?* The certificate
//!   replaces the shared secret at the token endpoint. AXIAM implements both
//!   variants: `tls_client_auth` (PKI — the certificate chains to a CA the
//!   deployment's listener trusts, and AXIAM matches a registered subject DN
//!   or SAN) and `self_signed_tls_client_auth` (the certificate *is* the
//!   registered credential, matched by thumbprint).
//! - **§3, sender-constrained tokens.** *May this bearer use this token?* The
//!   access token carries a `cnf.x5t#S256` confirmation naming the
//!   certificate it was issued to, so a stolen token is inert without the
//!   corresponding private key.
//!
//! # Where the trust actually comes from
//!
//! Nothing in this module verifies a certificate chain, and it must not: by
//! the time a [`PresentedCertificate`] exists, rustls has already verified the
//! peer chain against the configured client-CA bundle during the TLS 1.3
//! handshake (`axiam-server`'s `on_connect` hook → `VerifiedClientCert`). This
//! module's job is the *matching* step — deciding whether the certificate the
//! transport verified is the one this particular client registered.
//!
//! That division is why the `X-Client-Certificate` proxy header, which the
//! device-auth extractor accepts as a fallback, is **not** accepted here. That
//! header is an assertion by a reverse proxy; for device authentication, where
//! the certificate is looked up against a per-tenant issued-certificate table,
//! a deployment can reasonably choose to trust its own proxy. For OAuth2
//! client authentication under a FAPI profile it cannot: FAPI 2.0 requires the
//! authorization server to authenticate the client, and a header is forgeable
//! by anything that can reach the server on a non-mTLS port. So the header path
//! is absent by construction rather than gated by configuration — there is no
//! setting that turns it on.
//!
//! # Self-signed certificates and the `x5t#S256` shortcut
//!
//! RFC 8705 §2.2 registers a self-signed client's certificates inside its
//! `jwks`/`jwks_uri`. AXIAM registers the SHA-256 thumbprint instead. The
//! comparison the spec performs against a self-signed certificate reduces to
//! an equality check against a registered key, and a thumbprint is that check
//! without a JWKS parser on the authentication path. What it costs is
//! JWKS-driven rotation: a self-signed client's new certificate must be
//! registered rather than merely published. The operator guide says so.

use axiam_core::models::oauth2_client::{ClientAuthMethod, OAuth2Client};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::parse_x509_certificate;

use crate::error::OAuth2Error;

/// The single `error_description` every mTLS client-authentication failure
/// returns, whatever actually went wrong.
///
/// Same reasoning as `token::CLIENT_AUTH_FAILED`, which it deliberately
/// matches word for word: an unauthenticated caller must not be able to tell
/// "no certificate presented" from "certificate presented but the DN did not
/// match" from "this client does not use mTLS at all", because each of those
/// answers is a fact about a client id they have not authenticated as.
///
/// The distinctions are kept — they go to the tracing log, where an operator
/// debugging a genuine onboarding problem can see them and an attacker cannot.
pub(crate) const MTLS_AUTH_FAILED: &str = "invalid client credentials";

/// A client certificate that the TLS layer verified on this connection.
///
/// Constructed only from a chain rustls accepted.
///
/// # Why the X.509 parse is lazy
///
/// The thumbprint is computed eagerly, because it is one SHA-256 over bytes
/// already in memory and *every* certificate-bound token needs it. The subject
/// DN and SANs are not: they are needed only by the `tls_client_auth` variant
/// of client authentication, and parsing an X.509 structure to extract and
/// allocate strings nobody reads is real work on a hot path.
///
/// The distinction matters because these two costs land on different
/// populations. Certificate *binding* is what X5.1 advertises as cheap, and it
/// pays only the SHA-256. A deployment running mTLS with ordinary
/// `client_secret_post` clients — the IoT shape AXIAM targets — would
/// otherwise have paid for a DN parse on every token request in exchange for
/// nothing at all. Eager parsing was the first cut of this type; the
/// benchmark's A/B is what made the asymmetry visible.
#[derive(Debug, Clone)]
pub struct PresentedCertificate {
    /// DER encoding of the verified leaf certificate.
    der: Vec<u8>,
    /// Base64url (no padding) SHA-256 digest of [`Self::der`] — the
    /// `x5t#S256` value of RFC 8705 §3.1.
    pub thumbprint_s256: String,
}

/// The identity fields of a certificate, parsed on demand.
///
/// Separate from [`PresentedCertificate`] so the type system records which
/// operations need an X.509 parse and which do not: you cannot read a subject
/// DN without having called [`PresentedCertificate::identity`], and that call
/// is the parse.
#[derive(Debug, Clone)]
pub struct CertificateIdentity {
    /// Subject distinguished name in RFC 4514 string form.
    pub subject_dn: String,
    /// `dNSName` SAN entries, in certificate order.
    pub san_dns: Vec<String>,
    /// `uniformResourceIdentifier` SAN entries, in certificate order.
    pub san_uri: Vec<String>,
}

impl PresentedCertificate {
    /// Wrap a DER leaf certificate and compute its `x5t#S256` thumbprint.
    ///
    /// Infallible: a SHA-256 over arbitrary bytes always succeeds, and the
    /// bytes are not interpreted here. Anything that needs them to be a
    /// well-formed certificate goes through [`Self::identity`], which reports
    /// the parse failure at the point where it actually matters.
    pub fn from_der(der: &[u8]) -> Self {
        Self {
            der: der.to_vec(),
            thumbprint_s256: thumbprint_s256(der),
        }
    }

    /// Parse the subject DN and SANs (RFC 8705 §2.1.2 matching inputs).
    ///
    /// Returns `Err` only when the bytes are not a parseable X.509
    /// certificate. In the native-mTLS path that cannot happen — rustls parsed
    /// the same bytes to verify the chain — but the fallible signature is kept
    /// so a future caller cannot introduce an unchecked `unwrap`.
    pub fn identity(&self) -> Result<CertificateIdentity, String> {
        let (_, cert) =
            parse_x509_certificate(&self.der).map_err(|e| format!("parse client cert DER: {e}"))?;

        let mut san_dns = Vec::new();
        let mut san_uri = Vec::new();
        if let Ok(Some(ext)) = cert.subject_alternative_name() {
            for name in &ext.value.general_names {
                match name {
                    GeneralName::DNSName(s) => san_dns.push((*s).to_owned()),
                    GeneralName::URI(s) => san_uri.push((*s).to_owned()),
                    _ => {}
                }
            }
        }

        Ok(CertificateIdentity {
            subject_dn: cert.subject().to_string(),
            san_dns,
            san_uri,
        })
    }
}

/// RFC 8705 §3.1 `x5t#S256`: base64url-encoded, unpadded SHA-256 of the DER
/// certificate.
///
/// Base64url **without** padding is not a stylistic choice: the value travels
/// inside a JWT claim and an introspection response, and RFC 7515 §2 defines
/// base64url encoding in JOSE as omitting the `=` padding. A padded value
/// would not compare equal at a conforming resource server.
pub fn thumbprint_s256(der: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(Sha256::digest(der))
}

/// Compare two thumbprints without leaking, through timing, how many leading
/// characters matched.
///
/// A thumbprint is a public value in most threat models — it is derived from a
/// certificate the client transmits in the clear during the handshake — so
/// this is belt-and-braces rather than load-bearing. It is cheap, it is the
/// same discipline `client_secret` verification already applies, and the one
/// case where it *is* load-bearing is `self_signed_tls_client_auth`, where the
/// registered thumbprint is the entire credential and an attacker who could
/// grind it character by character would be forging a client identity rather
/// than merely recognising one.
fn thumbprints_match(a: &str, b: &str) -> bool {
    // `ConstantTimeEq` on unequal-length inputs short-circuits, which leaks
    // only the length — and both operands are fixed-length base64url SHA-256
    // digests whenever either is well-formed.
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// Authenticate a client by the certificate it presented (RFC 8705 §2).
///
/// Called *instead of* secret verification when the client's registered
/// [`ClientAuthMethod`] is an mTLS one. Returns `Ok(())` only when the
/// presented certificate matches what this specific client registered.
///
/// # The three ways this fails, and why they all look identical
///
/// 1. **No certificate on the connection.** The client reached a listener that
///    does not request client certificates, or presented none. This is the
///    failure an operator hits most often during onboarding, and the tracing
///    line says so explicitly.
/// 2. **The client registered no expectation.** A client whose method is
///    `tls_client_auth` but which has no `tls_client_auth_subject_dn`,
///    `…_san_dns` or `…_san_uri` cannot be authenticated by anything, and this
///    refuses rather than matching everything. Registration validation is meant
///    to make the state unreachable; this is the second line, because a row
///    edited directly in the database bypasses registration validation and the
///    failure mode of guessing here is *authenticating every certificate*.
/// 3. **The certificate does not match.** A real certificate, verified by
///    rustls, belonging to somebody else.
///
/// All three answer `invalid_client` with [`MTLS_AUTH_FAILED`]. See that
/// constant for why.
pub fn authenticate_mtls_client(
    client: &OAuth2Client,
    presented: Option<&PresentedCertificate>,
) -> Result<(), OAuth2Error> {
    let method = client.token_endpoint_auth_method;
    debug_assert!(
        method.is_mtls(),
        "authenticate_mtls_client called for a non-mTLS auth method"
    );

    let Some(cert) = presented else {
        tracing::debug!(
            client_id = %client.client_id,
            method = method.as_str(),
            "mTLS client authentication failed: no verified client certificate on this \
             connection (is the client reaching the mTLS listener?)"
        );
        return Err(OAuth2Error::InvalidClient(MTLS_AUTH_FAILED.into()));
    };

    let matched = match method {
        ClientAuthMethod::SelfSignedTlsClientAuth => {
            let registered = &client.self_signed_tls_client_auth_thumbprints;
            if registered.is_empty() {
                tracing::warn!(
                    client_id = %client.client_id,
                    "client is registered for self_signed_tls_client_auth but has no \
                     registered certificate thumbprint; it cannot authenticate"
                );
                return Err(OAuth2Error::InvalidClient(MTLS_AUTH_FAILED.into()));
            }
            // Every candidate is compared even after a match, so the number of
            // comparisons does not reveal the matching thumbprint's position
            // in the list.
            registered.iter().fold(false, |found, t| {
                thumbprints_match(t, &cert.thumbprint_s256) | found
            })
        }
        ClientAuthMethod::TlsClientAuth => {
            match client.mtls_binding_count() {
                0 => {
                    tracing::warn!(
                        client_id = %client.client_id,
                        "client is registered for tls_client_auth but registered no expected \
                         subject DN or SAN; it cannot authenticate"
                    );
                    return Err(OAuth2Error::InvalidClient(MTLS_AUTH_FAILED.into()));
                }
                // RFC 8705 §2.1.2 permits exactly one. Registration validation
                // rejects more, but a row that acquired two some other way must
                // not be authenticated by whichever happens to match — that is
                // an OR over credentials nobody intended to grant.
                n if n > 1 => {
                    tracing::error!(
                        client_id = %client.client_id,
                        registered = n,
                        "client has more than one tls_client_auth_* parameter registered, \
                         which RFC 8705 §2.1.2 forbids; refusing to guess which one \
                         authenticates"
                    );
                    return Err(OAuth2Error::InvalidClient(MTLS_AUTH_FAILED.into()));
                }
                _ => {}
            }

            // The X.509 parse happens here and nowhere else — this is the one
            // branch that needs a DN or a SAN. A parse failure is an
            // authentication failure, never a pass: rustls verified these
            // bytes, so unparseable-here means something is deeply wrong and
            // the only safe reading is "this is not the registered client".
            let identity = match cert.identity() {
                Ok(identity) => identity,
                Err(e) => {
                    tracing::error!(
                        client_id = %client.client_id,
                        error = %e,
                        "could not parse a client certificate rustls had already verified; \
                         refusing the authentication"
                    );
                    return Err(OAuth2Error::InvalidClient(MTLS_AUTH_FAILED.into()));
                }
            };

            if let Some(expected) = non_empty(client.tls_client_auth_subject_dn.as_deref()) {
                // The DN comparison is exact on the RFC 4514 string form. RFC
                // 8705 §2.1.2 describes this as a comparison of the DN, and a
                // structural comparison would be more faithful — but a
                // normalising comparison is exactly where DN-matching CVEs
                // live, and an exact match can only ever be *too strict*,
                // which fails an onboarding rather than authenticating a
                // stranger. The operator guide tells operators to copy the DN
                // out of `openssl x509 -noout -subject -nameopt rfc2253`.
                expected == identity.subject_dn
            } else if let Some(expected) = non_empty(client.tls_client_auth_san_dns.as_deref()) {
                // DNS names are case-insensitive (RFC 4343). No wildcard
                // handling: a wildcard registered here would authenticate
                // every certificate a CA issued under that suffix as this
                // client, which is not an authentication decision anybody
                // should be able to make by typing `*`.
                identity
                    .san_dns
                    .iter()
                    .any(|got| got.eq_ignore_ascii_case(expected))
            } else if let Some(expected) = non_empty(client.tls_client_auth_san_uri.as_deref()) {
                // URIs are compared exactly: unlike a DNS name, no component
                // of a URI is case-insensitive in a way that is safe to assume
                // here.
                identity.san_uri.iter().any(|got| got == expected)
            } else {
                // Unreachable: `mtls_binding_count()` returned 1 above, and it
                // counts exactly these three fields under the same
                // non-emptiness rule.
                false
            }
        }
        ClientAuthMethod::ClientSecretPost => false,
    };

    if !matched {
        tracing::debug!(
            client_id = %client.client_id,
            method = method.as_str(),
            "mTLS client authentication failed: the verified client certificate does not \
             match this client's registered expectation"
        );
        return Err(OAuth2Error::InvalidClient(MTLS_AUTH_FAILED.into()));
    }

    Ok(())
}

/// A registered value counts only when it is present *and* non-blank.
///
/// Mirrors `OAuth2Client::mtls_binding_count`'s rule exactly. The two must
/// agree: if the counter treated `Some("")` as registered and the matcher
/// treated it as absent, a client could reach the `else` branch with a count
/// of one and authenticate nothing — or, worse, the reverse.
fn non_empty(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::oauth2_client::ClientProfile;
    use chrono::Utc;
    use uuid::Uuid;

    /// A client with no mTLS registration at all — each test adds what it needs.
    fn client(method: ClientAuthMethod) -> OAuth2Client {
        OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            client_id: "oa_test".into(),
            client_secret_hash: String::new(),
            name: "test".into(),
            redirect_uris: vec![],
            grant_types: vec!["client_credentials".into()],
            scopes: vec![],
            post_logout_redirect_uris: vec![],
            backchannel_logout_uri: None,
            require_par: false,
            profile: ClientProfile::Standard,
            token_endpoint_auth_method: method,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: vec![],
            tls_client_certificate_bound_access_tokens: false,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    /// A real certificate, so the parser is exercised rather than mocked.
    fn cert_with_sans(sans: &[&str]) -> (Vec<u8>, PresentedCertificate) {
        let generated = rcgen::generate_simple_self_signed(
            sans.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
        )
        .expect("generate self-signed cert");
        let der = generated.cert.der().to_vec();
        (der.clone(), PresentedCertificate::from_der(&der))
    }

    /// The parsed identity of a generated certificate, for the tests that need
    /// to register the DN or SAN the certificate actually carries.
    fn identity_of(cert: &PresentedCertificate) -> CertificateIdentity {
        cert.identity()
            .expect("parse a certificate we just generated")
    }

    // -- parsing ---------------------------------------------------------

    #[test]
    fn from_der_extracts_dns_sans_and_thumbprint() {
        let (der, parsed) = cert_with_sans(&["client.example.com"]);
        assert_eq!(
            identity_of(&parsed).san_dns,
            vec!["client.example.com".to_string()]
        );
        assert_eq!(parsed.thumbprint_s256, thumbprint_s256(&der));
        // Base64url, unpadded, 32 bytes -> 43 chars.
        assert_eq!(parsed.thumbprint_s256.len(), 43);
        assert!(!parsed.thumbprint_s256.contains('='));
        assert!(!parsed.thumbprint_s256.contains('+'));
        assert!(!parsed.thumbprint_s256.contains('/'));
    }

    /// Wrapping garbage succeeds — a thumbprint is a digest over bytes, not an
    /// interpretation of them — but the moment anything asks for an identity,
    /// the parse failure surfaces. This is the seam the lazy parse introduced.
    #[test]
    fn garbage_der_yields_a_thumbprint_but_no_identity() {
        let cert = PresentedCertificate::from_der(b"not a certificate");
        assert_eq!(cert.thumbprint_s256.len(), 43);
        assert!(cert.identity().is_err());
    }

    /// ...and an unparseable certificate must fail authentication rather than
    /// slip through the `tls_client_auth` branch on a parse it never did.
    #[test]
    fn garbage_der_cannot_authenticate_a_tls_client_auth_client() {
        let cert = PresentedCertificate::from_der(b"not a certificate");
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.tls_client_auth_san_dns = Some("client.example.com".into());
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_err());
    }

    #[test]
    fn thumbprint_is_stable_and_distinguishes_certificates() {
        let (der_a, _) = cert_with_sans(&["a.example.com"]);
        let (der_b, _) = cert_with_sans(&["b.example.com"]);
        assert_eq!(thumbprint_s256(&der_a), thumbprint_s256(&der_a));
        assert_ne!(thumbprint_s256(&der_a), thumbprint_s256(&der_b));
    }

    // -- the binding-verification matrix (X5.5) --------------------------

    #[test]
    fn no_certificate_is_refused() {
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.tls_client_auth_san_dns = Some("client.example.com".into());
        let err = authenticate_mtls_client(&c, None).unwrap_err();
        assert!(matches!(err, OAuth2Error::InvalidClient(_)));
    }

    #[test]
    fn right_san_dns_authenticates() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.tls_client_auth_san_dns = Some("client.example.com".into());
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_ok());
    }

    #[test]
    fn san_dns_match_is_case_insensitive() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.tls_client_auth_san_dns = Some("CLIENT.Example.COM".into());
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_ok());
    }

    #[test]
    fn wrong_san_dns_is_refused() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.tls_client_auth_san_dns = Some("other.example.com".into());
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_err());
    }

    /// A wildcard must not authenticate a sibling name. Registering `*` is how
    /// an operator would accidentally turn one client's credential into every
    /// certificate the CA ever issued.
    #[test]
    fn wildcard_san_dns_does_not_match_anything() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.tls_client_auth_san_dns = Some("*.example.com".into());
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_err());
    }

    #[test]
    fn subject_dn_match_is_exact() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.tls_client_auth_subject_dn = Some(identity_of(&cert).subject_dn);
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_ok());

        // A different DN does not match, and nothing normalises the two into
        // agreement — no case folding, no attribute reordering, no
        // whitespace-inside-the-value collapsing. Those are the normalisations
        // DN-matching CVEs are built from.
        let mut wrong = client(ClientAuthMethod::TlsClientAuth);
        wrong.tls_client_auth_subject_dn =
            Some(identity_of(&cert).subject_dn.to_ascii_uppercase() + ",OU=extra");
        assert!(authenticate_mtls_client(&wrong, Some(&cert)).is_err());
    }

    /// Surrounding whitespace on the *registered* value is trimmed, because a
    /// DN copied out of `openssl x509 -noout -subject` routinely arrives with
    /// a leading space and refusing that is an onboarding papercut with no
    /// security value — no certificate's real DN differs from another's only
    /// by outer whitespace. Trimming is applied by `non_empty`, the same
    /// helper `mtls_binding_count` uses, so the two cannot disagree about
    /// what counts as registered.
    #[test]
    fn registered_subject_dn_is_trimmed_before_comparison() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.tls_client_auth_subject_dn = Some(format!("  {}  ", identity_of(&cert).subject_dn));
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_ok());
    }

    #[test]
    fn tls_client_auth_with_no_registered_expectation_is_refused() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let c = client(ClientAuthMethod::TlsClientAuth);
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_err());
    }

    /// A blank registration must not authenticate a certificate whose field is
    /// also absent — the emptiness rules in `mtls_binding_count` and
    /// `non_empty` have to agree, and this is the test that keeps them so.
    #[test]
    fn blank_registered_expectation_is_refused() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.tls_client_auth_subject_dn = Some("   ".into());
        assert_eq!(c.mtls_binding_count(), 0);
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_err());
    }

    #[test]
    fn two_registered_expectations_are_refused_rather_than_or_ed() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        // One of them is correct. RFC 8705 §2.1.2 still forbids the pair, and
        // matching on the correct one would be an OR over two credentials.
        c.tls_client_auth_san_dns = Some("client.example.com".into());
        c.tls_client_auth_subject_dn = Some("CN=somebody else".into());
        assert_eq!(c.mtls_binding_count(), 2);
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_err());
    }

    // -- self-signed variant ---------------------------------------------

    #[test]
    fn self_signed_right_thumbprint_authenticates() {
        let (der, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::SelfSignedTlsClientAuth);
        c.self_signed_tls_client_auth_thumbprints = vec![thumbprint_s256(&der)];
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_ok());
    }

    #[test]
    fn self_signed_wrong_thumbprint_is_refused() {
        let (der_a, _) = cert_with_sans(&["a.example.com"]);
        let (_, cert_b) = cert_with_sans(&["b.example.com"]);
        let mut c = client(ClientAuthMethod::SelfSignedTlsClientAuth);
        c.self_signed_tls_client_auth_thumbprints = vec![thumbprint_s256(&der_a)];
        assert!(authenticate_mtls_client(&c, Some(&cert_b)).is_err());
    }

    /// Rotation: an overlap window registers both, and both authenticate.
    #[test]
    fn self_signed_accepts_any_registered_thumbprint() {
        let (der_a, cert_a) = cert_with_sans(&["a.example.com"]);
        let (der_b, cert_b) = cert_with_sans(&["b.example.com"]);
        let mut c = client(ClientAuthMethod::SelfSignedTlsClientAuth);
        c.self_signed_tls_client_auth_thumbprints =
            vec![thumbprint_s256(&der_a), thumbprint_s256(&der_b)];
        assert!(authenticate_mtls_client(&c, Some(&cert_a)).is_ok());
        assert!(authenticate_mtls_client(&c, Some(&cert_b)).is_ok());
    }

    #[test]
    fn self_signed_with_no_registered_thumbprint_is_refused() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let c = client(ClientAuthMethod::SelfSignedTlsClientAuth);
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_err());
    }

    /// The DN registered for `tls_client_auth` must not be honoured when the
    /// client is registered as self-signed, and vice versa. The method selects
    /// the credential; the presence of a field does not.
    #[test]
    fn registered_dn_is_ignored_under_the_self_signed_method() {
        let (_, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::SelfSignedTlsClientAuth);
        c.tls_client_auth_subject_dn = Some(identity_of(&cert).subject_dn);
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_err());
    }

    #[test]
    fn thumbprint_registered_for_self_signed_is_ignored_under_tls_client_auth() {
        let (der, cert) = cert_with_sans(&["client.example.com"]);
        let mut c = client(ClientAuthMethod::TlsClientAuth);
        c.self_signed_tls_client_auth_thumbprints = vec![thumbprint_s256(&der)];
        assert!(authenticate_mtls_client(&c, Some(&cert)).is_err());
    }

    // -- the error is uniform --------------------------------------------

    /// Every refusal returns the identical description, so a caller cannot
    /// distinguish "no certificate" from "wrong certificate" from "client
    /// registered nothing" — each of which is a fact about a client id they
    /// have not authenticated as.
    #[test]
    fn every_failure_reports_the_same_description() {
        let (der_a, _) = cert_with_sans(&["a.example.com"]);
        let (_, cert_b) = cert_with_sans(&["b.example.com"]);

        let mut wrong_cert = client(ClientAuthMethod::SelfSignedTlsClientAuth);
        wrong_cert.self_signed_tls_client_auth_thumbprints = vec![thumbprint_s256(&der_a)];

        let unregistered = client(ClientAuthMethod::TlsClientAuth);

        let mut no_cert = client(ClientAuthMethod::TlsClientAuth);
        no_cert.tls_client_auth_san_dns = Some("a.example.com".into());

        let descriptions: Vec<String> = vec![
            authenticate_mtls_client(&wrong_cert, Some(&cert_b)).unwrap_err(),
            authenticate_mtls_client(&unregistered, Some(&cert_b)).unwrap_err(),
            authenticate_mtls_client(&no_cert, None).unwrap_err(),
        ]
        .into_iter()
        .map(|e| match e {
            OAuth2Error::InvalidClient(d) => d,
            other => panic!("expected invalid_client, got {other:?}"),
        })
        .collect();

        assert!(
            descriptions.iter().all(|d| d == MTLS_AUTH_FAILED),
            "all mTLS auth failures must share one description, got {descriptions:?}"
        );
    }
}

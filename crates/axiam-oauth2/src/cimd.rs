//! Client ID Metadata Documents — a `client_id` that is a URL (T21.5).
//!
//! Implements `draft-ietf-oauth-client-id-metadata-document`: a client
//! identifies itself with an `https` URL, and the authorization server fetches
//! that URL to learn the client's metadata instead of holding a registration
//! an administrator created. It is how Claude Code, VS Code and the MCP
//! Inspector can be *the same client* at every AXIAM deployment they ever talk
//! to, with nothing registered anywhere in advance.
//!
//! # The draft revision this implements
//!
//! **Not pinned to a numbered revision, deliberately, and this is a departure
//! from the plan's instruction.** The executing environment's egress proxy
//! refuses `datatracker.ietf.org` and `ietf.org` (HTTP 403 on CONNECT), so the
//! revision current on 2026-09-17 could not be read, and a number written from
//! memory would be a claim this code cannot support. What is implemented is
//! the draft's stable core — the URL rules, the document shape, and the
//! metadata members RFC 7591 §2 already defines — cross-checked against
//! Keycloak's `cimd` feature, whose validation list the plan names as the
//! reference behaviour. `docs/admin/client-id-metadata-documents.md` says the
//! same thing in the same words, and T7 or T8, from an environment with
//! egress, should replace both with the revision and re-read the diff.
//!
//! # What this module is, and what it is not
//!
//! It is a **pure decision** plus one **cache**. It decides whether a
//! `client_id` may be resolved at all, fetches the document behind the shared
//! SSRF guard, decides whether what came back is a client AXIAM will admit,
//! and produces the `CreateOAuth2Client` that a caller materialises. It holds
//! no repository, writes nothing, and answers every failure with one enum the
//! caller turns into today's "unknown client".
//!
//! # Why every failure is the same failure
//!
//! [`CimdError`] is rich for the logs and invisible on the wire. A caller that
//! cannot resolve a URL-shaped `client_id` does not materialise a row, so the
//! ordinary repository lookup runs and answers exactly what it answers today
//! for a `client_id` nobody registered. That is invariant I1 for the tenant
//! that has CIMD off, and it is also what stops this mechanism becoming a
//! probe: a stranger cannot learn from the response whether their document was
//! unreachable, oversize, malformed, refused by a domain rule or refused by
//! the SSRF guard.
//!
//! # The threat this module exists inside
//!
//! An unauthenticated request names a URL and AXIAM fetches it. Every bound
//! here is therefore a security control rather than a tuning knob, and each is
//! owned by something that has already been reviewed:
//!
//! | Bound | Owned by |
//! | --- | --- |
//! | Which hosts may be fetched at all | `CimdPolicy::trusted_client_id_domains`, empty refused at the settings layer |
//! | Private/loopback addresses, IPv4-mapped IPv6, DNS rebinding | `axiam_pki::ssrf` (SEC-054, SEC-094): resolve, canonicalise, validate, **pin** |
//! | Redirect following | the same guard: automatic redirects off, every hop re-validated, `MAX_HOPS` |
//! | Plaintext `http` | the same guard, plus [`CimdPolicy::allow_http`] |
//! | Response size | `CimdPolicy::max_metadata_bytes`, applied as a **streaming** cap |
//! | Request time | the guard's per-request client timeout |
//! | How often a fetch may repeat | `CimdPolicy::min_cache_secs` |
//! | How long a stranger may pin a client | `CimdPolicy::max_cache_secs` |
//!
//! No address classification, no redirect policy and no connection building
//! happens in this file. It was written once, reviewed once
//! (`claude_dev/security-review-f4bis-2026-08-15.md` §3), and fixed once; a
//! second copy here would be a second thing to get SEC-094 wrong in.
//!
//! # What a document may not decide
//!
//! The same four things a self-registered client may not decide, for the same
//! reasons, and one more:
//!
//! | The document may name | It is decided by |
//! | --- | --- |
//! | `redirect_uris` | the document, within `cimd.trusted_redirect_domains` |
//! | `scope` | the document, within `dcr_allowed_scopes` |
//! | `grant_types` | the document, within `{authorization_code, refresh_token}` |
//! | `token_endpoint_auth_method` | the document, within `{none, private_key_jwt}` |
//! | **audiences** (`allowed_resources`) | **the tenant, always** (D3) |
//! | **profile** | **forced to `standard`** (I5) |
//! | **provenance** (`managed_by`) | **forced to `cimd`** (D5) |
//! | **consent** | **forced on** (D4) |
//! | **a shared secret** | **cannot exist** — the registration is a public document |

use axiam_core::models::oauth2_client::{
    AuthnRequestParamsMode, ClientAuthMethod, ClientProfile, CreateOAuth2Client, ManagedBy,
};
use axiam_core::models::settings::{CimdPolicy, OidcPolicy};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;
use uuid::Uuid;

use crate::dcr::{DCR_GRANT_TYPES, host_glob_matches, redirect_host_is_allowed};

/// How long past its TTL a cached document may still be served when the
/// publisher is unreachable (24 hours).
///
/// The stale-while-revalidate window `JwksCache` uses (D-03), for the reason
/// it uses it: a publisher having a bad afternoon should not sign every one of
/// its users out of every MCP server they are using. It is bounded by the same
/// argument in the other direction — a document withdrawn for good stops
/// working within a day of its TTL expiring — and it is a window on a
/// *successful* previous fetch, so nothing enters the cache through it.
pub const STALE_WINDOW_SECS: i64 = 24 * 3600;

/// The `token_endpoint_auth_method` values a metadata document may name.
///
/// Two, and the absent third is the point: a client whose registration is a
/// document anybody can read cannot hold a shared secret, so
/// `client_secret_post` and `client_secret_basic` are not "unsupported here",
/// they are impossible. The two mutual-TLS methods are absent for the reason
/// `dcr::DCR_AUTH_METHODS` gives — registering one is a claim about the
/// deployment's PKI rather than about the client.
pub const CIMD_AUTH_METHODS: [ClientAuthMethod; 2] =
    [ClientAuthMethod::None, ClientAuthMethod::PrivateKeyJwt];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Why a URL-shaped `client_id` did not become a client.
///
/// Every variant produces the same outcome for the caller — no row, therefore
/// today's unknown-client refusal — and exists so the operator's log says
/// which rule fired. See this module's header for why the wire cannot tell
/// them apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CimdError {
    /// The tenant has `cimd.enabled` false. The first check and the cheapest:
    /// nothing is parsed, nothing is fetched, nothing is logged at a level an
    /// unauthenticated caller could make noisy.
    Disabled,
    /// The `client_id` is not a URL this server will resolve: wrong scheme, no
    /// path, a query, a fragment, userinfo, a dot segment, or a spelling that
    /// is not its own canonical form.
    UnusableClientId(String),
    /// The `client_id`'s host is not on `cimd.trusted_client_id_domains`.
    UntrustedPublisher { host: String },
    /// The fetch failed, was refused by the SSRF guard, timed out, answered a
    /// non-success status, or returned more bytes than the cap allows.
    Fetch(String),
    /// The response was not JSON, or was not a client metadata document.
    Malformed(String),
    /// The document parsed but names a client this tenant will not admit.
    Refused(String),
}

impl std::fmt::Display for CimdError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => {
                write!(
                    f,
                    "client ID metadata documents are disabled for this tenant"
                )
            }
            Self::UnusableClientId(d) => write!(f, "unusable client_id URL: {d}"),
            Self::UntrustedPublisher { host } => write!(
                f,
                "{host} is not on this tenant's cimd.trusted_client_id_domains"
            ),
            Self::Fetch(d) => write!(f, "the metadata document could not be fetched: {d}"),
            Self::Malformed(d) => write!(f, "the metadata document is not usable: {d}"),
            Self::Refused(d) => write!(
                f,
                "the metadata document names a client this tenant will not admit: {d}"
            ),
        }
    }
}

impl std::error::Error for CimdError {}

// ---------------------------------------------------------------------------
// The `client_id` URL
// ---------------------------------------------------------------------------

/// Whether a `client_id` is shaped like an absolute URL at all.
///
/// **The whole of I1's cost.** This runs on every authorization, PAR and token
/// request in the deployment, so it is a `find` over at most a handful of
/// bytes and it answers `false` for every `client_id` AXIAM has ever issued
/// (`oa_` followed by hex). Only when it answers `true` does anything read a
/// setting, and only then can a tenant's policy be consulted at all.
///
/// Deliberately looser than [`validate_client_id_url`]: this is the question
/// "is this worth looking at", not "is this acceptable". A URL-shaped
/// `client_id` that fails the real rules below is still an unknown client.
pub fn looks_like_url(client_id: &str) -> bool {
    // A scheme, "://", and something after it. `Url::parse` would also accept
    // `mailto:` and other schemes that have no authority; those are not
    // client_id URLs and are not worth a parse.
    client_id.starts_with("https://") || client_id.starts_with("http://")
}

/// Validate a `client_id` as a metadata document URL, against the tenant's
/// policy.
///
/// # The rules, and why each one is here
///
/// Keycloak's list, which the plan names as the reference behaviour, plus one
/// of AXIAM's own:
///
/// * **`https` only**, unless the tenant set `cimd.allow_http`. The document
///   *is* the registration; over plaintext it is rewritable in transit by
///   anybody on the path, who would then be choosing this client's redirect
///   URIs.
/// * **A path is required.** `https://example.com` identifies a *host*, and a
///   host is not a client: every party who can publish anything under that
///   origin would otherwise be the same client.
/// * **No `.` or `..` segments.** Two spellings of one document are two
///   `client_id`s, two shadow rows, and two consent records for one client.
/// * **No fragment, no query, no userinfo.** A fragment is not sent to the
///   server, so it can only ever create a second spelling; a query makes the
///   identifier's own equality depend on parameter order; userinfo puts a
///   credential in a public identifier.
/// * **The `client_id` must be its own canonical form.** AXIAM's own rule, and
///   the one that makes the four above sufficient rather than merely
///   necessary: the string is compared for equality against the document's own
///   `client_id`, used as the key of a cache, and stored as the `client_id` of
///   a row that a later request must find by exact match. If
///   `https://Example.com/a` and `https://example.com/a` could both be
///   presented, the three would not agree. Rejecting the non-canonical
///   spelling is one comparison and removes the class.
/// * **The host must be on `cimd.trusted_client_id_domains`.** See
///   `CimdPolicy`: the fetch is reachable by an unauthenticated caller who
///   chooses the URL.
pub fn validate_client_id_url(client_id: &str, policy: &CimdPolicy) -> Result<Url, CimdError> {
    let refuse = |why: &str| CimdError::UnusableClientId(format!("{client_id:?}: {why}"));

    let url = Url::parse(client_id).map_err(|e| refuse(&e.to_string()))?;

    match url.scheme() {
        "https" => {}
        "http" if policy.allow_http => {}
        "http" => {
            return Err(refuse(
                "http is permitted only when the tenant sets cimd.allow_http, which is a \
                 development posture",
            ));
        }
        other => return Err(refuse(&format!("scheme {other:?} is not https"))),
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err(refuse("a client_id URL must carry no userinfo"));
    }
    if url.query().is_some() {
        return Err(refuse("a client_id URL must carry no query string"));
    }
    if url.fragment().is_some() {
        return Err(refuse("a client_id URL must carry no fragment"));
    }

    let Some(host) = url.host_str().map(str::to_owned) else {
        return Err(refuse("a client_id URL must name a host"));
    };

    let path = url.path();
    if path.is_empty() || path == "/" {
        return Err(refuse(
            "a client_id URL must have a path component: an origin identifies a host, and a \
             host is not a client",
        ));
    }
    if path.split('/').any(|seg| seg == "." || seg == "..") {
        return Err(refuse(
            "a client_id URL must contain no . or .. path segment",
        ));
    }

    if url.as_str() != client_id {
        return Err(refuse(&format!(
            "is not its own canonical form (it normalises to {:?}); present the canonical \
             spelling, which is the one the document must also carry",
            url.as_str()
        )));
    }

    if !policy
        .trusted_client_id_domains
        .iter()
        .any(|p| host_glob_matches(p, &host))
    {
        return Err(CimdError::UntrustedPublisher { host });
    }

    Ok(url)
}

// ---------------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------------

/// A client metadata document, as fetched.
///
/// The members are RFC 7591 §2's, which the draft reuses. Everything AXIAM
/// cannot act on is dropped by `serde`, exactly as it is for a registration
/// request: RFC 7591 §2 requires a server to ignore metadata it does not
/// understand, and `client_uri`, `logo_uri`, `contacts`, `tos_uri` and
/// `policy_uri` all arrive from real clients.
///
/// There is no `software_statement` arm here, and its absence is not an
/// oversight: a document *is* an assertion about the client, made at a URL the
/// client controls, so a signed statement inside it would add a second,
/// unverifiable claim. A document carrying one is admitted and the member
/// ignored — unlike at the registration endpoint, where accepting one silently
/// would have meant treating an unverified assertion as verified.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientMetadataDocument {
    /// The draft's one required member: the URL this document was fetched
    /// from, restated by the document itself.
    #[serde(default)]
    pub client_id: Option<String>,
    /// Shown to the end user on the consent screen D4 forces.
    #[serde(default)]
    pub client_name: Option<String>,
    /// RFC 7591 §2 `redirect_uris`.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// RFC 7591 §2 `grant_types`; absent means `["authorization_code"]`.
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    /// RFC 7591 §2 `response_types`; absent means `["code"]`.
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    /// RFC 7591 §2 `token_endpoint_auth_method`; see
    /// [`resolve_auth_method`] for why absent means `none` here and
    /// `client_secret_basic` at the registration endpoint.
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    /// RFC 7591 §2 `scope`, space-delimited.
    #[serde(default)]
    pub scope: Option<String>,
    /// RFC 7591 §2 `jwks` — an inline JWK Set, for `private_key_jwt`.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// RFC 7591 §2 `jwks_uri`.
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

/// Resolve the document's `token_endpoint_auth_method`.
///
/// **Absent means `none`**, where `dcr::resolve_auth_method` reads absent as
/// RFC 7591 §2's `client_secret_basic`. The two defaults differ because the
/// two situations do: a registration request is a conversation in which the
/// server can mint a secret and hand it back, and a metadata document is a
/// public file. There is no secret for a CIMD client to have and no channel to
/// give it one on, so `client_secret_basic` here would not be a default, it
/// would be a client that can never authenticate.
fn resolve_auth_method(raw: Option<&str>) -> Result<ClientAuthMethod, CimdError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(ClientAuthMethod::None);
    };
    ClientAuthMethod::from_wire(raw)
        .filter(|m| CIMD_AUTH_METHODS.contains(m))
        .ok_or_else(|| {
            CimdError::Refused(format!(
                "token_endpoint_auth_method {raw:?} is not one a metadata document may name \
                 (allowed: {}); a client whose registration is a public document cannot hold \
                 a shared secret",
                CIMD_AUTH_METHODS
                    .iter()
                    .map(|m| m.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })
}

/// A document that passed every check, ready to be materialised.
#[derive(Debug, Clone)]
pub struct ValidatedCimdClient {
    /// The row to upsert. Its `managed_by`, `profile` and `allowed_resources`
    /// are the server's, not the document's.
    pub create: CreateOAuth2Client,
}

/// Validate a fetched document against the `client_id` it claims to describe
/// and the tenant's policy, and produce the row it becomes.
///
/// Pure: no clock, no database, no network. The caller has already decided
/// that the tenant permits CIMD at all and that the URL is one this tenant
/// will fetch.
///
/// # Order of refusals
///
/// Identity first. `client_id` inside the document must equal the URL it came
/// from, because every check after that is about *this* client and is
/// meaningless if the document is describing another one — a document copied
/// from elsewhere, or served by a host that mirrors other people's files, is
/// refused before its redirect URIs are ever read.
pub fn validate(
    tenant_id: Uuid,
    client_id: &Url,
    doc: &ClientMetadataDocument,
    policy: &OidcPolicy,
) -> Result<ValidatedCimdClient, CimdError> {
    let cimd = &policy.cimd;
    let client_id_str = client_id.as_str();

    // --- identity -----------------------------------------------------------
    match doc.client_id.as_deref() {
        Some(stated) if stated == client_id_str => {}
        Some(stated) => {
            return Err(CimdError::Refused(format!(
                "the document states client_id {stated:?} but was fetched from \
                 {client_id_str:?}; a document describes the URL it lives at and nothing else"
            )));
        }
        None => {
            return Err(CimdError::Refused(
                "the document states no client_id; the draft requires it, and without it a \
                 document cannot be distinguished from one copied from another publisher"
                    .into(),
            ));
        }
    }

    // --- redirect URIs ------------------------------------------------------
    if doc.redirect_uris.is_empty() {
        return Err(CimdError::Refused(
            "redirect_uris must name at least one URI: every grant a CIMD client may hold is \
             completed through a browser redirect"
                .into(),
        ));
    }
    let client_host = client_id.host_str().unwrap_or_default().to_owned();
    for uri in &doc.redirect_uris {
        let parsed = Url::parse(uri).map_err(|_| {
            CimdError::Refused(format!("redirect_uri {uri:?} is not a valid absolute URI"))
        })?;
        let host = parsed
            .host_str()
            .ok_or_else(|| {
                CimdError::Refused(format!("redirect_uri {uri:?} has no host component"))
            })?
            .to_owned();
        let loopback = is_loopback_host(&host);
        match parsed.scheme() {
            "https" => {}
            // RFC 8252 §7.3. A loopback callback never leaves the machine the
            // person is sitting at, which is why every desktop MCP client uses
            // one and why plaintext on it is not a transport exposure.
            "http" if loopback => {}
            other => {
                return Err(CimdError::Refused(format!(
                    "redirect_uri {uri:?} uses scheme {other:?}: a CIMD client's callback must \
                     be https, or http on a loopback host (RFC 8252 section 7.3)"
                )));
            }
        }
        if parsed.fragment().is_some() {
            return Err(CimdError::Refused(format!(
                "redirect_uri {uri:?} carries a fragment, which RFC 6749 section 3.1.2 forbids"
            )));
        }
        if !redirect_host_is_allowed(&cimd.trusted_redirect_domains, &host) {
            return Err(CimdError::Refused(format!(
                "the host {host:?} is not one this tenant accepts a CIMD redirect for; an \
                 administrator sets cimd.trusted_redirect_domains (loopback is always allowed)"
            )));
        }
        // The same-domain rule, which is why the desktop profiles turn it off:
        // a loopback callback can never share a host with an `https` client_id.
        if cimd.restrict_same_domain && !host.eq_ignore_ascii_case(&client_host) {
            return Err(CimdError::Refused(format!(
                "redirect_uri {uri:?} is on {host:?}, and this tenant requires every redirect \
                 to be on the client_id's own host ({client_host:?}). A client with a loopback \
                 callback needs cimd.restrict_same_domain off"
            )));
        }
    }

    // --- grants and response types -----------------------------------------
    if let Some(types) = &doc.response_types
        && let Some(bad) = types.iter().find(|t| t.trim() != "code")
    {
        return Err(CimdError::Refused(format!(
            "response_type {bad:?} is not supported; this server issues authorization codes only"
        )));
    }

    let grant_types: Vec<String> = match &doc.grant_types {
        None => vec!["authorization_code".to_owned()],
        Some(requested) => {
            for g in requested {
                if !DCR_GRANT_TYPES.contains(&g.trim()) {
                    return Err(CimdError::Refused(format!(
                        "grant_type {g:?} is not one a CIMD client may hold (allowed: {}); both \
                         absent grants mint a token on the strength of the client's own \
                         identity, and the identity of a CIMD client is a file a stranger \
                         publishes",
                        DCR_GRANT_TYPES.join(", ")
                    )));
                }
            }
            if !requested.iter().any(|g| g.trim() == "authorization_code") {
                return Err(CimdError::Refused(
                    "grant_types must include authorization_code: refresh_token alone would \
                     describe a client that can refresh a token it cannot obtain"
                        .into(),
                ));
            }
            requested.iter().map(|g| g.trim().to_owned()).collect()
        }
    };

    // --- client authentication ---------------------------------------------
    let token_endpoint_auth_method =
        resolve_auth_method(doc.token_endpoint_auth_method.as_deref())?;
    if cimd.confidential_only && token_endpoint_auth_method.is_public() {
        return Err(CimdError::Refused(
            "this tenant admits only confidential CIMD clients (cimd.confidential_only), and \
             this document names token_endpoint_auth_method: none"
                .into(),
        ));
    }
    if token_endpoint_auth_method == ClientAuthMethod::PrivateKeyJwt {
        let sources = usize::from(doc.jwks.is_some()) + usize::from(doc.jwks_uri.is_some());
        if sources != 1 {
            return Err(CimdError::Refused(format!(
                "private_key_jwt requires exactly one of jwks or jwks_uri (RFC 7591 section 2); \
                 the document names {sources}"
            )));
        }
        if let Some(uri) = doc.jwks_uri.as_deref() {
            let parsed = Url::parse(uri).map_err(|_| {
                CimdError::Refused(format!("jwks_uri {uri:?} is not an absolute URL"))
            })?;
            if parsed.scheme() != "https" {
                return Err(CimdError::Refused(format!(
                    "jwks_uri {uri:?} must be https: AXIAM fetches it to obtain the keys that \
                     authenticate this client"
                )));
            }
        }
    } else if doc.jwks.is_some() || doc.jwks_uri.is_some() {
        // The same consistency rule `fapi::validate_registration` applies to a
        // public registration: a client that authenticates with nothing does
        // not also register a key, and a document saying both says two
        // different things about which credential the token endpoint should
        // want.
        return Err(CimdError::Refused(
            "a document naming token_endpoint_auth_method: none may not also register jwks or \
             jwks_uri; a public client authenticates with nothing"
                .into(),
        ));
    }

    // --- scopes -------------------------------------------------------------
    //
    // The tenant's external-client scope list governs both mechanisms. It is
    // named for DCR because DCR defined it; what it means is "what an
    // externally registered client may ask for", and a CIMD client is one.
    // `validate_dcr_policy` already refuses `address` and `phone` on that
    // list, so the W7 interlock covers this lane with no second rule.
    let scopes: Vec<String> = doc
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    for scope in &scopes {
        if !policy.dcr_allowed_scopes.iter().any(|s| s == scope) {
            return Err(CimdError::Refused(format!(
                "scope {scope:?} is not one this tenant offers to externally registered \
                 clients; an administrator sets dcr_allowed_scopes"
            )));
        }
    }

    let name = doc
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map_or_else(|| client_id_str.to_owned(), str::to_owned);

    Ok(ValidatedCimdClient {
        create: CreateOAuth2Client {
            tenant_id,
            name,
            redirect_uris: doc.redirect_uris.clone(),
            grant_types,
            scopes,
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            // I5 — forced, never read from the document. A client materialised
            // from a stranger's file can never carry a FAPI profile;
            // `fapi::validate_registration` refuses the combination too, so
            // this is the first of two gates rather than the only one.
            profile: ClientProfile::Standard,
            token_endpoint_auth_method,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: Vec::new(),
            tls_client_certificate_bound_access_tokens: false,
            jwks: doc.jwks.as_ref().map(ToString::to_string),
            jwks_uri: doc.jwks_uri.clone(),
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            // D3 — the tenant's list, verbatim. The single most important line
            // in this module: a stranger must not be able to name the audience
            // of the tokens their client will obtain.
            allowed_resources: policy.external_client_allowed_resources.clone(),
            // D5 — forced. A document cannot claim to be an administrator's
            // client, because this value is built here rather than echoed.
            managed_by: ManagedBy::Cimd,
        },
    })
}

/// The three hosts RFC 8252 §7.3 contemplates for a native application's
/// callback.
///
/// `localhost` and `127.0.0.1` are **not** interchangeable, here or in the
/// T21.2 matcher: each client registers what it actually uses.
fn is_loopback_host(host: &str) -> bool {
    host.eq_ignore_ascii_case("127.0.0.1")
        || host.eq_ignore_ascii_case("localhost")
        || host.eq_ignore_ascii_case("[::1]")
        || host == "::1"
}

// ---------------------------------------------------------------------------
// The cache
// ---------------------------------------------------------------------------

/// One cached document.
#[derive(Debug, Clone)]
pub struct CachedDocument {
    /// The document as fetched and parsed.
    pub document: ClientMetadataDocument,
    /// When it was last fetched successfully.
    pub fetched_at: DateTime<Utc>,
    /// How long it may be served for, already clamped to the tenant's bounds
    /// and to the deployment constants.
    pub ttl_secs: u64,
}

/// Process-wide client-metadata-document cache, keyed by
/// `(tenant_id, client_id URL)`.
///
/// Modelled on `axiam_federation::jwks_cache::JwksCache` — the same TTL, the
/// same stale-while-revalidate discipline, the same shared SSRF guard — with
/// three differences that the threat demands:
///
/// 1. **The TTL is not a constant.** It comes from the document's own
///    `Cache-Control`, clamped to the tenant's `min_cache_secs` and
///    `max_cache_secs` and then to the deployment's own floor and ceiling. A
///    publisher may ask to be re-read sooner or trusted longer, within bounds
///    the publisher does not set.
/// 2. **The key includes the tenant.** Two tenants that both admit the same
///    document get their own entries, because they may have different bounds,
///    different trusted domains and different resource lists, and a cache
///    shared across them would let one tenant's policy decide another's.
/// 3. **Nothing negative is cached.** A refusal costs a fetch next time, which
///    is the right way round: caching a refusal would let one bad minute at a
///    publisher lock its users out for the length of a TTL they did not
///    choose.
/// 4. **Entries nobody can be served are evicted** (T21.8 / MCP-04), on the
///    insert path, so a cache miss pays for it and a hit does not. An entry
///    past its TTL *and* past [`STALE_WINDOW_SECS`] cannot be returned by
///    either branch of [`ClientMetadataCache::get_or_fetch`], so dropping it
///    changes no answer and keeps the map bounded by what is still live rather
///    than by every URL a stranger has ever named.
///
/// Per process, not per worker: it lives in `AppState` and is cloned (an `Arc`
/// clone) into every actix worker, exactly as the JWKS cache is.
#[derive(Clone, Default)]
pub struct ClientMetadataCache(Arc<RwLock<HashMap<(Uuid, String), CachedDocument>>>);

impl ClientMetadataCache {
    /// A new, empty cache.
    pub fn new() -> Self {
        Self(Arc::new(RwLock::new(HashMap::new())))
    }

    /// Return the document for `client_id`, fetching it if the cache has
    /// nothing fresh.
    ///
    /// 1. Cache hit within TTL → return it, no HTTP.
    /// 2. Miss or expired → fetch through the SSRF guard.
    ///    * Success → store and return.
    ///    * Failure with an entry inside [`STALE_WINDOW_SECS`] past its TTL →
    ///      serve stale with a WARN, exactly as the JWKS cache does.
    ///    * Failure with nothing usable → the error.
    pub async fn get_or_fetch(
        &self,
        tenant_id: Uuid,
        client_id: &Url,
        policy: &CimdPolicy,
    ) -> Result<ClientMetadataDocument, CimdError> {
        let key = (tenant_id, client_id.as_str().to_owned());
        let now = Utc::now();

        {
            let guard = self.0.read().await;
            if let Some(entry) = guard.get(&key)
                && entry.fetched_at + chrono::Duration::seconds(entry.ttl_secs as i64) > now
            {
                return Ok(entry.document.clone());
            }
        }

        match fetch_document(client_id, policy).await {
            Ok((document, ttl_secs)) => {
                let mut guard = self.0.write().await;
                // T21.8 / MCP-04 — evict what can no longer be served before
                // inserting. Without this the map grows by one entry per
                // distinct trusted URL an unauthenticated caller can name and
                // never shrinks, which is the same finding as the unswept
                // shadow rows, in RAM: a cache that is never evicted is not a
                // cache.
                //
                // On the insert path only, so a cache hit stays a read lock
                // and the common request pays nothing. O(n) under the write
                // lock, and n is bounded by the prune itself — an entry past
                // its TTL *and* past the stale window can be served to
                // nobody, by either branch of this function, so dropping it
                // changes no answer. Not a per-tenant cap: the quota in
                // `axiam-api-rest`'s `materialise_if_cimd` refuses before the
                // fetch that would populate this map.
                guard.retain(|_, entry| {
                    entry.fetched_at
                        + chrono::Duration::seconds(entry.ttl_secs as i64)
                        + chrono::Duration::seconds(STALE_WINDOW_SECS)
                        > now
                });
                guard.insert(
                    key,
                    CachedDocument {
                        document: document.clone(),
                        fetched_at: now,
                        ttl_secs,
                    },
                );
                Ok(document)
            }
            Err(fetch_err) => {
                let guard = self.0.read().await;
                if let Some(entry) = guard.get(&key)
                    && entry.fetched_at
                        + chrono::Duration::seconds(entry.ttl_secs as i64)
                        + chrono::Duration::seconds(STALE_WINDOW_SECS)
                        > now
                {
                    tracing::warn!(
                        client_id = %client_id,
                        error = %fetch_err,
                        "serving a stale client ID metadata document while its publisher is \
                         unreachable"
                    );
                    return Ok(entry.document.clone());
                }
                Err(fetch_err)
            }
        }
    }

    /// Test-only seam: move an entry's `fetched_at` backwards, so a test can
    /// reach the expiry and stale-window branches without sleeping.
    ///
    /// A seam rather than an injected clock because the clock is read in one
    /// place and the alternative — threading a `now` through every caller —
    /// would put a test parameter on a security-relevant API.
    #[doc(hidden)]
    pub async fn backdate_for_test(&self, tenant_id: Uuid, client_id: &str, by_secs: i64) -> bool {
        let mut guard = self.0.write().await;
        match guard.get_mut(&(tenant_id, client_id.to_owned())) {
            Some(entry) => {
                entry.fetched_at -= chrono::Duration::seconds(by_secs);
                true
            }
            None => false,
        }
    }

    /// Test-only seam: the TTL an entry was stored with, so a test can assert
    /// the cache bounds were applied.
    #[doc(hidden)]
    pub async fn ttl_for_test(&self, tenant_id: Uuid, client_id: &str) -> Option<u64> {
        let guard = self.0.read().await;
        guard
            .get(&(tenant_id, client_id.to_owned()))
            .map(|e| e.ttl_secs)
    }

    /// Test-only seam: how many entries the map holds, so a test can assert
    /// the eviction happened rather than infer it from a hit or a miss.
    #[doc(hidden)]
    pub async fn len_for_test(&self) -> usize {
        self.0.read().await.len()
    }
}

/// Fetch and parse one document. Returns it with the TTL it earned.
///
/// Every outbound property is the shared guard's: resolution, IPv4-mapped
/// canonicalisation, the private-address refusal, the pinning of the validated
/// address into the connection, the refusal to follow a redirect without
/// re-running all of it, the hop limit and the request timeout. This function
/// adds exactly three things on top — a status check, a content-type check and
/// a streaming byte cap — and each is the caller-side half of a control the
/// guard cannot make for us.
async fn fetch_document(
    client_id: &Url,
    policy: &CimdPolicy,
) -> Result<(ClientMetadataDocument, u64), CimdError> {
    // `allow_private` is the guard's test/development seam and is tied here to
    // `cimd.allow_http`, because the guard refuses a plaintext scheme on the
    // same flag that admits a private address. That coupling is stated on
    // `CimdPolicy::allow_http` and in the operator documentation: a deployment
    // that allows http has also stopped refusing 169.254.169.254 on the first
    // hop. Redirect hops are validated strictly regardless.
    let response =
        axiam_federation::ssrf::guarded_fetch(client_id.as_str(), policy.allow_http, |c, u| {
            c.get(u).header(reqwest::header::ACCEPT, "application/json")
        })
        .await
        .map_err(|e| CimdError::Fetch(e.to_string()))?;

    let status = response.status();
    if !status.is_success() {
        return Err(CimdError::Fetch(format!("the publisher answered {status}")));
    }

    // A document served as `text/html` is a login page, an error page or a
    // single-page application — not a registration. Checked before the body is
    // read so that an HTML response is refused rather than parsed.
    let content_type = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    if !is_json_content_type(&content_type) {
        return Err(CimdError::Malformed(format!(
            "the publisher served Content-Type {content_type:?}; a client ID metadata document \
             is application/json"
        )));
    }

    let advertised = max_age_secs(
        response
            .headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
    );
    let ttl_secs = policy.clamp_cache_secs(advertised);

    // The hard cap, applied while reading rather than after: a chunked
    // response with no `Content-Length` bypasses the guard's coarse header
    // check entirely, and buffering it first is precisely the memory
    // exhaustion this bound exists to prevent.
    let body =
        axiam_federation::ssrf::read_capped_body(response, policy.effective_max_metadata_bytes())
            .await
            .map_err(|e| CimdError::Fetch(e.to_string()))?;

    let document = serde_json::from_slice::<ClientMetadataDocument>(&body)
        .map_err(|e| CimdError::Malformed(e.to_string()))?;

    Ok((document, ttl_secs))
}

/// Whether a `Content-Type` names JSON.
///
/// `application/json`, with or without parameters, and the `+json` structured
/// suffix (RFC 6839) — a publisher serving
/// `application/client-metadata+json` is serving JSON and saying what kind.
/// Anything else is refused.
fn is_json_content_type(raw: &str) -> bool {
    let essence = raw
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    essence == "application/json" || essence.ends_with("+json")
}

/// The `max-age` of a `Cache-Control` header, if it names one.
///
/// Only `max-age`. `no-store` and `no-cache` are **not** honoured, and that is
/// deliberate: they would ask AXIAM to re-fetch on every authorization
/// request, which is the amplification `min_cache_secs` exists to bound. A
/// publisher that sends them gets the floor, which is also what a publisher
/// that sends nothing gets.
fn max_age_secs(header: Option<&str>) -> Option<u64> {
    let header = header?;
    header.split(',').find_map(|directive| {
        let directive = directive.trim();
        let value = directive
            .strip_prefix("max-age")
            .or_else(|| directive.strip_prefix("Max-Age"))?
            .trim_start()
            .strip_prefix('=')?
            .trim()
            .trim_matches('"');
        value.parse::<u64>().ok()
    })
}

// ---------------------------------------------------------------------------
// Resolution — the one entry point a caller needs
// ---------------------------------------------------------------------------

/// Decide whether a `client_id` is a CIMD client at all, and if so produce the
/// row it becomes.
///
/// The order is the whole of I1 and most of the abuse surface:
///
/// 1. **Is it URL-shaped?** A string comparison. Every `client_id` AXIAM has
///    ever issued stops here, having read no setting and touched no network.
/// 2. **Is CIMD on for this tenant?** The caller has read the policy by now;
///    `enabled` false answers [`CimdError::Disabled`] and nothing else runs.
/// 3. **Is the URL usable, and is its publisher trusted?** Pure, and before
///    any fetch, so an untrusted host costs a parse rather than a connection.
/// 4. **Fetch, cached.** Behind the SSRF guard and the cache bounds.
/// 5. **Does the document describe a client this tenant admits?** Pure.
pub async fn resolve(
    cache: &ClientMetadataCache,
    tenant_id: Uuid,
    client_id: &str,
    policy: &OidcPolicy,
) -> Result<ValidatedCimdClient, CimdError> {
    if !policy.cimd.enabled {
        return Err(CimdError::Disabled);
    }
    let url = validate_client_id_url(client_id, &policy.cimd)?;
    let document = cache.get_or_fetch(tenant_id, &url, &policy.cimd).await?;
    validate(tenant_id, &url, &document, policy)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::settings::{CimdPolicy, OidcPolicy};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn cimd_policy() -> CimdPolicy {
        CimdPolicy {
            enabled: true,
            allow_http: false,
            trusted_client_id_domains: vec!["*.example.com".into(), "example.com".into()],
            trusted_redirect_domains: Vec::new(),
            restrict_same_domain: false,
            confidential_only: false,
            ..CimdPolicy::default()
        }
    }

    fn oidc_policy(cimd: CimdPolicy) -> OidcPolicy {
        OidcPolicy {
            sensitive_scopes_enabled: false,
            default_locale: None,
            dynamic_registration: Default::default(),
            dcr_allowed_scopes: vec!["openid".into(), "profile".into()],
            dcr_allowed_redirect_hosts: Vec::new(),
            external_client_allowed_resources: vec!["https://mcp.example.com/".into()],
            dcr_max_clients: 20,
            dcr_unused_client_ttl_days: 30,
            cimd,
        }
    }

    /// A VS-Code-shaped document: public client, loopback callback, no scope
    /// beyond `openid`.
    fn vscode_document(client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "client_id": client_id,
            "client_name": "Example Editor",
            "redirect_uris": ["http://127.0.0.1/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "openid",
        })
    }

    /// A Claude-Code-shaped document: `localhost` rather than `127.0.0.1`, and
    /// no `grant_types` member at all (RFC 7591 §2's default).
    fn claude_code_document(client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "client_id": client_id,
            "client_name": "Example Agent",
            "redirect_uris": ["http://localhost/oauth/callback"],
            "token_endpoint_auth_method": "none",
            "scope": "openid profile",
        })
    }

    // --- the URL rules ------------------------------------------------------

    #[test]
    fn looks_like_url_answers_no_for_every_client_id_axiam_issues() {
        // The I1 fast path: an `oa_`-prefixed identifier never reaches a
        // setting read.
        assert!(!looks_like_url("oa_0123456789abcdef0123456789abcdef"));
        assert!(!looks_like_url("my-client"));
        assert!(!looks_like_url("urn:example:client"));
        assert!(looks_like_url("https://example.com/mcp.json"));
        assert!(looks_like_url("http://example.com/mcp.json"));
    }

    #[test]
    fn a_usable_client_id_url_is_accepted() {
        let url = validate_client_id_url("https://example.com/mcp.json", &cimd_policy())
            .expect("accepted");
        assert_eq!(url.as_str(), "https://example.com/mcp.json");
    }

    #[test]
    fn every_url_rule_refuses() {
        let policy = cimd_policy();
        for (candidate, why) in [
            ("http://example.com/mcp.json", "http without allow_http"),
            ("ftp://example.com/mcp.json", "not https"),
            ("https://example.com", "no path"),
            ("https://example.com/", "root path only"),
            ("https://example.com/a/../mcp.json", "dot-dot segment"),
            ("https://example.com/./mcp.json", "dot segment"),
            ("https://example.com/mcp.json?x=1", "query"),
            ("https://example.com/mcp.json#f", "fragment"),
            ("https://u:p@example.com/mcp.json", "userinfo"),
            ("https://EXAMPLE.com/mcp.json", "non-canonical host case"),
            (
                "https://example.com:443/mcp.json",
                "non-canonical default port",
            ),
            ("not a url at all", "not a URL"),
        ] {
            let result = validate_client_id_url(candidate, &policy);
            assert!(
                matches!(result, Err(CimdError::UnusableClientId(_))),
                "{candidate:?} must be refused ({why}), got {result:?}"
            );
        }
    }

    #[test]
    fn an_untrusted_publisher_is_refused_before_any_fetch() {
        let result = validate_client_id_url("https://evil.test/mcp.json", &cimd_policy());
        assert!(
            matches!(result, Err(CimdError::UntrustedPublisher { .. })),
            "got {result:?}"
        );
        // And the glob is a label-boundary match, not a suffix match.
        let result = validate_client_id_url("https://evil-example.com/mcp.json", &cimd_policy());
        assert!(
            matches!(result, Err(CimdError::UntrustedPublisher { .. })),
            "got {result:?}"
        );
    }

    #[test]
    fn allow_http_admits_http_and_nothing_else() {
        let policy = CimdPolicy {
            allow_http: true,
            ..cimd_policy()
        };
        assert!(validate_client_id_url("http://example.com/mcp.json", &policy).is_ok());
        assert!(matches!(
            validate_client_id_url("ftp://example.com/mcp.json", &policy),
            Err(CimdError::UnusableClientId(_))
        ));
    }

    /// **SEC-094, through this module's own call path.** An IPv4-mapped IPv6
    /// literal is canonicalised by the shared guard and refused; the guard's
    /// own table-driven test covers the families, and this one covers the fact
    /// that CIMD reaches it.
    #[tokio::test]
    async fn an_ipv4_mapped_ipv6_literal_is_refused_by_the_shared_guard() {
        let policy = CimdPolicy {
            trusted_client_id_domains: vec!["*".into()],
            ..cimd_policy()
        };
        let url = Url::parse("https://[::ffff:169.254.169.254]/mcp.json").expect("parses");
        let err = fetch_document(&url, &policy).await.expect_err("refused");
        assert!(
            matches!(err, CimdError::Fetch(_)),
            "an IPv4-mapped metadata address must be refused, got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_private_address_is_refused() {
        let policy = CimdPolicy {
            trusted_client_id_domains: vec!["*".into()],
            ..cimd_policy()
        };
        // `allow_http` is false, so the guard applies the address rule on the
        // first hop; `localhost` resolves to a loopback address.
        let url = Url::parse("https://localhost:1/mcp.json").expect("parses");
        let err = fetch_document(&url, &policy).await.expect_err("refused");
        assert!(matches!(err, CimdError::Fetch(_)), "got {err:?}");
    }

    // --- the document rules -------------------------------------------------

    fn parse_doc(v: &serde_json::Value) -> ClientMetadataDocument {
        serde_json::from_value(v.clone()).expect("document parses")
    }

    #[test]
    fn a_vscode_shaped_document_is_admitted() {
        let id = "https://example.com/vscode.json";
        let url = Url::parse(id).unwrap();
        let policy = oidc_policy(cimd_policy());
        let validated = validate(
            Uuid::new_v4(),
            &url,
            &parse_doc(&vscode_document(id)),
            &policy,
        )
        .expect("admitted");
        assert_eq!(validated.create.managed_by, ManagedBy::Cimd);
        assert_eq!(validated.create.profile, ClientProfile::Standard);
        assert_eq!(
            validated.create.token_endpoint_auth_method,
            ClientAuthMethod::None
        );
        // D3 — the tenant's list, not the document's.
        assert_eq!(
            validated.create.allowed_resources,
            vec!["https://mcp.example.com/".to_owned()]
        );
    }

    #[test]
    fn a_claude_code_shaped_document_is_admitted_with_the_rfc_default_grant() {
        let id = "https://agent.example.com/metadata.json";
        let url = Url::parse(id).unwrap();
        let policy = oidc_policy(cimd_policy());
        let validated = validate(
            Uuid::new_v4(),
            &url,
            &parse_doc(&claude_code_document(id)),
            &policy,
        )
        .expect("admitted");
        assert_eq!(validated.create.grant_types, vec!["authorization_code"]);
        assert_eq!(validated.create.scopes, vec!["openid", "profile"]);
    }

    #[test]
    fn a_document_describing_another_url_is_refused() {
        let url = Url::parse("https://example.com/mine.json").unwrap();
        let doc = parse_doc(&vscode_document("https://example.com/theirs.json"));
        let err =
            validate(Uuid::new_v4(), &url, &doc, &oidc_policy(cimd_policy())).expect_err("refused");
        assert!(matches!(err, CimdError::Refused(_)), "got {err:?}");
    }

    #[test]
    fn a_document_stating_no_client_id_is_refused() {
        let url = Url::parse("https://example.com/mine.json").unwrap();
        let doc: ClientMetadataDocument = serde_json::from_value(serde_json::json!({
            "redirect_uris": ["http://127.0.0.1/cb"],
        }))
        .unwrap();
        let err =
            validate(Uuid::new_v4(), &url, &doc, &oidc_policy(cimd_policy())).expect_err("refused");
        assert!(matches!(err, CimdError::Refused(_)), "got {err:?}");
    }

    #[test]
    fn a_redirect_to_a_non_loopback_http_host_is_refused() {
        let id = "https://example.com/a.json";
        let url = Url::parse(id).unwrap();
        let mut doc = parse_doc(&vscode_document(id));
        doc.redirect_uris = vec!["http://mcp.example.com/cb".into()];
        let err =
            validate(Uuid::new_v4(), &url, &doc, &oidc_policy(cimd_policy())).expect_err("refused");
        assert!(matches!(err, CimdError::Refused(_)), "got {err:?}");
    }

    #[test]
    fn a_redirect_outside_the_trusted_domains_is_refused_but_loopback_is_not() {
        let id = "https://example.com/a.json";
        let url = Url::parse(id).unwrap();
        let policy = oidc_policy(cimd_policy());

        let mut doc = parse_doc(&vscode_document(id));
        doc.redirect_uris = vec!["https://elsewhere.test/cb".into()];
        assert!(
            matches!(
                validate(Uuid::new_v4(), &url, &doc, &policy),
                Err(CimdError::Refused(_))
            ),
            "an https redirect outside the empty trusted list must be refused"
        );

        // The loopback three need no entry at all.
        for uri in [
            "http://127.0.0.1/cb",
            "http://localhost/cb",
            "http://[::1]/cb",
        ] {
            let mut doc = parse_doc(&vscode_document(id));
            doc.redirect_uris = vec![uri.into()];
            assert!(
                validate(Uuid::new_v4(), &url, &doc, &policy).is_ok(),
                "{uri} must be admitted"
            );
        }
    }

    #[test]
    fn restrict_same_domain_refuses_a_loopback_callback() {
        let id = "https://example.com/a.json";
        let url = Url::parse(id).unwrap();
        let policy = oidc_policy(CimdPolicy {
            restrict_same_domain: true,
            ..cimd_policy()
        });
        let err = validate(
            Uuid::new_v4(),
            &url,
            &parse_doc(&vscode_document(id)),
            &policy,
        )
        .expect_err("refused");
        assert!(matches!(err, CimdError::Refused(_)), "got {err:?}");
    }

    #[test]
    fn confidential_only_refuses_a_public_document() {
        let id = "https://example.com/a.json";
        let url = Url::parse(id).unwrap();
        let policy = oidc_policy(CimdPolicy {
            confidential_only: true,
            ..cimd_policy()
        });
        let err = validate(
            Uuid::new_v4(),
            &url,
            &parse_doc(&vscode_document(id)),
            &policy,
        )
        .expect_err("refused");
        assert!(matches!(err, CimdError::Refused(_)), "got {err:?}");
    }

    #[test]
    fn a_shared_secret_method_is_refused() {
        let id = "https://example.com/a.json";
        let url = Url::parse(id).unwrap();
        for method in [
            "client_secret_post",
            "client_secret_basic",
            "tls_client_auth",
        ] {
            let mut doc = parse_doc(&vscode_document(id));
            doc.token_endpoint_auth_method = Some(method.to_owned());
            let err = validate(Uuid::new_v4(), &url, &doc, &oidc_policy(cimd_policy()))
                .expect_err("refused");
            assert!(matches!(err, CimdError::Refused(_)), "{method}: {err:?}");
        }
    }

    #[test]
    fn private_key_jwt_needs_exactly_one_key_source() {
        let id = "https://example.com/a.json";
        let url = Url::parse(id).unwrap();
        let policy = oidc_policy(cimd_policy());

        let mut none = parse_doc(&vscode_document(id));
        none.token_endpoint_auth_method = Some("private_key_jwt".into());
        assert!(matches!(
            validate(Uuid::new_v4(), &url, &none, &policy),
            Err(CimdError::Refused(_))
        ));

        let mut both = parse_doc(&vscode_document(id));
        both.token_endpoint_auth_method = Some("private_key_jwt".into());
        both.jwks = Some(serde_json::json!({"keys": []}));
        both.jwks_uri = Some("https://example.com/jwks.json".into());
        assert!(matches!(
            validate(Uuid::new_v4(), &url, &both, &policy),
            Err(CimdError::Refused(_))
        ));

        let mut plaintext = parse_doc(&vscode_document(id));
        plaintext.token_endpoint_auth_method = Some("private_key_jwt".into());
        plaintext.jwks_uri = Some("http://example.com/jwks.json".into());
        assert!(matches!(
            validate(Uuid::new_v4(), &url, &plaintext, &policy),
            Err(CimdError::Refused(_))
        ));

        let mut one = parse_doc(&vscode_document(id));
        one.token_endpoint_auth_method = Some("private_key_jwt".into());
        one.jwks_uri = Some("https://example.com/jwks.json".into());
        assert!(validate(Uuid::new_v4(), &url, &one, &policy).is_ok());
    }

    #[test]
    fn a_public_document_may_not_also_register_a_key() {
        let id = "https://example.com/a.json";
        let url = Url::parse(id).unwrap();
        let mut doc = parse_doc(&vscode_document(id));
        doc.jwks_uri = Some("https://example.com/jwks.json".into());
        let err =
            validate(Uuid::new_v4(), &url, &doc, &oidc_policy(cimd_policy())).expect_err("refused");
        assert!(matches!(err, CimdError::Refused(_)), "got {err:?}");
    }

    #[test]
    fn a_scope_the_tenant_does_not_offer_is_refused() {
        let id = "https://example.com/a.json";
        let url = Url::parse(id).unwrap();
        let mut doc = parse_doc(&vscode_document(id));
        doc.scope = Some("openid email".into());
        let err =
            validate(Uuid::new_v4(), &url, &doc, &oidc_policy(cimd_policy())).expect_err("refused");
        assert!(matches!(err, CimdError::Refused(_)), "got {err:?}");
    }

    #[test]
    fn a_grant_this_endpoint_does_not_issue_is_refused() {
        let id = "https://example.com/a.json";
        let url = Url::parse(id).unwrap();
        for grants in [
            vec!["client_credentials".to_owned()],
            vec!["urn:ietf:params:oauth:grant-type:token-exchange".to_owned()],
            vec!["refresh_token".to_owned()],
        ] {
            let mut doc = parse_doc(&vscode_document(id));
            doc.grant_types = Some(grants.clone());
            let err = validate(Uuid::new_v4(), &url, &doc, &oidc_policy(cimd_policy()))
                .expect_err("refused");
            assert!(matches!(err, CimdError::Refused(_)), "{grants:?}: {err:?}");
        }
    }

    // --- the cache and its bounds ------------------------------------------

    /// Serve a document from a loopback mock server, which needs
    /// `allow_http` — the same seam every SSRF-guarded fetch's tests use.
    fn loopback_policy(server: &MockServer) -> CimdPolicy {
        let host = server.uri().replace("http://", "");
        let host = host.split(':').next().unwrap_or("127.0.0.1").to_owned();
        CimdPolicy {
            enabled: true,
            allow_http: true,
            trusted_client_id_domains: vec![host],
            trusted_redirect_domains: Vec::new(),
            restrict_same_domain: false,
            confidential_only: false,
            ..CimdPolicy::default()
        }
    }

    async fn serve(server: &MockServer, body: serde_json::Value, cache_control: Option<&str>) {
        let mut template = ResponseTemplate::new(200)
            .set_body_json(body)
            .insert_header("content-type", "application/json");
        if let Some(cc) = cache_control {
            template = template.insert_header("cache-control", cc);
        }
        Mock::given(method("GET"))
            .and(path("/mcp.json"))
            .respond_with(template)
            .mount(server)
            .await;
    }

    #[tokio::test]
    async fn a_document_is_fetched_cached_and_refreshed_after_its_ttl() {
        let server = MockServer::start().await;
        let policy = loopback_policy(&server);
        let id = format!("{}/mcp.json", server.uri());
        serve(&server, vscode_document(&id), Some("max-age=600")).await;

        let cache = ClientMetadataCache::new();
        let tenant = Uuid::new_v4();
        let url = Url::parse(&id).unwrap();

        let first = cache
            .get_or_fetch(tenant, &url, &policy)
            .await
            .expect("fetched");
        assert_eq!(first.client_id.as_deref(), Some(id.as_str()));
        assert_eq!(cache.ttl_for_test(tenant, &id).await, Some(600));

        // Second call inside the TTL is served from the cache: the mock has
        // one matching response mounted and wiremock counts the requests.
        cache
            .get_or_fetch(tenant, &url, &policy)
            .await
            .expect("cached");
        assert_eq!(server.received_requests().await.expect("recorded").len(), 1);

        // Past the TTL, the publisher is read again — and a document that has
        // changed since is picked up.
        server.reset().await;
        let mut changed = vscode_document(&id);
        changed["client_name"] = serde_json::json!("Renamed Editor");
        serve(&server, changed, Some("max-age=600")).await;
        assert!(cache.backdate_for_test(tenant, &id, 601).await);

        let refreshed = cache
            .get_or_fetch(tenant, &url, &policy)
            .await
            .expect("refetched");
        assert_eq!(refreshed.client_name.as_deref(), Some("Renamed Editor"));
    }

    /// Mount a document at a chosen path, so a test can hold several distinct
    /// cache keys against one mock server. `serve` above pins `/mcp.json`,
    /// which is right for every test that needs exactly one document.
    async fn serve_at(server: &MockServer, doc_path: &str, id: &str) {
        Mock::given(method("GET"))
            .and(path(doc_path.to_owned()))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(vscode_document(id))
                    .insert_header("content-type", "application/json")
                    .insert_header("cache-control", "max-age=600"),
            )
            .mount(server)
            .await;
    }

    /// **T21.8 / MCP-04.** An entry nobody can be served is gone after the
    /// next insert.
    ///
    /// Without this the map grows by one entry per distinct trusted URL an
    /// unauthenticated caller can name and never shrinks. The eviction runs on
    /// the insert path only, which is why another document has to be fetched
    /// for a dead entry to disappear — and why a cache *hit* still costs only
    /// a read lock.
    ///
    /// The boundary asserted is TTL **plus** the stale window: inside it the
    /// entry is still servable by `get_or_fetch`'s failure branch, so evicting
    /// it would change an answer. Past it, no branch can return it.
    #[tokio::test]
    async fn an_unservable_cache_entry_is_evicted_on_the_next_insert() {
        let server = MockServer::start().await;
        let tenant = Uuid::new_v4();
        let policy = loopback_policy(&server);
        let cache = ClientMetadataCache::new();

        let url_of = |n: &str| {
            let id = format!("{}/{n}.json", server.uri());
            (id.clone(), Url::parse(&id).unwrap())
        };
        let (one_id, one) = url_of("one");
        let (two_id, two) = url_of("two");
        let (three_id, three) = url_of("three");
        let (four_id, four) = url_of("four");

        for (doc_path, id) in [
            ("/one.json", &one_id),
            ("/two.json", &two_id),
            ("/three.json", &three_id),
            ("/four.json", &four_id),
        ] {
            serve_at(&server, doc_path, id).await;
        }

        cache.get_or_fetch(tenant, &one, &policy).await.unwrap();

        // A second, unrelated document. The first entry is still live, so both
        // are held: the eviction drops what is dead, not what is merely old.
        cache.get_or_fetch(tenant, &two, &policy).await.unwrap();
        assert_eq!(
            cache.len_for_test().await,
            2,
            "a live entry is not evicted by another document's fetch"
        );

        // Move the first entry past its TTL but *inside* the stale window. It
        // is still servable, so it must survive.
        assert!(
            cache
                .backdate_for_test(tenant, &one_id, 601 + STALE_WINDOW_SECS / 2)
                .await
        );
        cache.get_or_fetch(tenant, &three, &policy).await.unwrap();
        assert_eq!(
            cache.len_for_test().await,
            3,
            "an entry inside the stale window can still be served and must not be evicted"
        );

        // Past the stale window: unservable by either branch, so gone.
        assert!(
            cache
                .backdate_for_test(tenant, &one_id, STALE_WINDOW_SECS)
                .await
        );
        cache.get_or_fetch(tenant, &four, &policy).await.unwrap();
        assert_eq!(
            cache.ttl_for_test(tenant, &one_id).await,
            None,
            "an entry past its TTL and its stale window is evicted on the next insert"
        );
        assert_eq!(
            cache.len_for_test().await,
            3,
            "and the map shrank rather than only losing a lookup"
        );
    }

    #[tokio::test]
    async fn the_cache_bounds_clamp_what_the_publisher_asks_for() {
        let server = MockServer::start().await;
        let id = format!("{}/mcp.json", server.uri());
        let tenant = Uuid::new_v4();
        let url = Url::parse(&id).unwrap();

        // Far too short → the tenant's floor.
        serve(&server, vscode_document(&id), Some("max-age=5")).await;
        let policy = CimdPolicy {
            min_cache_secs: 300,
            max_cache_secs: 1_000,
            ..loopback_policy(&server)
        };
        let cache = ClientMetadataCache::new();
        cache.get_or_fetch(tenant, &url, &policy).await.unwrap();
        assert_eq!(cache.ttl_for_test(tenant, &id).await, Some(300));

        // Far too long → the tenant's ceiling.
        server.reset().await;
        serve(&server, vscode_document(&id), Some("max-age=99999999")).await;
        let cache = ClientMetadataCache::new();
        cache.get_or_fetch(tenant, &url, &policy).await.unwrap();
        assert_eq!(cache.ttl_for_test(tenant, &id).await, Some(1_000));

        // Nothing advertised, and `no-store`, both land on the floor.
        for header in [None, Some("no-store"), Some("no-cache, must-revalidate")] {
            server.reset().await;
            serve(&server, vscode_document(&id), header).await;
            let cache = ClientMetadataCache::new();
            cache.get_or_fetch(tenant, &url, &policy).await.unwrap();
            assert_eq!(
                cache.ttl_for_test(tenant, &id).await,
                Some(300),
                "{header:?} must land on the floor"
            );
        }
    }

    #[tokio::test]
    async fn an_oversize_document_is_refused() {
        let server = MockServer::start().await;
        let id = format!("{}/mcp.json", server.uri());
        let mut doc = vscode_document(&id);
        doc["client_name"] = serde_json::json!("x".repeat(20_000));
        serve(&server, doc, None).await;

        let policy = CimdPolicy {
            max_metadata_bytes: 5_000,
            ..loopback_policy(&server)
        };
        let err = ClientMetadataCache::new()
            .get_or_fetch(Uuid::new_v4(), &Url::parse(&id).unwrap(), &policy)
            .await
            .expect_err("refused");
        assert!(matches!(err, CimdError::Fetch(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_document_served_as_html_is_refused() {
        let server = MockServer::start().await;
        let id = format!("{}/mcp.json", server.uri());
        Mock::given(method("GET"))
            .and(path("/mcp.json"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_string("<html><body>sign in</body></html>")
                    .insert_header("content-type", "text/html"),
            )
            .mount(&server)
            .await;

        let err = ClientMetadataCache::new()
            .get_or_fetch(
                Uuid::new_v4(),
                &Url::parse(&id).unwrap(),
                &loopback_policy(&server),
            )
            .await
            .expect_err("refused");
        assert!(matches!(err, CimdError::Malformed(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_publisher_error_is_refused() {
        let server = MockServer::start().await;
        let id = format!("{}/mcp.json", server.uri());
        Mock::given(method("GET"))
            .and(path("/mcp.json"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let err = ClientMetadataCache::new()
            .get_or_fetch(
                Uuid::new_v4(),
                &Url::parse(&id).unwrap(),
                &loopback_policy(&server),
            )
            .await
            .expect_err("refused");
        assert!(matches!(err, CimdError::Fetch(_)), "got {err:?}");
    }

    /// **The redirect the guard must not follow.** The publisher answers a
    /// 302 to a private address; `allow_private` is honoured only on the first
    /// hop, so the second is validated strictly and refused.
    #[tokio::test]
    async fn a_redirect_to_a_private_address_is_refused() {
        let server = MockServer::start().await;
        let id = format!("{}/mcp.json", server.uri());
        Mock::given(method("GET"))
            .and(path("/mcp.json"))
            .respond_with(
                ResponseTemplate::new(302)
                    .insert_header("location", "http://169.254.169.254/latest/meta-data/"),
            )
            .mount(&server)
            .await;

        let err = ClientMetadataCache::new()
            .get_or_fetch(
                Uuid::new_v4(),
                &Url::parse(&id).unwrap(),
                &loopback_policy(&server),
            )
            .await
            .expect_err("refused");
        assert!(matches!(err, CimdError::Fetch(_)), "got {err:?}");
    }

    #[tokio::test]
    async fn a_stale_document_is_served_while_the_publisher_is_down_and_then_expires() {
        let server = MockServer::start().await;
        let policy = loopback_policy(&server);
        let id = format!("{}/mcp.json", server.uri());
        serve(&server, vscode_document(&id), Some("max-age=300")).await;

        let cache = ClientMetadataCache::new();
        let tenant = Uuid::new_v4();
        let url = Url::parse(&id).unwrap();
        cache.get_or_fetch(tenant, &url, &policy).await.unwrap();

        // The publisher stops answering the document.
        server.reset().await;
        Mock::given(method("GET"))
            .and(path("/mcp.json"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        // Inside the stale window: the client keeps working.
        assert!(cache.backdate_for_test(tenant, &id, 400).await);
        assert!(cache.get_or_fetch(tenant, &url, &policy).await.is_ok());

        // Past it: the document is gone and so is the client.
        assert!(
            cache
                .backdate_for_test(tenant, &id, STALE_WINDOW_SECS + 10)
                .await
        );
        assert!(cache.get_or_fetch(tenant, &url, &policy).await.is_err());
    }

    #[tokio::test]
    async fn resolve_refuses_everything_when_the_tenant_has_cimd_off() {
        let server = MockServer::start().await;
        let id = format!("{}/mcp.json", server.uri());
        serve(&server, vscode_document(&id), None).await;

        let policy = oidc_policy(CimdPolicy {
            enabled: false,
            ..loopback_policy(&server)
        });
        let err = resolve(&ClientMetadataCache::new(), Uuid::new_v4(), &id, &policy)
            .await
            .expect_err("refused");
        assert_eq!(err, CimdError::Disabled);
        // I1: nothing was fetched.
        assert!(
            server
                .received_requests()
                .await
                .expect("recorded")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn resolve_admits_a_whole_document_end_to_end() {
        let server = MockServer::start().await;
        let id = format!("{}/mcp.json", server.uri());
        serve(&server, vscode_document(&id), None).await;

        let policy = oidc_policy(loopback_policy(&server));
        let tenant = Uuid::new_v4();
        let validated = resolve(&ClientMetadataCache::new(), tenant, &id, &policy)
            .await
            .expect("admitted");
        assert_eq!(validated.create.tenant_id, tenant);
        assert_eq!(validated.create.managed_by, ManagedBy::Cimd);
        assert_eq!(
            validated.create.redirect_uris,
            vec!["http://127.0.0.1/callback"]
        );
    }

    #[test]
    fn max_age_is_read_and_nothing_else_is() {
        assert_eq!(max_age_secs(Some("max-age=600")), Some(600));
        assert_eq!(
            max_age_secs(Some("public, max-age=42, immutable")),
            Some(42)
        );
        assert_eq!(max_age_secs(Some("no-store")), None);
        assert_eq!(max_age_secs(Some("s-maxage=99")), None);
        assert_eq!(max_age_secs(None), None);
    }

    #[test]
    fn json_content_types_are_recognised_and_others_are_not() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("application/client-metadata+json"));
        assert!(!is_json_content_type("text/html"));
        assert!(!is_json_content_type("text/plain; charset=utf-8"));
        assert!(!is_json_content_type(""));
    }
}

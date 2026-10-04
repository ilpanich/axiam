//! RFC 7591 dynamic client registration — the request, the policy and the
//! refusals (T21.4).
//!
//! `POST /oauth2/register` is the first endpoint in AXIAM that **writes** on
//! behalf of a caller holding no credential. Everything in this module exists
//! because of that sentence. The REST handler owns the transport, the audit
//! event, the quota and the rate limit; this module owns the question *may
//! this registration exist, and what exactly does it become*, and answers it
//! as a pure function of the request and the tenant's policy so that the
//! answer can be tested without a database.
//!
//! # What a self-registered client may not decide
//!
//! Four things, and each one is a decision the tenant took in advance:
//!
//! | The request may name | It is decided by |
//! | --- | --- |
//! | `redirect_uris` | the request, within `dcr_allowed_redirect_hosts` |
//! | `scope` | the request, within `dcr_allowed_scopes` |
//! | `grant_types` | the request, within `{authorization_code, refresh_token}` |
//! | `token_endpoint_auth_method` | the request, within four methods |
//! | **audiences** (`allowed_resources`) | **the tenant, always** (D3) |
//! | **profile** | **forced to `standard`** (I5) |
//! | **provenance** (`managed_by`) | **forced to `dcr`** (D5) |
//! | **consent** | **forced on** (D4) |
//!
//! The bottom four are not validated, they are *overwritten*: a request
//! naming them is not refused, its value is discarded and the tenant's is
//! used. That is deliberate. RFC 7591 §3.2.1 already contemplates a server
//! returning metadata different from what was requested — "the authorization
//! server MAY replace any of the client's requested metadata values" — and a
//! refusal would turn a field an MCP client sends by habit into a registration
//! failure, while silently ignoring it would be a lie. The response echoes
//! what was actually stored, so a client that cares can see what it got.
//!
//! D3 is the one that matters. `allowed_resources` is what decides which
//! audiences a token this client obtains may carry; a stranger who could name
//! it could mint tokens for any service the deployment fronts. The list comes
//! from `OidcPolicy::external_client_allowed_resources` and from nowhere else,
//! and the settings layer refuses to enable anonymous registration while that
//! list is empty — see `axiam_core::models::settings::validate_dcr_policy`.
//!
//! # RFC 7592 — what a registered client may later change (T23.4.1)
//!
//! A successful registration is also issued a **registration access token**:
//! 32 CSPRNG bytes, base64url without padding, returned once beside a
//! `registration_client_uri` of `{issuer}/oauth2/register/{client_id}`. Only
//! its SHA-256 is stored, on the client row. Presented as
//! `Authorization: Bearer`, it — and nothing else, not a user's token, not a
//! service account's, not the client secret — lets the client read, replace
//! and delete its own registration.
//!
//! A replacement is not a second, weaker registration. [`validate_update`]
//! runs the request through the same [`validate`] a registration runs, against
//! the tenant's policy **as it is now**, so a `PUT` cannot widen a scope, add a
//! grant, leave the host glob or name an audience that a `POST` could not; the
//! four things a request does not decide are overwritten exactly as they are
//! at registration; and the repository type it lands in
//! (`DcrRegistrationReplacement`) has no field for the profile, the X7 flags,
//! the provenance or the tenant. On success the token rotates: the old one dies
//! in the same statement that writes the new one.

use axiam_core::models::oauth2_client::{
    ClientAuthMethod, ClientProfile, CreateOAuth2Client, OAuth2Client,
};
use axiam_core::models::settings::{DynamicRegistrationMode, OidcPolicy};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The grants a self-registered client may hold.
///
/// The two halves of a browser-driven code flow and nothing else.
/// `client_credentials` and the RFC 8693 exchange are absent for the reason
/// `GRANTS_FORBIDDEN_TO_PUBLIC_CLIENTS` gives in the admin handler and one
/// more besides: both mint a token on the strength of the client's own
/// identity, and the identity of a self-registered client is a row a stranger
/// created. The device grant is absent because a device that cannot open a
/// browser cannot run a registration request either.
pub const DCR_GRANT_TYPES: [&str; 2] = ["authorization_code", "refresh_token"];

/// The client-authentication methods a registration may name.
///
/// The four RFC 7591 §2 lists that AXIAM implements and that make sense for a
/// client nobody vetted. The two mutual-TLS methods are absent: they name a
/// certificate the deployment's listener must already trust, so registering
/// one is a claim about the deployment's PKI rather than about the client, and
/// an open endpoint has no business making it.
pub const DCR_AUTH_METHODS: [ClientAuthMethod; 4] = [
    ClientAuthMethod::None,
    ClientAuthMethod::ClientSecretBasic,
    ClientAuthMethod::ClientSecretPost,
    ClientAuthMethod::PrivateKeyJwt,
];

/// The hosts a redirect URI may always use, whatever `dcr_allowed_redirect_hosts`
/// says.
///
/// Every desktop MCP client — Claude Code, VS Code, MCP Inspector — receives
/// its callback on the loopback interface under RFC 8252 §7.3, so a tenant
/// whose host glob excluded them would have enabled registration for nobody.
/// Allowing them adds no reach: a loopback URI is reachable only from the
/// machine the browser is running on, which is the machine the end user is
/// sitting at.
const ALWAYS_ALLOWED_REDIRECT_HOSTS: [&str; 3] = ["127.0.0.1", "[::1]", "localhost"];

/// An RFC 7591 §2 client metadata document, as a registration request.
///
/// Only the members AXIAM can act on are fields. RFC 7591 §2 says a server
/// "MUST ignore any metadata parameters it does not understand", which is what
/// `serde` does with the rest — `client_uri`, `logo_uri`, `contacts`,
/// `tos_uri`, `policy_uri` and the localised `client_name#xx` forms all arrive
/// from MCP Inspector and are dropped. `software_statement` is the one
/// unimplemented member that is **not** ignored: see
/// [`DcrError::UnsupportedSoftwareStatement`].
#[derive(Debug, Clone, Default, Deserialize, utoipa::ToSchema)]
pub struct RegistrationRequest {
    /// RFC 7591 §2 `redirect_uris`. Required here, because every grant this
    /// endpoint issues is browser-driven.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// RFC 7591 §2 `client_name`. Shown to the end user on the consent screen
    /// D4 forces, so a registration that omits it gets a generated one rather
    /// than an empty label.
    #[serde(default)]
    pub client_name: Option<String>,
    /// RFC 7591 §2 `grant_types`. Defaults to `["authorization_code"]`, as
    /// §2 specifies.
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    /// RFC 7591 §2 `response_types`. Defaults to `["code"]`, as §2 specifies,
    /// and `code` is the only value AXIAM implements.
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    /// RFC 7591 §2 `token_endpoint_auth_method`. Defaults to
    /// `client_secret_basic`, as §2 specifies — see
    /// [`resolve_auth_method`] for why the RFC's default is used here rather
    /// than AXIAM's own.
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
    /// RFC 7591 §2 `software_statement`. Refused rather than ignored.
    #[serde(default)]
    pub software_statement: Option<String>,
}

/// Why a registration was refused, with the RFC 7591 §3.2.2 code it is
/// answered with.
///
/// A type rather than a string so the handler cannot invent a code, and so the
/// tests can assert which refusal fired rather than matching prose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DcrError {
    /// The tenant's policy is `disabled`.
    ///
    /// RFC 7591 §3.2.2 defines no code for "this server does not do that", and
    /// inventing one would tell a caller something about the deployment. The
    /// plan's answer is `403` with an `invalid_request`-shaped body: the path
    /// exists and the feature does not, and the two are indistinguishable from
    /// outside.
    RegistrationDisabled,
    /// `initial_access_token` mode and no usable bearer was presented.
    ///
    /// One variant for "absent", "malformed", "expired", "already spent" and
    /// "another tenant's", because the response must not distinguish them: a
    /// caller probing handles would otherwise learn which of its guesses named
    /// a real token.
    InitialAccessTokenRequired,
    /// A `redirect_uris` entry is unusable or outside the tenant's host glob.
    InvalidRedirectUri(String),
    /// Any other metadata the server will not accept (RFC 7591 §3.2.2).
    InvalidClientMetadata(String),
    /// `software_statement` was present.
    ///
    /// Said plainly rather than ignored. A software statement is a *signed*
    /// assertion about the client, so a server that dropped it would be
    /// treating an unverified request as though it had been verified — the one
    /// failure mode the member exists to prevent. RFC 7591 §3.2.2 defines
    /// `invalid_software_statement` for exactly this.
    UnsupportedSoftwareStatement,
    /// The tenant already holds `dcr_max_clients` self-registered clients.
    ClientQuotaExhausted { limit: u32 },
    /// An RFC 7592 §2.2 update the server cannot read as an update: a member
    /// the client must not send, or a `client_id` that is absent or names
    /// another client. `invalid_request`, because none of the RFC 7591
    /// metadata codes describes it.
    InvalidRequest(String),
}

impl DcrError {
    /// The RFC 7591 §3.2.2 `error` code.
    pub const fn error_code(&self) -> &'static str {
        match self {
            // §3.2.2 lists three codes and none of them means "refused by
            // policy"; `invalid_request` is what the plan specifies and what
            // an OAuth client library will already understand.
            Self::RegistrationDisabled
            | Self::InitialAccessTokenRequired
            | Self::ClientQuotaExhausted { .. } => "invalid_request",
            Self::InvalidRequest(_) => "invalid_request",
            Self::InvalidRedirectUri(_) => "invalid_redirect_uri",
            Self::InvalidClientMetadata(_) => "invalid_client_metadata",
            Self::UnsupportedSoftwareStatement => "invalid_software_statement",
        }
    }

    /// The HTTP status the handler answers with.
    ///
    /// `403` for the three policy refusals and `400` for the metadata ones,
    /// which is the ordinary split: the first three say "not you, or not
    /// here", and the rest say "not like that".
    pub const fn http_status(&self) -> u16 {
        match self {
            Self::RegistrationDisabled
            | Self::InitialAccessTokenRequired
            | Self::ClientQuotaExhausted { .. } => 403,
            _ => 400,
        }
    }

    /// The `error_description`.
    pub fn description(&self) -> String {
        match self {
            Self::RegistrationDisabled => {
                "dynamic client registration is not enabled for this tenant".to_owned()
            }
            Self::InitialAccessTokenRequired => {
                "this tenant requires an initial access token: present one as \
                 `Authorization: Bearer <token>` (RFC 7591 section 1.2)"
                    .to_owned()
            }
            Self::InvalidRedirectUri(d)
            | Self::InvalidClientMetadata(d)
            | Self::InvalidRequest(d) => d.clone(),
            Self::UnsupportedSoftwareStatement => {
                "software_statement is not supported by this authorization server; send the \
                 metadata directly"
                    .to_owned()
            }
            Self::ClientQuotaExhausted { limit } => format!(
                "this tenant has reached its limit of {limit} dynamically registered clients"
            ),
        }
    }
}

impl std::fmt::Display for DcrError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error_code(), self.description())
    }
}

impl std::error::Error for DcrError {}

/// Whether `host` matches one glob `pattern`.
///
/// The grammar is deliberately tiny — a literal host, or `*` as the **whole**
/// leftmost label (`*.example.com`), or `*` alone — because a host allow-list
/// in front of a redirect is a security check, and a general-purpose glob in
/// front of a security check is a place for a subtle matching bug to become an
/// open redirect. In particular:
///
/// * `*.example.com` matches `mcp.example.com` and `a.b.example.com`. It does
///   **not** match `example.com` itself (the pattern says there is a label
///   there) and it does not match `evil-example.com` (the dot is part of the
///   pattern, so the match is on a label boundary rather than on a suffix).
///   That last case is the whole reason this is not `ends_with`.
/// * `*` matches anything, which is what a tenant that wants no host
///   restriction writes. It is spelled out as a value rather than implied by
///   an empty list, because an empty list means the opposite: no host is
///   allowed beyond the loopback three.
/// * A pattern with `*` anywhere else (`mcp*.example.com`, `*.*.com`) matches
///   nothing at all. Refusing to guess is the fail-closed direction, and the
///   settings page documents the two forms.
///
/// Comparison is ASCII-case-insensitive, matching the DNS rule and what
/// `url::Url` already does to a host it parsed.
pub fn host_glob_matches(pattern: &str, host: &str) -> bool {
    let pattern = pattern.trim();
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // The remainder must itself be a plain host: `*.*.com` is not a
        // pattern this grammar admits.
        if suffix.contains('*') || suffix.is_empty() {
            return false;
        }
        // `host` must end with `.suffix`, so the wildcard covers at least one
        // whole label and the comparison lands on a label boundary.
        return host.len() > suffix.len() + 1
            && host[host.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.';
    }
    if pattern.contains('*') {
        return false;
    }
    pattern.eq_ignore_ascii_case(host)
}

/// Whether a redirect URI's host is one this tenant admits.
pub fn redirect_host_is_allowed(policy_hosts: &[String], host: &str) -> bool {
    ALWAYS_ALLOWED_REDIRECT_HOSTS
        .iter()
        .any(|h| h.eq_ignore_ascii_case(host))
        || policy_hosts.iter().any(|p| host_glob_matches(p, host))
}

/// Resolve the requested `token_endpoint_auth_method`.
///
/// An absent value is `client_secret_basic`, which is **RFC 7591 §2's**
/// default rather than AXIAM's (`client_secret_post`). Two defaults in one
/// server needs a reason, and it is this: a client registering through RFC
/// 7591 and then reading RFC 7591 to decide how to authenticate will use the
/// RFC's default, so a server that quietly stored a different one would have
/// created a client that cannot authenticate the way it believes it can. The
/// admin API's default is untouched, so nothing existing changes (I1); the
/// response echoes the stored method, so a client that omitted the member can
/// see what it got.
fn resolve_auth_method(raw: Option<&str>) -> Result<ClientAuthMethod, DcrError> {
    let Some(raw) = raw.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(ClientAuthMethod::ClientSecretBasic);
    };
    let method = ClientAuthMethod::from_wire(raw).filter(|m| DCR_AUTH_METHODS.contains(m));
    method.ok_or_else(|| {
        DcrError::InvalidClientMetadata(format!(
            "token_endpoint_auth_method {raw:?} is not one this endpoint issues (allowed: {})",
            DCR_AUTH_METHODS
                .iter()
                .map(|m| m.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })
}

/// A registration that passed every check, ready to be written.
///
/// Carries the `CreateOAuth2Client` the repository takes and the scopes as
/// resolved, so the handler echoes what will be stored rather than what was
/// asked for.
#[derive(Debug, Clone)]
pub struct ValidatedRegistration {
    /// The row to create. Its `managed_by`, `profile` and `allowed_resources`
    /// are the server's, not the request's.
    pub create: CreateOAuth2Client,
}

/// Validate a registration against a tenant's policy (RFC 7591 §3.1).
///
/// Pure: no clock, no database, no randomness. The caller has already decided
/// that the tenant's mode permits this request at all (and, in
/// `initial_access_token` mode, has already spent the token), because both of
/// those need state this module deliberately does not have.
///
/// # Order of refusals
///
/// Structural before policy, and the cheapest structural check first. A
/// registration with three problems should hear about the one that is most
/// obviously the client's own — a `software_statement` it should not have
/// sent, a grant type this server does not issue — before it hears about a
/// tenant allow-list, which is an operator's decision the client cannot act
/// on.
pub fn validate(
    tenant_id: Uuid,
    req: &RegistrationRequest,
    policy: &OidcPolicy,
) -> Result<ValidatedRegistration, DcrError> {
    // RFC 7591 §2's one unimplemented member, said plainly. First, because a
    // request carrying one is asking for a guarantee nothing below provides.
    if req
        .software_statement
        .as_deref()
        .is_some_and(|s| !s.trim().is_empty())
    {
        return Err(DcrError::UnsupportedSoftwareStatement);
    }

    // `response_types` defaults to `["code"]` (RFC 7591 §2), which is the only
    // value AXIAM implements — `authorize` refuses everything else, so
    // accepting another here would create a client that fails its first
    // request.
    if let Some(types) = &req.response_types
        && let Some(bad) = types.iter().find(|t| t.trim() != "code")
    {
        return Err(DcrError::InvalidClientMetadata(format!(
            "response_type {bad:?} is not supported; this server issues authorization codes only"
        )));
    }

    let grant_types: Vec<String> = match &req.grant_types {
        // RFC 7591 §2: absent means `["authorization_code"]`.
        None => vec!["authorization_code".to_owned()],
        Some(requested) => {
            if requested.is_empty() {
                return Err(DcrError::InvalidClientMetadata(
                    "grant_types must not be empty".into(),
                ));
            }
            for g in requested {
                if !DCR_GRANT_TYPES.contains(&g.trim()) {
                    return Err(DcrError::InvalidClientMetadata(format!(
                        "grant_type {g:?} is not one this endpoint issues (allowed: {})",
                        DCR_GRANT_TYPES.join(", ")
                    )));
                }
            }
            // `refresh_token` alone is a client that can refresh a token it can
            // never obtain. Refused rather than silently topped up with
            // `authorization_code`, because adding a grant nobody asked for is
            // how a registration ends up more capable than its request.
            if !requested.iter().any(|g| g.trim() == "authorization_code") {
                return Err(DcrError::InvalidClientMetadata(
                    "grant_types must include authorization_code: refresh_token alone would \
                     register a client that can refresh a token it cannot obtain"
                        .into(),
                ));
            }
            requested.iter().map(|g| g.trim().to_owned()).collect()
        }
    };

    let token_endpoint_auth_method =
        resolve_auth_method(req.token_endpoint_auth_method.as_deref())?;

    // --- redirect URIs ------------------------------------------------------
    //
    // Structure is the caller's to check with the same `validate_redirect_uris`
    // the admin API uses — one rule, one place. What is left here is the
    // tenant's host allow-list, which the admin API has no equivalent of
    // because an administrator registering a URI has already decided it is
    // acceptable.
    if req.redirect_uris.is_empty() {
        return Err(DcrError::InvalidRedirectUri(
            "redirect_uris must name at least one URI: every grant this endpoint issues is \
             completed through a browser redirect"
                .into(),
        ));
    }
    for uri in &req.redirect_uris {
        let parsed: url::Url = uri
            .parse()
            .map_err(|_| DcrError::InvalidRedirectUri(format!("{uri:?} is not a valid URI")))?;
        let host = parsed.host_str().ok_or_else(|| {
            DcrError::InvalidRedirectUri(format!("{uri:?} has no host component"))
        })?;
        if !redirect_host_is_allowed(&policy.dcr_allowed_redirect_hosts, host) {
            return Err(DcrError::InvalidRedirectUri(format!(
                "the host {host:?} is not one this tenant accepts a self-registered redirect \
                 for; an administrator sets dcr_allowed_redirect_hosts"
            )));
        }
    }

    // --- scopes -------------------------------------------------------------
    //
    // RFC 7591 §2 makes `scope` a space-delimited string, not an array. An
    // absent one registers no scopes at all rather than the tenant's whole
    // list: a client gets what it asked for, and a client that asked for
    // nothing is not handed everything.
    let scopes: Vec<String> = req
        .scope
        .as_deref()
        .unwrap_or("")
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    for scope in &scopes {
        if !policy.dcr_allowed_scopes.iter().any(|s| s == scope) {
            return Err(DcrError::InvalidClientMetadata(format!(
                "scope {scope:?} is not one this tenant offers to self-registered clients; an \
                 administrator sets dcr_allowed_scopes"
            )));
        }
    }

    // --- the four the request does not decide -------------------------------
    let name = req
        .client_name
        .as_deref()
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .map_or_else(|| "Dynamically registered client".to_owned(), str::to_owned);

    Ok(ValidatedRegistration {
        create: CreateOAuth2Client {
            tenant_id,
            name,
            redirect_uris: req.redirect_uris.clone(),
            grant_types,
            scopes,
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            // I5 — forced, never read from the request. `fapi::validate_registration`
            // refuses the combination anyway (a `dcr` row may carry no FAPI
            // profile at all), so this is the first of two gates rather than
            // the only one.
            profile: ClientProfile::Standard,
            token_endpoint_auth_method,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: Vec::new(),
            tls_client_certificate_bound_access_tokens: false,
            // RFC 7591 §2's key sources, carried through for
            // `private_key_jwt`. `fapi::validate_registration` enforces the
            // "exactly one" rule (`fapi.rs`'s `JwksSourceCount`) and refuses a
            // non-https `jwks_uri`, which is also the SSRF guard: the URL is
            // fetched later, by the same cache a federated IdP's JWKS goes
            // through.
            jwks: req.jwks.as_ref().map(ToString::to_string),
            jwks_uri: req.jwks_uri.clone(),
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: axiam_core::models::oauth2_client::AuthnRequestParamsMode::Ignore,
            browser_sso: false,
            // D3 — the tenant's list, verbatim. The single most important line
            // in this module: it is what stops a party that registered itself
            // from naming the audience of the tokens it will obtain.
            allowed_resources: policy.external_client_allowed_resources.clone(),
            // D5 — forced. A request cannot claim to be an administrator's
            // client, because this value is built here rather than echoed.
            managed_by: axiam_core::models::oauth2_client::ManagedBy::Dcr,
        },
    })
}

/// What the tenant's mode demands of a caller, before any metadata is looked
/// at.
///
/// Separated from [`validate`] because the answer needs the request's
/// `Authorization` header and, in one case, a database write — neither of
/// which belongs in a pure validator. The handler asks this first, so a tenant
/// with registration off never reaches the metadata rules at all and cannot be
/// probed for what they are.
pub const fn gate(mode: DynamicRegistrationMode, bearer_present: bool) -> Result<(), DcrError> {
    match mode {
        DynamicRegistrationMode::Disabled => Err(DcrError::RegistrationDisabled),
        DynamicRegistrationMode::InitialAccessToken if !bearer_present => {
            Err(DcrError::InitialAccessTokenRequired)
        }
        _ => Ok(()),
    }
}

/// An RFC 7591 §3.2.1 registration response, which is also RFC 7592 §3's
/// client information response.
///
/// One shape for all three answers — the `201` of a registration, the `200`
/// of a read and the `200` of a replacement — because RFC 7592 §3 defines the
/// client information response as the RFC 7591 one plus two members, and a
/// client that round-trips what it read must find the members it was given.
/// What differs between the three is which of the two secrets is present:
///
/// | | `client_secret` | `registration_access_token` |
/// |---|---|---|
/// | `POST /oauth2/register` (201) | once, if issued | **once** |
/// | `GET  …/register/{client_id}` | never | never |
/// | `PUT  …/register/{client_id}` | never | **once** (the rotated one) |
///
/// A read never returns the token. Only its digest is stored, so it could not
/// be returned if we wanted to; and the plan rotates on update only, so a read
/// has no new one to hand out (RFC 7592 §2.1 permits rotation on read; AXIAM
/// does not do it). The secret is never returned after the registration for
/// the same reason: the row holds a keyed hash.
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
pub struct RegistrationResponse {
    /// The issued `client_id`.
    pub client_id: String,
    /// The issued secret, shown exactly once.
    ///
    /// Absent for a `none` registration, which is every MCP desktop client:
    /// a public client is created with no secret at all, and sending `""`
    /// would read as a secret that happens to be empty.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// RFC 7591 §3.2.1 — when the `client_id` was issued, as a Unix timestamp.
    pub client_id_issued_at: i64,
    /// RFC 7591 §3.2.1 — `0` means the secret does not expire.
    ///
    /// Present only when a secret was issued, as §3.2.1 requires ("REQUIRED if
    /// `client_secret` is issued"). AXIAM does not expire client secrets, so
    /// the value is always `0`; a client that read a non-zero value here and
    /// planned a rotation around it would be planning around a promise this
    /// server does not make.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret_expires_at: Option<i64>,
    /// The stored client name.
    pub client_name: String,
    /// The stored redirect URIs.
    pub redirect_uris: Vec<String>,
    /// The stored grant types.
    pub grant_types: Vec<String>,
    /// `["code"]`, always.
    pub response_types: Vec<String>,
    /// The stored authentication method.
    pub token_endpoint_auth_method: String,
    /// The stored scopes, space-delimited (RFC 7591 §2's encoding).
    pub scope: String,
    /// RFC 7591 §2 `jwks`, as stored, for a `private_key_jwt` client.
    ///
    /// Echoed so that an RFC 7592 §2.2 replacement — which is a full
    /// replacement, and treats an omitted member as a request to delete it —
    /// can be built from a read without silently dropping the client's keys.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<serde_json::Value>,
    /// RFC 7591 §2 `jwks_uri`, as stored. Echoed for the reason `jwks` is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// RFC 7592 §3 `registration_client_uri`: where this client reads,
    /// replaces and deletes its registration.
    ///
    /// `{issuer}/oauth2/register/{client_id}`, built from the issuer the
    /// request arrived under (see [`registration_client_uri`]).
    pub registration_client_uri: String,
    /// RFC 7592 §3 `registration_access_token`. **Sensitive**: a bearer
    /// credential for this registration. Present on the registration and on a
    /// replacement (the rotated value), each exactly once; absent on a read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registration_access_token: Option<String>,
}

/// Mint an RFC 7592 registration access token: `(plaintext, digest)`.
///
/// 32 bytes from the operating system's CSPRNG, base64url without padding —
/// `axiam_auth::token::generate_refresh_token`'s generator, called afresh, so
/// the bytes are this credential's own and shared with nothing. The digest is
/// `hash_refresh_token`'s SHA-256, the one refresh tokens and RFC 7591 initial
/// access tokens are stored under. 256 bits of entropy is why an unsalted,
/// unkeyed digest is enough: there is no dictionary to precompute against.
///
/// No prefix, unlike the initial access token's `axiam_dcr_`: the plan fixes
/// the encoding as the bare 43 characters, and an SDK is told to treat the
/// value as opaque either way.
#[must_use]
pub fn mint_registration_access_token() -> (String, String) {
    let raw = axiam_auth::token::generate_refresh_token();
    let digest = axiam_auth::token::hash_refresh_token(&raw);
    (raw, digest)
}

/// The digest a presented registration access token is looked up under.
#[must_use]
pub fn registration_access_token_digest(presented: &str) -> String {
    axiam_auth::token::hash_refresh_token(presented)
}

/// RFC 7592 §3 `registration_client_uri` for a client.
///
/// `issuer` is the issuer the registration request arrived under:
/// `{root}/t/{tenant_id}` on a T21.6 tenant path, whose URL needs nothing
/// else, or `{root}`, whose URL must carry the tenant the way every other
/// endpoint on that form does — as `?tenant_id=`, which is what
/// `tenant_query` is for (`None` on a tenant path). RFC 7592 §3 asks for "the
/// fully qualified URL of the client configuration endpoint", and RFC 6749 §3
/// permits an endpoint URL a query component; a client uses the value as
/// given rather than rebuilding it.
///
/// `client_id` is placed in the path as is. Only a `dcr` client is ever given
/// this URI, and its identifier is `oa_` plus 32 hex digits, minted here —
/// nothing a caller chose, and nothing that needs escaping.
#[must_use]
pub fn registration_client_uri(
    issuer: &str,
    client_id: &str,
    tenant_query: Option<Uuid>,
) -> String {
    let base = format!(
        "{}/oauth2/register/{client_id}",
        issuer.trim_end_matches('/')
    );
    match tenant_query {
        Some(tenant_id) => format!("{base}?tenant_id={tenant_id}"),
        None => base,
    }
}

/// The client information response for a stored client (RFC 7592 §3).
///
/// `client_secret` is `Some` only on the registration that minted it, and
/// `registration_access_token` only on a registration or a replacement; see
/// [`RegistrationResponse`] for the table.
#[must_use]
pub fn client_information(
    client: &OAuth2Client,
    registration_client_uri: String,
    client_secret: Option<String>,
    registration_access_token: Option<String>,
) -> RegistrationResponse {
    let is_public = client.token_endpoint_auth_method.is_public();
    RegistrationResponse {
        client_id: client.client_id.clone(),
        // A public client has no secret to show — none was minted. Omitted
        // rather than `""`, which an MCP client would read as a secret that
        // happens to be empty.
        client_secret: client_secret.filter(|_| !is_public),
        client_id_issued_at: client.created_at.timestamp(),
        // RFC 7591 §3.2.1: REQUIRED if a secret was issued, and `0` means it
        // does not expire. Present on every answer about a confidential
        // client, because the secret exists whether or not this response
        // carries it.
        client_secret_expires_at: (!is_public).then_some(0),
        client_name: client.name.clone(),
        redirect_uris: client.redirect_uris.clone(),
        grant_types: client.grant_types.clone(),
        response_types: vec!["code".to_owned()],
        token_endpoint_auth_method: client.token_endpoint_auth_method.as_str().to_owned(),
        scope: client.scopes.join(" "),
        // Stored as the raw document; a value that no longer parses is
        // omitted rather than echoed as a string the client did not send.
        jwks: client
            .jwks
            .as_deref()
            .and_then(|j| serde_json::from_str(j).ok()),
        jwks_uri: client.jwks_uri.clone(),
        registration_client_uri,
        registration_access_token,
    }
}

/// The members RFC 7592 §2.2 says an update request MUST NOT include.
///
/// All four are the server's to state: two describe the configuration
/// endpoint itself and two describe when the server issued something. A
/// request carrying one is refused rather than ignored — §2.2 states the
/// prohibition as a MUST NOT on the client, and a client that round-trips a
/// read verbatim has sent the token in a request body, which is the leak the
/// rule exists to prevent. Refusing teaches it; ignoring would let it keep
/// doing it.
pub const RFC7592_SERVER_MEMBERS: [&str; 4] = [
    "registration_access_token",
    "registration_client_uri",
    "client_secret_expires_at",
    "client_id_issued_at",
];

/// Validate an RFC 7592 §2.2 replacement of a stored `dcr` client.
///
/// Pure, like [`validate`], which it ends by calling: the replacement is held
/// to exactly the rules a registration is, under the tenant's policy as it is
/// **now** — so a scope the tenant has since withdrawn cannot be kept by
/// re-sending it, and the audiences are the tenant's current list.
///
/// What it adds before that:
///
/// 1. The body is a JSON object, and none of [`RFC7592_SERVER_MEMBERS`] is in
///    it (`invalid_request`).
/// 2. `client_id` is present and equals the path's (`invalid_request`) —
///    §2.2's "MUST be the same as its currently issued client identifier".
/// 3. After validation, the authentication method is the stored one
///    (`invalid_client_metadata`). A change of method is a change of
///    credential — `none` to `client_secret_basic` would name a secret the
///    row does not hold, and the reverse would leave one behind — and §2.2
///    forbids a client choosing its own secret. Register a new client
///    instead. Note what full replacement means here: an **omitted** method
///    is RFC 7591 §2's default, `client_secret_basic`, so a public client must
///    send `none` back.
///
/// `client_secret`, if present, must match the stored secret; that check
/// needs the keyed hasher and is the handler's.
pub fn validate_update(
    tenant_id: Uuid,
    path_client_id: &str,
    body: &serde_json::Value,
    stored: &OAuth2Client,
    policy: &OidcPolicy,
) -> Result<ValidatedRegistration, DcrError> {
    let Some(object) = body.as_object() else {
        return Err(DcrError::InvalidRequest(
            "the client metadata must be a JSON object".into(),
        ));
    };
    if let Some(member) = RFC7592_SERVER_MEMBERS
        .iter()
        .find(|m| object.contains_key(**m))
    {
        return Err(DcrError::InvalidRequest(format!(
            "{member} must not be sent in an update: it is the server's to state (RFC 7592 \
             section 2.2)"
        )));
    }
    match object.get("client_id") {
        Some(serde_json::Value::String(c)) if c == path_client_id => {}
        _ => {
            return Err(DcrError::InvalidRequest(
                "client_id must be present and equal to the client being updated (RFC 7592 \
                 section 2.2)"
                    .into(),
            ));
        }
    }
    // A fixed message rather than serde's, which can quote the input.
    let req: RegistrationRequest = serde_json::from_value(body.clone()).map_err(|_| {
        DcrError::InvalidClientMetadata(
            "the client metadata could not be read as RFC 7591 section 2 metadata".into(),
        )
    })?;
    let validated = validate(tenant_id, &req, policy)?;
    if validated.create.token_endpoint_auth_method != stored.token_endpoint_auth_method {
        return Err(DcrError::InvalidClientMetadata(format!(
            "token_endpoint_auth_method cannot be changed from {} through the client \
             configuration endpoint; register a new client instead",
            stored.token_endpoint_auth_method.as_str()
        )));
    }
    Ok(validated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axiam_core::models::settings::system_defaults;

    fn policy(mutate: impl FnOnce(&mut OidcPolicy)) -> OidcPolicy {
        let d = system_defaults();
        let mut p = OidcPolicy {
            sensitive_scopes_enabled: d.sensitive_scopes_enabled,
            default_locale: d.default_locale,
            dynamic_registration: DynamicRegistrationMode::Anonymous,
            dcr_allowed_scopes: vec!["openid".into(), "profile".into()],
            dcr_allowed_redirect_hosts: Vec::new(),
            external_client_allowed_resources: vec!["https://mcp.example.com/mcp".into()],
            cimd: d.cimd.clone(),
            dcr_max_clients: d.dcr_max_clients,
            dcr_unused_client_ttl_days: d.dcr_unused_client_ttl_days,
            saml_idp_enabled: d.saml_idp_enabled,
            ssf_enabled: d.ssf_enabled,
        };
        mutate(&mut p);
        p
    }

    /// The request MCP Inspector actually sends, reduced to the members that
    /// reach a decision.
    fn inspector_request() -> RegistrationRequest {
        RegistrationRequest {
            redirect_uris: vec!["http://127.0.0.1:6274/oauth/callback".into()],
            client_name: Some("MCP Inspector".into()),
            grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
            response_types: Some(vec!["code".into()]),
            token_endpoint_auth_method: Some("none".into()),
            scope: Some("openid profile".into()),
            ..RegistrationRequest::default()
        }
    }

    // -----------------------------------------------------------------------
    // The mode gate
    // -----------------------------------------------------------------------

    /// I1, as a unit test: the default policy refuses, and refuses the same
    /// way whether or not a bearer was presented, so the endpoint is not an
    /// oracle for which mode a tenant is in.
    #[test]
    fn a_disabled_tenant_refuses_whatever_the_caller_presents() {
        for bearer in [true, false] {
            assert_eq!(
                gate(DynamicRegistrationMode::Disabled, bearer),
                Err(DcrError::RegistrationDisabled)
            );
        }
    }

    #[test]
    fn initial_access_token_mode_needs_a_bearer_and_anonymous_does_not() {
        assert_eq!(
            gate(DynamicRegistrationMode::InitialAccessToken, false),
            Err(DcrError::InitialAccessTokenRequired)
        );
        assert!(gate(DynamicRegistrationMode::InitialAccessToken, true).is_ok());
        assert!(gate(DynamicRegistrationMode::Anonymous, false).is_ok());
        // A bearer on an anonymous tenant is ignored rather than refused: RFC
        // 7591 §1.2 does not forbid one, and a client that habitually sends
        // an `Authorization` header should not be told its registration is
        // malformed because of it.
        assert!(gate(DynamicRegistrationMode::Anonymous, true).is_ok());
    }

    // -----------------------------------------------------------------------
    // The host glob — a security check, so its edges are the tests
    // -----------------------------------------------------------------------

    /// The case this grammar exists for. `ends_with` would admit every one of
    /// the four refusals below.
    #[test]
    fn a_wildcard_label_matches_on_a_label_boundary_and_never_on_a_suffix() {
        assert!(host_glob_matches("*.example.com", "mcp.example.com"));
        assert!(host_glob_matches("*.example.com", "a.b.example.com"));
        assert!(host_glob_matches("*.example.com", "MCP.EXAMPLE.COM"));

        for host in [
            // The pattern says there is a label there.
            "example.com",
            // The dot is part of the pattern, so this is not a match.
            "evil-example.com",
            "notexample.com",
            // A different registrable domain that merely ends the same way.
            "example.com.attacker.test",
        ] {
            assert!(
                !host_glob_matches("*.example.com", host),
                "{host} must not match *.example.com"
            );
        }
    }

    #[test]
    fn a_literal_pattern_matches_itself_and_a_star_matches_everything() {
        assert!(host_glob_matches("mcp.example.com", "mcp.example.com"));
        assert!(!host_glob_matches("mcp.example.com", "other.example.com"));
        assert!(host_glob_matches("*", "anything.at.all"));
    }

    /// Anything outside the two admitted forms matches nothing. Refusing to
    /// guess is the fail-closed direction: an operator who wrote
    /// `mcp*.example.com` gets a registration refused and reads the
    /// documentation, rather than a pattern that means something they did not
    /// intend.
    #[test]
    fn a_pattern_this_grammar_does_not_admit_matches_nothing() {
        for pattern in ["mcp*.example.com", "*.*.com", "*.", "**", "*mcp"] {
            assert!(
                !host_glob_matches(pattern, "mcp.example.com"),
                "{pattern} must match nothing"
            );
        }
    }

    /// The loopback three are allowed whatever the tenant wrote, including
    /// when it wrote nothing — which is the default, and the state every MCP
    /// desktop client registers under.
    #[test]
    fn the_loopback_hosts_are_always_allowed() {
        for host in ["127.0.0.1", "[::1]", "localhost"] {
            assert!(redirect_host_is_allowed(&[], host), "{host}");
        }
        assert!(!redirect_host_is_allowed(&[], "mcp.example.com"));
        assert!(redirect_host_is_allowed(
            &["*.example.com".to_string()],
            "mcp.example.com"
        ));
    }

    // -----------------------------------------------------------------------
    // Validation
    // -----------------------------------------------------------------------

    /// The happy path, and the four values the request did not get to decide.
    #[test]
    fn an_mcp_inspector_registration_is_accepted_and_the_server_decides_four_things() {
        let tenant = Uuid::new_v4();
        let out = validate(tenant, &inspector_request(), &policy(|_| {})).unwrap();
        let c = out.create;

        assert_eq!(c.tenant_id, tenant);
        assert_eq!(c.token_endpoint_auth_method, ClientAuthMethod::None);
        assert_eq!(c.scopes, vec!["openid".to_string(), "profile".to_string()]);

        // D3 — the audiences are the tenant's, not the request's.
        assert_eq!(c.allowed_resources, vec!["https://mcp.example.com/mcp"]);
        // D5 — the provenance is forced.
        assert_eq!(
            c.managed_by,
            axiam_core::models::oauth2_client::ManagedBy::Dcr
        );
        // I5 — the profile is forced.
        assert_eq!(c.profile, ClientProfile::Standard);
        // Nothing sender-constraining and no PAR requirement was invented on
        // the client's behalf.
        assert!(!c.require_par);
        assert!(!c.dpop_bound_access_tokens);
    }

    /// X7.1 (T23.1.1 audit): the two Basic-OP switches are the server's to
    /// set, and it sets both to the stricter default for every self-registered
    /// client — however the request spells a wish for the honour lane or the
    /// login hop. `RegistrationRequest` has no member for either, so serde
    /// drops them; this pins that nobody adds one that is read.
    #[test]
    fn a_registration_cannot_opt_itself_into_the_honour_lane_or_the_login_hop() {
        let req: RegistrationRequest = serde_json::from_value(serde_json::json!({
            "redirect_uris": ["http://127.0.0.1:6274/oauth/callback"],
            "token_endpoint_auth_method": "none",
            "scope": "openid",
            "authn_request_params": "honour",
            "browser_sso": true,
            "profile": "fapi2",
        }))
        .expect("unknown RFC 7591 members are ignored, not refused");
        let c = validate(Uuid::new_v4(), &req, &policy(|_| {}))
            .unwrap()
            .create;
        assert_eq!(
            c.authn_request_params,
            axiam_core::models::oauth2_client::AuthnRequestParamsMode::Ignore
        );
        assert!(!c.browser_sso);
        assert_eq!(c.profile, ClientProfile::Standard);
    }

    /// D3 again, stated as the property rather than as one value: whatever the
    /// request says about resources, the stored list is the tenant's. The
    /// request type has no such member, so this test is really asserting that
    /// nobody adds one.
    #[test]
    fn allowed_resources_come_from_the_tenant_and_only_from_the_tenant() {
        let p = policy(|p| {
            p.external_client_allowed_resources = vec![
                "https://a.example.com".into(),
                "https://b.example.com".into(),
            ];
        });
        let out = validate(Uuid::new_v4(), &inspector_request(), &p).unwrap();
        assert_eq!(
            out.create.allowed_resources,
            p.external_client_allowed_resources
        );
    }

    #[test]
    fn a_software_statement_is_refused_rather_than_ignored() {
        let mut req = inspector_request();
        req.software_statement = Some("eyJhbGciOiJSUzI1NiJ9.e30.sig".into());
        let err = validate(Uuid::new_v4(), &req, &policy(|_| {})).unwrap_err();
        assert_eq!(err, DcrError::UnsupportedSoftwareStatement);
        assert_eq!(err.error_code(), "invalid_software_statement");
    }

    #[test]
    fn only_the_two_code_grants_are_issued() {
        for bad in [
            "client_credentials",
            "urn:ietf:params:oauth:grant-type:token-exchange",
            "urn:ietf:params:oauth:grant-type:device_code",
            "implicit",
        ] {
            let mut req = inspector_request();
            req.grant_types = Some(vec!["authorization_code".into(), bad.into()]);
            let err = validate(Uuid::new_v4(), &req, &policy(|_| {})).unwrap_err();
            assert_eq!(err.error_code(), "invalid_client_metadata", "{bad}");
        }
    }

    #[test]
    fn refresh_token_alone_is_refused_rather_than_topped_up() {
        let mut req = inspector_request();
        req.grant_types = Some(vec!["refresh_token".into()]);
        assert_eq!(
            validate(Uuid::new_v4(), &req, &policy(|_| {}))
                .unwrap_err()
                .error_code(),
            "invalid_client_metadata"
        );
    }

    /// RFC 7591 §2's defaults, applied rather than invented.
    #[test]
    fn the_rfc_defaults_are_what_an_omitted_member_gets() {
        let req = RegistrationRequest {
            redirect_uris: vec!["http://localhost/cb".into()],
            ..RegistrationRequest::default()
        };
        let out = validate(Uuid::new_v4(), &req, &policy(|_| {})).unwrap();
        assert_eq!(out.create.grant_types, vec!["authorization_code"]);
        assert_eq!(
            out.create.token_endpoint_auth_method,
            ClientAuthMethod::ClientSecretBasic,
            "RFC 7591 section 2 makes client_secret_basic the default, and a client that \
             omitted the member will be reading the same sentence"
        );
        // A client that asked for no scope gets none, rather than the tenant's
        // whole list.
        assert!(out.create.scopes.is_empty());
    }

    #[test]
    fn the_two_mtls_methods_and_anything_unknown_are_refused() {
        for bad in [
            "tls_client_auth",
            "self_signed_tls_client_auth",
            "client_secret_jwt",
            "nonsense",
        ] {
            let mut req = inspector_request();
            req.token_endpoint_auth_method = Some(bad.into());
            assert_eq!(
                validate(Uuid::new_v4(), &req, &policy(|_| {}))
                    .unwrap_err()
                    .error_code(),
                "invalid_client_metadata",
                "{bad}"
            );
        }
    }

    #[test]
    fn a_scope_outside_the_tenants_list_is_refused() {
        let mut req = inspector_request();
        req.scope = Some("openid admin".into());
        assert_eq!(
            validate(Uuid::new_v4(), &req, &policy(|_| {}))
                .unwrap_err()
                .error_code(),
            "invalid_client_metadata"
        );
    }

    #[test]
    fn a_redirect_host_outside_the_glob_is_refused() {
        let mut req = inspector_request();
        req.redirect_uris = vec!["https://mcp.example.com/cb".into()];
        // Default policy: no hosts beyond the loopback three.
        let err = validate(Uuid::new_v4(), &req, &policy(|_| {})).unwrap_err();
        assert_eq!(err.error_code(), "invalid_redirect_uri");

        // With the glob, the same request is accepted.
        let p = policy(|p| p.dcr_allowed_redirect_hosts = vec!["*.example.com".into()]);
        assert!(validate(Uuid::new_v4(), &req, &p).is_ok());
    }

    #[test]
    fn an_empty_or_unparseable_redirect_list_is_refused() {
        let mut req = inspector_request();
        req.redirect_uris = Vec::new();
        assert_eq!(
            validate(Uuid::new_v4(), &req, &policy(|_| {}))
                .unwrap_err()
                .error_code(),
            "invalid_redirect_uri"
        );

        req.redirect_uris = vec!["/relative/callback".into()];
        assert_eq!(
            validate(Uuid::new_v4(), &req, &policy(|_| {}))
                .unwrap_err()
                .error_code(),
            "invalid_redirect_uri"
        );
    }

    /// The two response shapes, checked where the RFC is fussy: `403` for a
    /// policy refusal and `400` for a metadata one, and every code one RFC
    /// 7591 §3.2.2 actually defines.
    #[test]
    fn every_refusal_carries_a_code_and_a_status_the_rfc_recognises() {
        for (err, code, status) in [
            (DcrError::RegistrationDisabled, "invalid_request", 403),
            (DcrError::InitialAccessTokenRequired, "invalid_request", 403),
            (
                DcrError::ClientQuotaExhausted { limit: 20 },
                "invalid_request",
                403,
            ),
            (
                DcrError::InvalidRedirectUri("x".into()),
                "invalid_redirect_uri",
                400,
            ),
            (
                DcrError::InvalidClientMetadata("x".into()),
                "invalid_client_metadata",
                400,
            ),
            (
                DcrError::UnsupportedSoftwareStatement,
                "invalid_software_statement",
                400,
            ),
            (DcrError::InvalidRequest("x".into()), "invalid_request", 400),
        ] {
            assert_eq!(err.error_code(), code);
            assert_eq!(err.http_status(), status);
            assert!(!err.description().is_empty());
        }
    }

    /// The two scopes W7 gates cannot reach a self-registered client, because
    /// the settings layer refuses to put them in `dcr_allowed_scopes` — and
    /// this crate's copy of that list is the one the refusal is written
    /// against. Asserted here so the two cannot drift: `axiam-core` is layer 0
    /// and cannot import `SENSITIVE_SCOPES`, so it spells the two names out.
    #[test]
    fn the_sensitive_scope_list_core_refuses_is_the_one_this_crate_defines() {
        for scope in crate::sensitive::SENSITIVE_SCOPES {
            assert_eq!(
                axiam_core::models::settings::sensitive_scope_in_dcr_list(&[scope.to_string()]),
                Some(scope),
                "axiam-core's dcr_allowed_scopes refusal must name every sensitive scope"
            );
        }
    }

    // -----------------------------------------------------------------------
    // RFC 7592 (T23.4.1)
    // -----------------------------------------------------------------------

    /// The row a registration of `req` would have stored.
    fn stored(req: &RegistrationRequest) -> OAuth2Client {
        let c = validate(Uuid::new_v4(), req, &policy(|_| {}))
            .unwrap()
            .create;
        OAuth2Client {
            id: Uuid::new_v4(),
            tenant_id: c.tenant_id,
            client_id: "oa_00112233445566778899aabbccddeeff".into(),
            client_secret_hash: String::new(),
            name: c.name,
            redirect_uris: c.redirect_uris,
            grant_types: c.grant_types,
            scopes: c.scopes,
            post_logout_redirect_uris: Vec::new(),
            backchannel_logout_uri: None,
            require_par: false,
            profile: c.profile,
            token_endpoint_auth_method: c.token_endpoint_auth_method,
            tls_client_auth_subject_dn: None,
            tls_client_auth_san_dns: None,
            tls_client_auth_san_uri: None,
            self_signed_tls_client_auth_thumbprints: Vec::new(),
            tls_client_certificate_bound_access_tokens: false,
            jwks: None,
            jwks_uri: None,
            dpop_bound_access_tokens: false,
            dpop_require_nonce: false,
            authn_request_params: c.authn_request_params,
            browser_sso: c.browser_sso,
            allowed_resources: c.allowed_resources,
            managed_by: c.managed_by,
            last_authorized_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// What a client sends back after a read: its metadata plus its
    /// `client_id`, with the four server-stated members stripped.
    fn update_body(client_id: &str) -> serde_json::Value {
        serde_json::json!({
            "client_id": client_id,
            "client_name": "MCP Inspector",
            "redirect_uris": ["http://127.0.0.1:6274/oauth/callback"],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "openid profile",
        })
    }

    #[test]
    fn a_registration_access_token_is_32_random_bytes_base64url_and_stored_as_a_digest() {
        let (a, digest_a) = mint_registration_access_token();
        let (b, _) = mint_registration_access_token();
        assert_eq!(a.len(), 43, "32 bytes, base64url, no padding: {a}");
        assert!(
            a.bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'),
            "{a}"
        );
        assert_ne!(a, b);
        assert_eq!(digest_a.len(), 64);
        assert_ne!(digest_a, a, "the digest is not the token");
        assert_eq!(registration_access_token_digest(&a), digest_a);
    }

    #[test]
    fn the_registration_client_uri_follows_the_issuer_the_request_used() {
        let tenant = Uuid::new_v4();
        assert_eq!(
            registration_client_uri("https://a.example.com/", "oa_1", Some(tenant)),
            format!("https://a.example.com/oauth2/register/oa_1?tenant_id={tenant}")
        );
        assert_eq!(
            registration_client_uri(&format!("https://a.example.com/t/{tenant}"), "oa_1", None),
            format!("https://a.example.com/t/{tenant}/oauth2/register/oa_1")
        );
    }

    #[test]
    fn an_update_that_restates_the_registration_is_accepted() {
        let stored = stored(&inspector_request());
        let mut body = update_body(&stored.client_id);
        body["redirect_uris"] = serde_json::json!(["http://localhost:9000/cb"]);
        let out = validate_update(
            stored.tenant_id,
            &stored.client_id,
            &body,
            &stored,
            &policy(|_| {}),
        )
        .unwrap();
        assert_eq!(out.create.redirect_uris, vec!["http://localhost:9000/cb"]);
    }

    #[test]
    fn an_update_naming_a_server_stated_member_is_refused() {
        let stored = stored(&inspector_request());
        for member in RFC7592_SERVER_MEMBERS {
            let mut body = update_body(&stored.client_id);
            body[member] = serde_json::json!("x");
            let err = validate_update(
                stored.tenant_id,
                &stored.client_id,
                &body,
                &stored,
                &policy(|_| {}),
            )
            .unwrap_err();
            assert_eq!(err.error_code(), "invalid_request", "{member}");
            assert_eq!(err.http_status(), 400);
        }
    }

    #[test]
    fn an_update_must_name_its_own_client_id() {
        let stored = stored(&inspector_request());
        for client_id in [
            serde_json::Value::Null,
            serde_json::json!("oa_somebody_else"),
            serde_json::json!(7),
        ] {
            let mut body = update_body(&stored.client_id);
            body["client_id"] = client_id.clone();
            assert!(matches!(
                validate_update(
                    stored.tenant_id,
                    &stored.client_id,
                    &body,
                    &stored,
                    &policy(|_| {})
                ),
                Err(DcrError::InvalidRequest(_))
            ));
        }
        let mut body = update_body(&stored.client_id);
        body.as_object_mut().unwrap().remove("client_id");
        assert!(matches!(
            validate_update(
                stored.tenant_id,
                &stored.client_id,
                &body,
                &stored,
                &policy(|_| {})
            ),
            Err(DcrError::InvalidRequest(_))
        ));
        assert!(matches!(
            validate_update(
                stored.tenant_id,
                &stored.client_id,
                &serde_json::json!([]),
                &stored,
                &policy(|_| {})
            ),
            Err(DcrError::InvalidRequest(_))
        ));
    }

    /// The widening refusals are `validate`'s own, reached through the update.
    #[test]
    fn an_update_cannot_widen_scopes_grants_hosts_or_the_auth_method() {
        let stored = stored(&inspector_request());
        let cases: [(&str, serde_json::Value, &str); 4] = [
            (
                "scope",
                serde_json::json!("openid profile email"),
                "invalid_client_metadata",
            ),
            (
                "grant_types",
                serde_json::json!(["authorization_code", "client_credentials"]),
                "invalid_client_metadata",
            ),
            (
                "redirect_uris",
                serde_json::json!(["https://evil.example.net/cb"]),
                "invalid_redirect_uri",
            ),
            (
                "token_endpoint_auth_method",
                serde_json::json!("client_secret_basic"),
                "invalid_client_metadata",
            ),
        ];
        for (member, value, code) in cases {
            let mut body = update_body(&stored.client_id);
            body[member] = value;
            let err = validate_update(
                stored.tenant_id,
                &stored.client_id,
                &body,
                &stored,
                &policy(|_| {}),
            )
            .unwrap_err();
            assert_eq!(err.error_code(), code, "{member}");
            assert_eq!(err.http_status(), 400, "{member}");
        }
        // Full replacement: an omitted method is RFC 7591's default, which is
        // not what a public client holds.
        let mut body = update_body(&stored.client_id);
        body.as_object_mut()
            .unwrap()
            .remove("token_endpoint_auth_method");
        assert!(matches!(
            validate_update(
                stored.tenant_id,
                &stored.client_id,
                &body,
                &stored,
                &policy(|_| {})
            ),
            Err(DcrError::InvalidClientMetadata(_))
        ));
    }

    /// T23.1.1's registration pin, held for the update: however the body
    /// spells a wish for the honour lane, the login hop, a FAPI profile, a
    /// provenance or an audience, what comes out is the stricter default and
    /// the tenant's list.
    #[test]
    fn an_update_cannot_opt_itself_into_the_honour_lane_or_the_login_hop() {
        let stored = stored(&inspector_request());
        let mut body = update_body(&stored.client_id);
        for (k, v) in [
            ("authn_request_params", serde_json::json!("honour")),
            ("browser_sso", serde_json::json!(true)),
            ("profile", serde_json::json!("fapi2")),
            ("managed_by", serde_json::json!("admin")),
            (
                "allowed_resources",
                serde_json::json!(["https://elsewhere.example"]),
            ),
            ("tenant_id", serde_json::json!(Uuid::new_v4())),
        ] {
            body[k] = v;
        }
        let c = validate_update(
            stored.tenant_id,
            &stored.client_id,
            &body,
            &stored,
            &policy(|_| {}),
        )
        .unwrap()
        .create;
        assert_eq!(
            c.authn_request_params,
            axiam_core::models::oauth2_client::AuthnRequestParamsMode::Ignore
        );
        assert!(!c.browser_sso);
        assert_eq!(c.profile, ClientProfile::Standard);
        assert_eq!(
            c.managed_by,
            axiam_core::models::oauth2_client::ManagedBy::Dcr
        );
        assert_eq!(c.allowed_resources, vec!["https://mcp.example.com/mcp"]);
        assert_eq!(c.tenant_id, stored.tenant_id);
    }

    /// A read never carries a secret; the registration and a replacement carry
    /// the token once.
    #[test]
    fn the_client_information_response_carries_each_secret_only_where_it_should() {
        let stored = stored(&inspector_request());
        let read = serde_json::to_value(client_information(
            &stored,
            "https://a.example.com/oauth2/register/x".into(),
            None,
            None,
        ))
        .unwrap();
        assert!(read.get("registration_access_token").is_none());
        assert!(read.get("client_secret").is_none());
        assert_eq!(
            read["registration_client_uri"],
            "https://a.example.com/oauth2/register/x"
        );
        let put = serde_json::to_value(client_information(
            &stored,
            "u".into(),
            Some("never-for-a-public-client".into()),
            Some("tok".into()),
        ))
        .unwrap();
        assert_eq!(put["registration_access_token"], "tok");
        assert!(
            put.get("client_secret").is_none(),
            "a public client has no secret to show"
        );
    }
}

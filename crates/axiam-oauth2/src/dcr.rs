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

use axiam_core::models::oauth2_client::{ClientAuthMethod, ClientProfile, CreateOAuth2Client};
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
            Self::InvalidRedirectUri(d) | Self::InvalidClientMetadata(d) => d.clone(),
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

/// An RFC 7591 §3.2.1 registration response.
///
/// `registration_access_token` and `registration_client_uri` are **absent**:
/// RFC 7592's client configuration endpoint is deferred (the plan's item 4),
/// and RFC 7591 §3.2.1 makes both OPTIONAL. Returning them would promise an
/// endpoint that does not exist, which a conforming client would then try.
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
}

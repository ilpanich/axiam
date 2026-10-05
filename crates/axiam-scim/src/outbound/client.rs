//! The outbound HTTP client: the one way a request leaves the process, the
//! OAuth2 client-credentials token fetch and its in-memory cache (D-57).
//!
//! # The only way out
//!
//! Every request — SCIM calls and the token request — is sent with
//! `axiam_federation::ssrf::guarded_fetch_no_redirect` and the deliverer's
//! `allow_private` flag, which is **`false`** except for the integration tests'
//! loopback server (see [`super::ScimPushDeliverer::admitting_private_networks_for_tests`]).
//! The guard resolves the host fresh, refuses any non-global address, pins the
//! validated address into the connection, requires `https`, and returns a `3xx`
//! to the caller instead of following it: the credential header can reach no
//! host but the one the administrator named, by construction.
//!
//! # What is never kept or shown
//!
//! * A credential reaches a request only as a `HeaderValue` marked
//!   `set_sensitive(true)`; the bearer token, the client secret and the cached
//!   access token live in [`Zeroizing`] buffers and are never formatted.
//! * A response body is read to a hard cap and **never logged**. The failure
//!   reasons this module produces are a fixed vocabulary: no URL (a transport
//!   error's own text names the URL it was fetching), body, name or value.
//! * The access token is cached **in memory only**, per target and the
//!   `updated_at` the credential was read under, and never persisted.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axiam_federation::ssrf::{SsrfError, guarded_fetch_no_redirect, read_capped_body};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use chrono::{DateTime, Utc};
use reqwest::Method;
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderValue};
use uuid::Uuid;
use zeroize::Zeroizing;

use super::wire::SCIM_CONTENT_TYPE;

/// One request is given this long, connect to last byte.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// The most of a receiver's response body that is read for a write: enough for
/// the created resource's `id`, and a hard stop for anything else.
pub(crate) const RESPONSE_BODY_CAP: usize = 64 * 1024;

/// The most of a `GET …?filter=` list response that is read (reconciliation
/// will page larger lists with the same cap).
pub(crate) const LIST_BODY_CAP: usize = 1024 * 1024;

/// A cached access token is used for at most this long, whatever `expires_in`
/// says (D-57).
pub(crate) const MAX_TOKEN_LIFETIME: Duration = Duration::from_secs(3600);

/// The lifetime assumed for a token response that names none.
const DEFAULT_TOKEN_LIFETIME: Duration = Duration::from_secs(300);

/// Why an attempt stopped before it delivered.
///
/// `Retry` and `Dead` carry a reason from the fixed vocabulary; `Fail` is a
/// failure of AXIAM's own datastore, which the consumer loop treats as a retry.
#[derive(Debug)]
pub(crate) enum Exit {
    Retry(String),
    Dead(String),
    Fail(String),
}

impl Exit {
    pub(crate) fn retry(reason: &str) -> Self {
        Self::Retry(reason.to_owned())
    }

    pub(crate) fn dead(reason: &str) -> Self {
        Self::Dead(reason.to_owned())
    }

    pub(crate) fn fail(reason: &str) -> Self {
        Self::Fail(reason.to_owned())
    }
}

pub(crate) type Step<T> = Result<T, Exit>;

/// The audit-safe reading of a guard error: a fixed phrase, never the error's
/// own text.
pub(crate) fn classify_transport(error: &SsrfError) -> Exit {
    match error {
        SsrfError::Blocked => {
            Exit::retry("the endpoint resolves to an address AXIAM does not connect to")
        }
        SsrfError::ResolveFailed => Exit::retry("the endpoint's host did not resolve"),
        SsrfError::InsecureScheme => Exit::dead("the endpoint is not https"),
        SsrfError::InvalidUrl => Exit::dead("the endpoint is not a valid URL"),
        SsrfError::TooManyRedirects => Exit::retry("the receiver redirected too often"),
        SsrfError::ResponseTooLarge(_) => Exit::retry("the receiver's response was too large"),
        SsrfError::ClientBuildFailed => Exit::retry("the HTTP client could not be built"),
        SsrfError::RequestFailed(_) => {
            Exit::retry("the receiver could not be reached or did not answer in time")
        }
    }
}

/// A response, reduced to what the deliverer reads: the status and a capped body.
pub(crate) struct Response {
    pub(crate) status: u16,
    pub(crate) body: Vec<u8>,
}

/// What a request carries besides its method and URL.
pub(crate) struct Payload {
    pub(crate) content_type: &'static str,
    pub(crate) accept: &'static str,
    pub(crate) body: Option<Vec<u8>>,
}

impl Payload {
    /// A SCIM request: `application/scim+json` both ways, with an optional body.
    pub(crate) fn scim(body: Option<Vec<u8>>) -> Self {
        Self {
            content_type: SCIM_CONTENT_TYPE,
            accept: SCIM_CONTENT_TYPE,
            body,
        }
    }
}

/// Send one request through the shared guard. A `3xx` is returned as a
/// response; a transport failure is an [`Exit`].
pub(crate) async fn send(
    allow_private: bool,
    method: Method,
    url: &str,
    authorization: &HeaderValue,
    payload: Payload,
    body_cap: usize,
) -> Step<Response> {
    let response = guarded_fetch_no_redirect(url, allow_private, |client, target| {
        let mut request = client
            .request(method.clone(), target)
            .timeout(REQUEST_TIMEOUT)
            .header(ACCEPT, payload.accept)
            .header(AUTHORIZATION, authorization.clone());
        if let Some(body) = &payload.body {
            request = request
                .header(CONTENT_TYPE, payload.content_type)
                .body(body.clone());
        }
        request
    })
    .await
    .map_err(|error| classify_transport(&error))?;

    let status = response.status().as_u16();
    // Read even for an error status (the body is dropped, never kept or
    // logged) so that the connection is drained within the cap.
    let body = read_capped_body(response, body_cap)
        .await
        .map_err(|error| classify_transport(&error))?;
    Ok(Response { status, body })
}

// ---------------------------------------------------------------------------
// The OAuth2 client-credentials token
// ---------------------------------------------------------------------------

struct Cached {
    /// The `updated_at` of the target version the credential was read under.
    updated_at: DateTime<Utc>,
    token: Zeroizing<String>,
    expires_at: Instant,
}

/// Access tokens obtained with a target's client credentials, in memory only.
///
/// One entry per target, valid for exactly the `updated_at` it was fetched
/// under: an administrator's write to the target (a new secret, a new
/// `token_url`) changes `updated_at` and retires the entry without anybody
/// having to flush it.
#[derive(Default)]
pub(crate) struct TokenCache {
    entries: Mutex<HashMap<Uuid, Cached>>,
}

impl TokenCache {
    /// The cached token for this version of the target, if it has not expired.
    pub(crate) fn get(
        &self,
        target_id: Uuid,
        updated_at: DateTime<Utc>,
    ) -> Option<Zeroizing<String>> {
        let entries = self.entries.lock().ok()?;
        let cached = entries.get(&target_id)?;
        (cached.updated_at == updated_at && cached.expires_at > Instant::now())
            .then(|| cached.token.clone())
    }

    /// Keep `token` for this version of the target, for `lifetime` capped at
    /// [`MAX_TOKEN_LIFETIME`].
    pub(crate) fn put(
        &self,
        target_id: Uuid,
        updated_at: DateTime<Utc>,
        token: Zeroizing<String>,
        lifetime: Duration,
    ) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(
                target_id,
                Cached {
                    updated_at,
                    token,
                    expires_at: Instant::now() + lifetime.min(MAX_TOKEN_LIFETIME),
                },
            );
        }
    }

    /// Forget the target's token (the downstream answered `401`).
    pub(crate) fn flush(&self, target_id: Uuid) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(&target_id);
        }
    }
}

/// The inputs of the token request.
pub(crate) struct TokenRequest<'a> {
    pub(crate) token_url: &'a str,
    pub(crate) client_id: &'a str,
    pub(crate) client_secret: &'a str,
    pub(crate) scope: Option<&'a str>,
}

/// An access token and how long it is good for.
pub(crate) struct AccessToken {
    pub(crate) token: Zeroizing<String>,
    pub(crate) lifetime: Duration,
}

fn form_encode(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

/// RFC 6749 §4.4: `grant_type=client_credentials` (+ `scope`) with HTTP Basic
/// client authentication (§2.3.1: the id and the secret are form-encoded before
/// they are joined and base64-encoded).
pub(crate) async fn fetch_access_token(
    allow_private: bool,
    request: TokenRequest<'_>,
) -> Step<AccessToken> {
    let basic = Zeroizing::new(
        BASE64.encode(
            format!(
                "{}:{}",
                form_encode(request.client_id),
                form_encode(request.client_secret)
            )
            .as_bytes(),
        ),
    );
    let mut authorization = HeaderValue::from_str(&format!("Basic {}", basic.as_str()))
        .map_err(|_| Exit::dead("the client credentials are not valid for a request"))?;
    authorization.set_sensitive(true);

    // The serializer is not `Send`: it must not live across an await.
    let body = {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "client_credentials");
        if let Some(scope) = request.scope {
            form.append_pair("scope", scope);
        }
        form.finish().into_bytes()
    };
    let payload = Payload {
        content_type: "application/x-www-form-urlencoded",
        accept: "application/json",
        body: Some(body),
    };

    let response = send(
        allow_private,
        Method::POST,
        request.token_url,
        &authorization,
        payload,
        RESPONSE_BODY_CAP,
    )
    .await?;

    match response.status {
        200..=299 => parse_token_response(&response.body),
        300..=399 => Err(Exit::retry(
            "the token endpoint answered with a redirect, which is not followed",
        )),
        // The client credentials are wrong until someone fixes them.
        400 | 401 | 403 => Err(Exit::Dead(format!(
            "the token endpoint refused the client credentials (HTTP {})",
            response.status
        ))),
        408 | 429 | 500..=599 => Err(Exit::Retry(format!(
            "the token endpoint answered HTTP {}",
            response.status
        ))),
        400..=499 => Err(Exit::Dead(format!(
            "token endpoint HTTP {}",
            response.status
        ))),
        other => Err(Exit::Retry(format!(
            "the token endpoint answered an unexpected HTTP {other}"
        ))),
    }
}

fn parse_token_response(body: &[u8]) -> Step<AccessToken> {
    let malformed = || Exit::retry("the token response is malformed");
    let value: serde_json::Value = serde_json::from_slice(body).map_err(|_| malformed())?;
    let token = value
        .get("access_token")
        .and_then(serde_json::Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(malformed)?;
    let lifetime = value
        .get("expires_in")
        .and_then(serde_json::Value::as_u64)
        .map_or(DEFAULT_TOKEN_LIFETIME, Duration::from_secs)
        .min(MAX_TOKEN_LIFETIME);
    Ok(AccessToken {
        token: Zeroizing::new(token.to_owned()),
        lifetime,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_transport_reason_never_carries_the_error_text() {
        let url = "https://scim.example.test/v2/Users?token=abc";
        for error in [
            SsrfError::RequestFailed(format!("error sending request for url ({url})")),
            SsrfError::Blocked,
            SsrfError::ResolveFailed,
            SsrfError::TooManyRedirects,
            SsrfError::ResponseTooLarge(1),
            SsrfError::ClientBuildFailed,
            SsrfError::InsecureScheme,
            SsrfError::InvalidUrl,
        ] {
            let reason = match classify_transport(&error) {
                Exit::Retry(reason) | Exit::Dead(reason) => reason,
                Exit::Fail(_) => panic!("a transport failure is a retry or a dead letter"),
            };
            assert!(!reason.contains("scim.example.test") && !reason.contains("token"));
        }
    }

    #[test]
    fn a_token_lifetime_is_capped_at_one_hour() {
        let parsed = parse_token_response(br#"{"access_token":"x","expires_in":86400}"#).unwrap();
        assert_eq!(parsed.lifetime, MAX_TOKEN_LIFETIME);
        let short = parse_token_response(br#"{"access_token":"x","expires_in":60}"#).unwrap();
        assert_eq!(short.lifetime, Duration::from_secs(60));
        let none = parse_token_response(br#"{"access_token":"x"}"#).unwrap();
        assert_eq!(none.lifetime, DEFAULT_TOKEN_LIFETIME);
        for bad in [&br#"{}"#[..], br#"{"access_token":""}"#, b"not json"] {
            assert!(matches!(parse_token_response(bad), Err(Exit::Retry(_))));
        }
    }

    #[test]
    fn the_cache_is_per_target_version_and_flushable() {
        let cache = TokenCache::default();
        let id = Uuid::new_v4();
        let version = Utc::now();
        assert!(cache.get(id, version).is_none());
        cache.put(
            id,
            version,
            Zeroizing::new("t".into()),
            Duration::from_secs(60),
        );
        assert!(cache.get(id, version).is_some());
        // Another version of the target (an administrator wrote it) is a miss.
        assert!(
            cache
                .get(id, version + chrono::Duration::seconds(1))
                .is_none()
        );
        // Expired.
        cache.put(id, version, Zeroizing::new("t".into()), Duration::ZERO);
        assert!(cache.get(id, version).is_none());
        cache.put(
            id,
            version,
            Zeroizing::new("t".into()),
            Duration::from_secs(60),
        );
        cache.flush(id);
        assert!(cache.get(id, version).is_none());
    }
}

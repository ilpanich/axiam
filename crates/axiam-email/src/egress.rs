//! Where an email provider may connect (#529, P23W3-11, T-473).
//!
//! An organization or tenant administrator chooses the provider: an SMTP host
//! and port, or an HTTP provider's `api_url`. Both used to be dialled as
//! written — `lettre` resolved the SMTP host itself and `reqwest` the API URL —
//! so the email configuration was T-300's problem again: a field that makes
//! AXIAM open a connection to loopback, the cloud metadata service or the pod
//! network, and send an SMTP greeting or an HTTP `POST` carrying the provider
//! key there.
//!
//! * **SMTP** is held to the connector address guard the directory uses
//!   ([`axiam_pki::address`], D-32): the host is resolved once; loopback,
//!   link-local (the metadata service), unspecified, multicast and
//!   special-purpose addresses and AXIAM's own listeners are always refused; a
//!   private address only inside the networks the operator lists in
//!   [`ALLOWED_PRIVATE_NETWORKS_ENV`]. The SMTP connection is opened to the
//!   vetted address, with the configured host as the TLS name.
//! * **HTTP providers** go through [`guarded_fetch_no_redirect`] — the API key
//!   is a credential, so no redirect is ever followed — and are held to its
//!   rule: HTTPS, globally routable, an exception only for a host the operator
//!   names in `AXIAM__PKI__SSRF_ALLOWED_HOSTS` (SEC-107).
//!
//! The same check runs when a configuration is saved ([`EmailEgress::check`])
//! and at every send, so a name re-pointed after the save is caught on the next
//! message. What an administrator is told about a refusal of a host **name** is
//! one sentence whatever the name resolved to ([`HOST_NOT_PERMITTED`], the
//! P23W3-04 lesson); the specific rule goes to the operator's log. A connection
//! that fails after the guard admitted the address is reported as
//! [`PROVIDER_UNREACHABLE`], so a refused port and a silent one read the same.

use std::sync::Arc;

use axiam_core::error::AxiamError;
use axiam_core::models::email::ProviderConfig;
pub use axiam_pki::address::{
    AddressPolicy, GuardError, GuardedTarget, ResolveFuture, Resolver, SystemResolver,
    parse_allowed_networks,
};
use axiam_pki::address::{guard_host, is_ip_literal};
use axiam_pki::ssrf::{SsrfError, guarded_fetch_no_redirect, resolve_and_pick};

/// The environment variable that lists the private networks an SMTP provider
/// may be in: comma-separated CIDR blocks (`10.20.0.0/16`, `fd12:3456::/48`)
/// or single addresses. Unset or empty — the default — admits no private
/// address at all. Separate from the directory's list on purpose: where mail
/// relays live and where directories live are two decisions.
pub const ALLOWED_PRIVATE_NETWORKS_ENV: &str = "AXIAM__EMAIL__ALLOWED_PRIVATE_NETWORKS";

/// The one answer every resolution-dependent refusal of a host **name** gets
/// (P23W3-04): it says nothing about which names exist or where they point.
pub const HOST_NOT_PERMITTED: &str = "the email provider host does not resolve to an address \
     this deployment permits an email connection to; check the name, or ask the deployment's \
     operator whether its network is allowed";

/// The one answer every connection failure after the guard gets: refused,
/// reset, timed out and a failed TLS handshake read the same. The operator's
/// log has the cause.
pub const PROVIDER_UNREACHABLE: &str =
    "the connection to the email provider failed; the deployment's log names the cause";

/// A refused provider address: what the administrator is told and what the
/// operator's log records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EgressRefusal {
    /// The field refused: `smtp host` or `api_url`.
    pub field: &'static str,
    /// The specific rule, for the operator's log (never the administrator's
    /// answer when the host is a name).
    pub rule: &'static str,
    detail: String,
    about_the_text: bool,
}

impl EgressRefusal {
    fn smtp(host: &str, error: &GuardError) -> Self {
        Self {
            field: "smtp host",
            rule: error.rule(),
            detail: error.to_string(),
            about_the_text: matches!(error, GuardError::InvalidUrl) || is_ip_literal(host),
        }
    }

    fn api_url(host: Option<&str>, error: &SsrfError) -> Self {
        let (rule, about_the_text) = match error {
            SsrfError::InvalidUrl => ("ssrf.invalid_url", true),
            SsrfError::InsecureScheme => ("ssrf.insecure_scheme", true),
            SsrfError::ResolveFailed => ("ssrf.unresolvable", false),
            _ => ("ssrf.blocked", false),
        };
        Self {
            field: "api_url",
            rule,
            detail: error.to_string(),
            about_the_text: about_the_text || host.is_some_and(is_ip_literal),
        }
    }

    /// What the administrator is told. For a host **name**, every refusal that
    /// depends on what it resolved to is [`HOST_NOT_PERMITTED`]; for an IP
    /// literal, and for a value refused for its own text, the specific rule —
    /// it reveals nothing the administrator did not type.
    #[must_use]
    pub fn public_message(&self) -> String {
        if self.about_the_text {
            format!("{}: {}", self.field, self.detail)
        } else {
            format!("{}: {HOST_NOT_PERMITTED}", self.field)
        }
    }

    /// The refusal at send time, as the error the caller sees.
    #[must_use]
    pub fn into_error(self) -> AxiamError {
        AxiamError::EmailConfig(self.public_message())
    }

    fn log(&self, when: &'static str) {
        tracing::warn!(
            target: "axiam::email",
            field = self.field,
            rule = self.rule,
            detail = %self.detail,
            when,
            "an email provider address was refused by the outbound address policy"
        );
    }
}

/// The deployment's outbound rule for email providers. Built once at
/// composition from deployment configuration; tenants cannot change it.
/// Cheap to clone.
#[derive(Clone)]
pub struct EmailEgress {
    policy: Arc<AddressPolicy>,
    resolver: Arc<dyn Resolver>,
    allow_private_http: bool,
}

impl Default for EmailEgress {
    /// The strict rule: no private network, no listener known, the system
    /// resolver.
    fn default() -> Self {
        Self::new(AddressPolicy::new())
    }
}

impl std::fmt::Debug for EmailEgress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EmailEgress")
            .field("policy", &self.policy)
            .field("allow_private_http", &self.allow_private_http)
            .finish_non_exhaustive()
    }
}

impl EmailEgress {
    /// SMTP held to `policy` (the operator's allow-list and AXIAM's listener
    /// ports), names resolved by the system resolver.
    #[must_use]
    pub fn new(policy: AddressPolicy) -> Self {
        Self {
            policy: Arc::new(policy),
            resolver: Arc::new(SystemResolver),
            allow_private_http: false,
        }
    }

    /// Resolve SMTP host names with `resolver` (tests script answers).
    #[must_use]
    pub fn with_resolver(mut self, resolver: Arc<dyn Resolver>) -> Self {
        self.resolver = resolver;
        self
    }

    /// **Tests only.** Let an HTTP provider reach a plain-`http` loopback mock
    /// server — `guarded_fetch`'s `allow_private` seam. Never called by
    /// production code; a grep for this name finds every exception.
    #[doc(hidden)]
    #[must_use]
    pub fn allowing_private_http_for_tests(mut self) -> Self {
        self.allow_private_http = true;
        self
    }

    /// The SMTP address policy.
    #[must_use]
    pub fn policy(&self) -> &AddressPolicy {
        &self.policy
    }

    /// Resolve the SMTP `host` once and vet every address.
    ///
    /// # Errors
    ///
    /// The refusal, when the host is empty, does not resolve, or resolves to
    /// an address the policy refuses.
    pub async fn guard_smtp(&self, host: &str, port: u16) -> Result<GuardedTarget, EgressRefusal> {
        guard_host(host, port, &self.policy, self.resolver.as_ref())
            .await
            .map_err(|error| EgressRefusal::smtp(host, &error))
    }

    /// The save-time check of an HTTP provider's `api_url`: the rule
    /// [`guarded_fetch_no_redirect`] applies at send — an `https` URL whose
    /// host resolves to globally routable addresses only (or is on
    /// `AXIAM__PKI__SSRF_ALLOWED_HOSTS`). Nothing is sent.
    ///
    /// # Errors
    ///
    /// The refusal.
    pub async fn check_api_url(&self, api_url: &str) -> Result<(), EgressRefusal> {
        let refuse = |host: Option<&str>, error: SsrfError| EgressRefusal::api_url(host, &error);
        let parsed = url::Url::parse(api_url).map_err(|_| refuse(None, SsrfError::InvalidUrl))?;
        let Some(host) = parsed.host_str().filter(|h| !h.is_empty()) else {
            return Err(refuse(None, SsrfError::InvalidUrl));
        };
        if parsed.scheme() != "https" && !self.allow_private_http {
            return Err(refuse(Some(host), SsrfError::InsecureScheme));
        }
        let port = parsed.port_or_known_default().unwrap_or(443);
        // The host exactly as the send path hands it to the resolver, so the
        // save and the send cannot disagree.
        resolve_and_pick(host, port, self.allow_private_http)
            .await
            .map(|_| ())
            .map_err(|error| refuse(Some(host), error))
    }

    /// The save-time check of a provider configuration: the SMTP host through
    /// the address guard, an explicit `api_url` through the HTTP rule. A
    /// provider's built-in API URL is AXIAM's own constant and is not checked.
    ///
    /// # Errors
    ///
    /// The refusal; the caller answers [`EgressRefusal::public_message`].
    pub async fn check(&self, provider: &ProviderConfig) -> Result<(), EgressRefusal> {
        let result = match provider {
            ProviderConfig::Smtp(smtp) => self.guard_smtp(&smtp.host, smtp.port).await.map(|_| ()),
            ProviderConfig::SendGrid(api)
            | ProviderConfig::Postmark(api)
            | ProviderConfig::Resend(api)
            | ProviderConfig::Brevo(api) => match api.api_url.as_deref() {
                Some(url) => self.check_api_url(url).await,
                None => Ok(()),
            },
        };
        if let Err(refusal) = &result {
            refusal.log("save");
        }
        result
    }

    /// One HTTP provider request through [`guarded_fetch_no_redirect`]: `url`
    /// resolved once, vetted, pinned, and never redirected. A refusal is the
    /// administrator-safe [`EgressRefusal`] error; a failed connection is
    /// [`PROVIDER_UNREACHABLE`].
    pub(crate) async fn post(
        &self,
        provider: &'static str,
        url: &str,
        build: impl Fn(&reqwest::Client, &str) -> reqwest::RequestBuilder,
    ) -> Result<reqwest::Response, AxiamError> {
        match guarded_fetch_no_redirect(url, self.allow_private_http, build).await {
            Ok(response) => Ok(response),
            Err(
                error @ (SsrfError::InvalidUrl
                | SsrfError::InsecureScheme
                | SsrfError::ResolveFailed
                | SsrfError::Blocked),
            ) => {
                let host = url::Url::parse(url)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_owned));
                let refusal = EgressRefusal::api_url(host.as_deref(), &error);
                refusal.log("send");
                Err(refusal.into_error())
            }
            Err(error) => {
                tracing::warn!(
                    target: "axiam::email",
                    provider,
                    error = %error,
                    "the email provider's API could not be reached"
                );
                Err(AxiamError::EmailDelivery(format!(
                    "{provider}: {PROVIDER_UNREACHABLE}"
                )))
            }
        }
    }

    /// The SMTP send-time guard: the refusal, logged, as the caller's error.
    pub(crate) async fn smtp_target(
        &self,
        host: &str,
        port: u16,
    ) -> Result<GuardedTarget, AxiamError> {
        self.guard_smtp(host, port).await.map_err(|refusal| {
            refusal.log("send");
            refusal.into_error()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_names_refusal_is_one_sentence_and_a_literals_names_the_rule() {
        let by_name = EgressRefusal::smtp("relay.example.com", &GuardError::Loopback);
        assert_eq!(by_name.rule, "address_guard.loopback");
        assert_eq!(
            by_name.public_message(),
            format!("smtp host: {HOST_NOT_PERMITTED}")
        );
        let by_literal = EgressRefusal::smtp("127.0.0.1", &GuardError::Loopback);
        assert!(by_literal.public_message().contains("loopback"));
        let unresolved = EgressRefusal::api_url(Some("api.example.com"), &SsrfError::ResolveFailed);
        assert_eq!(
            unresolved.public_message(),
            format!("api_url: {HOST_NOT_PERMITTED}")
        );
        let plaintext = EgressRefusal::api_url(Some("api.example.com"), &SsrfError::InsecureScheme);
        assert!(plaintext.public_message().contains("non-HTTPS"));
    }
}

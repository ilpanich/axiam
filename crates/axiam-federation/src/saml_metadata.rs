//! SAML SP: the IdP's metadata document — its signature and its cache (#530,
//! P23W3-07).
//!
//! The SP reads three things from an IdP's metadata: its entity ID, its SSO
//! URL and the binding of that URL. The assertion signing certificate is
//! **not** among them (it is pinned on the federation configuration), so forged
//! metadata cannot forge an assertion. It can still choose the HTTPS URL a
//! person is redirected to with the `AuthnRequest` — a phishing redirect — and
//! before this module every SP-initiated sign-in fetched the document again, so
//! every sign-in also depended on the metadata host being up.
//!
//! # Signature
//!
//! When the configuration carries `idp_metadata_signing_cert_pem`, the
//! document must be signed, and only one place may hold the signature: the
//! enveloped child of the `md:EntityDescriptor` root, with one reference,
//! naming the root's `ID` — the IdP receiver's placement rule
//! ([`signature_placement`], D-23), applied to a different root. Any other
//! `ds:Signature` refuses the document. The one admitted signature is verified
//! by xmlsec on its own node against the configured certificate, with the SHA-2
//! algorithms only ([`ALLOWED_XML_SIGNATURE_ALGORITHMS`]; a configuration's
//! `allow_sha1_signatures` applies to responses, not to metadata), and what is
//! then read is xmlsec's **pre-digest** output — the bytes the digest covered —
//! not the document as fetched, so nothing outside the signature is read.
//!
//! Every document, signed or not, is first refused on its bytes if it carries a
//! markup declaration or an encoding other than UTF-8, as a SAML response is
//! (#531): metadata has no use for a DTD.
//!
//! # Cache
//!
//! [`SamlMetadataCache`] holds the parsed document per process, keyed by the
//! federation configuration's id and checked against the metadata URL and the
//! configuration's `updated_at`, so any edit of the configuration — a new URL,
//! a new certificate — misses. An entry lives for the document's
//! `cacheDuration` ([`DEFAULT_TTL`] when it states none), held between
//! [`MIN_TTL`] and [`MAX_TTL`], and never past its `validUntil`. A document
//! whose `validUntil` has passed is refused.
//!
//! A refetch whose SSO URL names another host than the entry it replaces is
//! reported ([`SsoHostChange`]) for the caller to audit: the metadata host can
//! move users, so a move should be visible.

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use axiam_core::models::federation::FederationConfig;
use chrono::{DateTime, Duration, Utc};
use samael::crypto::{CertificateDer, CryptoProvider, ReduceMode, XmlSec};
use samael::metadata::{EntityDescriptorType, HTTP_POST_BINDING, HTTP_REDIRECT_BINDING};
use uuid::Uuid;

use crate::error::FederationError;
use crate::saml::IdpMetadata;
use crate::saml_idp::request::{
    ALLOWED_XML_SIGNATURE_ALGORITHMS, refuse_markup_declarations, refuse_other_encodings,
    signature_placement,
};

/// SAML 2.0 metadata namespace.
const NS_METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";

/// The largest metadata document read: 512 KiB.
pub const MAX_METADATA_SIZE: usize = 512 * 1024;

/// How long a document that states no `cacheDuration` is kept: one hour, the
/// OIDC discovery cache's TTL.
pub const DEFAULT_TTL: Duration = Duration::hours(1);

/// The shortest time an entry is kept, whatever `cacheDuration` says — so a
/// document stating `PT0S` does not turn the cache off — unless its
/// `validUntil` comes first.
pub const MIN_TTL: Duration = Duration::minutes(5);

/// The longest time an entry is kept, whatever `cacheDuration` says: a moved
/// or re-keyed IdP is picked up within a day without an edit.
pub const MAX_TTL: Duration = Duration::hours(24);

/// The fetch a cache miss runs: the metadata URL in, the document's text out.
pub type MetadataFetcher = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<String, FederationError>> + Send>>
        + Send
        + Sync,
>;

/// The production fetcher: HTTPS only, through the IP-pinning SSRF guard, at
/// most [`MAX_METADATA_SIZE`] bytes, UTF-8.
pub fn guarded_metadata_fetcher() -> MetadataFetcher {
    Arc::new(|url| Box::pin(fetch_metadata_document(url)))
}

/// Fetch a metadata document (no parsing, no cache).
///
/// # Errors
///
/// [`FederationError::InvalidMetadataUrl`] for a URL that is not HTTPS;
/// [`FederationError::SamlMetadataFailed`] for a refused or failed fetch, a
/// non-2xx answer, a body over [`MAX_METADATA_SIZE`] or one that is not UTF-8.
pub async fn fetch_metadata_document(metadata_url: String) -> Result<String, FederationError> {
    crate::validate_metadata_url(&metadata_url)?;

    // SECHRD-02: route the metadata GET through the shared, IP-pinning SSRF
    // guard (D-01a/b/c). Production always fails closed against
    // private/loopback/link-local addresses and internal redirect targets —
    // `allow_private=false`.
    let response = crate::ssrf::guarded_fetch(&metadata_url, false, |c, u| c.get(u))
        .await
        .map_err(|e| FederationError::SamlMetadataFailed(e.to_string()))?;

    if !response.status().is_success() {
        return Err(FederationError::SamlMetadataFailed(format!(
            "HTTP {} from metadata endpoint",
            response.status()
        )));
    }

    let bytes = response.bytes().await.map_err(|e| {
        FederationError::SamlMetadataFailed(format!("Failed to read metadata body: {e}"))
    })?;
    if bytes.len() > MAX_METADATA_SIZE {
        return Err(FederationError::SamlMetadataFailed(format!(
            "Metadata document too large: {} bytes (max {MAX_METADATA_SIZE})",
            bytes.len(),
        )));
    }

    String::from_utf8(bytes.to_vec())
        .map_err(|e| FederationError::SamlMetadataFailed(format!("Invalid UTF-8 in metadata: {e}")))
}

/// A metadata document, verified when a certificate was given, and read.
#[derive(Debug, Clone)]
pub struct ParsedIdpMetadata {
    /// What the SP uses.
    pub metadata: IdpMetadata,
    /// `validUntil`, when the document states one (still in the future).
    pub valid_until: Option<DateTime<Utc>>,
    /// `cacheDuration`, when the document states one AXIAM can read.
    pub cache_duration: Option<Duration>,
}

impl ParsedIdpMetadata {
    /// When a cache entry made from this document at `now` expires:
    /// `cacheDuration` (or [`DEFAULT_TTL`]) held to [`MIN_TTL`]..=[`MAX_TTL`],
    /// and never later than `validUntil`.
    #[must_use]
    pub fn expires_at(&self, now: DateTime<Utc>) -> DateTime<Utc> {
        let ttl = self
            .cache_duration
            .unwrap_or(DEFAULT_TTL)
            .clamp(MIN_TTL, MAX_TTL);
        let by_ttl = now + ttl;
        self.valid_until.map_or(by_ttl, |until| by_ttl.min(until))
    }
}

fn metadata_failed(reason: impl Into<String>) -> FederationError {
    FederationError::SamlMetadataFailed(reason.into())
}

/// Read an IdP metadata document; with `signing_cert_pem`, only after its
/// signature verified (see the module documentation for the rule).
///
/// # Errors
///
/// [`FederationError::SamlMetadataFailed`]: a markup declaration or another
/// encoding; with a certificate, an unsigned document, a signature anywhere but
/// on the `EntityDescriptor` root, or one that does not verify; a document
/// whose `validUntil` is not after `now`; no `EntityDescriptor`, `entityID`,
/// `IDPSSODescriptor` or HTTPS SSO endpoint on either binding.
/// [`FederationError::InvalidIdpCert`] for a certificate that is not PEM.
pub fn parse_idp_metadata(
    text: &str,
    signing_cert_pem: Option<&str>,
    now: DateTime<Utc>,
) -> Result<ParsedIdpMetadata, FederationError> {
    // #531's rule for SAML responses, on the bytes and before any parser.
    refuse_other_encodings(text).map_err(|_| metadata_failed("metadata is not plain UTF-8"))?;
    refuse_markup_declarations(text)
        .map_err(|_| metadata_failed("metadata declares a DTD or an entity"))?;

    let verified;
    let readable = match signing_cert_pem {
        Some(pem) => {
            verified = verify_metadata_signature(text, pem)?;
            verified.as_str()
        }
        None => text,
    };

    let descriptor_type: EntityDescriptorType = readable
        .parse()
        .map_err(|e| metadata_failed(format!("Failed to parse metadata XML: {e}")))?;

    // A signed document is one `EntityDescriptor` (the root the signature is
    // on); an unsigned one may be an aggregate, whose first entity is read.
    let (outer_valid_until, outer_cache_duration) = match &descriptor_type {
        EntityDescriptorType::EntitiesDescriptor(all) => {
            (all.valid_until, all.cache_duration.clone())
        }
        EntityDescriptorType::EntityDescriptor(_) => (None, None),
    };
    let ed = descriptor_type
        .iter()
        .next()
        .ok_or_else(|| metadata_failed("No EntityDescriptor found in metadata"))?;

    let valid_until = match (ed.valid_until, outer_valid_until) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    };
    if valid_until.is_some_and(|until| until <= now) {
        return Err(metadata_failed("metadata validUntil has passed"));
    }
    let cache_duration = ed
        .cache_duration
        .as_deref()
        .or(outer_cache_duration.as_deref())
        .and_then(parse_xs_duration);

    let entity_id = ed
        .entity_id
        .clone()
        .ok_or_else(|| metadata_failed("EntityDescriptor missing entityID"))?;
    let idp = ed
        .idp_sso_descriptors
        .as_ref()
        .and_then(|d| d.first())
        .ok_or_else(|| metadata_failed("No IDPSSODescriptor in metadata"))?;

    // Prefer HTTP-POST binding, fall back to HTTP-Redirect.
    let sso_endpoint = idp
        .single_sign_on_services
        .iter()
        .find(|ep| ep.binding == HTTP_POST_BINDING)
        .or_else(|| {
            idp.single_sign_on_services
                .iter()
                .find(|ep| ep.binding == HTTP_REDIRECT_BINDING)
        })
        .ok_or_else(|| metadata_failed("No HTTP-POST or HTTP-Redirect SSO endpoint"))?;

    // The SSO endpoint must be HTTPS, so a person is never sent to an insecure
    // origin. Fail closed on a URL that does not parse.
    let sso_parsed = url::Url::parse(&sso_endpoint.location)
        .map_err(|e| metadata_failed(format!("IdP SSO endpoint is not a valid URL: {e}")))?;
    if sso_parsed.scheme() != "https" {
        return Err(metadata_failed("IdP SSO endpoint must use HTTPS"));
    }

    Ok(ParsedIdpMetadata {
        metadata: IdpMetadata {
            entity_id,
            sso_url: sso_endpoint.location.clone(),
            sso_binding: sso_endpoint.binding.clone(),
        },
        valid_until,
        cache_duration,
    })
}

/// Verify the metadata's one enveloped signature and return the bytes it
/// covers (xmlsec's pre-digest output: the `EntityDescriptor`, canonicalized,
/// without its signature).
fn verify_metadata_signature(text: &str, pem: &str) -> Result<String, FederationError> {
    let der = crate::cert::pem_cert_to_der(pem)?;

    let doc = libxml::parser::Parser::default()
        .parse_string(text.as_bytes())
        .map_err(|_| metadata_failed("metadata is not XML"))?;
    let root = doc
        .get_root_element()
        .ok_or_else(|| metadata_failed("metadata has no root element"))?;
    let root_is_entity = root.get_name() == "EntityDescriptor"
        && root
            .get_namespace()
            .is_some_and(|ns| ns.get_href() == NS_METADATA);
    if !root_is_entity {
        return Err(metadata_failed(
            "signed metadata must be one md:EntityDescriptor",
        ));
    }
    let root_id = root
        .get_attribute("ID")
        .filter(|id| !id.is_empty())
        .ok_or_else(|| metadata_failed("metadata is not signed (its root has no ID)"))?;
    // The reference names the root by `ID`; a second element carrying the same
    // value would leave xmlsec and this check free to mean different nodes.
    let mut context = libxml::xpath::Context::new(&doc)
        .map_err(|()| metadata_failed("metadata: XPath context failed"))?;
    let bearers = context
        .findnodes("//*[@ID]", None)
        .map_err(|()| metadata_failed("metadata: XPath evaluation failed"))?;
    if bearers
        .iter()
        .filter(|n| n.get_attribute("ID").as_deref() == Some(root_id.as_str()))
        .count()
        != 1
    {
        return Err(metadata_failed("metadata repeats its root ID"));
    }

    match signature_placement(&doc, &root, &root_id) {
        Ok(true) => {}
        Ok(false) => return Err(metadata_failed("metadata is not signed")),
        Err(_) => {
            return Err(metadata_failed(
                "a metadata signature may only be the EntityDescriptor root's own",
            ));
        }
    }

    <XmlSec as CryptoProvider>::reduce_xml_to_signed_with_allowed_algorithms(
        text,
        &[CertificateDer::from(der)],
        ReduceMode::PreDigest,
        Some(&ALLOWED_XML_SIGNATURE_ALGORITHMS),
    )
    .map_err(|_| metadata_failed("metadata signature does not verify"))
}

/// An `xs:duration` (`PnYnMnDTnHnMnS`, seconds may be fractional) as a
/// [`Duration`]. A year counts 365 days and a month 30: the result is only
/// ever compared with [`MAX_TTL`]. `None` for a negative or malformed value,
/// which then reads as "no `cacheDuration`".
#[must_use]
pub fn parse_xs_duration(raw: &str) -> Option<Duration> {
    let rest = raw.trim().strip_prefix('P')?;
    let (date, time) = match rest.split_once('T') {
        Some((d, t)) if !t.is_empty() => (d, Some(t)),
        Some(_) => return None,
        None => (rest, None),
    };
    if date.is_empty() && time.is_none() {
        return None;
    }
    let mut millis: i64 = 0;
    let mut add = |digits: &str, unit_ms: i64| -> Option<()> {
        let value = if let Some((whole, frac)) = digits.split_once('.') {
            if unit_ms != 1_000 || whole.is_empty() {
                return None;
            }
            let whole: i64 = whole.parse().ok()?;
            let frac_ms: i64 = format!("{frac:0<3}")[..3].parse().ok()?;
            whole.checked_mul(1_000)?.checked_add(frac_ms)?
        } else {
            digits.parse::<i64>().ok()?.checked_mul(unit_ms)?
        };
        millis = millis.checked_add(value)?;
        Some(())
    };
    let mut walk = |part: &str, units: &[(char, i64)]| -> Option<()> {
        let mut digits = String::new();
        let mut next_unit = 0;
        for c in part.chars() {
            if c.is_ascii_digit() || c == '.' {
                digits.push(c);
                continue;
            }
            let at = units[next_unit..].iter().position(|(u, _)| *u == c)? + next_unit;
            if digits.is_empty() {
                return None;
            }
            add(&digits, units[at].1)?;
            digits.clear();
            next_unit = at + 1;
        }
        digits.is_empty().then_some(())
    };
    const DAY: i64 = 86_400_000;
    walk(date, &[('Y', 365 * DAY), ('M', 30 * DAY), ('D', DAY)])?;
    if let Some(time) = time {
        walk(time, &[('H', 3_600_000), ('M', 60_000), ('S', 1_000)])?;
    }
    Some(Duration::milliseconds(millis))
}

/// The SSO URL's host moved between two fetches of one federation's metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SsoHostChange {
    /// The host the previous document named.
    pub old_host: String,
    /// The host the new document names.
    pub new_host: String,
}

/// Metadata as the SP uses it, and whether this resolution moved the SSO host.
#[derive(Debug, Clone)]
pub struct ResolvedIdpMetadata {
    /// The parsed document (from the cache or just fetched).
    pub metadata: IdpMetadata,
    /// `Some` only on a fetch whose SSO URL names another host than the entry
    /// it replaced in this process.
    pub sso_host_change: Option<SsoHostChange>,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    metadata_url: String,
    config_version: DateTime<Utc>,
    metadata: IdpMetadata,
    expires_at: DateTime<Utc>,
}

/// Per-process cache of parsed IdP metadata, keyed by federation
/// configuration. Cheap to clone; clones share the map.
#[derive(Clone, Default)]
pub struct SamlMetadataCache(Arc<Mutex<HashMap<Uuid, CacheEntry>>>);

impl SamlMetadataCache {
    /// An empty cache.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<Uuid, CacheEntry>> {
        // A panic while the lock was held leaves a map of whole entries; keep
        // using it rather than failing every sign-in.
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The configuration's IdP metadata: the cached entry when it was made
    /// from this configuration (same id, metadata URL and `updated_at`) and has
    /// not expired at `now`, otherwise `fetch`ed, verified, parsed and stored.
    ///
    /// The lock is never held across `fetch`: two misses at once both fetch,
    /// and the later store wins.
    ///
    /// # Errors
    ///
    /// [`FederationError::SamlMetadataFailed`] when the configuration has no
    /// metadata URL; otherwise whatever `fetch` or [`parse_idp_metadata`]
    /// returns. A failure stores nothing and leaves an earlier entry in place.
    pub async fn resolve<F, Fut>(
        &self,
        config: &FederationConfig,
        now: DateTime<Utc>,
        fetch: F,
    ) -> Result<ResolvedIdpMetadata, FederationError>
    where
        F: FnOnce(String) -> Fut,
        Fut: Future<Output = Result<String, FederationError>>,
    {
        let metadata_url = config
            .metadata_url
            .as_deref()
            .ok_or_else(|| metadata_failed("No metadata URL configured"))?;

        if let Some(entry) = self.entries().get(&config.id)
            && entry.metadata_url == metadata_url
            && entry.config_version == config.updated_at
            && now < entry.expires_at
        {
            return Ok(ResolvedIdpMetadata {
                metadata: entry.metadata.clone(),
                sso_host_change: None,
            });
        }

        let text = fetch(metadata_url.to_owned()).await?;
        let parsed =
            parse_idp_metadata(&text, config.idp_metadata_signing_cert_pem.as_deref(), now)?;
        let entry = CacheEntry {
            metadata_url: metadata_url.to_owned(),
            config_version: config.updated_at,
            metadata: parsed.metadata.clone(),
            expires_at: parsed.expires_at(now),
        };
        let previous = self.entries().insert(config.id, entry);

        let new_host = sso_host(&parsed.metadata.sso_url);
        let sso_host_change = previous
            .map(|p| sso_host(&p.metadata.sso_url))
            .filter(|old_host| *old_host != new_host)
            .map(|old_host| SsoHostChange { old_host, new_host });
        Ok(ResolvedIdpMetadata {
            metadata: parsed.metadata,
            sso_host_change,
        })
    }
}

/// The host of an SSO URL `parse_idp_metadata` accepted (so it parses).
fn sso_host(sso_url: &str) -> String {
    url::Url::parse(sso_url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    fn document(sso_url: &str, attributes: &str) -> String {
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.test" {attributes}><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"><md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{sso_url}"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
        )
    }

    fn config() -> FederationConfig {
        let mut config = crate::saml::tests::test_federation_config(None);
        config.metadata_url = Some("https://idp.example.test/metadata".into());
        config
    }

    /// A fetcher that serves `doc` and counts its calls.
    fn serving(
        doc: String,
        calls: &AtomicUsize,
    ) -> impl FnOnce(String) -> std::future::Ready<Result<String, FederationError>> + '_ {
        move |_url| {
            calls.fetch_add(1, Ordering::SeqCst);
            std::future::ready(Ok(doc))
        }
    }

    #[test]
    fn xs_durations_read_as_the_spec_writes_them() {
        assert_eq!(parse_xs_duration("PT1H"), Some(Duration::hours(1)));
        assert_eq!(parse_xs_duration("P1D"), Some(Duration::days(1)));
        assert_eq!(
            parse_xs_duration("P1DT2H3M4.5S"),
            Some(
                Duration::days(1)
                    + Duration::hours(2)
                    + Duration::minutes(3)
                    + Duration::milliseconds(4_500)
            )
        );
        assert_eq!(parse_xs_duration("PT90S"), Some(Duration::seconds(90)));
        assert_eq!(parse_xs_duration("P1M"), Some(Duration::days(30)));
        for bad in [
            "", "P", "PT", "-PT1H", "PT1H2D", "1H", "PTH", "P1.5D", "PT1H1H",
        ] {
            assert_eq!(parse_xs_duration(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn freshness_honours_cache_duration_under_the_cap_and_valid_until() {
        let now = Utc::now();
        let parsed = |valid_until, cache_duration| ParsedIdpMetadata {
            metadata: IdpMetadata {
                entity_id: String::new(),
                sso_url: String::new(),
                sso_binding: String::new(),
            },
            valid_until,
            cache_duration,
        };
        assert_eq!(parsed(None, None).expires_at(now), now + DEFAULT_TTL);
        assert_eq!(
            parsed(None, Some(Duration::hours(3))).expires_at(now),
            now + Duration::hours(3)
        );
        assert_eq!(
            parsed(None, Some(Duration::days(30))).expires_at(now),
            now + MAX_TTL
        );
        assert_eq!(
            parsed(None, Some(Duration::zero())).expires_at(now),
            now + MIN_TTL
        );
        // validUntil wins over every other bound, the floor included.
        let soon = now + Duration::minutes(2);
        assert_eq!(parsed(Some(soon), None).expires_at(now), soon);
        assert_eq!(
            parsed(Some(soon), Some(Duration::hours(3))).expires_at(now),
            soon
        );
    }

    #[test]
    fn a_document_past_its_valid_until_is_refused() {
        let now = Utc::now();
        let past = (now - Duration::minutes(1)).to_rfc3339();
        let err = parse_idp_metadata(
            &document(
                "https://sso.example.test/sso",
                &format!(r#"validUntil="{past}""#),
            ),
            None,
            now,
        )
        .unwrap_err();
        assert!(err.to_string().contains("validUntil"), "{err}");

        let future = (now + Duration::hours(2)).to_rfc3339();
        let parsed = parse_idp_metadata(
            &document(
                "https://sso.example.test/sso",
                &format!(r#"validUntil="{future}" cacheDuration="PT6H""#),
            ),
            None,
            now,
        )
        .unwrap();
        assert_eq!(parsed.cache_duration, Some(Duration::hours(6)));
        assert!(parsed.expires_at(now) <= now + Duration::hours(2));
    }

    #[test]
    fn metadata_carrying_a_dtd_is_refused_before_parsing() {
        let doc = format!(
            "<!DOCTYPE md:EntityDescriptor [<!ENTITY x \"y\">]>{}",
            document("https://sso.example.test/sso", "")
        );
        let err = parse_idp_metadata(&doc, None, Utc::now()).unwrap_err();
        assert!(err.to_string().contains("DTD"), "{err}");
    }

    /// #530: a second sign-in within the document's freshness is served from
    /// the cache; it is fetched again once the entry expires, and at once when
    /// the configuration is edited (its `updated_at` moves).
    #[tokio::test]
    async fn p23w3_07_metadata_is_cached_until_it_expires_or_the_configuration_changes() {
        let cache = SamlMetadataCache::new();
        let mut config = config();
        let doc = document("https://sso.example.test/sso", r#"cacheDuration="PT1H""#);
        let calls = AtomicUsize::new(0);
        let now = Utc::now();

        let first = cache
            .resolve(&config, now, serving(doc.clone(), &calls))
            .await
            .unwrap();
        assert_eq!(first.metadata.sso_url, "https://sso.example.test/sso");
        assert!(first.sso_host_change.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // A hit: no second fetch within the hour.
        let hit = cache
            .resolve(
                &config,
                now + Duration::minutes(59),
                serving(doc.clone(), &calls),
            )
            .await
            .unwrap();
        assert_eq!(hit.metadata.sso_url, first.metadata.sso_url);
        assert_eq!(calls.load(Ordering::SeqCst), 1, "served from the cache");

        // Expired: fetched again.
        cache
            .resolve(
                &config,
                now + Duration::hours(1),
                serving(doc.clone(), &calls),
            )
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2, "refetched after expiry");

        // An edited configuration misses at once.
        config.updated_at += Duration::seconds(1);
        cache
            .resolve(
                &config,
                now + Duration::hours(1),
                serving(doc.clone(), &calls),
            )
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 3, "an edit invalidates");

        // So does a new metadata URL.
        config.metadata_url = Some("https://idp.example.test/other".into());
        cache
            .resolve(&config, now + Duration::hours(1), serving(doc, &calls))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 4);
    }

    /// A failed refetch stores nothing: the next sign-in tries again rather
    /// than being served a document that was never verified.
    #[tokio::test]
    async fn a_refused_document_is_not_cached() {
        let cache = SamlMetadataCache::new();
        let config = config();
        let calls = AtomicUsize::new(0);
        let now = Utc::now();
        let insecure = document("http://sso.example.test/sso", "");
        assert!(
            cache
                .resolve(&config, now, serving(insecure, &calls))
                .await
                .is_err()
        );
        let good = document("https://sso.example.test/sso", "");
        cache
            .resolve(&config, now, serving(good, &calls))
            .await
            .unwrap();
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    /// #530: a refetch whose SSO URL names another host reports the move, once;
    /// a new path on the same host is not a move.
    #[tokio::test]
    async fn p23w3_07_a_refetch_that_moves_the_sso_host_is_reported() {
        let cache = SamlMetadataCache::new();
        let mut config = config();
        let calls = AtomicUsize::new(0);
        let now = Utc::now();

        cache
            .resolve(
                &config,
                now,
                serving(document("https://sso.example.test/a", ""), &calls),
            )
            .await
            .unwrap();

        config.updated_at += Duration::seconds(1);
        let same_host = cache
            .resolve(
                &config,
                now,
                serving(document("https://SSO.example.test/b", ""), &calls),
            )
            .await
            .unwrap();
        assert!(same_host.sso_host_change.is_none());

        config.updated_at += Duration::seconds(1);
        let moved = cache
            .resolve(
                &config,
                now,
                serving(document("https://phish.example.net/sso", ""), &calls),
            )
            .await
            .unwrap();
        assert_eq!(
            moved.sso_host_change,
            Some(SsoHostChange {
                old_host: "sso.example.test".into(),
                new_host: "phish.example.net".into(),
            })
        );
        // Served from the cache afterwards: nothing more to report.
        let hit = cache
            .resolve(
                &config,
                now,
                serving(document("https://other.example.org/sso", ""), &calls),
            )
            .await
            .unwrap();
        assert!(hit.sso_host_change.is_none());
        assert_eq!(hit.metadata.sso_url, "https://phish.example.net/sso");
    }
}

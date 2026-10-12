//! Certificate revocation lists — one per issuing CA (RFC 5280 §5; #565,
//! T-102).
//!
//! Revoking a certificate sets the status on its row. Until this module that
//! status reached exactly the places that read the row — device sign-in, and
//! since the same change OAuth2 `tls_client_auth` — and nowhere else: a
//! relying party that validates AXIAM-issued certificates itself, a FreeRADIUS
//! server doing EAP-TLS or a VPN gateway, had no channel through which to learn
//! of a revocation, although every AXIAM CA carries the `cRLSign` bit.
//!
//! # What is published
//!
//! A complete, version 2 CRL per issuing CA, DER-encoded, at
//! `GET /pki/v1/{org_id}/ca/{ca_id}/crl` ([`crl_path`]), unauthenticated:
//!
//! - **signed with the CA's own key, fetched from the CA's own custodian** —
//!   the custodian the CA row names, through the same `load` the leaf path
//!   uses, so an RSA-4096 CA and an Ed25519 CA sign their lists exactly as they
//!   sign certificates;
//! - `thisUpdate` the moment it was signed, `nextUpdate` a configurable
//!   interval later ([`DEFAULT_CRL_NEXT_UPDATE_SECS`]) and never past the CA's
//!   own `notAfter`;
//! - a CRL number and an authority key identifier equal to the CA's subject key
//!   identifier — the two extensions RFC 5280 §5.2 requires of every CRL;
//! - an entry for every certificate the CA signed and revoked that has not yet
//!   expired: its leaves in every tenant, and the subordinate CAs it signed, so
//!   an organization CA's list names a revoked tenant signing CA. Each entry
//!   carries the serial read out of the certificate and the date AXIAM recorded
//!   the revocation. No reason code: AXIAM does not record one, and RFC 5280
//!   §5.3.1 prefers an absent reason to `unspecified`.
//!
//! # Which CAs publish one
//!
//! A CA AXIAM can sign with, while it is active and in date. Three kinds
//! answer `404` instead, the same `404` as a CA that does not exist:
//!
//! - **a revoked or expired CA.** AXIAM signs nothing with one; its own status
//!   is on its parent's list;
//! - **an imported trust anchor with no key** (`external` custody): it cannot
//!   sign anything, a list included;
//! - **a CA whose key Vault's PKI engine holds** (`vault_pki`). Vault signs on
//!   AXIAM's behalf only certificate requests; it has no operation that signs a
//!   list AXIAM composed, and AXIAM never holds the key. Vault publishes that
//!   CA's list itself, and AXIAM revokes each leaf there too
//!   ([`crate::CertService::revoke`], T-470), so Vault's list names it. Leaves of
//!   such a CA carry no AXIAM distribution point — Vault issues them with its
//!   own profile, naming whatever the operator configured on the mount
//!   (`config/urls`) — so nothing points at a route that cannot answer, and
//!   relying parties read Vault's list (`/v1/<mount>/issuer/<issuer>/crl/der`).
//!
//! # Signing on request, and the cache in front of it
//!
//! A list is signed when it is first asked for and kept, per CA, until either
//! the set of revoked certificates changes or half of its validity has passed;
//! every request still reads the set, so a revocation is in the next response.
//! Two things follow. A relying party revalidating with `If-None-Match` gets a
//! `304` until the list really changes, because an unchanged list is the same
//! bytes. And a flood of requests costs one database read each and no
//! signature, which matters on an unauthenticated route whose custodian may be
//! a Vault round trip away.
//!
//! That read is light (#607): each revoked certificate's fingerprint and the
//! date its entry states, never the certificate. The PEMs — what an entry's
//! serial is read from — are read only when the list is actually signed.
//!
//! Each CA is re-signed on its own (#607). One request at a time re-signs a
//! given CA's list, through the custodian `load`, the crypto permit and the
//! signature; requests for the same CA's changed list wait for it, and nothing
//! else does. A cached list is answered without waiting on any re-sign, this
//! CA's or another's. The permit comes from the semaphore issuance and password
//! hashing share, and a re-sign waits for one at most
//! [`DEFAULT_CRL_PERMIT_WAIT`]; past that the route answers `503` rather than
//! queueing an unauthenticated caller without bound.
//!
//! The CRL number is the signing time in milliseconds since the Unix epoch,
//! and strictly greater than the last number this process issued for the CA.
//! Monotonic across replicas and restarts for as long as the clocks are, which
//! is what RFC 5280 §5.2.3 asks of it, without a counter every replica would
//! have to agree on.
//!
//! # The distribution point
//!
//! [`CrlDistribution`] is the absolute URL of the route, built from the
//! deployment's public base URL. `CertService` and `CaService` write it into
//! every certificate they sign in-process from then on — leaves on both paths,
//! and subordinate CAs — so a relying party that follows distribution points
//! finds the list without being told. With no public base URL there is no
//! absolute URL to write, and the extension is omitted; the composition root
//! says so at boot.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, PoisonError};

use axiam_core::ca_keys::CaKeyCustody;
use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::certificate::{CaCertificate, CertificateStatus, RevokedCertificate};
use axiam_core::repository::{CaCertificateRepository, CertificateRepository};
use chrono::{DateTime, Duration, Utc};
use rcgen::{
    CertificateRevocationListParams, CrlDistributionPoint, Issuer, KeyIdMethod, KeyPair,
    RevokedCertParams, SerialNumber,
};
use sha2::{Digest, Sha256};
use tokio::sync::{Mutex, Semaphore};
use uuid::Uuid;
use x509_parser::extensions::ParsedExtension;
use x509_parser::prelude::{FromDer, X509Certificate};
use zeroize::Zeroize;

use crate::ca::CaService;
use crate::ca_key_store::CaKeyCustodians;

/// The media type a DER CRL is served as (RFC 5280 §4.2.1.13).
pub const CRL_MEDIA_TYPE: &str = "application/pkix-crl";

/// Default interval between a list's `thisUpdate` and its `nextUpdate`: one
/// day. Env: `AXIAM__PKI__CRL_NEXT_UPDATE_SECS`.
///
/// It bounds how long a relying party that caches a list honours a certificate
/// revoked after the list was fetched, which is the revocation window this
/// whole module exists to shorten. A day is the common choice for a CA whose
/// relying parties fetch on schedule; a deployment that needs a shorter window
/// sets a shorter interval and pays for it in fetches.
pub const DEFAULT_CRL_NEXT_UPDATE_SECS: u64 = 86_400;

/// Shortest accepted interval: five minutes. Below it a relying party would
/// spend more time fetching the list than trusting it.
pub const MIN_CRL_NEXT_UPDATE_SECS: u64 = 300;

/// Longest accepted interval: seven days. Past it the list stops being a
/// revocation channel anybody should rely on.
pub const MAX_CRL_NEXT_UPDATE_SECS: u64 = 604_800;

/// The route a CA's list is published at, relative to the deployment's public
/// base URL.
pub fn crl_path(organization_id: Uuid, ca_id: Uuid) -> String {
    format!("/pki/v1/{organization_id}/ca/{ca_id}/crl")
}

/// Check an operator's `nextUpdate` interval against
/// [`MIN_CRL_NEXT_UPDATE_SECS`] and [`MAX_CRL_NEXT_UPDATE_SECS`].
pub fn validate_next_update_secs(secs: u64) -> Result<u64, String> {
    if (MIN_CRL_NEXT_UPDATE_SECS..=MAX_CRL_NEXT_UPDATE_SECS).contains(&secs) {
        Ok(secs)
    } else {
        Err(format!(
            "the CRL nextUpdate interval must be between {MIN_CRL_NEXT_UPDATE_SECS} and \
             {MAX_CRL_NEXT_UPDATE_SECS} seconds, not {secs}"
        ))
    }
}

/// Where a relying party finds a CA's list: the absolute URL written into the
/// CRL distribution points extension of every certificate signed after it is
/// configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CrlDistribution {
    /// `scheme://host[:port][/path]`, with no trailing slash.
    base: String,
}

impl CrlDistribution {
    /// Validate a public base URL: absolute, `http` or `https`, with a host,
    /// no userinfo and no query or fragment.
    ///
    /// What is stored is the parser's own serialisation of what was validated
    /// (without the trailing slash), not the operator's text: the parser drops
    /// tabs and newlines, lowercases the host and percent-encodes what needs
    /// it, so the URI written into certificates is exactly the URL that passed
    /// these checks.
    ///
    /// `http` is accepted on purpose. A CRL is signed, so the transport adds no
    /// integrity, and RFC 5280 §4.2.1.13 expects distribution points that a
    /// relying party can fetch before it can validate anything — some cannot
    /// follow an `https` one without the chain they are trying to check.
    pub fn new(base_url: &str) -> Result<Self, String> {
        let trimmed = base_url.trim();
        let parsed = url::Url::parse(trimmed)
            .map_err(|e| format!("the CRL base URL is not an absolute URL: {e}"))?;
        if !matches!(parsed.scheme(), "http" | "https") {
            return Err(format!(
                "the CRL base URL must be http or https, not {}",
                parsed.scheme()
            ));
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err("the CRL base URL has no host".into());
        }
        if parsed.query().is_some() || parsed.fragment().is_some() {
            return Err("the CRL base URL must carry no query or fragment".into());
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err("the CRL base URL must carry no credentials (userinfo)".into());
        }
        Ok(Self {
            base: parsed.as_str().trim_end_matches('/').to_owned(),
        })
    }

    /// The distribution point configured explicitly, or else the one derived
    /// from the deployment's issuer URL — `None` when neither is an absolute
    /// `http(s)` URL.
    ///
    /// An explicit value that does not parse is an error rather than a
    /// fallback: an operator who set one meant it, and certificates naming the
    /// issuer instead would point somewhere they did not choose. An issuer that
    /// is not a URL (the JWT `iss` fallback is often a bare name) yields `None`.
    pub fn resolve(explicit: Option<&str>, issuer_url: &str) -> Result<Option<Self>, String> {
        match explicit.map(str::trim).filter(|v| !v.is_empty()) {
            Some(value) => Self::new(value).map(Some),
            None => Ok(Self::new(issuer_url).ok()),
        }
    }

    /// The absolute URL of a CA's list.
    pub fn uri_for(&self, organization_id: Uuid, ca_id: Uuid) -> String {
        format!("{}{}", self.base, crl_path(organization_id, ca_id))
    }

    /// The extension value for a certificate `issuer` signs.
    pub(crate) fn point_for(&self, issuer: &CaCertificate) -> CrlDistributionPoint {
        CrlDistributionPoint {
            uris: vec![self.uri_for(issuer.organization_id, issuer.id)],
        }
    }
}

/// A signed list, as the route serves it.
#[derive(Debug, Clone)]
pub struct PublishedCrl {
    /// The DER encoding.
    pub der: Arc<[u8]>,
    /// The list's `thisUpdate`.
    pub this_update: DateTime<Utc>,
    /// The list's `nextUpdate`.
    pub next_update: DateTime<Utc>,
    /// The list's CRL number.
    pub crl_number: u64,
    /// A strong entity tag over the DER, quoted.
    pub etag: String,
}

impl PublishedCrl {
    /// Seconds a cache may keep this list: until its `nextUpdate`, never
    /// negative.
    pub fn max_age_secs(&self, now: DateTime<Utc>) -> u64 {
        u64::try_from((self.next_update - now).num_seconds().max(0)).unwrap_or(0)
    }

    /// Whether an `If-None-Match` header names this list (RFC 9110 §13.1.2):
    /// `*`, or any listed tag equal to [`Self::etag`], weak or strong.
    pub fn matches_if_none_match(&self, header: &str) -> bool {
        let wanted = self.etag.trim_start_matches("W/");
        header
            .split(',')
            .map(str::trim)
            .any(|candidate| candidate == "*" || candidate.trim_start_matches("W/") == wanted)
    }
}

/// What the cache keeps per CA.
struct CachedCrl {
    crl: PublishedCrl,
    /// Digest of the entries the list was signed over.
    entries_digest: [u8; 32],
    /// When the list is re-signed even if nothing was revoked: half-way to its
    /// `nextUpdate`, so a cached response always has half its life left.
    refresh_at: DateTime<Utc>,
}

/// One CA's place in the cache: its last list, and the right to re-sign it
/// (#607).
///
/// Two locks, so that reading never waits on signing. `published` is held only
/// to look at or replace the cached list — never across an `await` — and
/// `signing` is held by the one request re-signing this CA's list, through the
/// custodian `load`, the crypto permit and the signature. A request for an
/// unchanged list takes only the first; a request for a changed list queues on
/// the second behind the re-sign already in flight for the same CA, and on
/// nothing any other CA is doing.
#[derive(Default)]
struct CaSlot {
    published: StdMutex<Option<CachedCrl>>,
    signing: Mutex<()>,
}

impl CaSlot {
    /// The cached list, if it was signed over exactly `digest` and is not yet
    /// due for its refresh.
    fn fresh(&self, digest: &[u8; 32], now: DateTime<Utc>) -> Option<PublishedCrl> {
        let published = self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        published
            .as_ref()
            .filter(|cached| cached.entries_digest == *digest && now < cached.refresh_at)
            .map(|cached| cached.crl.clone())
    }

    /// The CRL number of the last list signed, if any.
    fn last_number(&self) -> Option<u64> {
        let published = self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        published.as_ref().map(|cached| cached.crl.crl_number)
    }

    fn store(&self, cached: CachedCrl) {
        *self
            .published
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(cached);
    }
}

/// How long a re-sign waits for a permit of the shared crypto semaphore before
/// the route answers `503` (#607): five seconds, the default wait of the
/// password-hash gate the semaphore also serves.
///
/// The semaphore is shared with issuance and with every Argon2id hash and
/// verify. Without a bound a saturated gate would queue unauthenticated CRL
/// requests without limit; with it, a caller is told to come back, and a cached
/// list — which needs no permit — is served throughout.
pub const DEFAULT_CRL_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// Signs and caches each issuing CA's certificate revocation list.
#[derive(Clone)]
pub struct CrlService<CA, CR> {
    ca_repo: CA,
    cert_repo: CR,
    /// Shared bounding semaphore for CPU-bound crypto (CQ-B02).
    crypto_semaphore: Arc<Semaphore>,
    /// How long a re-sign waits for a crypto permit ([`DEFAULT_CRL_PERMIT_WAIT`]).
    permit_wait: std::time::Duration,
    /// Who holds the CA signing keys. See [`crate::ca_key_store`].
    custodians: Arc<CaKeyCustodians>,
    next_update: Duration,
    /// One slot per CA that publishes a list. The map's lock is held only to
    /// find or insert a slot, and a slot is inserted only for a CA that exists
    /// and publishes one, so requests for made-up CA ids — the route is
    /// unauthenticated — add nothing to it; a CA found to publish no list
    /// (revoked or expired since) has its slot removed.
    slots: Arc<StdMutex<HashMap<Uuid, Arc<CaSlot>>>>,
}

impl<CA: CaCertificateRepository, CR: CertificateRepository> CrlService<CA, CR> {
    /// `next_update_secs` is the `thisUpdate` → `nextUpdate` interval; the
    /// composition root validates it with [`validate_next_update_secs`].
    pub fn new(
        ca_repo: CA,
        cert_repo: CR,
        crypto_semaphore: Arc<Semaphore>,
        custodians: Arc<CaKeyCustodians>,
        next_update_secs: u64,
    ) -> Self {
        Self {
            ca_repo,
            cert_repo,
            crypto_semaphore,
            permit_wait: DEFAULT_CRL_PERMIT_WAIT,
            custodians,
            next_update: Duration::seconds(i64::try_from(next_update_secs).unwrap_or(i64::MAX)),
            slots: Arc::default(),
        }
    }

    /// Replace [`DEFAULT_CRL_PERMIT_WAIT`].
    #[must_use]
    pub fn with_permit_wait(mut self, wait: std::time::Duration) -> Self {
        self.permit_wait = wait;
        self
    }

    /// The current list of CA `ca_id` of organization `organization_id`.
    ///
    /// `NotFound` for a CA that does not exist in that organization **and** for
    /// one that publishes no list (see the module docs): the route is
    /// unauthenticated, and which of the two it is — or which custodian holds a
    /// key — is not an outsider's business. The reason is logged.
    ///
    /// `ServiceUnavailable` when the list has to be signed and no crypto permit
    /// came free within the permit wait ([`Self::with_permit_wait`]).
    pub async fn current(&self, organization_id: Uuid, ca_id: Uuid) -> AxiamResult<PublishedCrl> {
        let not_published = || AxiamError::NotFound {
            entity: "certificate revocation list".into(),
            id: ca_id.to_string(),
        };

        // Organization-scoped, as every CA lookup is (T-98): a CA id under the
        // wrong organization is not found, not served.
        let ca = match self.ca_repo.get_by_id(organization_id, ca_id).await {
            Ok(ca) => ca,
            Err(AxiamError::NotFound { .. }) => return Err(not_published()),
            Err(e) => return Err(e),
        };
        let now = Utc::now();
        if let Some(reason) = Self::why_unpublished(&ca, now) {
            tracing::debug!(%organization_id, %ca_id, reason, "no CRL is published for this CA");
            self.forget(ca.id);
            return Err(not_published());
        }
        let store = self.custodians.store_for(ca.key_custody)?;
        if store.signs_remotely() {
            tracing::debug!(
                %organization_id,
                %ca_id,
                "no CRL is published for this CA: its key is held by a custodian that signs \
                 certificate requests only (vault_pki), and publishes the CA's list itself"
            );
            self.forget(ca.id);
            return Err(not_published());
        }

        // Read on every request, and before any lock: a revocation is in the
        // very next response. Only fingerprints and dates (#607) — whether the
        // list changed is decided without reading a single certificate.
        let mut stamps = self
            .cert_repo
            .list_revocation_stamps_by_issuer(ca.id)
            .await?;
        stamps.extend(self.ca_repo.list_revoked_children_stamps(ca.id).await?);
        stamps.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let digest = entries_digest(stamps.iter().map(|s| {
            (
                s.fingerprint.as_str(),
                revocation_time(s.revoked_at, s.not_before),
            )
        }));

        let slot = self.slot(ca.id);
        if let Some(crl) = slot.fresh(&digest, now) {
            return Ok(crl);
        }

        // One re-sign per CA at a time. A request that waited here finds the
        // list the one ahead of it signed, when that list is of the state this
        // request read.
        let _flight = slot.signing.lock().await;
        let now = Utc::now();
        if let Some(crl) = slot.fresh(&digest, now) {
            return Ok(crl);
        }

        // The certificates, read only to sign — and read again rather than
        // trusted from the stamps, so the list is of the state as it is now.
        let mut entries = self.cert_repo.list_revoked_by_issuer(ca.id).await?;
        entries.extend(self.ca_repo.list_revoked_children(ca.id).await?);
        entries.sort_by(|a, b| a.fingerprint.cmp(&b.fingerprint));
        let digest = entries_digest(entries.iter().map(|e| {
            (
                e.fingerprint.as_str(),
                revocation_time(e.revoked_at, e.not_before),
            )
        }));
        let last_number = slot.last_number();

        // Whole seconds: a CRL's times are encoded to the second, and the
        // `Last-Modified` header and the list must say the same thing.
        let this_update = DateTime::from_timestamp(now.timestamp(), 0).unwrap_or(now);
        let next_update = (this_update + self.next_update).min(ca.not_after);
        if next_update <= this_update {
            tracing::debug!(%organization_id, %ca_id, "no CRL is published: the CA expires now");
            return Err(not_published());
        }
        let crl_number = u64::try_from(now.timestamp_millis())
            .unwrap_or(0)
            .max(last_number.map_or(0, |n| n.saturating_add(1)));

        let key_ref = CaService::<CA>::key_ref(&ca);
        let ca_key_pem = store
            .load(&key_ref, ca.encrypted_private_key.as_deref())
            .await?
            .to_string();
        let _permit = self.crypto_permit(organization_id, ca_id).await?;
        let ca_cert_pem = ca.public_cert_pem.clone();
        let der = tokio::task::spawn_blocking(move || {
            sign_crl(
                &ca_cert_pem,
                ca_key_pem,
                &entries,
                this_update,
                next_update,
                crl_number,
            )
        })
        .await
        .map_err(|e| AxiamError::Internal(format!("spawn_blocking join error: {e}")))??;

        let etag = format!("\"{}\"", hex::encode(&Sha256::digest(&der)[..16]));
        let crl = PublishedCrl {
            der: Arc::from(der),
            this_update,
            next_update,
            crl_number,
            etag,
        };
        slot.store(CachedCrl {
            crl: crl.clone(),
            entries_digest: digest,
            refresh_at: this_update + (next_update - this_update) / 2,
        });
        Ok(crl)
    }

    /// A permit of the shared crypto semaphore, or `ServiceUnavailable` once
    /// the permit wait has passed (#607).
    async fn crypto_permit(
        &self,
        organization_id: Uuid,
        ca_id: Uuid,
    ) -> AxiamResult<tokio::sync::SemaphorePermit<'_>> {
        match tokio::time::timeout(self.permit_wait, self.crypto_semaphore.acquire()).await {
            Ok(Ok(permit)) => Ok(permit),
            Ok(Err(_closed)) => Err(AxiamError::Internal("crypto semaphore closed".into())),
            Err(_elapsed) => {
                tracing::warn!(
                    %organization_id,
                    %ca_id,
                    wait_ms = u64::try_from(self.permit_wait.as_millis()).unwrap_or(u64::MAX),
                    "the CRL could not be re-signed: no crypto permit came free in time"
                );
                Err(AxiamError::ServiceUnavailable(
                    "the certificate revocation list cannot be signed right now; retry shortly"
                        .into(),
                ))
            }
        }
    }

    /// The slot of a CA that publishes a list, inserted on first use.
    fn slot(&self, ca_id: Uuid) -> Arc<CaSlot> {
        let mut slots = self.slots.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(slots.entry(ca_id).or_default())
    }

    /// Drop the slot of a CA that no longer publishes a list.
    fn forget(&self, ca_id: Uuid) {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&ca_id);
    }

    /// How many CAs the cache holds a slot for.
    #[doc(hidden)]
    pub fn cached_ca_count(&self) -> usize {
        self.slots
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }

    /// Why `ca` publishes no list, if it does not — the reasons that need no
    /// custodian to answer.
    fn why_unpublished(ca: &CaCertificate, now: DateTime<Utc>) -> Option<&'static str> {
        if ca.status != CertificateStatus::Active {
            return Some("the CA is not active; its own status is on its parent's list");
        }
        if now < ca.not_before || now >= ca.not_after {
            return Some("the CA is outside its validity window");
        }
        if ca.key_custody == CaKeyCustody::External {
            return Some("AXIAM holds no key for this CA: it was imported as a trust anchor");
        }
        None
    }
}

/// A digest that changes exactly when the list's entries would: over each
/// entry's fingerprint and stated date, in fingerprint order.
fn entries_digest<'a>(entries: impl Iterator<Item = (&'a str, DateTime<Utc>)>) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (fingerprint, revoked) in entries {
        hasher.update(fingerprint.as_bytes());
        hasher.update(b":");
        hasher.update(revoked.timestamp().to_be_bytes());
        hasher.update(b"\n");
    }
    hasher.finalize().into()
}

/// The date an entry states: when AXIAM recorded the revocation, or — for a
/// certificate revoked before the date was kept — its own `notBefore`, the
/// earliest moment anyone could have relied on it.
fn revocation_time(revoked_at: Option<DateTime<Utc>>, not_before: DateTime<Utc>) -> DateTime<Utc> {
    revoked_at.unwrap_or(not_before)
}

fn to_offset(t: DateTime<Utc>) -> AxiamResult<time::OffsetDateTime> {
    time::OffsetDateTime::from_unix_timestamp(t.timestamp())
        .map_err(|e| AxiamError::Internal(format!("CRL time out of range: {e}")))
}

/// Sign a CRL over `entries` with the CA's key. Pure and blocking — the caller
/// runs it under the crypto semaphore, off the async runtime.
///
/// A revoked certificate whose PEM does not parse fails the whole list rather
/// than being left off it: a list that silently omits a revocation is worse
/// than no list, because a relying party trusts what it says.
pub(crate) fn sign_crl(
    ca_cert_pem: &str,
    mut ca_key_pem: String,
    entries: &[RevokedCertificate],
    this_update: DateTime<Utc>,
    next_update: DateTime<Utc>,
    crl_number: u64,
) -> AxiamResult<Vec<u8>> {
    let key_pair = KeyPair::from_pem(&ca_key_pem)
        .map_err(|e| AxiamError::Certificate(format!("invalid CA private key: {e}")));
    // Scrubbed as soon as it is parsed, as on the leaf path.
    ca_key_pem.zeroize();
    let key_pair = key_pair?;

    // The authority key identifier must equal the CA certificate's subject key
    // identifier, whatever method produced it — an imported CA's is usually a
    // SHA-1 of its key, not rcgen's default — so it is read from the
    // certificate rather than derived again.
    let (_, ca_block) = x509_parser::pem::parse_x509_pem(ca_cert_pem.as_bytes())
        .map_err(|e| AxiamError::Certificate(format!("invalid CA certificate PEM: {e}")))?;
    let (_, ca_x509) = X509Certificate::from_der(&ca_block.contents)
        .map_err(|e| AxiamError::Certificate(format!("invalid CA certificate: {e}")))?;
    let key_identifier_method = ca_x509
        .extensions()
        .iter()
        .find_map(|ext| match ext.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(kid) => Some(kid.0.to_vec()),
            _ => None,
        })
        .map_or(KeyIdMethod::Sha256, KeyIdMethod::PreSpecified);

    let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, key_pair)
        .map_err(|e| AxiamError::Certificate(format!("invalid CA certificate PEM: {e}")))?;

    let revoked_certs = entries
        .iter()
        .map(|entry| {
            let (_, block) = x509_parser::pem::parse_x509_pem(entry.public_cert_pem.as_bytes())
                .map_err(|e| {
                    AxiamError::Internal(format!(
                        "revoked certificate {} is not PEM: {e}",
                        entry.fingerprint
                    ))
                })?;
            let (_, cert) = X509Certificate::from_der(&block.contents).map_err(|e| {
                AxiamError::Internal(format!(
                    "revoked certificate {} does not parse: {e}",
                    entry.fingerprint
                ))
            })?;
            Ok(RevokedCertParams {
                serial_number: SerialNumber::from_slice(&cert.serial.to_bytes_be()),
                revocation_time: to_offset(revocation_time(entry.revoked_at, entry.not_before))?,
                reason_code: None,
                invalidity_date: None,
            })
        })
        .collect::<AxiamResult<Vec<_>>>()?;

    let params = CertificateRevocationListParams {
        this_update: to_offset(this_update)?,
        next_update: to_offset(next_update)?,
        crl_number: SerialNumber::from(crl_number),
        // A complete list: every certificate this CA signed, leaves and CAs.
        issuing_distribution_point: None,
        revoked_certs,
        key_identifier_method,
    };
    let crl = params
        .signed_by(&issuer)
        .map_err(|e| AxiamError::Certificate(format!("CRL signing failed: {e}")))?;
    Ok(crl.der().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_route_is_the_one_the_distribution_point_names() {
        let org = Uuid::new_v4();
        let ca = Uuid::new_v4();
        let distribution = CrlDistribution::new("https://id.example.com/").unwrap();
        assert_eq!(
            distribution.uri_for(org, ca),
            format!("https://id.example.com/pki/v1/{org}/ca/{ca}/crl")
        );
    }

    #[test]
    fn a_base_url_must_be_absolute_http_with_no_query() {
        for bad in [
            "id.example.com",
            "ftp://id.example.com",
            "https://id.example.com/?a=b",
            "https://id.example.com/#x",
            "",
        ] {
            assert!(
                CrlDistribution::new(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
        assert!(CrlDistribution::new("http://crl.internal:8080/axiam").is_ok());
    }

    #[test]
    fn the_stored_base_is_the_parsed_url_without_a_trailing_slash() {
        let org = Uuid::new_v4();
        let ca = Uuid::new_v4();
        for (given, base) in [
            ("https://id.example.com/", "https://id.example.com"),
            (
                "https://id.example.com/axiam/",
                "https://id.example.com/axiam",
            ),
            // The parser removes tabs and newlines anywhere in the input...
            (
                "https://id.exa\tmple.com/ax\niam",
                "https://id.example.com/axiam",
            ),
            (
                "  https://id.example.com/a\r\nb/  ",
                "https://id.example.com/ab",
            ),
            // ...lowercases the host and drops a default port...
            (
                "HTTPS://ID.Example.COM:443/axiam",
                "https://id.example.com/axiam",
            ),
            // ...and percent-encodes what a path may not carry verbatim.
            ("https://id.example.com/a b", "https://id.example.com/a%20b"),
            (
                "https://id.example.com/caf\u{e9}",
                "https://id.example.com/caf%C3%A9",
            ),
        ] {
            let distribution = CrlDistribution::new(given).unwrap();
            assert_eq!(distribution.base, base, "{given:?}");
            assert_eq!(
                distribution.uri_for(org, ca),
                format!("{base}/pki/v1/{org}/ca/{ca}/crl"),
                "{given:?}"
            );
        }
    }

    #[test]
    fn a_base_url_with_userinfo_is_refused() {
        for bad in [
            "https://user:pw@id.example.com/axiam",
            "https://user@id.example.com/axiam",
            "http://:pw@id.example.com",
        ] {
            assert!(
                CrlDistribution::new(bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    #[test]
    fn resolve_prefers_the_explicit_value_and_never_falls_back_from_a_bad_one() {
        let issuer = "https://id.example.com";
        assert_eq!(
            CrlDistribution::resolve(None, issuer).unwrap(),
            Some(CrlDistribution::new(issuer).unwrap())
        );
        assert_eq!(
            CrlDistribution::resolve(Some("http://crl.internal"), issuer).unwrap(),
            Some(CrlDistribution::new("http://crl.internal").unwrap())
        );
        assert!(CrlDistribution::resolve(Some("not a url"), issuer).is_err());
        // The JWT issuer fallback is often a bare name: no distribution point.
        assert_eq!(CrlDistribution::resolve(None, "axiam").unwrap(), None);
        assert_eq!(CrlDistribution::resolve(Some("  "), "axiam").unwrap(), None);
    }

    #[test]
    fn the_interval_is_bounded() {
        assert!(validate_next_update_secs(DEFAULT_CRL_NEXT_UPDATE_SECS).is_ok());
        assert!(validate_next_update_secs(MIN_CRL_NEXT_UPDATE_SECS - 1).is_err());
        assert!(validate_next_update_secs(MAX_CRL_NEXT_UPDATE_SECS + 1).is_err());
    }

    #[test]
    fn if_none_match_accepts_star_lists_and_weak_tags() {
        let crl = PublishedCrl {
            der: Arc::from(vec![1u8, 2, 3]),
            this_update: Utc::now(),
            next_update: Utc::now(),
            crl_number: 1,
            etag: "\"abc\"".into(),
        };
        assert!(crl.matches_if_none_match("\"abc\""));
        assert!(crl.matches_if_none_match("\"x\", W/\"abc\""));
        assert!(crl.matches_if_none_match("*"));
        assert!(!crl.matches_if_none_match("\"abd\""));
    }
}

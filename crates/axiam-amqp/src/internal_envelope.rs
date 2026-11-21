//! The signed envelope of the server-internal queues (SA-14, N3).
//!
//! `axiam.mail.outbound` and the four outbound kinds' queues (`axiam.webhook`,
//! `axiam.ssf_push`, `axiam.scim_push`, `axiam.ciba_ping` and their retry
//! queues) are written and read only by AXIAM itself, yet what their consumers
//! do with a message is the server's most trusted output: tenant-branded mail
//! through the tenant's provider, webhook POSTs signed with the webhook's
//! secret, Security Event Tokens signed with the deployment key. Until SA-14
//! they decoded plain JSON, so broker write access to a queue was control-plane
//! authority.
//!
//! Every message on those queues now travels inside an [`InternalEnvelope`]
//! carrying the same §8 v2 protections as the authorization and audit queues —
//! an HMAC-SHA256 over the canonical JSON, a `key_version`, a per-message
//! `nonce` recorded in the durable replay store, and an `issued_at` freshness
//! gate — with one difference that is the point of this module: the key is
//! **server-only**. It is derived from the master key under a distinct HKDF
//! label ([`derive_internal_key`]), not from a tenant's subkey, so the subkey
//! a tenant's own producers hold for the authz and audit queues cannot sign a
//! message here. The `purpose` (one per queue family) is mixed into the
//! derivation as well, so a signed mail message cannot be replayed onto a
//! webhook queue or the reverse.
//!
//! The body inside the envelope is exactly the JSON each queue carried before
//! (`OutboundMailMessage`, `WebhookMessage`, `OutboundMessage`), so the
//! envelope adds authentication without redefining any message.
//!
//! **Rolling upgrade.** A consumer verifies every envelope it receives. What it
//! does with a message in the old, un-enveloped shape is
//! `AXIAM__AMQP__INTERNAL_QUEUES__REQUIRE_SIGNATURE`: `true` (the default)
//! rejects it; `false` accepts it with a warning, for the one deployment in
//! which old and new replicas share the queues (see the upgrade notes in
//! `docs/deployment/README.md`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axiam_core::error::{AxiamError, AxiamResult};
use axiam_core::models::audit::{ActorType, AuditOutcome, CreateAuditLogEntry};
use axiam_core::outbound::OutboundKind;
use axiam_core::repository::AmqpNonceRepository;
use chrono::{DateTime, Utc};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use uuid::Uuid;

use crate::messages::{
    APP_SALT, CURRENT_KEY_VERSION, MIN_ACCEPTED_KEY_VERSION, is_fresh, sign_payload, verify_payload,
};

/// HKDF `info` prefix of the server-only key. Distinct from the per-tenant
/// tag (`axiam-amqp-v1`) from its twelfth byte on, so no tenant subkey
/// derivation can produce the same `info`, and therefore the same key.
const INTERNAL_DOMAIN_TAG: &[u8] = b"axiam-amqp-internal-v1";

/// The `purpose` of the mail queue's envelope.
pub const MAIL_PURPOSE: &str = "mail";

/// The audit action of a message an internal-queue consumer refused.
pub const REJECTED_ACTION: &str = "amqp.internal_message_rejected";

/// The tenant id the internal queues' nonces are recorded under. The nonce
/// store is keyed by `(tenant_id, nonce)`; the internal queues are not a
/// tenant's, so their nonces live in one namespace of their own, and the
/// rejection rows go to the system (nil-tenant) audit log for the same reason.
pub const INTERNAL_SCOPE: Uuid = Uuid::nil();

/// The `purpose` of an outbound kind's envelope: `outbound.<slug>`.
pub fn outbound_purpose(kind: OutboundKind) -> String {
    format!("outbound.{}", kind.as_str())
}

/// Derive the server-only signing key of one internal queue family.
///
/// HKDF-SHA256 over the AMQP master key, with the same salt as the per-tenant
/// derivation and `info = "axiam-amqp-internal-v1" || key_version || purpose`.
pub fn derive_internal_key(master: &[u8], key_version: u8, purpose: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(APP_SALT), master);
    let mut info = Vec::with_capacity(INTERNAL_DOMAIN_TAG.len() + 1 + purpose.len());
    info.extend_from_slice(INTERNAL_DOMAIN_TAG);
    info.push(key_version);
    info.extend_from_slice(purpose.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(&info, &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// The bytes on an internal queue.
///
/// **Wire order is load-bearing**: the HMAC is over this struct serialized in
/// declaration order with `hmac_signature` absent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalEnvelope {
    /// The queue family: [`MAIL_PURPOSE`] or [`outbound_purpose`].
    pub purpose: String,
    /// Master-key rotation / envelope version; at least
    /// [`MIN_ACCEPTED_KEY_VERSION`].
    pub key_version: u8,
    /// Per-message nonce, recorded in the durable replay store.
    pub nonce: Uuid,
    /// When the message becomes current. The publish time, except for an
    /// outbound retry copy, which carries the time its retry-queue TTL expires
    /// (see `AmqpOutboundPublisher::publish_retry`).
    pub issued_at: DateTime<Utc>,
    /// The queue's message, in the JSON it carried before the envelope.
    pub body: serde_json::Value,
    /// HMAC-SHA256 (hex) of the envelope with this field absent, under
    /// [`derive_internal_key`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_signature: Option<String>,
}

/// Seals messages for the internal queues. Held by their publishers.
#[derive(Clone)]
pub struct InternalSigner {
    master: Arc<Vec<u8>>,
}

impl std::fmt::Debug for InternalSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalSigner").finish_non_exhaustive()
    }
}

impl InternalSigner {
    /// A signer over the AMQP master key (`AmqpConfig::resolve_signing_key`).
    pub fn new(master: Vec<u8>) -> Self {
        Self {
            master: Arc::new(master),
        }
    }

    /// Wrap `body` in a signed [`InternalEnvelope`] for `purpose`, current
    /// from `issued_at`, and return its bytes.
    pub fn seal<T: Serialize + ?Sized>(
        &self,
        purpose: &str,
        body: &T,
        issued_at: DateTime<Utc>,
    ) -> Result<Vec<u8>, serde_json::Error> {
        let mut envelope = InternalEnvelope {
            purpose: purpose.to_owned(),
            key_version: CURRENT_KEY_VERSION,
            nonce: Uuid::new_v4(),
            issued_at,
            body: serde_json::to_value(body)?,
            hmac_signature: None,
        };
        let canonical = serde_json::to_vec(&envelope)?;
        let key = derive_internal_key(&self.master, envelope.key_version, purpose);
        envelope.hmac_signature = Some(sign_payload(&key, &canonical));
        serde_json::to_vec(&envelope)
    }
}

/// Why an internal-queue consumer refused a message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rejection {
    /// Not JSON, or an envelope that does not parse.
    Malformed,
    /// No envelope (the pre-SA-14 shape while signatures are required), or an
    /// envelope without a signature.
    Unsigned,
    /// An envelope for another queue family.
    WrongPurpose,
    /// The signature does not verify under the server-only key.
    BadSignature,
    /// A `key_version` below [`MIN_ACCEPTED_KEY_VERSION`].
    KeyVersion,
    /// `issued_at` outside the freshness window.
    Stale,
    /// The nonce was already consumed.
    Replay,
    /// The nonce could not be recorded; refused rather than risk a replay.
    NonceStore,
    /// A verified envelope whose body is not the queue's message.
    MalformedBody,
}

impl Rejection {
    /// The reason recorded in the audit row's metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::Unsigned => "unsigned",
            Self::WrongPurpose => "wrong_purpose",
            Self::BadSignature => "bad_signature",
            Self::KeyVersion => "key_version",
            Self::Stale => "stale",
            Self::Replay => "replay",
            Self::NonceStore => "nonce_store_error",
            Self::MalformedBody => "malformed_body",
        }
    }
}

/// What [`InternalQueueGate::open`] admitted.
#[derive(Debug, Clone, PartialEq)]
pub enum Opened {
    /// A verified, fresh, first-seen envelope's body.
    Verified(serde_json::Value),
    /// A message in the pre-SA-14 shape, admitted only because
    /// `require_signature` is `false`.
    LegacyUnsigned(serde_json::Value),
}

impl Opened {
    /// The message, however it was admitted.
    pub fn into_body(self) -> serde_json::Value {
        match self {
            Self::Verified(body) | Self::LegacyUnsigned(body) => body,
        }
    }
}

/// The audit row of a refused message: the system log, no actor, the queue
/// and the reason. Nothing from the message itself, which is unauthenticated.
pub fn rejection_audit_entry(queue: &str, rejection: Rejection) -> CreateAuditLogEntry {
    CreateAuditLogEntry {
        tenant_id: INTERNAL_SCOPE,
        actor_id: Uuid::nil(),
        actor_type: ActorType::System,
        action: REJECTED_ACTION.into(),
        resource_id: None,
        outcome: AuditOutcome::Denied,
        ip_address: None,
        metadata: Some(serde_json::json!({
            "queue": queue,
            "reason": rejection.as_str(),
        })),
        organization_id: None,
    }
}

type NonceFuture<'a> = Pin<Box<dyn Future<Output = AxiamResult<()>> + Send + 'a>>;

/// Object-safe face of [`AmqpNonceRepository::insert_nonce`], so the gate is
/// one concrete, cheaply cloned type.
trait NonceSink: Send + Sync {
    fn record(&self, nonce: Uuid, expires_at: DateTime<Utc>) -> NonceFuture<'_>;
}

struct RepoNonceSink<N>(N);

impl<N: AmqpNonceRepository> NonceSink for RepoNonceSink<N> {
    fn record(&self, nonce: Uuid, expires_at: DateTime<Utc>) -> NonceFuture<'_> {
        Box::pin(self.0.insert_nonce(INTERNAL_SCOPE, nonce, expires_at))
    }
}

/// Verifies what the internal queues' consumers take off the broker.
#[derive(Clone)]
pub struct InternalQueueGate {
    master: Arc<Vec<u8>>,
    require_signature: bool,
    skew: chrono::Duration,
    nonces: Arc<dyn NonceSink>,
}

impl std::fmt::Debug for InternalQueueGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InternalQueueGate")
            .field("require_signature", &self.require_signature)
            .field("skew", &self.skew)
            .finish_non_exhaustive()
    }
}

impl InternalQueueGate {
    /// A gate over the AMQP master key, the freshness `skew`
    /// (`AmqpConfig::replay_skew`) and the durable nonce store.
    /// `require_signature` is `amqp.internal_queues.require_signature`.
    pub fn new<N>(
        master: Vec<u8>,
        require_signature: bool,
        skew: chrono::Duration,
        nonces: N,
    ) -> Self
    where
        N: AmqpNonceRepository + 'static,
    {
        Self {
            master: Arc::new(master),
            require_signature,
            skew,
            nonces: Arc::new(RepoNonceSink(nonces)),
        }
    }

    /// Whether a message in the pre-SA-14 shape is refused.
    pub fn require_signature(&self) -> bool {
        self.require_signature
    }

    /// Admit `raw`, taken off a queue of family `purpose`, at `now`.
    ///
    /// The checks run in the order of the authz consumer's: parse, signature,
    /// key version, freshness, then the nonce, so a message that fails any
    /// earlier check never consumes a nonce.
    pub async fn open(
        &self,
        purpose: &str,
        raw: &[u8],
        now: DateTime<Utc>,
    ) -> Result<Opened, Rejection> {
        let value: serde_json::Value =
            serde_json::from_slice(raw).map_err(|_| Rejection::Malformed)?;

        // Every envelope has a `body`; no pre-SA-14 message on these queues
        // does (`OutboundMailMessage`, `WebhookMessage`, `OutboundMessage`).
        if value.get("body").is_none() {
            return if self.require_signature {
                Err(Rejection::Unsigned)
            } else {
                tracing::warn!(
                    purpose,
                    "unsigned internal-queue message admitted: \
                     AXIAM__AMQP__INTERNAL_QUEUES__REQUIRE_SIGNATURE=false (SA-14)"
                );
                Ok(Opened::LegacyUnsigned(value))
            };
        }

        let mut envelope: InternalEnvelope =
            serde_json::from_value(value).map_err(|_| Rejection::Malformed)?;
        let Some(signature) = envelope.hmac_signature.take() else {
            return Err(Rejection::Unsigned);
        };
        if envelope.purpose != purpose {
            return Err(Rejection::WrongPurpose);
        }
        let canonical = serde_json::to_vec(&envelope).map_err(|_| Rejection::Malformed)?;
        let key = derive_internal_key(&self.master, envelope.key_version, purpose);
        if !verify_payload(&key, &canonical, &signature) {
            return Err(Rejection::BadSignature);
        }
        if envelope.key_version < MIN_ACCEPTED_KEY_VERSION {
            return Err(Rejection::KeyVersion);
        }
        if !is_fresh(envelope.issued_at, now, self.skew) {
            return Err(Rejection::Stale);
        }
        match self
            .nonces
            .record(envelope.nonce, envelope.issued_at + self.skew)
            .await
        {
            Ok(()) => Ok(Opened::Verified(envelope.body)),
            Err(AxiamError::ReplayDetected) => Err(Rejection::Replay),
            Err(e) => {
                tracing::error!(error = %e, purpose, "could not record an internal-queue nonce");
                Err(Rejection::NonceStore)
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::messages::derive_tenant_key;
    use std::collections::HashSet;
    use std::sync::Mutex;

    /// An in-memory nonce store with the durable one's contract.
    #[derive(Clone, Default)]
    pub(crate) struct MemNonces(Arc<Mutex<HashSet<(Uuid, Uuid)>>>);

    impl AmqpNonceRepository for MemNonces {
        async fn insert_nonce(
            &self,
            tenant_id: Uuid,
            nonce: Uuid,
            _expires_at: DateTime<Utc>,
        ) -> AxiamResult<()> {
            if self.0.lock().unwrap().insert((tenant_id, nonce)) {
                Ok(())
            } else {
                Err(AxiamError::ReplayDetected)
            }
        }
        async fn cleanup_expired(&self) -> AxiamResult<u64> {
            Ok(0)
        }
    }

    pub(crate) const MASTER: &[u8] = b"sa14-test-master-key";

    pub(crate) fn gate(require_signature: bool) -> InternalQueueGate {
        InternalQueueGate::new(
            MASTER.to_vec(),
            require_signature,
            chrono::Duration::seconds(300),
            MemNonces::default(),
        )
    }

    pub(crate) fn signer() -> InternalSigner {
        InternalSigner::new(MASTER.to_vec())
    }

    fn body() -> serde_json::Value {
        serde_json::json!({"tenant_id": Uuid::new_v4(), "n": 1, "f": 0.1, "s": "x"})
    }

    #[tokio::test]
    async fn a_sealed_message_opens_once() {
        let g = gate(true);
        let b = body();
        let raw = signer().seal(MAIL_PURPOSE, &b, Utc::now()).unwrap();
        assert_eq!(
            g.open(MAIL_PURPOSE, &raw, Utc::now()).await,
            Ok(Opened::Verified(b))
        );
        assert_eq!(
            g.open(MAIL_PURPOSE, &raw, Utc::now()).await,
            Err(Rejection::Replay)
        );
    }

    #[tokio::test]
    async fn an_unsigned_message_is_refused_unless_signatures_are_optional() {
        let raw = serde_json::to_vec(&body()).unwrap();
        assert_eq!(
            gate(true).open(MAIL_PURPOSE, &raw, Utc::now()).await,
            Err(Rejection::Unsigned)
        );
        assert!(matches!(
            gate(false).open(MAIL_PURPOSE, &raw, Utc::now()).await,
            Ok(Opened::LegacyUnsigned(_))
        ));
        assert_eq!(
            gate(true).open(MAIL_PURPOSE, b"not json", Utc::now()).await,
            Err(Rejection::Malformed)
        );
    }

    /// `require_signature = false` admits the old shape only: a bad envelope
    /// is refused all the same.
    #[tokio::test]
    async fn optional_signatures_still_verify_every_envelope() {
        let mut env: InternalEnvelope =
            serde_json::from_slice(&signer().seal(MAIL_PURPOSE, &body(), Utc::now()).unwrap())
                .unwrap();
        env.body["n"] = serde_json::json!(2);
        let tampered = serde_json::to_vec(&env).unwrap();
        assert_eq!(
            gate(false).open(MAIL_PURPOSE, &tampered, Utc::now()).await,
            Err(Rejection::BadSignature)
        );
        env.hmac_signature = None;
        let stripped = serde_json::to_vec(&env).unwrap();
        assert_eq!(
            gate(false).open(MAIL_PURPOSE, &stripped, Utc::now()).await,
            Err(Rejection::Unsigned)
        );
    }

    #[tokio::test]
    async fn a_stale_or_future_message_is_refused() {
        let now = Utc::now();
        for issued_at in [
            now - chrono::Duration::seconds(301),
            now + chrono::Duration::seconds(301),
        ] {
            let raw = signer().seal(MAIL_PURPOSE, &body(), issued_at).unwrap();
            assert_eq!(
                gate(true).open(MAIL_PURPOSE, &raw, now).await,
                Err(Rejection::Stale)
            );
        }
    }

    /// The tenant subkey that a tenant's producers hold for the authz and
    /// audit queues cannot sign an internal-queue message, whatever tenant it
    /// is derived for — including the nil tenant the internal scope uses.
    #[tokio::test]
    async fn a_tenant_subkey_cannot_sign_an_internal_message() {
        for tenant in [Uuid::nil(), Uuid::new_v4()] {
            let subkey = derive_tenant_key(MASTER, tenant, CURRENT_KEY_VERSION);
            assert_ne!(
                subkey,
                derive_internal_key(MASTER, CURRENT_KEY_VERSION, MAIL_PURPOSE)
            );
            let mut env = InternalEnvelope {
                purpose: MAIL_PURPOSE.into(),
                key_version: CURRENT_KEY_VERSION,
                nonce: Uuid::new_v4(),
                issued_at: Utc::now(),
                body: body(),
                hmac_signature: None,
            };
            let canonical = serde_json::to_vec(&env).unwrap();
            env.hmac_signature = Some(sign_payload(&subkey, &canonical));
            let raw = serde_json::to_vec(&env).unwrap();
            assert_eq!(
                gate(true).open(MAIL_PURPOSE, &raw, Utc::now()).await,
                Err(Rejection::BadSignature)
            );
        }
    }

    /// A mail envelope cannot be replayed onto a webhook queue, even with its
    /// `purpose` rewritten: the purpose is in the key.
    #[tokio::test]
    async fn an_envelope_is_bound_to_its_queue_family() {
        let webhook = outbound_purpose(OutboundKind::Webhook);
        let raw = signer().seal(MAIL_PURPOSE, &body(), Utc::now()).unwrap();
        assert_eq!(
            gate(true).open(&webhook, &raw, Utc::now()).await,
            Err(Rejection::WrongPurpose)
        );
        let mut env: InternalEnvelope = serde_json::from_slice(&raw).unwrap();
        env.purpose = webhook.clone();
        let relabelled = serde_json::to_vec(&env).unwrap();
        assert_eq!(
            gate(true).open(&webhook, &relabelled, Utc::now()).await,
            Err(Rejection::BadSignature)
        );
    }

    #[tokio::test]
    async fn a_pre_v2_key_version_is_refused() {
        let mut env = InternalEnvelope {
            purpose: MAIL_PURPOSE.into(),
            key_version: 1,
            nonce: Uuid::new_v4(),
            issued_at: Utc::now(),
            body: body(),
            hmac_signature: None,
        };
        let canonical = serde_json::to_vec(&env).unwrap();
        let key = derive_internal_key(MASTER, 1, MAIL_PURPOSE);
        env.hmac_signature = Some(sign_payload(&key, &canonical));
        let raw = serde_json::to_vec(&env).unwrap();
        assert_eq!(
            gate(true).open(MAIL_PURPOSE, &raw, Utc::now()).await,
            Err(Rejection::KeyVersion)
        );
    }

    #[test]
    fn the_rejection_row_names_the_queue_and_reason_only() {
        let entry = rejection_audit_entry("axiam.mail.outbound", Rejection::Replay);
        assert_eq!(entry.tenant_id, Uuid::nil());
        assert_eq!(entry.action, REJECTED_ACTION);
        assert!(matches!(entry.outcome, AuditOutcome::Denied));
        assert_eq!(
            entry.metadata,
            Some(serde_json::json!({"queue": "axiam.mail.outbound", "reason": "replay"}))
        );
    }
}

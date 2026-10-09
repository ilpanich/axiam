// AUTO-GENERATED — do not edit by hand.
//
// Headline counts from the OWASP Threat Dragon model, emitted by
// `npm run gen:threat-model` alongside `threatModel.ts`. Kept as a separate,
// tiny module so pages can quote the numbers without pulling in the whole model.

export interface ThreatModelArea {
  id: number;
  title: string;
  total: number;
  open: number;
  /** Threats recorded `NotApplicable`: written for a surface that is not built. */
  notApplicable: number;
}

/** One row of a coverage table — a STRIDE category, or a severity. */
export interface ThreatModelBucket {
  name: string;
  total: number;
  open: number;
  notApplicable: number;
}

/** One entry of the open risk register. */
export interface ThreatModelOpenRisk {
  number: number;
  title: string;
  category: string;
  severity: string;
  /** Diagram the threat sits on, for deep-linking into the explorer. */
  diagramId: number;
  area: string;
  element: string;
  /**
   * The model's mitigation field. For an open item it states the residual risk
   * and where responsibility for it lands.
   */
  residualRisk: string;
}

export interface ThreatModelSummary {
  /** Threat Dragon model schema version. */
  version: string;
  diagramCount: number;
  total: number;
  open: number;
  mitigated: number;
  /**
   * Threats recorded `NotApplicable` — entries for a surface that is not
   * built. Counted in `total`, in neither `open` nor `mitigated`.
   */
  notApplicable: number;
  /** Per-diagram counts, in model order. */
  areas: ThreatModelArea[];
  /** Counts per STRIDE category, in STRIDE order. */
  categories: ThreatModelBucket[];
  /** Counts per severity, most severe first. */
  severities: ThreatModelBucket[];
  /** Every threat recorded as open, most severe first. */
  openRisks: ThreatModelOpenRisk[];
}

export const THREAT_MODEL_SUMMARY: ThreatModelSummary = {
 "version": "2.38.0",
 "diagramCount": 10,
 "total": 469,
 "open": 21,
 "mitigated": 427,
 "notApplicable": 21,
 "areas": [
  {
   "id": 0,
   "title": "System diagram",
   "total": 33,
   "open": 2,
   "notApplicable": 0
  },
  {
   "id": 1,
   "title": "Authentication & session management",
   "total": 36,
   "open": 1,
   "notApplicable": 0
  },
  {
   "id": 2,
   "title": "OAuth2 / OIDC authorization server",
   "total": 85,
   "open": 0,
   "notApplicable": 0
  },
  {
   "id": 3,
   "title": "Federation — SAML SP & OIDC relying party",
   "total": 125,
   "open": 3,
   "notApplicable": 0
  },
  {
   "id": 4,
   "title": "Authorization engine — RBAC, hierarchy & scopes",
   "total": 27,
   "open": 0,
   "notApplicable": 0
  },
  {
   "id": 5,
   "title": "PKI, certificates & IoT device identity",
   "total": 30,
   "open": 2,
   "notApplicable": 0
  },
  {
   "id": 6,
   "title": "Audit, webhooks, email & notifications",
   "total": 55,
   "open": 4,
   "notApplicable": 0
  },
  {
   "id": 7,
   "title": "Deployment & platform (Kubernetes)",
   "total": 29,
   "open": 6,
   "notApplicable": 0
  },
  {
   "id": 8,
   "title": "Client SDKs & admin UI integration surface",
   "total": 28,
   "open": 3,
   "notApplicable": 0
  },
  {
   "id": 9,
   "title": "RADIUS front end — not built (G-11, declined 2026-10-06)",
   "total": 21,
   "open": 0,
   "notApplicable": 21
  }
 ],
 "categories": [
  {
   "name": "Spoofing",
   "total": 101,
   "open": 5,
   "notApplicable": 3
  },
  {
   "name": "Tampering",
   "total": 93,
   "open": 1,
   "notApplicable": 5
  },
  {
   "name": "Repudiation",
   "total": 16,
   "open": 2,
   "notApplicable": 1
  },
  {
   "name": "Information disclosure",
   "total": 110,
   "open": 7,
   "notApplicable": 4
  },
  {
   "name": "Denial of service",
   "total": 59,
   "open": 4,
   "notApplicable": 4
  },
  {
   "name": "Elevation of privilege",
   "total": 90,
   "open": 2,
   "notApplicable": 4
  }
 ],
 "severities": [
  {
   "name": "Critical",
   "total": 43,
   "open": 2,
   "notApplicable": 2
  },
  {
   "name": "High",
   "total": 196,
   "open": 10,
   "notApplicable": 9
  },
  {
   "name": "Medium",
   "total": 195,
   "open": 8,
   "notApplicable": 9
  },
  {
   "name": "Low",
   "total": 35,
   "open": 1,
   "notApplicable": 1
  }
 ],
 "openRisks": [
  {
   "number": 148,
   "title": "Compromised release pipeline publishes a backdoored SDK",
   "category": "Tampering",
   "severity": "Critical",
   "diagramId": 8,
   "area": "Client SDKs & admin UI integration surface",
   "element": "Public package registries",
   "residualRisk": "Partially enacted, and narrowed at beta03. Nine of the eleven pipelines carry no long-lived registry credential: Rust, TypeScript, Python and C# and the shared axiam-opaque core publish via Trusted Publishing (OIDC); PHP through Packagist's webhook; Go, Swift, C and C++ from git tags. Every release workflow in the fleet now pins its actions by commit digest, and every published artifact — the server's binary tarballs and CycloneDX SBOMs, the container images, and each SDK's release artifacts — carries a GitHub build-provenance attestation, so an integrator can verify build origin with `gh attestation verify`. Maven Central (Java, Kotlin) still requires a stored Portal user token: Central has no trusted-publishing equivalent, and its OIDC surfaces are account sign-in and Sigstore signing, neither of which authorises an upload — see claude_dev/maven-central-publishing-decision.md. Those two are bounded by compensating controls instead: the credential is an environment secret behind a required-reviewer GitHub environment restricted to v* tags, every published file carries a Sigstore bundle (`.sigstore.json`) alongside its PGP signature — keyless, signed against the release workflow's GitHub OIDC identity and validated by the Central Publisher Portal, so the artifact set Central itself serves carries a statement of build origin the Portal token cannot forge — and the token rotates quarterly. A pull-request gate in each of those two repositories performs a real keyless signing run of the real artifact set on every change, so a release-path misconfiguration surfaces on a pull request rather than at a tag. Open because a stored bearer credential still exists for two of eleven registries."
  },
  {
   "number": 306,
   "title": "A leaked signing key keeps forging assertions after the credential is retired",
   "category": "Spoofing",
   "severity": "Critical",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML service provider (registered per tenant)",
   "residualRisk": "Partly mitigated. Retiring the credential destroys its key and takes its certificate out of the tenant's metadata (D-21; the metadata endpoint is T23.2.5), and a credential is valid for at most two years (`MAX_SAML_IDP_CREDENTIAL_VALIDITY_DAYS`), after which AXIAM's own signer refuses it (T-308) and SPs that check validity do too. Open because nothing AXIAM does reaches an SP's pinned trust: recovering from a leak means telling every SP administrator, which is a procedure, not a control. T-304 and T-305 are what keep the key from leaking."
  },
  {
   "number": 18,
   "title": "Backup or snapshot exfiltration",
   "category": "Information disclosure",
   "severity": "High",
   "diagramId": 0,
   "area": "System diagram",
   "element": "SurrealDB cluster (all tenant data)",
   "residualRisk": "Not addressed by AXIAM itself. Deployment guidance: encrypt backups at rest, restrict snapshot IAM, and treat backup media as in-scope for the same access review as the live cluster."
  },
  {
   "number": 94,
   "title": "Key extracted from device firmware or flash",
   "category": "Spoofing",
   "severity": "High",
   "diagramId": 5,
   "area": "PKI, certificates & IoT device identity",
   "element": "IoT device",
   "residualRisk": "Outside AXIAM's control: private keys are generated for the device and returned once, never stored server-side, but hardware protection is the integrator's responsibility. AXIAM limits the blast radius with per-device certificates, a maximum validity policy and immediate revocation."
  },
  {
   "number": 102,
   "title": "A revoked certificate stays valid to every relying party that does not terminate at AXIAM",
   "category": "Spoofing",
   "severity": "High",
   "diagramId": 5,
   "area": "PKI, certificates & IoT device identity",
   "element": "Revocation (status in AXIAM's store; no CRL published)",
   "residualRisk": "Open since model 2.36.0 (T23.11.1, item D7 of the RADIUS spike). Where AXIAM authenticates a device by its certificate, revocation takes effect at once: `DeviceAuthService::authenticate_der` reads the certificate's status on every device sign-in, and a revoked CA anywhere in the chain refuses the leaf. Nothing else AXIAM terminates reads it (corrected by the W6 F4 review, model 2.36.1): neither listener's TLS handshake checks revocation, and OAuth2 `tls_client_auth` matches the client's registered subject DN or SAN on a certificate that chains to a trust anchor, so a revoked AXIAM-issued leaf keeps authenticating its OAuth2 client until it expires or the registration changes. Outside AXIAM there is no revocation channel: the only bound is the leaf's own validity, capped per tenant by `max_cert_validity_days`, so a relying party that needs revocation today must let the connection terminate at AXIAM (the device authenticates there and presents the certificate-bound token it receives, T-283) or rely on short-lived leaves. Publishing a CRL per issuing CA, and deciding on OCSP, is tracked by ilpanich/axiam#565 (spike record §8, D1); this entry closes with it, together with the listeners' verifiers loading that list or `tls_client_auth` reading the certificate's status."
  },
  {
   "number": 108,
   "title": "Action succeeds while its audit write fails",
   "category": "Repudiation",
   "severity": "High",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "Audit middleware & service",
   "residualRisk": "Carried to the W5 F4 review (T23.8.2, review P23W5-A10). Until model 2.34.0 this entry read “audit writes share the transactional path with the action they record where the datastore allows it, and audit failures are surfaced as errors and raise a compliance notification rather than being swallowed”; no code does either. What is built: AXIAM's own request rows are written by the audit middleware off the request path — a bounded queue of 4 096 entries and one worker — so a full queue drops the entry with an `ERROR` line and a failed append is a `WARN` line while the action stands; the GDPR erasure and tenant-deletion records dead-letter a failed write to an append-only file and a structured `axiam.audit.dlq` event (T19.27, `write_erasure_audit_with_dlq`); every orderly stop drains the queue (T-444). What is not: a fallback for any other row, the GDPR request records included (P23W5-A8), and any counter or notification when a row is dropped or fails (P23W5-A10). An attacker who can exhaust the datastore can act while the rows recording it are dropped, and only the server log says so."
  },
  {
   "number": 124,
   "title": "Operator credentials grant unaudited data access",
   "category": "Spoofing",
   "severity": "High",
   "diagramId": 7,
   "area": "Deployment & platform (Kubernetes)",
   "element": "Cluster operator / SRE",
   "residualRisk": "Outside the application boundary. Restrict RBAC on Secrets and exec, enable Kubernetes audit logging, and treat cluster-admin as equivalent to full AXIAM compromise in your threat register."
  },
  {
   "number": 133,
   "title": "Backup media accessible outside the cluster",
   "category": "Information disclosure",
   "severity": "High",
   "diagramId": 7,
   "area": "Deployment & platform (Kubernetes)",
   "element": "Backups / volume snapshots",
   "residualRisk": "Not addressed by AXIAM. Encrypt backups at rest with a key separate from the cluster, restrict snapshot IAM, and include backup media in the same access review as the live data tier."
  },
  {
   "number": 135,
   "title": "Dependency-confusion or typosquatted SDK package",
   "category": "Spoofing",
   "severity": "High",
   "diagramId": 8,
   "area": "Client SDKs & admin UI integration surface",
   "element": "Integrator / developer",
   "residualRisk": "Not fully controllable from this repository. Publish under reserved names, enable 2FA and trusted publishing on every registry, sign releases, and document the exact canonical package names in the SDK contract so integrators can verify what they installed."
  },
  {
   "number": 146,
   "title": "Long-lived client secret committed to a repository",
   "category": "Information disclosure",
   "severity": "High",
   "diagramId": 8,
   "area": "Client SDKs & admin UI integration surface",
   "element": "SDK configuration (client secrets, CA bundles)",
   "residualRisk": "Outside AXIAM's control. Mitigate by preferring mTLS or short-lived workload identity over static secrets, rotating regularly through the client-rotation endpoint, and enabling secret scanning on integrator repositories."
  },
  {
   "number": 180,
   "title": "Vault concentrates every long-lived secret behind one credential",
   "category": "Information disclosure",
   "severity": "High",
   "diagramId": 7,
   "area": "Deployment & platform (Kubernetes)",
   "element": "Secrets (Vault / K8s Secrets / ConfigMap)",
   "residualRisk": "Deployment responsibility, stated in docs/deployment/vault.md rather than enforceable in-product: run a production-mode Vault with TLS (the shipped prod stack does — TLS material, init, unseal, then seed), scope AXIAM's token to read-only on its own KV path with the documented policy, keep unseal keys and the root token offline, and enable Vault's audit device so secret reads are attributable. The tooling is shaped to help, and since H-4 it CHECKS rather than merely advises: just vault-status queries sys/capabilities-self and reports the capabilities the token in hand actually holds on AXIAM's KV path, flagging anything beyond read — and a root token as what it is — with --strict to make it a failure in a deployment smoke test. It still reports secret presence only, never a value, and the seeder never rewrites a secret that already exists. Since 1.0.0-beta10 the token is no longer strictly read-only: it holds `read` on the startup path and `create`/`update` on `secret/data/axiam/ca-keys/*`, from the one policy file `docker/vault/axiam-policy.hcl`, and `just vault-status` reports missing capabilities as well as excess ones (T-232). Since 2026-09-12 (R-5) three more secrets sit behind that one credential — the datastore username and password and the broker URL, moved off the container spec to close T-132's follow-up — which widens exactly the concentration this entry records rather than narrowing it, and is the honest trade: a credential in a pod spec is readable by anyone with `get pod`, while a credential behind Vault is readable by whoever holds the token and revocable after the fact. The policy needed no change, because it grants `read` on the path rather than on fields."
  },
  {
   "number": 216,
   "title": "The unseal key sits on the same disk as the sealed data",
   "category": "Elevation of privilege",
   "severity": "High",
   "diagramId": 7,
   "area": "Deployment & platform (Kubernetes)",
   "element": "Secrets (Vault / K8s Secrets / ConfigMap)",
   "residualRisk": "Narrowed, not closed. `prod-up` now writes the read-only `axiam` policy from `docs/deployment/vault.md` §5.4 and issues a **scoped, periodic token** for the server, refusing to fall back to root if that fails; seeding keeps its own short-lived credential, because the seeding token and the serving token were never the same thing. Both the Compose stack and `k8s/vault/statefulset.yml` move from the `file` backend to **Raft**, which has a consistent backup story (`vault operator raft snapshot save`) and a migration path to three nodes that does not require a re-seed — a re-seed changes the OPAQUE setup key, i.e. a password reset for every user in every tenant. What remains **open** is auto-unseal, which cannot be closed from inside AXIAM: every Vault OSS seal type needs a cloud KMS or a second Vault elsewhere, and `pkcs11` is Enterprise-only, so a TPM is not an option whatever the hardware. `docs/deployment/vault.md` §5.3 and the Pi runbook §7.1 give the honest option table — GCP Cloud KMS at roughly $0.06 per key per month is the cheapest real answer — and state plainly that a deployment which configures none of them needs a human with three shares after every restart and is not production. A script that unseals from shares kept on the machine is explicitly **not** offered as an alternative: it removes the seal rather than automating it, and is strictly worse than Shamir because the shares are now in the one place an attacker already has. Two amendments since: the server's token is no longer strictly read-only — it holds `create`/`update` on the CA-key prefix, from the one policy file (T-232) — and the seeder that runs after unseal can no longer mistake a refused read for an empty Vault and mint fresh keys over the live ones (T-231). Vault itself runs unprivileged: the prod Compose stack chowns the Raft volume in a one-shot init container rather than running the process that holds every secret as root. Made **checkable** in 1.0.0-beta12 (R-7), the way H-4 made T-180's token scope checkable. `just vault-status` gains a Seal section from the unauthenticated `sys/seal-status` — so it answers even when the token is wrong and even when the Vault is sealed: it names the seal type, reads `OK` for any auto-unseal type, and for `shamir` says \"no auto-unseal; every restart needs t of n key shares, not production\" with the quorum quoted from the response. A Vault sealed at that instant gets its own line, because that is a state somebody is about to fix rather than a statement about the configured seal, and conflating the two would train an operator to ignore both; a request that fails reports `unknown`, never `OK`. `--strict` fails on an unconfirmed auto-unseal, and `just vault-status` still does not pass it so the dev stack's deliberate root-token-on-Shamir does not turn every local run red. **Status stays Open**: the control is a check, not a seal — nothing in this repository can configure auto-unseal, and R-7 does not pretend otherwise."
  },
  {
   "number": 9,
   "title": "Connection flood exhausts ingress capacity",
   "category": "Denial of service",
   "severity": "Medium",
   "diagramId": 0,
   "area": "System diagram",
   "element": "Ingress / TLS 1.3 termination",
   "residualRisk": "Partly outside the application boundary: AXIAM enforces per-IP and per-user rate limits and Argon2 backpressure, but edge-level protection (WAF, connection limits, autoscaling) is a deployment responsibility and is not shipped with AXIAM."
  },
  {
   "number": 117,
   "title": "Alert flooding buries a real incident",
   "category": "Denial of service",
   "severity": "Medium",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "Notification rules (admin alerts)",
   "residualRisk": "Reopened at model 2.35.0 by the W5 F4 review (P23W5-13). Until then this entry read “notifications are delivered in configurable batches through the mail queue, and rules are per-category so a noisy category can be tuned without disabling the rest”; nothing batches them. What is built: rules are per event, so a noisy event can be taken out of a rule without disabling the rest; a mail is fixed text; the events a caller can provoke ride rate-limited routes (sign-in per address and per account, with brute-force lockout, T-27); and the one event a background process raises, `scim_delivery_failed`, is coalesced to one notification per target per hour (T-418, D-73). What is not: `NotificationDispatcher::dispatch` enqueues one mail per matched recipient per audit row, so a request-path event an attacker can produce in volume — failed sign-ins spread over addresses and accounts — mails each recipient of a rule for it once per event, with no coalescing, cool-down or digest. Open until per-rule coalescing exists (issue body in the W5 F4 review, §14)."
  },
  {
   "number": 123,
   "title": "Final mail hop is not confidential",
   "category": "Information disclosure",
   "severity": "Medium",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "deliver mail",
   "residualRisk": "Inherent to email. Bounded by making the tokens carried in mail single-use and short-lived, so interception has a narrow window. Deploy MTA-STS and DANE on the sending domain to harden the onward hops."
  },
  {
   "number": 134,
   "title": "Backup stream unencrypted in transit",
   "category": "Information disclosure",
   "severity": "Medium",
   "diagramId": 7,
   "area": "Deployment & platform (Kubernetes)",
   "element": "scheduled backup",
   "residualRisk": "Deployment responsibility: use an encrypted transport and server-side encryption on the backup target."
  },
  {
   "number": 380,
   "title": "SP sessions outlive the AXIAM session they came from",
   "category": "Elevation of privilege",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "Accepted design trade-off (D-38, D-39). SAML has no back channel through the browser; the SOAP binding that would provide one is not implemented. What bounds it: SLO revokes the AXIAM session first, so a broken chain never keeps an AXIAM session alive; assertions are valid for five minutes and single-use; a revoked session or a suspended account obtains no new assertion (T-328), so the SP session cannot be renewed through AXIAM; and the SP's own session lifetime is the SP administrator's to set. A later decision may add SOAP back-channel logout or drive a chain from `end_session`."
  },
  {
   "number": 405,
   "title": "A security event is lost and nobody is told",
   "category": "Denial of service",
   "severity": "Medium",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "SET push / poll response",
   "residualRisk": "Accepted design trade-off (D-52, the webhook precedent): failing a logout, a password reset or an erasure because a receiver's queue is unavailable would trade a security action for the notice of it. Where an event can be lost, and what records it: a failure to read the streams, the tenant's settings or the subject, to prepare the event, to publish it to `axiam.ssf_push` or to write it to the buffer, and a step-up record that could not be written, each log a `WARN` on `axiam::ssf` and nothing else: no audit row, no counter. The buffer drops its oldest event at 1 000 (T-395) and the dead-letter queue its messages after seven days (T-402), both by design. What is not lost, in the full profile: once queued, push is at-least-once and a failed attempt retries on the dispatcher's schedule; every dead-lettered push writes an `ssf_push.delivery_failed` audit row with its reason; and a held event a poll cannot sign (the deployment key unusable) is logged at `ERROR` once per poll request (W4 F4, P23W4-03: a long poll used to log it on every half-second look) and stays in the buffer for the next poll, which answers an empty `sets` meanwhile. What bounds the consequence: a signal is a hint, never the only record. The website's SSF page (*Shared Signals (SSF) transmitter*, `#/docs/ssf`) tells receivers that production is best effort and to read the account's current state from AXIAM when they need certainty about it; an AXIAM access token still lives at most fifteen minutes; and where the revocation feed is on (T-39) the same session revocations reach SDK verifiers without SSF. Open because the loss is real and silent. A later decision could make it visible (a counter, or an audit row per event that was not queued) without making it fail the operation. In the minimal profile (`AXIAM__AMQP__ENABLED=false`, D-59) a queued push waits in an in-process queue and is lost on restart, and a dead letter is its audit row alone (T-445)."
  },
  {
   "number": 445,
   "title": "The minimal profile loses queued deliveries and mail, and the audit rows they would have written, on restart",
   "category": "Repudiation",
   "severity": "Medium",
   "diagramId": 7,
   "area": "Deployment & platform (Kubernetes)",
   "element": "AXIAM deployment (N replicas, HPA)",
   "residualRisk": "Accepted design trade-off (D-59): the profile exists to run without a broker, and a SurrealDB-backed durable queue was rejected as a second dispatcher. What bounds it: the profile is opt-in (`true` is the default) and says what it lacks at boot (a `WARN` naming the in-process queues as lost on restart and external audit ingestion as unavailable), in `/health` (`profile: minimal`; `unavailable` lists `amqp_audit_ingestion`) and in the deployment guide; AXIAM's own audit rows never rode the broker and are written directly in both profiles, and an orderly stop drains them (T-444); the GDPR erasure records keep their dead-letter fallback (T19.27); a delivery that exhausts its attempts writes `<kind>.delivery_failed` in both profiles; outbound SCIM is repaired by the next reconciliation. The review (`claude_dev/audit-durability-review-minimal-profile-2026-10-05.md`) states what the deployment documentation must say and proposes a terminal row for a delivery abandoned at stop or refused at enqueue (P23W5-A4). Open because the loss is real."
  },
  {
   "number": 469,
   "title": "A locked account is refused without the equalising password verify, so its cost, or its status under load, tells it apart",
   "category": "Information disclosure",
   "severity": "Medium",
   "diagramId": 1,
   "area": "Authentication & session management",
   "element": "Login endpoints /auth/login + /auth/opaque/*",
   "residualRisk": "Open (W6 F4 review, 2026-10-06, model 2.36.1; found by the T23.11.1 RADIUS spike, whose T-457 requires the same of any RADIUS build). Fix: run the equalising dummy verify, under the same bounded permit, on the lockout branch (still before the directory is contacted, T-302, and without verifying the real hash, so a correct password during a lockout neither succeeds nor shows) and on every refusal of `ValidateCredentials`. A timing-free test pins it: with no hash permit available, a locked account must answer the 503 an unknown name answers; today it answers 401 (ilpanich/axiam#564). Bounded meanwhile by the per-IP login limiter and by the lockout's exponential backoff, which makes every probe cost N failed attempts against a real user."
  },
  {
   "number": 161,
   "title": "A partner's IdP silently populates the AXIAM user table (X4)",
   "category": "Denial of service",
   "severity": "Low",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "Attribute mapping & JIT provisioning",
   "residualRisk": "Off by default (linked_only refuses unknown subjects). Every JIT provision is audited with the provider and the external subject, and a provisioned user holds no roles, so the exchange that created them still yields no token. Residual risk accepted: the same exposure the browser SSO JIT path already carries, bounded by the same per-client exchange rate limit."
  }
 ]
};

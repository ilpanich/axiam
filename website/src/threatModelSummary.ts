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
 "version": "2.43.0",
 "diagramCount": 10,
 "total": 488,
 "open": 21,
 "mitigated": 457,
 "notApplicable": 10,
 "areas": [
  {
   "id": 0,
   "title": "System diagram",
   "total": 34,
   "open": 2,
   "notApplicable": 0
  },
  {
   "id": 1,
   "title": "Authentication & session management",
   "total": 36,
   "open": 0,
   "notApplicable": 0
  },
  {
   "id": 2,
   "title": "OAuth2 / OIDC authorization server",
   "total": 87,
   "open": 0,
   "notApplicable": 0
  },
  {
   "id": 3,
   "title": "Federation — SAML SP & OIDC relying party",
   "total": 127,
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
   "total": 32,
   "open": 1,
   "notApplicable": 0
  },
  {
   "id": 6,
   "title": "Audit, webhooks, email & notifications",
   "total": 56,
   "open": 2,
   "notApplicable": 0
  },
  {
   "id": 7,
   "title": "Deployment & platform (Kubernetes)",
   "total": 30,
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
   "title": "RADIUS front end — native listener not built (G-11, declined 2026-10-06); FreeRADIUS recipe (1.0.1); decision route (1.1.0)",
   "total": 31,
   "open": 4,
   "notApplicable": 10
  }
 ],
 "categories": [
  {
   "name": "Spoofing",
   "total": 105,
   "open": 4,
   "notApplicable": 2
  },
  {
   "name": "Tampering",
   "total": 96,
   "open": 1,
   "notApplicable": 2
  },
  {
   "name": "Repudiation",
   "total": 17,
   "open": 1,
   "notApplicable": 0
  },
  {
   "name": "Information disclosure",
   "total": 113,
   "open": 7,
   "notApplicable": 1
  },
  {
   "name": "Denial of service",
   "total": 61,
   "open": 4,
   "notApplicable": 4
  },
  {
   "name": "Elevation of privilege",
   "total": 96,
   "open": 4,
   "notApplicable": 1
  }
 ],
 "severities": [
  {
   "name": "Critical",
   "total": 43,
   "open": 2,
   "notApplicable": 0
  },
  {
   "name": "High",
   "total": 201,
   "open": 9,
   "notApplicable": 6
  },
  {
   "name": "Medium",
   "total": 204,
   "open": 8,
   "notApplicable": 3
  },
  {
   "name": "Low",
   "total": 40,
   "open": 2,
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
   "number": 450,
   "title": "MD5-only attribute hiding gives up the Wi-Fi session key or a password to whoever holds the shared secret",
   "category": "Information disclosure",
   "severity": "High",
   "diagramId": 9,
   "area": "RADIUS front end — native listener not built (G-11, declined 2026-10-06); FreeRADIUS recipe (1.0.1); decision route (1.1.0)",
   "element": "Access-Request / Accept / Reject / Challenge",
   "residualRisk": "**Corrected 2026-10-14 (R101W6-09, the W6 F4 review; model 2.41.0): Open for the operator-run recipe.** The entry was recorded Not applicable from model 2.36.0, and W6.2 (2026-10-13) kept it there while stating, below, that the recipe carries this residual. Not applicable is this model's status for “nothing is exposed”, which the recipe contradicts, so the status now follows the residual. The responsibility lands on whoever runs the recipe (`docs/pki/freeradius.md`, 1.0.1, #563). FreeRADIUS terminates RADIUS and EAP-TLS there, and on plain UDP — the only transport its end-to-end exercises, since `eapol_test` speaks UDP only — the EAP-TLS keys (`MS-MPPE-Send-Key` and `MS-MPPE-Recv-Key`, from which the access point derives the Wi-Fi session key) travel under the MD5 obfuscation this entry describes, keyed with the per-client shared secret; anyone who captures the traffic and learns or guesses the secret recovers them. FreeRADIUS enforces no minimum secret length, the recipe generates no secret and no test asserts a floor; the guide states one. The control is a choice the operator makes, not one AXIAM enforces: RadSec (RFC 6614) where the NAS supports it, where the obfuscation is keyed with a fixed public string and TLS carries the confidentiality. The guide documents the block and says to use it; the end-to-end does not exercise it. The weakness is inherent in the legacy transport and is accepted only by the operator who stays on it. The entry's own text for a native build already said it would stay Open for every legacy NAS. No test is claimed, and no status here rests on one. **Native front end (option A), unchanged and not built:** Not built (G-11 declined 2026-10-06; spike record §4.2, §4.3, §6.3, R3). The W5 F4 review's constraint (§15): **MD5-only attributes treated as the weakness they are**. Required of any build: PAP and `MS-MPPE-*` carried only over RadSec or, preferably, RADIUS/1.1 over TLS 1.3, where the obfuscation is removed and TLS carries the confidentiality; on plain UDP only for a NAS registered `legacy_udp`, with a generated secret of at least 128 bits, flagged in the API, the console and each decision's audit row — never PAP over UDP without that flag; CHAP, MS-CHAP, MS-CHAPv2 and EAP-MD5 not implemented (an Argon2id store cannot verify them, and should not be able to); RADIUS accounting not implemented. If built as specified this entry stays **Open** for every `legacy_udp` NAS: the weakness is inherent in the legacy profile and is accepted only per NAS, by an explicit flag. **1.0.1 (W6.2, #563; 2026-10-13): stayed Not applicable, superseded above.** On plain UDP the recipe carries the EAP-TLS keys under the MD5 obfuscation this entry describes; the guide says to use RadSec where the NAS allows, and the RadSec block is documented but not exercised (`eapol_test` speaks UDP only). The entry's residual is unchanged."
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
   "residualRisk": "Accepted design trade-off (D-59): the profile exists to run without a broker, and a SurrealDB-backed durable queue was rejected as a second dispatcher. What bounds it: the profile is opt-in (`true` is the default) and says what it lacks at boot (a `WARN` naming the in-process queues as lost on restart and external audit ingestion as unavailable), in `/health` (`profile: minimal`; `unavailable` lists `amqp_audit_ingestion`) and in the deployment guide; AXIAM's own audit rows never rode the broker and are written directly in both profiles, and an orderly stop drains them (T-444); the GDPR erasure records keep their dead-letter fallback (T19.27); a delivery that exhausts its attempts writes `<kind>.delivery_failed` in both profiles; outbound SCIM is repaired by the next reconciliation. The review (`claude_dev/audit-durability-review-minimal-profile-2026-10-05.md`) stated what the deployment documentation must say and proposed a terminal row for a delivery abandoned at stop or refused at enqueue; that row is built (P23W5-A4, #555). At an orderly stop each kind's in-process consumer gives the attempt in flight 500 ms to finish, closes its channel and writes one `<kind>.delivery_abandoned` row (outcome `Failure`, the system actor, the target as resource, a fixed `reason`, the delivery id and the attempts made) for every message still queued and every retry still waiting, within `OUTBOUND_DRAIN_DEADLINE` (2 s) and before the audit drain; an enqueue the queue refuses (full, or the dispatcher gone) writes one too. The action is deliberately not `delivery_failed`: only `scim_push.delivery_failed` maps to the `scim_delivery_failed` notification event, so a restart mails nobody. Tests: `crates/axiam-amqp/src/outbound/inprocess.rs` `stopping_with_queued_deliveries_writes_one_abandoned_row_per_lost_delivery`, `stopping_with_a_retry_waiting_writes_an_abandoned_row_and_never_retries`, `an_attempt_that_outlives_the_grace_is_abandoned_with_the_queue`, `a_refused_enqueue_writes_one_abandoned_row`, `an_enqueue_after_the_stop_is_refused_and_leaves_a_row`; `crates/axiam-core/src/models/notification_rule.rs` `a_delivery_abandoned_row_is_no_notification_event`; `crates/axiam-server/tests/scim_dead_letter_notification_test.rs` `an_abandoned_delivery_row_mails_nobody`. Residuals: a `SIGKILL`, an out-of-memory kill and a stop that overruns its deadline lose the queue without a row; a lost mail has no such row; an attempt cancelled at the stop may or may not have reached its receiver. Open because the loss is real. **Amended 2026-10-13 (release 1.0.1, #596).** The row an enqueue refusal leaves is no longer written on the producer's path. `InProcessOutboundPublisher::enqueue` used to await the audit append (and a `WARN`) for every refused enqueue, so a sustained full queue (a slow receiver) turned each event-producing request into an extra datastore write and a log line. The row is now handed to `AuditMiddleware::try_record`, the request rows' non-blocking channel (4 096 slots): the producer waits on nothing, one `<kind>.delivery_abandoned` row is still kept per refusal, and when that channel is full the row is counted as a lost audit row (`GET /health/jobs` `request_audit.dropped`) and offered to the dead-letter file with reason `channel_full`, like every other refused audit row. The `WARN` is logged for the first refusal of a kind and then at most once a minute per kind, with the count suppressed since; the audit row, not the log line, is the record. The rows an orderly stop writes stay awaited on the consumer's task, off the producers' path, and a publisher used before the composition root has bound the middleware falls back to the consumer's sink, as before. Tests: `crates/axiam-amqp/src/outbound/inprocess.rs` `a_refused_enqueue_is_recorded_through_the_audit_middleware`, `a_refusal_with_the_audit_channel_full_writes_nothing_and_counts_a_loss`, `the_refusal_warn_is_rate_limited_to_one_line_per_interval`; `crates/axiam-audit/tests/request_audit_loss.rs` `try_record_queues_without_waiting_and_a_full_channel_is_a_counted_loss`. The status is unchanged. **Amended 2026-10-13 (release 1.0.1, R101W4-01 / R101W4-06, in-wave fix of #596).** The refusal rows are now paced, and request rows keep a reserve. The amendment above handed every refusal's row to the request rows' channel with nothing pacing them, and the W4 review measured what that costs: a SCIM reconciliation enqueues one reference per in-scope user against a 1 024-slot queue and carried on after a refusal, so a tenant above about five thousand users made 10 000 refusals in 87 ms, filled the channel (5 904 more were dropped and dead-lettered) and then lost 100 of 100 request rows of every tenant, nightly and on every `POST …/reconcile`, spending the dead-letter file's request share on noise. Two changes, either of which removes the flood: (1) the bulk producers stop at the first refusal of a run — the reconciliation (`queue_again`, step 1 and step 2's repairs), the provisioning fan-out and a linked user's group convergence offer nothing more once one reference is refused, count the rest in `enqueue_failed`, and record them as **one** `scim_push.delivery_abandoned` row for the run (`OutboundPublisher::record_not_offered`; metadata `refused_count`, the fixed `reason`, no delivery id) beside the refused reference's own row; the next run offers them again; (2) `AuditMiddleware::try_record` never takes the last quarter of the audit channel (`REQUEST_RESERVE`, 1 024 of 4 096): below it, or with the channel closed, the row is shed and counted in its own counter, `GET /health/jobs` `request_audit.outbound_abandoned_dropped`, and is neither counted in `request_audit.dropped` nor written to the dead-letter file, so `dropped` again counts request rows only (R101W4-06). Webhook, SSF and CIBA producers were left as they are: the SSF resume already stops at its first failure and keeps the rest held, CIBA enqueues one message, and a webhook emit enqueues one message per subscribed webhook of one event, which scales with the tenant's configuration rather than its users and is bounded by the reserve. Correction to the amendment above: a refusal row the channel cannot take is no longer counted in `request_audit.dropped` nor written to the dead-letter file as `channel_full`, and its two tests were renamed for what they now assert — `a_refusal_with_the_audit_channel_full_writes_nothing_and_counts_the_shed_row` and `try_record_queues_without_waiting_and_a_full_channel_sheds_apart_from_request_rows`. Tests: `crates/axiam-amqp/src/outbound/inprocess.rs` `a_refusal_burst_leaves_the_audit_reserve_to_request_rows` (the review's probe kept: a one-slot SCIM queue behind a gated deliverer, the audit channel at 4 096 over a 1 ms datastore, 10 000 refused enqueues from a producer that does not stop, then 100 request rows through the real middleware: none dropped, at most one dead-letter line), `the_messages_a_bulk_producer_held_back_are_one_row_with_the_count`; `crates/axiam-audit/tests/request_audit_loss.rs` `a_refusal_burst_leaves_the_request_reserve_and_every_request_row_is_queued`; `crates/axiam-scim/tests/outbound_reconcile_test.rs` `a_run_that_meets_a_full_queue_stops_and_records_one_row_with_the_count`, `a_run_refused_only_at_its_last_reference_adds_no_row`; `crates/axiam-scim/tests/outbound_provisioner_test.rs` `a_refused_reference_ends_the_fan_out_and_the_rest_are_one_record`; `crates/axiam-scim/tests/outbound_scim_test.rs` `a_refused_group_ends_the_convergence_and_the_rest_are_one_record`; `crates/axiam-server/src/job_health.rs` `the_snapshot_reports_the_request_audit_loss_counters`. Residual: a shed refusal row is a count, not a row; the producer's rate-limited `WARN` and the count say that it happened. The status is unchanged. **Corrected 2026-10-14 (release 1.0.1, R101-01): a reconciliation no longer stops at its first refusal, and \"the next run offers them again\" did not hold.** The amendment above has every bulk producer stop at the first refusal of its run. For the reconciliation that was a loss, not a deferral: a run offered the in-scope users first and its links last, so in the minimal profile a target larger than the in-process queue stopped at the same user every night, and its links (the `erase_pending` retry, deprovisioning) and step 2's repairs were never offered (T-415, amended the same day). The reconciliation now offers through `OutboundPublisher::enqueue_paced`, which waits for room in the in-process queue — sending only while more than a quarter of it is free (`PACED_RESERVE_DIVISOR`) — until the run's five-minute deadline, and is ended within a 10 ms poll by a stop request and at once by a closed channel; it offers the links before the users, and stops offering at a refusal only for those three causes, for the rest of the step. A paced run makes no refusal burst, so the flood the amendment above closed stays closed; a refusal it does meet keeps its own row, and what the step then held back is the run's one `record_not_offered` row. The provisioning fan-out, which runs on the request that made the change, and a linked user's group convergence, which runs on the SCIM consumer's own task (a wait there would wait for itself), do not pace and keep the rule above. Tests: those of T-415's 2026-10-14 amendment; the reconciliation tests named above stand unchanged. The status is unchanged."
  },
  {
   "number": 462,
   "title": "A revoked certificate or disabled account keeps its network port until the session re-authenticates",
   "category": "Elevation of privilege",
   "severity": "Medium",
   "diagramId": 9,
   "area": "RADIUS front end — native listener not built (G-11, declined 2026-10-06); FreeRADIUS recipe (1.0.1); decision route (1.1.0)",
   "element": "RADIUS decision (tenant, authN, reply attributes)",
   "residualRisk": "**Amended 2026-10-15 (W6.6, RADIUS D4, #563; 1.1.0): the D4 column — still Open.** With the decision route (`POST /api/v1/network/decide`, T-468; `docs/pki/freeradius.md` section 5) a revoked certificate and a disabled service account are refused at the device's **next authentication**: the decision reads the certificate's row and runs `authenticate_der` on every request, uncached, and requires the account to be `Active`, so the CRL lag described below does not apply to it (FreeRADIUS's `check_crl` stays on, a second check with its own lag). Tests: `crates/axiam-api-rest/tests/network_decide_test.rs::revocation_and_a_disabled_account_refuse_at_the_next_request`; `crates/axiam-server/tests/radius_e2e.rs::a_decision_per_authentication_places_revokes_and_quarantines` (a device revoked in AXIAM is refused at once while FreeRADIUS still holds the old list). A quarantine (a deny of `network:join`) and any change to an assignment, a segment or a profile take effect at the next authentication too — after `AXIAM__AUTHZ__DECISION_CACHE_TTL_SECS` (5 s by default) on another replica when the optional decision cache is on without its broadcast. What remains is this entry's residual: a device that is **already connected** keeps its port until `Session-Timeout`, which its profile sets between 300 seconds and the tenant's cap (`network.session_timeout_max_secs`, 300 to 86 400, default 3 600; T-485), and then re-authenticates under `Termination-Action = RADIUS-Request` and meets the decision. No control ends a session already admitted: dynamic authorization (RFC 5176 CoA and Disconnect) is in neither AXIAM nor the recipe. The status stays Open (plan §12 Q9); the text below is the D3 profile's, unchanged for a deployment that does not run D4. **Corrected 2026-10-14 (R101W6-09, the W6 F4 review; model 2.41.0): Open for the operator-run recipe.** The entry was recorded Not applicable from model 2.36.0, and W6.2 (2026-10-13) kept it there while stating, below, the revocation lag the recipe carries. Not applicable is this model's status for “nothing is exposed”, which the recipe contradicts, so the status now follows the residual. The responsibility lands on whoever runs the recipe (`docs/pki/freeradius.md`, 1.0.1, #563), and its bound is stated: a revoked certificate stops being admitted at the first new EAP conversation after FreeRADIUS has read the new list, not at once, and a session the NAS has already admitted outlives it. AXIAM publishes a revocation at once (the CRL route's next response names the serial); the operator's fetch job brings it to the `ca_path` directory at most one fetch interval later; FreeRADIUS re-reads the lists only at the first new EAP conversation after `ca_path_reload_interval`, whose smallest accepted value is 300 s; and a device that is already connected keeps its port until `Session-Timeout`. The bound is the fetch interval plus 300 seconds plus the `Session-Timeout` — with the guide's figures roughly an hour and ten minutes in the worst case, a few minutes for a device that is not connected. Measured: `crates/axiam-server/tests/radius_e2e.rs::eap_tls_with_an_axiam_issued_device_certificate` revokes a device, sees AXIAM serve the new list, sees FreeRADIUS still admit the device because it holds the old one, and then sees it refused as revoked once the list is in `ca_path` (284 s after the revocation in the W6.2 run). Not covered by it: the session step — it connects no session and revokes it under it. No control ends a session already admitted: dynamic authorization (RFC 5176) is in neither AXIAM nor the recipe, and the recipe does not call AXIAM when a device authenticates (the real-time check, deferred item D4, is not built), so a disabled service account is seen only when its certificate is revoked. The operator's levers are the three numbers (a shorter fetch interval and `Session-Timeout`) and a shorter `validity_days` on devices; a fetch that stops is the other way this goes wrong, since a list past its `nextUpdate` refuses every device of the tenant (fail-closed, and an outage). The entry's own text for a native build already said it would stay Open until dynamic authorization ships. No test is claimed for the bound as a mitigation, and no status here rests on one. **Native front end (option A), unchanged and not built:** Not built (G-11 declined 2026-10-06; spike record R21). Required of any build: `Session-Timeout` capped per tenant and the bound stated in the product. Dynamic authorization is a separate, later item and inherits T-467's binding rule: AXIAM's own messages, carrying session and user identifiers, go to the registered NAS address only. If built as specified this entry stays **Open** — a residual bounded by the session timeout until dynamic authorization ships. **1.0.1 (W6.2, #563; 2026-10-13): stayed Not applicable, superseded above.** The recipe bounds this with the CRL fetch interval, FreeRADIUS's `ca_path_reload_interval` (300 s at the smallest) and `Session-Timeout`; the guide states the bound and the end-to-end shows a revoked device still admitted until the list is re-read. No control ends a session already admitted, so the residual stands until dynamic authorization exists. **Amended 2026-10-15 (R101W6-04, #643; release 1.1.0, W5.1): the fetch step.** The fetch job the guide described was a snippet whose signature check did not hold: `openssl crl -verify` prints `verify failure` and exits 0 when a list names the trusted CA but another key signed it (probed, OpenSSL 3.0.13), so a list forged under the CA's name by whoever could answer the fetch replaced the genuine one, refused the whole tenant and dropped the genuine revocations from disk, and an older list the CA had signed could undo a revocation. The step now ships as `docker/radius/fetch-crl.sh`, which installs a list only when `openssl crl -verify` prints exactly `verify OK`, its CRL number is not lower than the installed list's and the server answered 200, installs it atomically, and revalidates with the stored `ETag` as `If-None-Match` (a 304 changes nothing). `crates/axiam-server/tests/radius_e2e.rs::eap_tls_with_an_axiam_issued_device_certificate` runs this script as its refresh step and shows each refusal against the installed list: a list re-signed under another key with the CA's name (a higher number, so only its signature stops it), a lower-numbered list the CA signed, and a 304; each case fails when its check is removed from the script. A replay of the genuine current list, served again after a newer one exists, is accepted (the numbers are equal): it lengthens the lag and is not otherwise caught. Status unchanged: **Open** (the lag and the session step stand, per the 2026-10-14 decision to keep it Open for the recipe); the fetch is now a test, not a claim. **Amended 2026-10-15 (R101W6-06 and R101W6-05, #645 and #644; release 1.1.0, W5.2): the fetch path and the reload.** The bound above assumed that the fetch job reads AXIAM directly. The CRL route answers `Cache-Control: public, max-age=N`, with N running to the next scheduled re-sign (at most half `nextUpdate`, twelve hours by default), so a fetch job behind a shared cache or CDN can be served the list from before a revocation for that long. The bound is therefore the fetch interval, plus 300 seconds, plus the `Session-Timeout`, plus any shared cache's `max-age`; `docs/pki/freeradius.md` tells the operator to fetch AXIAM directly or through a cache told `no-cache` (the fetch script sends the stored `ETag` as `If-None-Match`, so a revalidation is a 304), and the reply-profile note's §6.3 cell, which read “CRL refresh (`nextUpdate` ≤ 1 day by default) + `Session-Timeout`”, now reads the same bound, with its own dated correction. Separately, `ca_path_reload_interval` makes FreeRADIUS rebuild its whole store, `ca_file` included, and a reload that fails (a deleted or unreadable `ca.pem`, a file replaced non-atomically) logs `Error replacing X509 store` and keeps the old store, lists and trust alike, until the process restarts: the bound holds only while the reloads succeed, and the guide now says to replace `ca.pem` atomically, never to delete it without a restart, and to alert on that log line. Neither point is exercised by a test (the end-to-end fetches directly and never fails a reload), so no test is claimed for them and the status is unchanged: **Open**. **Amended 2026-10-15 (R110W5-01, the W5 F4 review of release 1.1.0; fixed in the wave): the stored tag.** The fetch script stored any printable `ETag` and read any 304 as \"unchanged\". AXIAM's CRL route matches a tag of `*`, alone or in a list, against every list (RFC 9110), so whoever answered one fetch with the genuine current list and `ETag: *` (plain HTTP, a TLS-intercepting proxy, a compromised mirror or cache) made every later run send `If-None-Match: *`, read the 304 as \"unchanged\" and exit 0 after they were gone, until the list's `nextUpdate` (probed: the installed number stayed at 0xFF00 against a newer 0x10000). The script now stores a tag only when it is one entity-tag (`\"...\"` or `W/\"...\"`, no inner quote, so never `*` and never a list), stores the SHA-256 of the installed file beside it and sends no `If-None-Match` when the file in `ca_path` no longer matches (a replaced, deleted or corrupted list is fetched again), and reads a 304 as \"unchanged\" only when its `ETag` is the tag it sent: any other 304 is followed by an unconditional request, and a 304 to that is refused. `docker/radius/tests/fetch-crl-test.sh` (the `radius-e2e.yml` job, under `dash` and `bash`) holds the cases: an answer carrying `ETag: *`, a comma list or a malformed tag is not stored and the next, newer list is installed; a 304 whose `ETag` differs, is missing or is `*` is followed by an unconditional fetch; a replaced or corrupted installed file is fetched again; a server that answers 304 to everything is refused. A replay of the genuine current list is still accepted (the numbers are equal) and bounded by the lag. Status unchanged: **Open**. **Amended 2026-10-15 (R110W5-02, the W5 F4 review of release 1.1.0; fixed in the wave): overlapping runs.** The fetch script had no lock. Two runs that overlapped (a manual run during the timer, a cron entry beside a systemd timer, a CronJob with `concurrencyPolicy: Allow`) could both pass the CRL-number check against the same installed list and then rename in the wrong order, leaving the older of two lists installed with the newer list's `ETag` beside it: the next runs got a 304 and kept the older list, a revocation lost until AXIAM's list next changed (up to half `nextUpdate`, twelve hours by default), under a file fresh enough that the age alert stays silent. The run now holds a lock for its whole length: `flock` on `<capath>/.fetch-crl.<key>.lock` where `flock` exists (it is in the pinned FreeRADIUS image and in util-linux), else a directory of that name plus `.d`, broken as stale when its owner process is gone, its owner file is missing or unreadable, or it is older than 120 s. A run that finds the lock held exits 0, says so and touches nothing; the SHA-256 binding of R110W5-01 additionally makes a list that does not match its stored tag fetch again. `docker/radius/tests/fetch-crl-test.sh` (the `radius-e2e.yml` job, under `dash` and `bash`, each with `flock` and without) slows one of two overlapping runs between its number check and its rename and shows that the older list does not replace the newer one, that the installed list and the state agree, that the second run exits 0 untouched and that the next run installs the newest list; it also covers the directory lock's stale cases (dead owner, a lock older than 120 s, no owner file, a garbled one) and its release on SIGTERM, and fails against the script without the lock. Status unchanged: **Open**. **Amended 2026-10-15 (R110W5-03, the W5 F4 review of release 1.1.0; fixed in the wave): the fetch's `curl`.** The script's `curl` read the `~/.curlrc` of the user who runs it (probed: a `location` line there made it follow a redirect it otherwise refuses; `insecure` would have turned certificate verification off the same way), took a URL starting with `-` as an option, and accepted any scheme although the guide says to use HTTPS. It now runs `curl -q ... --url <url>` (`-q` first, so no configuration file; the URL is an option's value and cannot be read as an option), refuses a URL that does not start with `https://`, refuses `http://` unless `FETCH_CRL_ALLOW_HTTP=1` is set in its environment (decided: the list is signed, so HTTP costs no integrity, but whoever answers a plain-HTTP fetch can withhold a newer list, which is the lag this entry already states; the end-to-end test's loopback stand-in is plain HTTP and sets the variable), pins `--proto` to the scheme given and follows no redirect (`--max-redirs 0`; a 3xx is an error and the installed list stays). `--max-filesize` still stops an unsized body only from curl 8.4; before that `--max-time` bounds it, which the header and the guide now say. `docker/radius/tests/fetch-crl-test.sh` shows each point (a `~/.curlrc` of `location` and of `output` has no effect; `-o...`, `--output=...` and `-K<file>` as the URL, `file:`, `ftp:`, `gopher:`, an upper-case scheme and an empty URL are refused before curl runs; `http://` is refused without the variable and with any value but `1`; a redirect is not followed with the variable set; `https://` is attempted), and `radius_e2e.rs::eap_tls_with_an_axiam_issued_device_certificate` shows that the stand-in's `http://` URL is refused without the variable and leaves the installed list unchanged. Status unchanged: **Open**. **Corrected 2026-10-16 (release 1.1.0, the W8.3 reconciliation).** The 2026-10-14 correction above says “the recipe does not call AXIAM when a device authenticates (the real-time check, deferred item D4, is not built), so a disabled service account is seen only when its certificate is revoked.” That is the D3 profile's account, and it stays true of D3. D4 is built in 1.1.0: in the D4 profile FreeRADIUS asks AXIAM once per authentication, and a disabled account or a revoked certificate is refused at the device's next authentication (the amendment at the head of this entry). The status is unchanged: **Open**. **Amended 2026-10-19 (release 1.1.1, W5.4 and W5.5, #695 and #696; R111W5-06).** Two sentences above are corrected. The fetch script now sends `Cache-Control: no-cache` on every request, which makes a shared cache that honours request directives revalidate with AXIAM instead of answering with a list from before a revocation; a cache that ignores request directives still needs its own setting, and the bound above is unchanged for it. And “the age alert” is the script's own exit status: it exits 3 when the installed list expires in less than a quarter of its lifetime (`nextUpdate` minus `lastUpdate`) or has expired, read off the list itself after a 200, a 304 or a refusal alike, and that status takes the place of 0 or 1 (a refusal's reason is still on stderr), because FreeRADIUS refuses every device of the tenant once the list passes its `nextUpdate`; AXIAM re-signs at half the lifetime, so a healthy list never gets there, and the guide tells the operator to alert on any non-zero exit. Tests: `docker/radius/tests/fetch-crl-test.sh` (the `radius-e2e.yml` job, under `dash` and `bash`). The status is unchanged: **Open**."
  },
  {
   "number": 486,
   "title": "AXIAM unavailable, or reached through a proxy that ends TLS, refuses every device's authentication",
   "category": "Denial of service",
   "severity": "Medium",
   "diagramId": 9,
   "area": "RADIUS front end — native listener not built (G-11, declined 2026-10-06); FreeRADIUS recipe (1.0.1); decision route (1.1.0)",
   "element": "authorize (rlm_rest)",
   "residualRisk": "**Open: the accepted price of the Live profile, and the operator's to carry (entered 2026-10-15 by W6.6; `docs/pki/freeradius.md`, section 5).** Failing closed is the design — no fallback placement, no cached decision — because an outage that admitted devices would admit revoked and quarantined ones. What AXIAM provides: an allowance per caller sized for a site's power-restore storm (`network_decide_per_min`, 6 000 a minute), one `check_access_batch` per decision through the decision cache, and a recipe whose connection pool starts empty so that FreeRADIUS starts without AXIAM. What the operator carries, as the guide says: AXIAM run as a service the network depends on; mutual TLS that ends at AXIAM (a layer-4 pass-through is fine); one service account per FreeRADIUS server, so one site's storm stays out of another's bucket; FreeRADIUS's own certificate renewed before it ends; the list fetched while `check_crl` is on. `crates/axiam-server/tests/radius_e2e.rs::a_decision_per_authentication_places_revokes_and_quarantines` shows the failure is closed (AXIAM unreachable is a refusal); that is not a mitigation of the outage, and no status rests on it. **Amended 2026-10-16 (release 1.1.0; R110-01, the 1.1.0 combined review, #711).** One more item for what the operator carries: the listener FreeRADIUS reaches is AXIAM's only listener, serving every route, and with no appending proxy in front of it every per-address limiter keys on the `X-Forwarded-For` a caller writes (T-212's amendment of the same date). Expose that listener only to the FreeRADIUS servers (a firewall or a network policy) and keep the HTTP ingress, with its appending proxy, for everything else; `docs/pki/freeradius.md` section 5 says so. The status is unchanged: **Open**. **Amended 2026-10-19 (release 1.1.1; R110W6-10, #707).** The recipe no longer keeps a refused token for half its life: when the decision answers `401` the cache entry is dropped at once and, if the token came from the cache, `check-eap-tls` logs in again and asks the decision once more before rejecting (a token fetched in the same authentication is not retried; a second `401`, a `403` and every other failure still reject). A revoked and re-issued FreeRADIUS certificate, or a rotated AXIAM signing key, therefore costs one extra login, not up to half a token's life of refused authentications. Tests: the rotation step of `radius_e2e.rs::a_decision_per_authentication_places_revokes_and_quarantines` (the account's binding rotated under the cached token; the next authentication is admitted with no wait for the entry) and a stand-in `401` that is refused after the one retry. The status is unchanged: **Open**. **Residuals named 2026-10-19 (release 1.1.1, W5 F4 review, R111W5-01 and R111W5-03, #720 and #722; Low and Informational).** The retry above is not safe under concurrency: `Cache-TTL := 0` on an absent entry inserts the current `Tmp-String-2`, and the retry's store, finding an entry, merges it over the token just fetched, so concurrent `401`s can put the refused token back, the request that did it decides with the old token, gets a `401` and is rejected, and the cache holds the old token again. It fails closed, and an authentication that does not overlap another repeats the drop and the retry. Two statements above claim more than their tests show: in `post-auth` `rlm_rest` maps every `4xx` to `invalid`, so a `403` continues and is rejected by the status test (the outcome described, not the mechanism the file's comment gives), and the stand-in's `401` case does not assert that the retry ran, so it also passes against the 1.1.0 file. Not closed. The status is unchanged: **Open**."
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
  },
  {
   "number": 481,
   "title": "The network gate clears a write on a state that changes before the write lands",
   "category": "Elevation of privilege",
   "severity": "Low",
   "diagramId": 9,
   "area": "RADIUS front end — native listener not built (G-11, declined 2026-10-06); FreeRADIUS recipe (1.0.1); decision route (1.1.0)",
   "element": "Network management API and write gate",
   "residualRisk": "**Open (entered 2026-10-15 by W6.6; W6.2's residual 1, for the W6 F4 review, W6.7, to decide).** Nothing re-checks the gate's reads inside the write's transaction. The window is the time between the gate's read and the write. Bounding it: every check is uncached, so the window is one request's, not a cache TTL's; a binding that races an assignment or a release ends in a state the note's §5.3 also admits in the other order (bind first, then the assignment, which needs `network:grant` at the node), so it confers nothing a sequential pair could not — what the race changes is who was asked; and every write, and every refusal, is audited. Segment, profile and cap writes are the exception: each is conditional on the versions the caller read, inside the write's transaction (T-478). What would close the rest: re-reading the writer's grant and the account's joins inside the write's transaction, or a version on the account that both edges' writes claim (the two-writer rule). No test is claimed. **Corrected 2026-10-16 (release 1.1.0; R110-05 (d), the 1.1.0 combined review, #715; and the W6 F4 review's decision).** “Segment, profile and cap writes are the exception” says more than they do. Each is conditional on the versions the caller read, inside the write's transaction, and since `9dff2aa97` and `122b9ea92` the segment replace and delete and the profile delete also re-read, inside theirs, whether the segment has a profile; what they re-check is the row, not the writer's rights, so a `network:grant` or `network:segments_write` withdrawn between the gate and the commit is the same one-request window as the other writes here. The W6 F4 review (R110W6-04, 2026-10-16) confirmed the entry Low, added one interleaving — a grant of `network:join` to a role racing that role's assignment to a group leaves a network role on a group, through which membership then confers the join — and kept it Open, filed for 1.1.x as #701. The status is unchanged: **Open**. **Corrected 2026-10-17 (release 1.1.0; R110W6-04, #701, fixed in 1.1.0 at the maintainer's review of #716).** Every role write the gate decides now acts, with the gate's reads of the role, as one transaction. The role row carries two epochs (schema v101): `grant_epoch` moves with a `network:` grant or revoke and with an `is_global` write, `holder_epoch` with every assignment and unassignment. The gate reads them before anything else about the role and hands the write a claim (`GateClearance::role_claim`); the write's own transaction compares it (an assignment or unassignment the grant epoch, a grant, revoke or delete both, an `is_global` update the grant epoch), moves its own epoch, and when the claim no longer holds refuses with `409 conflict`, `reason_code` `stale_version`, and one `network_role.*_refused` audit row (`version:stale`); sent again, the request goes back through the gate. SurrealDB 3.3.4 detects only write-write conflicts (snapshot isolation; on `surrealkv` a plain read is never validated at commit), so a compare alone would not do: every claimed write also writes the role row, two overlapping ones conflict on that key, and the loser is retried on a fresh snapshot, where its compare fails. A revoke also deletes only the grant whose effect its gate read. Rule 2 is re-asserted inside the `network:` grant and group-assignment transactions as well, for writers that make no claim; the boot reconcile withholds, and logs, a `network:` grant to a super-admin that a group holds rather than failing the boot. The interleavings this closes, each with a race test on `surrealkv` that holds both requests at a barrier after their gates cleared them: rule 2 (a `network:` grant racing a group assignment, the review's case); H6 (a writer granting `network:join` to a role while assigning the role to itself — T-482's escalation); rule 1 (`is_global: true` racing a `network:` grant); rule 3 (an `inherit: false` assignment racing a deny); and a revoke racing a deny, which could delete a quarantine the revoke's gate never saw. Tests: `crates/axiam-api-rest/tests/network_gate_test.rs::r110w6_04_rule_2_a_grant_racing_a_group_assignment_never_lands_both`, `::r110w6_04_h6_a_join_grant_racing_a_self_assignment_never_lands_both`, `::r110w6_04_rule_1_a_global_update_racing_a_network_grant_never_lands_both`, `::r110w6_04_rule_3_a_non_inheriting_assignment_racing_a_deny_never_lands_both`, `::r110w6_04_a_revoke_racing_a_quarantine_never_deletes_the_deny`, `::a_network_grant_that_loses_to_a_group_assignment_is_409_stale_version_and_audited`; `crates/axiam-db/tests/network_role_group_rule_test.rs`; `crates/axiam-authz/src/network_gate/tests.rs::r110w6_04_every_decided_role_write_claims_the_epochs_it_read`, `::r110w6_04_a_write_that_reads_no_role_state_claims_nothing`, `::r110w6_04_a_revoke_claims_the_effect_it_read`. What stays open, and why the status does not change: what the gate reads about the **writer's own** rights, and about the account a certificate is bound to, is not claimed — a writer whose `network:grant` is withdrawn between the gate and the commit still writes, and a binding can land just after an assignment or release it did not see (the first two sentences of this entry); group membership is not on the role row either, which rule 2 makes moot for a role carrying a `network:` permission. The status is unchanged: **Open**. **Corrected 2026-10-19 (release 1.1.1; R110-05 (d), #715).** The first correction above left the entry's opening claim standing, so it is restated once, as the rule: the segment, profile and cap transactions re-check **the row** (the version the caller read and, for a segment replace or delete and a profile delete, whether the segment has a profile), **not the writer's rights**. They are no exception to this entry: a `network:grant` or `network:segments_write` withdrawn between the gate and the commit is the same one-request window as every other write here. The status is unchanged: **Open**."
  }
 ]
};

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
}

/** One row of a coverage table — a STRIDE category, or a severity. */
export interface ThreatModelBucket {
  name: string;
  total: number;
  open: number;
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
  /** Per-diagram counts, in model order. */
  areas: ThreatModelArea[];
  /** Counts per STRIDE category, in STRIDE order. */
  categories: ThreatModelBucket[];
  /** Counts per severity, most severe first. */
  severities: ThreatModelBucket[];
  /** Every threat not recorded as mitigated, most severe first. */
  openRisks: ThreatModelOpenRisk[];
}

export const THREAT_MODEL_SUMMARY: ThreatModelSummary = {
 "version": "2.27.0",
 "diagramCount": 9,
 "total": 401,
 "open": 19,
 "mitigated": 382,
 "areas": [
  {
   "id": 0,
   "title": "System diagram",
   "total": 33,
   "open": 2
  },
  {
   "id": 1,
   "title": "Authentication & session management",
   "total": 35,
   "open": 0
  },
  {
   "id": 2,
   "title": "OAuth2 / OIDC authorization server",
   "total": 60,
   "open": 0
  },
  {
   "id": 3,
   "title": "Federation — SAML SP & OIDC relying party",
   "total": 125,
   "open": 3
  },
  {
   "id": 4,
   "title": "Authorization engine — RBAC, hierarchy & scopes",
   "total": 27,
   "open": 0
  },
  {
   "id": 5,
   "title": "PKI, certificates & IoT device identity",
   "total": 30,
   "open": 1
  },
  {
   "id": 6,
   "title": "Audit, webhooks, email & notifications",
   "total": 35,
   "open": 5
  },
  {
   "id": 7,
   "title": "Deployment & platform (Kubernetes)",
   "total": 28,
   "open": 5
  },
  {
   "id": 8,
   "title": "Client SDKs & admin UI integration surface",
   "total": 28,
   "open": 3
  }
 ],
 "categories": [
  {
   "name": "Spoofing",
   "total": 92,
   "open": 4
  },
  {
   "name": "Tampering",
   "total": 79,
   "open": 2
  },
  {
   "name": "Repudiation",
   "total": 11,
   "open": 0
  },
  {
   "name": "Information disclosure",
   "total": 92,
   "open": 7
  },
  {
   "name": "Denial of service",
   "total": 46,
   "open": 4
  },
  {
   "name": "Elevation of privilege",
   "total": 81,
   "open": 2
  }
 ],
 "severities": [
  {
   "name": "Critical",
   "total": 41,
   "open": 2
  },
  {
   "name": "High",
   "total": 174,
   "open": 9
  },
  {
   "name": "Medium",
   "total": 159,
   "open": 7
  },
  {
   "name": "Low",
   "total": 27,
   "open": 1
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
   "number": 392,
   "title": "The push endpoint is used to reach internal services",
   "category": "Information disclosure",
   "severity": "High",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "SSF transmitter (SET issuance, stream API, discovery)",
   "residualRisk": "Write time is built: every endpoint an administrator or a receiver supplies is held to the webhook outbound address policy (D-49, `validate_push_endpoint`): `https` only, no credentials or fragment, no IP literal that is not globally routable (loopback, private, link-local, the metadata address, IPv4-mapped forms), no `localhost`, `*.local` or `*.internal`. Tests: `crates/axiam-oauth2/src/ssf.rs` `the_push_endpoint_policy_is_the_webhook_one`; `crates/axiam-api-rest/tests/ssf_test.rs` `every_value_rule_and_the_receiver_binding_are_400s_that_name_the_rule`, `a_receiver_cannot_repoint_its_endpoint_to_a_refused_address`. Open until T23.5.3's `SsfPush` deliverer sends every push only through `axiam_pki::ssrf::guarded_fetch` with `allow_private = false` (resolve, refuse, pin; no redirect followed; a capped response), with its test — a name that resolves to an internal address is only caught there."
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
   "number": 388,
   "title": "A captured SET is replayed to its receiver",
   "category": "Tampering",
   "severity": "Medium",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "SET push / poll response",
   "residualRisk": "AXIAM's half is built: every SET has a fresh 128-bit `jti` from the OS CSPRNG, and a retried push or a repeated poll re-signs the same pending event to byte-identical SET (Ed25519 is deterministic), so one event is one `jti` (D-48). Tests: `crates/axiam-oauth2/src/ssf.rs` `every_jti_is_unique`, `signing_the_same_pending_event_twice_gives_the_same_set`. Push travels over TLS to an `https` endpoint only, and poll responses are `no-store`. Open because the control is the receiver's: RFC 8417 §4.1 / contract §32.7 require it to remember the `jti`s it processed and refuse a repeat, and the receiver helper that does so ships in the SDKs only after the post-merge fan-out (D-35); a receiver that does not de-duplicate stays exposed for as long as it treats an old SET as news."
  },
  {
   "number": 394,
   "title": "A receiver is flooded with events",
   "category": "Denial of service",
   "severity": "Medium",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "SET push / poll response",
   "residualRisk": "Specified (D-48, D-52): one SET per event per stream, only for the events the stream carries; push goes through the shared outbound dispatcher (D-36), which bounds retries per kind (`max_attempts`, exponential backoff with a ceiling, then the dead-letter queue) and delivers one attempt per message, so a receiver that is down receives a bounded number of attempts per event and never a retry storm; a paused stream receives nothing. Open until T23.5.3 lands the `SsfPush` deliverer and the event sources on that dispatcher with the retry, dead-letter and pause tests; the residual then is that a mass revocation is as many SETs as sessions, by design (SSF has no batching)."
  },
  {
   "number": 395,
   "title": "The poll buffer grows without bound",
   "category": "Denial of service",
   "severity": "Medium",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "ssf_stream + ssf_event_buffer",
   "residualRisk": "Specified (D-48): at most 1 000 events per stream, the oldest dropped to admit the newest (SSF §8.1.2 permits dropping held events), a seven-day `expires_at` enforced by the sweeper, one row per `(tenant, stream, jti)` in the datastore, and the rows deleted with their stream and their tenant. Built so far: the table, its unique index and both cascades — `crates/axiam-db/tests/ssf_stream_repository_test.rs` `the_buffer_holds_one_row_per_jti`, `deleting_a_stream_removes_its_buffer_and_nothing_else`, `a_tenant_delete_removes_its_streams_and_buffers`. Open until T23.5.3 writes the buffer (bound, drop-oldest, expiry, acknowledgement) and registers its sweep in `/health/jobs`, with their tests."
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

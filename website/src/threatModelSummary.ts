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
 "version": "2.25.0",
 "diagramCount": 9,
 "total": 384,
 "open": 31,
 "mitigated": 353,
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
   "open": 19
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
   "total": 18,
   "open": 1
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
   "total": 90,
   "open": 8
  },
  {
   "name": "Tampering",
   "total": 77,
   "open": 5
  },
  {
   "name": "Repudiation",
   "total": 10,
   "open": 1
  },
  {
   "name": "Information disclosure",
   "total": 86,
   "open": 10
  },
  {
   "name": "Denial of service",
   "total": 43,
   "open": 4
  },
  {
   "name": "Elevation of privilege",
   "total": 78,
   "open": 3
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
   "total": 168,
   "open": 10
  },
  {
   "name": "Medium",
   "total": 150,
   "open": 13
  },
  {
   "name": "Low",
   "total": 25,
   "open": 6
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
   "number": 372,
   "title": "XML external entities, entity expansion or a decompression bomb in a logout message",
   "category": "Tampering",
   "severity": "High",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-38: T23.2.3's receiver, unchanged — 96 KiB encoded and 64 KiB decoded caps, inflating stopped one byte past the cap, any markup declaration and any non-UTF-8 encoding refused on the bytes, libxml without recovery or network — before any lookup. Closes when T23.2.4 lands with the receiver's refusal tests run against `/slo`."
  },
  {
   "number": 373,
   "title": "A logout message signed by the tenant's key is harvested as a signature-wrapping gadget",
   "category": "Spoofing",
   "severity": "High",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-38: AXIAM signs a `LogoutRequest` only for a session its holder ended or a verified SP request ended, and a `LogoutResponse` only in reply to a verified request — never for an unauthenticated party, so obtaining one needs a session (whose holder can already obtain signed responses for their own account) or an SP's key. On HTTP-Redirect the signature is the detached query signature, so no XML signature exists to harvest, and import prefers Redirect (D-41); on HTTP-POST it is enveloped like the assertion's (root child, one reference to the root `ID`) and re-verified before sending. AXIAM's own SP verifier refuses misplaced signatures (D-23). Closes when T23.2.4 lands with tests that no logout message is signed for an unverified request and that a Redirect-binding message carries no `ds:Signature`."
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
   "number": 312,
   "title": "Service providers link a user across SPs, or back to the AXIAM account",
   "category": "Information disclosure",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML assertion issuer (saml_idp)",
   "residualRisk": "Decision D-22: the default persistent `NameID` is HMAC-SHA256 under the dedicated deployment key `saml_pairwise_key` over a versioned label, the tenant id, the user id and the length-prefixed SP entity id, hex-encoded: different per SP and per tenant, not reversible without the key, and independent of the signing credential so a rotation changes nothing. Tests: `the_pairwise_name_id_differs_across_sps_tenants_users_and_keys`, `the_pairwise_name_id_is_stable_across_calls_and_across_a_credential_rotation`, `the_pairwise_name_id_contains_neither_the_user_id_nor_the_tenant_id`. An `emailAddress` `NameID`, and email, username, group and role attributes, are linkable by design and are released only to an SP an administrator configured them for. Open because `SessionIndex` is still the AXIAM session id at every SP of one sign-on. Decided (T23.2.8, 2026-10-04, D-37): a per-SP random `SessionIndex` recorded in `saml_sp_session` before signing and mapped back by the SLO endpoint by (tenant, SP, index) and then `NameID`, so SLO and the revocation feed still revoke the same session. Closes when T23.2.4 lands; the residual then is `AuthnInstant`, the session's authentication time at every SP, which colluding SPs can compare (T-314 forbids misstating it)."
  },
  {
   "number": 366,
   "title": "A registry row is read or written across tenants, or outlives the SP it described",
   "category": "Tampering",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "saml_service_provider (SP registry)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** Every repository method is tenant-keyed and `entity_id` is unique per tenant (T23.2.1, Mitigated at the repository); rows go with their tenant in the tenant-delete transaction. D-37 and §29.3 rule 5: deleting an SP deletes its `saml_sp_session` rows in the same transaction. The registry holds no secret (certificates are public), so a read discloses configuration, not credentials. Closes when T23.2.5 lands with the delete cascade test (T23.2.4 adds the table it cascades to)."
  },
  {
   "number": 370,
   "title": "A forged LogoutRequest ends another user's sessions",
   "category": "Spoofing",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-38: every `LogoutRequest` must be signed by the issuing SP's registered certificate — HTTP-Redirect over the exact octets received, RSA-SHA-2 only; HTTP-POST as the one enveloped signature of the root, verified on that node by xmlsec with SHA-1 refused; `verify_signed_xml` is never used — and an SP without a certificate cannot start a logout; `Destination` must be the tenant's SLO URL and `IssueInstant` fresh. D-37: the request resolves only sessions recorded for that SP whose `NameID` matches. Closes when T23.2.4 lands with tests for an unsigned, a wrongly signed, a misplaced-signature, a SHA-1, a wrong-`Destination` and a stale request, each ending nothing."
  },
  {
   "number": 371,
   "title": "A captured logout message is replayed",
   "category": "Spoofing",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-38: a `LogoutRequest` `ID` is single-use per SP (`replay_key` `{sp_id}:{ID}`, UNIQUE per tenant) for longer than the five-minute `IssueInstant` window; D-39: each outbound request `ID` is 256 random bits, stored as a digest and consumed once on the X6 arbiter when its response arrives, from the SP it was sent to. Closes when T23.2.4 lands with replay tests for both message kinds."
  },
  {
   "number": 374,
   "title": "A flood or an endless chain exhausts the SLO endpoint",
   "category": "Denial of service",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-38/D-39: the tenant check and D-20 `404` before the body is read; per-route governors with the `end_session_per_min` preset and the buckets `saml_idp_slo` and `saml_idp_sso_logout`; the receiver's size caps; at most 32 `SessionIndex` elements per request and 32 SPs per chain, then `PartialLogout`; runs expire after ten minutes. Closes when T23.2.4 lands with the limiters wired and the caps tested."
  },
  {
   "number": 375,
   "title": "The SLO endpoint delivers messages or the browser to a location an SP never registered",
   "category": "Tampering",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-38/D-39: outbound messages go only to the SP's registered `slo_url` on its registered `slo_binding`, the final response only to the initiating SP's registered `slo_url`; an SP's `RelayState` (≤ 80 bytes) is echoed to that SP only; the IdP-initiated trigger ends on AXIAM's own page with no redirect parameter; the POST binding renders through the D-27 auto-post page (`form-action` = the `slo_url` origin), so no second CSP setter appears. Closes when T23.2.4 lands with tests that a request naming another location is answered at the registered one."
  },
  {
   "number": 379,
   "title": "An SP's logout reaches sessions it never took part in, or another tenant's",
   "category": "Elevation of privilege",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-37/D-39: sessions are resolved by (path tenant, the verified issuer's SP, `SessionIndex`) in `saml_sp_session`, and the row's `NameID` value and format must equal the request's; with no index, only the sessions recorded for that SP and that `NameID`. Indexes are 256-bit random per SP. Closes when T23.2.4 lands with tests for another SP's index, a mismatched `NameID` and another tenant's path."
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
   "number": 381,
   "title": "The participant table links a person's sessions to the SPs they use",
   "category": "Information disclosure",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "saml_sp_session (per-SP SessionIndex)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-37: rows are tenant-scoped, deleted when SLO revokes their session, swept once the session has expired or is gone, deleted with their SP and their tenant, and removed by both erasure paths by `user_id`; they hold no credential (a `SessionIndex` alone ends nothing, since a logout request must be signed). Closes when T23.2.4 lands with the sweep, cascade and erasure tests."
  },
  {
   "number": 382,
   "title": "An assertion is issued whose session SLO cannot find",
   "category": "Tampering",
   "severity": "Medium",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "saml_sp_session (per-SP SessionIndex)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-37: the continue leg writes (or reads back) the participant row after consuming the handle and before signing; the issuer takes its `SessionIndex` from the row; a failed write answers `Responder` and issues nothing. Closes when T23.2.4 lands with a test that a failed participant write yields no assertion."
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
   "number": 376,
   "title": "A logout cannot be traced to the SP, the sessions and the outcome",
   "category": "Repudiation",
   "severity": "Low",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-39: an audit row `saml_idp.logout` per logout (initiator, SP, outcome, sessions ended, SPs told, partial), never a `NameID`; session revocation itself is recorded as every logout is. Closes when T23.2.4 lands with an audit test."
  },
  {
   "number": 377,
   "title": "Logout messages, NameIDs and RelayState are recorded in request logs",
   "category": "Information disclosure",
   "severity": "Low",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "LogoutRequest / LogoutResponse (Redirect / POST, via the browser)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** The W3 F4 request tracer (`RedactingRootSpanBuilder`) already redacts every query value not on `KEPT_QUERY_PARAMETERS`; D-38 adds no SLO parameter to that list, and the handlers log no message, `NameID`, `RelayState` or cookie. Closes when T23.2.4 lands with a test that `/slo`'s recorded target carries `[redacted]` for `SAMLRequest`, `SAMLResponse`, `RelayState`, `SigAlg` and `Signature`."
  },
  {
   "number": 378,
   "title": "A third-party page signs the visitor out of AXIAM and every SP",
   "category": "Spoofing",
   "severity": "Low",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "SAML SLO endpoint (/saml/v2/{tenant}/slo)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-39: `GET /saml/v2/{t}/sso/logout` is refused with `403` for `Sec-Fetch-Site: cross-site` (D-26's rule) and acts only on the session the browser's own OP cookie names, resolved through the tenant-keyed lookup; `/slo` itself acts only on signed SP requests. Residual as D-26: a browser that sends no fetch metadata is admitted. Closes when T23.2.4 lands with the cross-site refusal test."
  },
  {
   "number": 383,
   "title": "A database read yields a usable logout-chain identifier",
   "category": "Information disclosure",
   "severity": "Low",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "saml_logout_run (logout chains)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-39: the outbound request `ID` is stored as its SHA-256 digest, consumed once, and accepted only from the SP it was sent to (with its signature when it registered a certificate); runs are tenant-scoped, expire after ten minutes and go with their tenant. A forged response could at most continue a logout already under way. Closes when T23.2.4 lands with a test that the table holds no raw `ID`."
  },
  {
   "number": 384,
   "title": "Participant and logout-chain rows accumulate without bound",
   "category": "Denial of service",
   "severity": "Low",
   "diagramId": 3,
   "area": "Federation — SAML SP & OIDC relying party",
   "element": "saml_sp_session (per-SP SessionIndex)",
   "residualRisk": "**Specified, not yet built (T23.2.8, 2026-10-04).** D-37/D-39: one participant row per (session, SP), refreshed rather than duplicated; runs expire after ten minutes; both tables are swept by the cleanup scheduler and reported on `/health/jobs`. Closes when T23.2.4 lands with the sweep tests."
  }
 ]
};

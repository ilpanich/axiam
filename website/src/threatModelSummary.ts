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
 "version": "2.11.0",
 "diagramCount": 9,
 "total": 236,
 "open": 17,
 "mitigated": 219,
 "areas": [
  {
   "id": 0,
   "title": "System diagram",
   "total": 29,
   "open": 2
  },
  {
   "id": 1,
   "title": "Authentication & session management",
   "total": 32,
   "open": 1
  },
  {
   "id": 2,
   "title": "OAuth2 / OIDC authorization server",
   "total": 24,
   "open": 0
  },
  {
   "id": 3,
   "title": "Federation — SAML SP & OIDC relying party",
   "total": 31,
   "open": 1
  },
  {
   "id": 4,
   "title": "Authorization engine — RBAC, hierarchy & scopes",
   "total": 26,
   "open": 0
  },
  {
   "id": 5,
   "title": "PKI, certificates & IoT device identity",
   "total": 24,
   "open": 1
  },
  {
   "id": 6,
   "title": "Audit, webhooks, email & notifications",
   "total": 18,
   "open": 2
  },
  {
   "id": 7,
   "title": "Deployment & platform (Kubernetes)",
   "total": 26,
   "open": 6
  },
  {
   "id": 8,
   "title": "Client SDKs & admin UI integration surface",
   "total": 26,
   "open": 4
  }
 ],
 "categories": [
  {
   "name": "Spoofing",
   "total": 58,
   "open": 3
  },
  {
   "name": "Tampering",
   "total": 49,
   "open": 1
  },
  {
   "name": "Repudiation",
   "total": 5,
   "open": 0
  },
  {
   "name": "Information disclosure",
   "total": 57,
   "open": 7
  },
  {
   "name": "Denial of service",
   "total": 22,
   "open": 3
  },
  {
   "name": "Elevation of privilege",
   "total": 45,
   "open": 3
  }
 ],
 "severities": [
  {
   "name": "Critical",
   "total": 28,
   "open": 1
  },
  {
   "name": "High",
   "total": 113,
   "open": 8
  },
  {
   "name": "Medium",
   "total": 88,
   "open": 7
  },
  {
   "name": "Low",
   "total": 7,
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
   "residualRisk": "Deployment responsibility, stated in docs/deployment/vault.md rather than enforceable in-product: run a production-mode Vault with TLS (the shipped prod stack does — TLS material, init, unseal, then seed), scope AXIAM's token to read-only on its own KV path with the documented policy, keep unseal keys and the root token offline, and enable Vault's audit device so secret reads are attributable. The tooling is shaped to help, and since H-4 it CHECKS rather than merely advises: just vault-status queries sys/capabilities-self and reports the capabilities the token in hand actually holds on AXIAM's KV path, flagging anything beyond read — and a root token as what it is — with --strict to make it a failure in a deployment smoke test. It still reports secret presence only, never a value, and the seeder never rewrites a secret that already exists. Since 1.0.0-beta10 the token is no longer strictly read-only: it holds `read` on the startup path and `create`/`update` on `secret/data/axiam/ca-keys/*`, from the one policy file `docker/vault/axiam-policy.hcl`, and `just vault-status` reports missing capabilities as well as excess ones (T-232)."
  },
  {
   "number": 216,
   "title": "The unseal key sits on the same disk as the sealed data",
   "category": "Elevation of privilege",
   "severity": "High",
   "diagramId": 7,
   "area": "Deployment & platform (Kubernetes)",
   "element": "Secrets (Vault / K8s Secrets / ConfigMap)",
   "residualRisk": "Narrowed, not closed. `prod-up` now writes the read-only `axiam` policy from `docs/deployment/vault.md` §5.4 and issues a **scoped, periodic token** for the server, refusing to fall back to root if that fails; seeding keeps its own short-lived credential, because the seeding token and the serving token were never the same thing. Both the Compose stack and `k8s/vault/statefulset.yml` move from the `file` backend to **Raft**, which has a consistent backup story (`vault operator raft snapshot save`) and a migration path to three nodes that does not require a re-seed — a re-seed changes the OPAQUE setup key, i.e. a password reset for every user in every tenant. What remains **open** is auto-unseal, which cannot be closed from inside AXIAM: every Vault OSS seal type needs a cloud KMS or a second Vault elsewhere, and `pkcs11` is Enterprise-only, so a TPM is not an option whatever the hardware. `docs/deployment/vault.md` §5.3 and the Pi runbook §7.1 give the honest option table — GCP Cloud KMS at roughly $0.06 per key per month is the cheapest real answer — and state plainly that a deployment which configures none of them needs a human with three shares after every restart and is not production. A script that unseals from shares kept on the machine is explicitly **not** offered as an alternative: it removes the seal rather than automating it, and is strictly worse than Shamir because the shares are now in the one place an attacker already has. Two amendments since: the server's token is no longer strictly read-only — it holds `create`/`update` on the CA-key prefix, from the one policy file (T-232) — and the seeder that runs after unseal can no longer mistake a refused read for an empty Vault and mint fresh keys over the live ones (T-231). Vault itself runs unprivileged: the prod Compose stack chowns the Raft volume in a one-shot init container rather than running the process that holds every secret as root."
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
   "number": 39,
   "title": "Access token still valid after entitlement revocation",
   "category": "Elevation of privilege",
   "severity": "Medium",
   "diagramId": 1,
   "area": "Authentication & session management",
   "element": "Token service EdDSA JWT + refresh rotation",
   "residualRisk": "Accepted trade-off for stateless verification. The 15-minute lifetime bounds the window; sessions are invalidated on password change; deployments needing immediate revocation should use the gRPC introspection path rather than local JWT verification."
  },
  {
   "number": 110,
   "title": "Personal data over-collected into an immutable log",
   "category": "Information disclosure",
   "severity": "Medium",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "Audit middleware & service",
   "residualRisk": "Partially addressed: audit metadata is deliberately minimised, erasure anonymises the subject rather than deleting audit records, and a default retention sweep bounds the log at 730 days — the table's only deletion path, configurable and disableable with 0 (T-119). What remains open is the collection side: nothing prevents a deployment from writing personal data into fields the sweep will hold for the full window, so the retention period must still be set consistent with the deployment's lawful basis."
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
   "number": 143,
   "title": "Local JWT verification misses a revoked entitlement",
   "category": "Elevation of privilege",
   "severity": "Medium",
   "diagramId": 8,
   "area": "Client SDKs & admin UI integration surface",
   "element": "SDK token verification (JWKS cache, iss/aud)",
   "residualRisk": "Bounded by the 15-minute access-token lifetime. CONTRACT §10 and §11 expose route-guard and declarative-authorization helpers; integrations needing immediate revocation should call gRPC introspection or CheckAccess rather than verifying locally."
  },
  {
   "number": 234,
   "title": "The gRPC TLS leaf expires because tonic reads it once at startup",
   "category": "Denial of service",
   "severity": "Medium",
   "diagramId": 7,
   "area": "Deployment & platform (Kubernetes)",
   "element": "AXIAM deployment (N replicas, HPA)",
   "residualRisk": "Open, with the residual bounded operationally. tonic 0.14's `ServerTlsConfig` does not accept a rustls `ServerConfig`, so the existing `ReloadableCertResolver` cannot be installed behind it; the structural fix is a hand-rolled accept loop over `tokio-rustls` using that resolver, which would close the reload gap and the TLS-version gap in one change and needs its own tests. Until it exists the runbook states the workaround rather than leaving it to be discovered at day 90: when gRPC TLS is on, the certbot deploy hook restarts the container — roughly fifteen seconds every sixty days, at a moment the operator controls — while keeping the REST listener's `SIGHUP` reload, so removing the restart later leaves a correct hook rather than a broken one. The exposure is opt-in twice over: the listener is loopback-bound unless published (T-233), and its TLS is off unless both paths are set. On the documented topology the only client of that leg is Caddy on loopback, which negotiates TLS 1.3, and the public half can be pinned with `protocols tls1.3`."
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

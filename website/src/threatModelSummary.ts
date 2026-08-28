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
 "version": "2.8.0",
 "diagramCount": 9,
 "total": 199,
 "open": 16,
 "mitigated": 183,
 "areas": [
  {
   "id": 0,
   "title": "System diagram",
   "total": 28,
   "open": 2
  },
  {
   "id": 1,
   "title": "Authentication & session management",
   "total": 29,
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
   "total": 23,
   "open": 1
  },
  {
   "id": 4,
   "title": "Authorization engine — RBAC, hierarchy & scopes",
   "total": 19,
   "open": 0
  },
  {
   "id": 5,
   "title": "PKI, certificates & IoT device identity",
   "total": 23,
   "open": 1
  },
  {
   "id": 6,
   "title": "Audit, webhooks, email & notifications",
   "total": 18,
   "open": 3
  },
  {
   "id": 7,
   "title": "Deployment & platform (Kubernetes)",
   "total": 13,
   "open": 4
  },
  {
   "id": 8,
   "title": "Client SDKs & admin UI integration surface",
   "total": 22,
   "open": 4
  }
 ],
 "categories": [
  {
   "name": "Spoofing",
   "total": 49,
   "open": 3
  },
  {
   "name": "Tampering",
   "total": 39,
   "open": 2
  },
  {
   "name": "Repudiation",
   "total": 5,
   "open": 0
  },
  {
   "name": "Information disclosure",
   "total": 52,
   "open": 7
  },
  {
   "name": "Denial of service",
   "total": 19,
   "open": 2
  },
  {
   "name": "Elevation of privilege",
   "total": 35,
   "open": 2
  }
 ],
 "severities": [
  {
   "name": "Critical",
   "total": 26,
   "open": 1
  },
  {
   "name": "High",
   "total": 91,
   "open": 7
  },
  {
   "name": "Medium",
   "total": 75,
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
   "residualRisk": "Partially enacted: the Rust, TypeScript, Python and C# SDKs and the shared axiam-opaque core publish via Trusted Publishing (OIDC), so no long-lived registry token exists to steal for them; PHP publishes through Packagist's webhook and Go, Swift, C and C++ from git tags. Maven Central (Java, Kotlin) still requires stored credentials, and a compromised release workflow remains a live risk everywhere — pin and review workflow actions by digest as this repository's CI already does, and publish provenance attestations so integrators can verify build origin."
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
   "residualRisk": "Deployment responsibility, stated in docs/deployment/vault.md rather than enforceable in-product: run a production-mode Vault with TLS (the shipped prod stack does — TLS material, init, unseal, then seed), scope AXIAM's token to read-only on its own KV path with the documented policy, keep unseal keys and the root token offline, and enable Vault's audit device so secret reads are attributable. The tooling is shaped to help: just vault-status reports presence only, never values, and the seeder never rewrites a secret that already exists."
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
   "number": 118,
   "title": "Audit trail deleted along with the tenant",
   "category": "Tampering",
   "severity": "Medium",
   "diagramId": 6,
   "area": "Audit, webhooks, email & notifications",
   "element": "audit_log (append-only, signed)",
   "residualRisk": "Not resolved in-product: retention of audit records past tenant deletion is a deployment decision that conflicts with GDPR erasure. Export audit records to an external WORM sink before deletion if your retention obligations require it."
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

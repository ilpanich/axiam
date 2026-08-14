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

export interface ThreatModelSummary {
  /** Threat Dragon model schema version. */
  version: string;
  diagramCount: number;
  total: number;
  open: number;
  mitigated: number;
  /** Per-diagram counts, in model order. */
  areas: ThreatModelArea[];
}

export const THREAT_MODEL_SUMMARY: ThreatModelSummary = {
 "version": "2.7.0",
 "diagramCount": 9,
 "total": 165,
 "open": 23,
 "mitigated": 142,
 "areas": [
  {
   "id": 0,
   "title": "System diagram",
   "total": 26,
   "open": 3
  },
  {
   "id": 1,
   "title": "Authentication & session management",
   "total": 22,
   "open": 1
  },
  {
   "id": 2,
   "title": "OAuth2 / OIDC authorization server",
   "total": 16,
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
   "total": 15,
   "open": 1
  },
  {
   "id": 5,
   "title": "PKI, certificates & IoT device identity",
   "total": 18,
   "open": 2
  },
  {
   "id": 6,
   "title": "Audit, webhooks, email & notifications",
   "total": 18,
   "open": 4
  },
  {
   "id": 7,
   "title": "Deployment & platform (Kubernetes)",
   "total": 12,
   "open": 7
  },
  {
   "id": 8,
   "title": "Client SDKs & admin UI integration surface",
   "total": 15,
   "open": 4
  }
 ]
};

import { describe, it, expect, beforeEach, vi } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  webauthnPolicyService,
  effectiveUnknownAaguid,
  validateAttestationPolicy,
  isValidAaguid,
  parseAaguidList,
  isUnknownCredential,
  complianceReasonLabel,
  DEFAULT_ATTESTATION_POLICY,
  UNKNOWN_CREDENTIAL_REASON,
  type WebauthnAttestationPolicy,
  type ComplianceReportEntry,
} from "./webauthnPolicy";

beforeEach(() => {
  vi.clearAllMocks();
});

// ─── effectiveUnknownAaguid ─────────────────────────────────────────────────
// Mirrors WebauthnAttestationPolicy::effective_unknown_aaguid in
// crates/axiam-core/src/models/webauthn_policy.rs exactly.

describe("effectiveUnknownAaguid", () => {
  it("resolves to deny under direct_required when unset", () => {
    expect(
      effectiveUnknownAaguid({ mode: "direct_required", unknown_aaguid: null }),
    ).toBe("deny");
  });

  it("resolves to allow under none/indirect when unset", () => {
    expect(effectiveUnknownAaguid({ mode: "none", unknown_aaguid: null })).toBe(
      "allow",
    );
    expect(
      effectiveUnknownAaguid({ mode: "indirect", unknown_aaguid: null }),
    ).toBe("allow");
  });

  it("an explicit value always wins over the mode default, in both directions", () => {
    expect(
      effectiveUnknownAaguid({ mode: "direct_required", unknown_aaguid: "allow" }),
    ).toBe("allow");
    expect(
      effectiveUnknownAaguid({ mode: "none", unknown_aaguid: "deny" }),
    ).toBe("deny");
  });
});

// ─── validateAttestationPolicy ──────────────────────────────────────────────

describe("validateAttestationPolicy", () => {
  it("accepts the default policy", () => {
    expect(validateAttestationPolicy(DEFAULT_ATTESTATION_POLICY)).toBeNull();
  });

  it("rejects require_fido_certified with mode none", () => {
    const err = validateAttestationPolicy({
      ...DEFAULT_ATTESTATION_POLICY,
      require_fido_certified: true,
    });
    expect(err).toMatch(/require_fido_certified/);
  });

  it("rejects min_certification with mode none", () => {
    const err = validateAttestationPolicy({
      ...DEFAULT_ATTESTATION_POLICY,
      min_certification: "L1",
    });
    expect(err).toMatch(/min_certification/);
  });

  it("accepts both fields under direct_required", () => {
    const err = validateAttestationPolicy({
      ...DEFAULT_ATTESTATION_POLICY,
      mode: "direct_required",
      require_fido_certified: true,
      min_certification: "L1",
    });
    expect(err).toBeNull();
  });
});

// ─── AAGUID parsing ─────────────────────────────────────────────────────────

describe("isValidAaguid", () => {
  it("accepts a well-formed UUID", () => {
    expect(isValidAaguid("ee882879-721c-4913-9775-3dfcce97072a")).toBe(true);
  });

  it("rejects garbage", () => {
    expect(isValidAaguid("not-a-uuid")).toBe(false);
    expect(isValidAaguid("")).toBe(false);
  });
});

describe("parseAaguidList", () => {
  it("splits on commas, whitespace and newlines, dropping blanks", () => {
    const raw = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa, bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb\n\ncccccccc-cccc-cccc-cccc-cccccccccccc";
    expect(parseAaguidList(raw)).toEqual([
      "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
      "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
      "cccccccc-cccc-cccc-cccc-cccccccccccc",
    ]);
  });

  it("lowercases entries", () => {
    expect(parseAaguidList("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")).toEqual([
      "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    ]);
  });

  it("returns [] for blank input", () => {
    expect(parseAaguidList("   \n  ")).toEqual([]);
  });
});

// ─── Compliance report helpers ──────────────────────────────────────────────

function entry(overrides: Partial<ComplianceReportEntry> = {}): ComplianceReportEntry {
  return {
    credential_id: "c1",
    user_id: "u1",
    name: "My key",
    aaguid: "ee882879-721c-4913-9775-3dfcce97072a",
    authenticator_name: "YubiKey 5",
    compliant: true,
    reason: null,
    ...overrides,
  };
}

describe("isUnknownCredential", () => {
  it("is true whenever aaguid is null, regardless of compliant/reason", () => {
    expect(
      isUnknownCredential(
        entry({ aaguid: null, compliant: true, reason: UNKNOWN_CREDENTIAL_REASON }),
      ),
    ).toBe(true);
  });

  it("is false for a credential with a recorded aaguid, compliant or not", () => {
    expect(isUnknownCredential(entry({ compliant: true }))).toBe(false);
    expect(
      isUnknownCredential(entry({ compliant: false, reason: "aaguid_blocked" })),
    ).toBe(false);
  });
});

describe("complianceReasonLabel", () => {
  it("returns null for a null reason", () => {
    expect(complianceReasonLabel(null)).toBeNull();
  });

  it("maps every documented deny reason to human copy", () => {
    for (const reason of [
      "attestation_required",
      "aaguid_blocked",
      "aaguid_not_allowed",
      "unknown_authenticator",
      "authenticator_revoked",
      "not_fido_certified",
      "certification_too_low",
    ]) {
      const label = complianceReasonLabel(reason);
      expect(label).not.toBeNull();
      expect(label).not.toBe(reason);
    }
  });

  it("falls back to the raw string for an unrecognized reason rather than hiding it", () => {
    expect(complianceReasonLabel("some_future_reason")).toBe("some_future_reason");
  });
});

// ─── Service ────────────────────────────────────────────────────────────────

describe("webauthnPolicyService", () => {
  const tenantId = "t1";

  it("getPolicy calls the tenant-scoped GET", async () => {
    apiMock.get.mockResolvedValue(res(DEFAULT_ATTESTATION_POLICY));
    const result = await webauthnPolicyService.getPolicy(tenantId);
    expect(apiMock.get).toHaveBeenCalledWith(
      "/api/v1/tenants/t1/webauthn/attestation-policy",
    );
    expect(result).toEqual(DEFAULT_ATTESTATION_POLICY);
  });

  it("setPolicy PUTs the full policy body", async () => {
    const policy: WebauthnAttestationPolicy = {
      ...DEFAULT_ATTESTATION_POLICY,
      mode: "direct_required",
      unknown_aaguid: "deny",
    };
    apiMock.put.mockResolvedValue(res(policy));
    const result = await webauthnPolicyService.setPolicy(tenantId, policy);
    expect(apiMock.put).toHaveBeenCalledWith(
      "/api/v1/tenants/t1/webauthn/attestation-policy",
      policy,
    );
    expect(result).toEqual(policy);
  });

  it("complianceReport unwraps a bare array", async () => {
    apiMock.get.mockResolvedValue(res([entry()]));
    const result = await webauthnPolicyService.complianceReport(tenantId);
    expect(apiMock.get).toHaveBeenCalledWith(
      "/api/v1/tenants/t1/webauthn/compliance-report",
    );
    expect(result).toEqual([entry()]);
  });

  it("complianceReport unwraps an { items } envelope", async () => {
    apiMock.get.mockResolvedValue(res({ items: [entry()] }));
    const result = await webauthnPolicyService.complianceReport(tenantId);
    expect(result).toEqual([entry()]);
  });
});

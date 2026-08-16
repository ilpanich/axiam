import { describe, it, expect, beforeEach, vi } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  validateClientPosture,
  isStrongAuthMethod,
  OAUTH2_SCOPES,
  type ClientPosturePayload,
} from "@/services/oauth2clients";
import {
  emailConfigService,
  validateOrgEmailConfig,
  type SetOrgEmailConfigPayload,
} from "@/services/emailConfig";
import { federationLinkService } from "@/services/federation";
import { auditService } from "@/services/audit";
import { certificateService } from "@/services/certificates";

beforeEach(() => {
  vi.clearAllMocks();
});

// ─── X5.1 client posture ──────────────────────────────────────────────────────

/** A `standard` client authenticating with a secret — the pre-X5.1 shape. */
const STANDARD: ClientPosturePayload = {
  profile: "standard",
  token_endpoint_auth_method: "client_secret_post",
};

describe("validateClientPosture", () => {
  it("accepts the pre-X5.1 client shape without a single check firing", () => {
    expect(validateClientPosture(STANDARD)).toBeNull();
  });

  it("accepts an empty posture, since every field defaults", () => {
    expect(validateClientPosture({})).toBeNull();
  });

  // RFC 8705 §2.1.2 — exactly one binding, whatever the profile.
  it("rejects tls_client_auth with no binding registered", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "tls_client_auth",
      })
    ).toMatch(/exactly one of Subject DN/);
  });

  it("rejects tls_client_auth with two bindings registered", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "tls_client_auth",
        tls_client_auth_subject_dn: "CN=a",
        tls_client_auth_san_dns: "a.example.com",
      })
    ).toMatch(/2 registered/);
  });

  it("accepts tls_client_auth with exactly one binding", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "tls_client_auth",
        tls_client_auth_san_dns: "a.example.com",
      })
    ).toBeNull();
  });

  it("treats a blank binding as unregistered, matching the backend", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "tls_client_auth",
        tls_client_auth_subject_dn: "   ",
      })
    ).toMatch(/0 registered/);
  });

  it("rejects self_signed_tls_client_auth with no thumbprint", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "self_signed_tls_client_auth",
        self_signed_tls_client_auth_thumbprints: [],
      })
    ).toMatch(/at least one certificate thumbprint/);
  });

  it("rejects a malformed thumbprint even under a method that ignores it", () => {
    expect(
      validateClientPosture({
        ...STANDARD,
        self_signed_tls_client_auth_thumbprints: ["too-short"],
      })
    ).toMatch(/not a well-formed thumbprint/);
  });

  it("accepts a 43-character base64url thumbprint", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "self_signed_tls_client_auth",
        self_signed_tls_client_auth_thumbprints: ["a".repeat(43)],
      })
    ).toBeNull();
  });

  // RFC 7591 §2 — jwks or jwks_uri, never both and never neither.
  it("rejects private_key_jwt with neither key source", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "private_key_jwt",
      })
    ).toMatch(/0 registered/);
  });

  it("rejects private_key_jwt with both key sources", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "private_key_jwt",
        jwks: '{"keys":[]}',
        jwks_uri: "https://c.example.com/jwks.json",
      })
    ).toMatch(/2 registered/);
  });

  it("rejects an unparseable inline JWKS", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "private_key_jwt",
        jwks: "not json",
      })
    ).toMatch(/valid JSON/);
  });

  it("rejects a non-https jwks_uri", () => {
    expect(
      validateClientPosture({
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "http://c.example.com/jwks.json",
      })
    ).toMatch(/absolute https URL/);
  });

  // The FAPI 2.0 bundle.
  it("rejects a fapi2 client that does not require PAR", () => {
    expect(
      validateClientPosture({
        profile: "fapi2",
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://c.example.com/jwks.json",
        dpop_bound_access_tokens: true,
        require_par: false,
      })
    ).toMatch(/must require pushed authorization requests/);
  });

  it("rejects a fapi2 client authenticating with a secret", () => {
    expect(
      validateClientPosture({
        profile: "fapi2",
        token_endpoint_auth_method: "client_secret_post",
        require_par: true,
        dpop_bound_access_tokens: true,
      })
    ).toMatch(/cannot authenticate with client_secret_post/);
  });

  it("rejects a fapi2 client whose tokens are not sender-constrained", () => {
    expect(
      validateClientPosture({
        profile: "fapi2",
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://c.example.com/jwks.json",
        require_par: true,
      })
    ).toMatch(/must sender-constrain its tokens/);
  });

  it("accepts a complete fapi2 registration via private_key_jwt + DPoP", () => {
    expect(
      validateClientPosture({
        profile: "fapi2",
        token_endpoint_auth_method: "private_key_jwt",
        jwks_uri: "https://c.example.com/jwks.json",
        require_par: true,
        dpop_bound_access_tokens: true,
      })
    ).toBeNull();
  });

  it("accepts a complete fapi2 registration via mTLS + certificate binding", () => {
    expect(
      validateClientPosture({
        profile: "fapi2",
        token_endpoint_auth_method: "tls_client_auth",
        tls_client_auth_subject_dn: "CN=payments,O=Example",
        require_par: true,
        tls_client_certificate_bound_access_tokens: true,
      })
    ).toBeNull();
  });
});

describe("isStrongAuthMethod", () => {
  it("counts only client_secret_post as weak", () => {
    expect(isStrongAuthMethod("client_secret_post")).toBe(false);
    expect(isStrongAuthMethod("tls_client_auth")).toBe(true);
    expect(isStrongAuthMethod("self_signed_tls_client_auth")).toBe(true);
    expect(isStrongAuthMethod("private_key_jwt")).toBe(true);
  });
});

describe("OAUTH2_SCOPES", () => {
  // X2 — without this a resource server cannot be onboarded to the UMA
  // Protection API from the admin UI at all.
  it("offers uma_protection", () => {
    expect(OAUTH2_SCOPES).toContain("uma_protection");
  });
});

// ─── Email configuration ──────────────────────────────────────────────────────

const SMTP_CONFIG: SetOrgEmailConfigPayload = {
  enabled: true,
  from_name: "Example",
  from_email: "no-reply@example.com",
  reply_to: null,
  provider: {
    kind: "smtp",
    host: "smtp.example.com",
    port: 587,
    username: "u",
    password: "",
    starttls: true,
  },
};

describe("validateOrgEmailConfig", () => {
  it("accepts a well-formed SMTP configuration", () => {
    expect(validateOrgEmailConfig(SMTP_CONFIG)).toBeNull();
  });

  it("rejects an empty from_name", () => {
    expect(
      validateOrgEmailConfig({ ...SMTP_CONFIG, from_name: "  " })
    ).toMatch(/From name/);
  });

  it("rejects a from_email with no @", () => {
    expect(
      validateOrgEmailConfig({ ...SMTP_CONFIG, from_email: "nobody" })
    ).toMatch(/valid email address/);
  });

  it("accepts a null reply_to but rejects a malformed one", () => {
    expect(
      validateOrgEmailConfig({ ...SMTP_CONFIG, reply_to: null })
    ).toBeNull();
    expect(
      validateOrgEmailConfig({ ...SMTP_CONFIG, reply_to: "nope" })
    ).toMatch(/Reply-to/);
  });

  it("rejects an empty SMTP host and a zero port", () => {
    expect(
      validateOrgEmailConfig({
        ...SMTP_CONFIG,
        provider: { ...SMTP_CONFIG.provider, kind: "smtp", host: "" } as never,
      })
    ).toMatch(/SMTP host/);
    expect(
      validateOrgEmailConfig({
        ...SMTP_CONFIG,
        provider: { ...SMTP_CONFIG.provider, kind: "smtp", port: 0 } as never,
      })
    ).toMatch(/SMTP port/);
  });

  it("accepts an API provider with no api_key — the preserve-stored sentinel", () => {
    expect(
      validateOrgEmailConfig({
        ...SMTP_CONFIG,
        provider: { kind: "send_grid", api_key: "", api_url: null },
      })
    ).toBeNull();
  });
});

describe("emailConfigService", () => {
  it("reads the org config", async () => {
    apiMock.get.mockResolvedValue(res({ id: "e1" }));
    await expect(emailConfigService.getOrgConfig("o1")).resolves.toEqual({
      id: "e1",
    });
    expect(apiMock.get).toHaveBeenCalledWith(
      "/api/v1/organizations/o1/email-config"
    );
  });

  // A scope that has never been configured answers 404, which is a state to
  // render, not an error to throw.
  it("maps a 404 to null rather than throwing", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 404 } });
    await expect(emailConfigService.getOrgConfig("o1")).resolves.toBeNull();
  });

  it("rethrows a non-404 failure", async () => {
    apiMock.get.mockRejectedValue({ response: { status: 500 } });
    await expect(emailConfigService.getOrgConfig("o1")).rejects.toBeDefined();
  });

  it("writes the org config", async () => {
    apiMock.put.mockResolvedValue(res({ id: "e1" }));
    await emailConfigService.setOrgConfig("o1", SMTP_CONFIG);
    expect(apiMock.put).toHaveBeenCalledWith(
      "/api/v1/organizations/o1/email-config",
      SMTP_CONFIG
    );
  });

  it("deletes the org config", async () => {
    apiMock.delete.mockResolvedValue(res(undefined));
    await emailConfigService.deleteOrgConfig("o1");
    expect(apiMock.delete).toHaveBeenCalledWith(
      "/api/v1/organizations/o1/email-config"
    );
  });

  it("reads, writes and clears the tenant override", async () => {
    apiMock.get.mockResolvedValue(res({ enabled: false }));
    await expect(
      emailConfigService.getTenantOverride("t1")
    ).resolves.toEqual({ enabled: false });
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/tenants/t1/email-config");

    apiMock.put.mockResolvedValue(res({ enabled: false }));
    await emailConfigService.setTenantOverride("t1", { enabled: false });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/tenants/t1/email-config", {
      enabled: false,
    });

    apiMock.delete.mockResolvedValue(res(undefined));
    await emailConfigService.deleteTenantOverride("t1");
    expect(apiMock.delete).toHaveBeenCalledWith(
      "/api/v1/tenants/t1/email-config"
    );
  });
});

// ─── Federation links ─────────────────────────────────────────────────────────

describe("federationLinkService", () => {
  it("lists a user's links, unwrapping the pagination envelope", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "fl1" }] }));
    await expect(
      federationLinkService.listForUser("u1")
    ).resolves.toEqual([{ id: "fl1" }]);
    expect(apiMock.get).toHaveBeenCalledWith(
      "/api/v1/federation-links/user/u1"
    );
  });

  it("unlinks by link id, not by user id", async () => {
    apiMock.delete.mockResolvedValue(res(undefined));
    await federationLinkService.unlink("fl1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/federation-links/fl1");
  });
});

// ─── System audit trail ───────────────────────────────────────────────────────

describe("auditService.listSystem", () => {
  it("targets the system endpoint with the same filter query", async () => {
    apiMock.get.mockResolvedValue(res({ items: [], total: 0 }));
    await auditService.listSystem({ offset: 20, limit: 20, action: "login" });
    expect(apiMock.get).toHaveBeenCalledWith(
      "/api/v1/audit-logs/system?offset=20&limit=20&action=login"
    );
  });

  it("widens a bare date to full-day UTC bounds, as the tenant list does", async () => {
    apiMock.get.mockResolvedValue(res({ items: [], total: 0 }));
    await auditService.listSystem({ from: "2026-01-01", to: "2026-01-31" });
    const url = apiMock.get.mock.calls[0][0] as string;
    expect(url).toContain("from=2026-01-01T00%3A00%3A00Z");
    expect(url).toContain("to=2026-01-31T23%3A59%3A59Z");
  });
});

// ─── Service-account certificate binding ──────────────────────────────────────

describe("certificateService.bindToServiceAccount", () => {
  // Routed under the service account, bodied with the certificate id.
  it("posts the certificate id to the service account's bind endpoint", async () => {
    apiMock.post.mockResolvedValue(
      res({ certificate_id: "c1", service_account_id: "sa1", status: "bound" })
    );
    await expect(
      certificateService.bindToServiceAccount("sa1", "c1")
    ).resolves.toEqual({
      certificate_id: "c1",
      service_account_id: "sa1",
      status: "bound",
    });
    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/service-accounts/sa1/bind-certificate",
      { certificate_id: "c1" }
    );
  });
});

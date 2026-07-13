import { describe, it, expect, beforeEach, vi } from "vitest";
import { apiMock, res } from "@/test/apiMock";

// Every service module imports the singleton axios instance from "@/lib/api".
// Mock it once here so we can assert the exact URL/method/body each service
// call emits and drive the response-mapping logic.
vi.mock("@/lib/api", () => ({ default: apiMock }));

import { unwrapList } from "@/services/_pagination";
import { userService, groupService } from "@/services/users";
import {
  orgService,
  tenantService,
  caCertService,
  orgSettingsService,
  flattenOrgSettings,
  type SecuritySettings,
} from "@/services/organizations";
import { authService } from "@/services/auth";
import { auditService } from "@/services/audit";
import { certificateService } from "@/services/certificates";
import { federationService } from "@/services/federation";
import {
  notificationRuleService,
  notificationEventLabel,
  NOTIFICATION_EVENTS,
} from "@/services/notificationRules";
import { oauth2ClientService } from "@/services/oauth2clients";
import { permissionService } from "@/services/permissions";
import { pgpService } from "@/services/pgp";
import { resourceService, resourceTypeLabel } from "@/services/resources";
import { roleService } from "@/services/roles";
import { serviceAccountService } from "@/services/serviceAccounts";
import { settingsService } from "@/services/settings";
import { webhookService } from "@/services/webhooks";

beforeEach(() => {
  vi.clearAllMocks();
});

// ─── _pagination ────────────────────────────────────────────────────────────

describe("unwrapList", () => {
  it("returns a bare array unchanged", () => {
    expect(unwrapList([1, 2, 3])).toEqual([1, 2, 3]);
  });
  it("unwraps a { items } envelope", () => {
    expect(unwrapList({ items: ["a"] })).toEqual(["a"]);
  });
  it("returns [] for a missing items field", () => {
    expect(unwrapList({})).toEqual([]);
  });
  it("returns [] for null / undefined", () => {
    expect(unwrapList(null)).toEqual([]);
    expect(unwrapList(undefined)).toEqual([]);
  });
});

// ─── users ──────────────────────────────────────────────────────────────────

describe("userService", () => {
  const dto = {
    id: "u1",
    username: "alice",
    email: "alice@x.io",
    mfa_enabled: false,
    email_verified: true,
    created_at: "t",
    updated_at: "t",
    status: "Active",
    is_locked: false,
    locked_until: null,
    failed_login_attempts: 0,
    metadata: { display_name: "Alice A" },
  };

  it("list builds offset/limit params and lifts display_name from metadata", async () => {
    apiMock.get.mockResolvedValue(
      res({ items: [dto], total: 1, offset: 0, limit: 20 })
    );
    const out = await userService.list(2, 20);
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/users?offset=20&limit=20");
    expect(out.items[0].display_name).toBe("Alice A");
  });

  it("list applies client-side search across username/email/display_name", async () => {
    const other = { ...dto, id: "u2", username: "bob", email: "bob@x.io", metadata: {} };
    apiMock.get.mockResolvedValue(
      res({ items: [dto, other], total: 2, offset: 0, limit: 20 })
    );
    const out = await userService.list(1, 20, "  ALICE ");
    expect(out.items).toHaveLength(1);
    expect(out.items[0].username).toBe("alice");
  });

  it("list without search returns the mapped page as-is", async () => {
    apiMock.get.mockResolvedValue(
      res({ items: [{ ...dto, metadata: {} }], total: 1, offset: 0, limit: 20 })
    );
    const out = await userService.list();
    expect(out.items[0].display_name).toBeUndefined();
  });

  it("get maps a single user", async () => {
    apiMock.get.mockResolvedValue(res(dto));
    const u = await userService.get("u1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/users/u1");
    expect(u.display_name).toBe("Alice A");
  });

  it("create routes display_name into metadata", async () => {
    apiMock.post.mockResolvedValue(res(dto));
    await userService.create({
      username: "alice",
      email: "a@x.io",
      password: "pw",
      display_name: "Alice A",
    });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/users", {
      username: "alice",
      email: "a@x.io",
      password: "pw",
      metadata: { display_name: "Alice A" },
    });
  });

  it("create omits metadata when no display_name", async () => {
    apiMock.post.mockResolvedValue(res(dto));
    await userService.create({ username: "a", email: "a@x.io", password: "pw" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/users", {
      username: "a",
      email: "a@x.io",
      password: "pw",
    });
  });

  it("update sends metadata only when display_name is defined (even empty)", async () => {
    apiMock.put.mockResolvedValue(res(dto));
    await userService.update("u1", { display_name: "", status: "Active" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/users/u1", {
      status: "Active",
      metadata: { display_name: "" },
    });
  });

  it("update without display_name omits metadata", async () => {
    apiMock.put.mockResolvedValue(res(dto));
    await userService.update("u1", { email: "new@x.io" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/users/u1", { email: "new@x.io" });
  });

  it("remove/mfa/reset/unlock hit the expected endpoints", async () => {
    apiMock.delete.mockResolvedValue(res(undefined));
    apiMock.get.mockResolvedValue(res([{ id: "m1" }]));
    apiMock.post.mockResolvedValue(res(dto));
    await userService.remove("u1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/users/u1");
    const methods = await userService.listMfaMethods("u1");
    expect(methods).toEqual([{ id: "m1" }]);
    await userService.deleteMfaMethod("u1", "m1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/users/u1/mfa-methods/m1");
    await userService.resetMfa("u1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/users/u1/reset-mfa");
    const unlocked = await userService.unlock("u1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/users/u1/unlock");
    expect(unlocked.id).toBe("u1");
  });
});

describe("groupService", () => {
  it("list unwraps items", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "g1" }] }));
    expect(await groupService.list()).toEqual([{ id: "g1" }]);
  });
  it("create defaults description to empty string", async () => {
    apiMock.post.mockResolvedValue(res({ id: "g1" }));
    await groupService.create({ name: "n", description: undefined as unknown as string });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/groups", { name: "n", description: "" });
  });
  it("get/update/remove/members endpoints", async () => {
    apiMock.get.mockResolvedValue(res({ id: "g1" }));
    await groupService.get("g1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/groups/g1");
    apiMock.put.mockResolvedValue(res({ id: "g1" }));
    await groupService.update("g1", { name: "x" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/groups/g1", { name: "x" });
    apiMock.delete.mockResolvedValue(res(undefined));
    await groupService.remove("g1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/groups/g1");
    apiMock.get.mockResolvedValue(res({ items: [{ id: "u1", metadata: { display_name: "D" } }] }));
    const members = await groupService.listMembers("g1");
    expect(members[0].display_name).toBe("D");
    apiMock.post.mockResolvedValue(res(undefined));
    await groupService.addMember("g1", "u1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/groups/g1/members", { user_id: "u1" });
    await groupService.removeMember("g1", "u1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/groups/g1/members/u1");
  });
});

// ─── organizations / tenants / CA / settings ───────────────────────────────

describe("orgService & tenantService & caCertService & orgSettingsService", () => {
  it("orgService CRUD", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "o1" }] }));
    expect(await orgService.list()).toEqual([{ id: "o1" }]);
    apiMock.get.mockResolvedValue(res({ id: "o1" }));
    await orgService.get("o1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/organizations/o1");
    apiMock.post.mockResolvedValue(res({ id: "o1" }));
    await orgService.create({ name: "n", slug: "s" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/organizations", { name: "n", slug: "s" });
    apiMock.put.mockResolvedValue(res({ id: "o1" }));
    await orgService.update("o1", { name: "n2" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/organizations/o1", { name: "n2" });
    apiMock.delete.mockResolvedValue(res(undefined));
    await orgService.remove("o1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/organizations/o1");
  });

  it("tenantService CRUD is org-scoped", async () => {
    apiMock.get.mockResolvedValue(res([{ id: "t1" }]));
    await tenantService.list("o1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/organizations/o1/tenants");
    apiMock.get.mockResolvedValue(res({ id: "t1" }));
    await tenantService.get("o1", "t1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/organizations/o1/tenants/t1");
    apiMock.post.mockResolvedValue(res({ id: "t1" }));
    await tenantService.create("o1", { name: "n", slug: "s" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/organizations/o1/tenants", { name: "n", slug: "s" });
    apiMock.put.mockResolvedValue(res({ id: "t1" }));
    await tenantService.update("o1", "t1", { status: "Suspended" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/organizations/o1/tenants/t1", { status: "Suspended" });
    apiMock.delete.mockResolvedValue(res(undefined));
    await tenantService.remove("o1", "t1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/organizations/o1/tenants/t1");
  });

  it("caCertService list/generate/revoke", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "ca1" }] }));
    await caCertService.list("o1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/organizations/o1/ca-certificates");
    apiMock.post.mockResolvedValue(res({ id: "ca1", private_key_pem: "PK" }));
    const g = await caCertService.generate("o1", { subject: "s", key_algorithm: "Ed25519", validity_days: 365 });
    expect(g.private_key_pem).toBe("PK");
    await caCertService.revoke("o1", "ca1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/organizations/o1/ca-certificates/ca1/revoke");
  });

  it("orgSettingsService get/update", async () => {
    apiMock.get.mockResolvedValue(res({ id: "s" }));
    await orgSettingsService.get("o1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/organizations/o1/settings");
    apiMock.put.mockResolvedValue(res({ id: "s" }));
    await orgSettingsService.update("o1", { min_length: 8 } as never);
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/organizations/o1/settings", { min_length: 8 });
  });

  it("flattenOrgSettings maps nested policy into the flat write shape", () => {
    const nested: SecuritySettings = {
      id: "s",
      scope: "Org",
      scope_id: "o1",
      password: {
        min_length: 10,
        require_uppercase: true,
        require_lowercase: false,
        require_digits: true,
        require_symbols: false,
        password_history_count: 3,
        hibp_check_enabled: true,
      },
      mfa: { mfa_enforced: true, mfa_challenge_lifetime_secs: 120 },
      lockout: {
        max_failed_login_attempts: 4,
        lockout_duration_secs: 60,
        lockout_backoff_multiplier: 2,
        max_lockout_duration_secs: 600,
      },
      token: { access_token_lifetime_secs: 900, refresh_token_lifetime_secs: 1000 },
      email: { email_verification_required: true, email_verification_grace_period_hours: 12 },
      certificate: { default_cert_validity_days: 30, max_cert_validity_days: 90 },
      notification: { admin_notifications_enabled: false },
      created_at: "t",
      updated_at: "t",
    };
    const flat = flattenOrgSettings(nested);
    expect(flat.min_length).toBe(10);
    expect(flat.mfa_enforced).toBe(true);
    expect(flat.max_lockout_duration_secs).toBe(600);
    expect(flat.email_verification_grace_period_hours).toBe(12);
    expect(flat.default_cert_validity_days).toBe(30);
    expect(flat.admin_notifications_enabled).toBe(false);
  });
});

// ─── auth ───────────────────────────────────────────────────────────────────

describe("authService", () => {
  it("requestPasswordReset sends email + optional slugs", async () => {
    apiMock.post.mockResolvedValue(res(undefined));
    await authService.requestPasswordReset("a@x.io", "org", "ten");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/reset", {
      email: "a@x.io",
      org_slug: "org",
      tenant_slug: "ten",
    });
  });
  it("confirmPasswordReset sends tenant_id/token/new_password", async () => {
    apiMock.post.mockResolvedValue(res(undefined));
    await authService.confirmPasswordReset("tid", "tok", "pw");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/reset/confirm", {
      tenant_id: "tid",
      token: "tok",
      new_password: "pw",
    });
  });
  it("verifyEmail / resendVerification", async () => {
    apiMock.post.mockResolvedValue(res(undefined));
    await authService.verifyEmail("tid", "tok");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/verify-email", { tenant_id: "tid", token: "tok" });
    await authService.resendVerification("tid", "a@x.io");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/resend-verification", { tenant_id: "tid", email: "a@x.io" });
  });
  it("changePassword", async () => {
    apiMock.post.mockResolvedValue(res(undefined));
    await authService.changePassword("old", "new");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/password/change", {
      current_password: "old",
      new_password: "new",
    });
  });
  it("enrollMfa / confirmMfa return/send correctly", async () => {
    apiMock.post.mockResolvedValue(res({ secret_base32: "SEC", totp_uri: "otpauth://x" }));
    const enroll = await authService.enrollMfa();
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/mfa/enroll");
    expect(enroll.secret_base32).toBe("SEC");
    await authService.confirmMfa("123456");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/mfa/confirm", { totp_code: "123456" });
  });
  it("setupEnrollMfa / setupConfirmMfa carry the setup_token", async () => {
    apiMock.post.mockResolvedValue(res({ secret_base32: "S", totp_uri: "u" }));
    await authService.setupEnrollMfa("stok");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/mfa/setup/enroll", { setup_token: "stok" });
    await authService.setupConfirmMfa("stok", "000111");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/auth/mfa/setup/confirm", {
      setup_token: "stok",
      totp_code: "000111",
    });
  });
});

// ─── audit ──────────────────────────────────────────────────────────────────

describe("auditService.list", () => {
  it("defaults offset/limit and omits empty filters", async () => {
    apiMock.get.mockResolvedValue(res({ items: [], total: 0, offset: 0, limit: 20 }));
    await auditService.list();
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/audit-logs?offset=0&limit=20");
  });
  it("widens bare YYYY-MM-DD dates to full-day UTC bounds and trims filters", async () => {
    apiMock.get.mockResolvedValue(res({ items: [], total: 0, offset: 0, limit: 20 }));
    await auditService.list({
      offset: 40,
      limit: 10,
      actor_id: " a1 ",
      action: " login ",
      resource_id: " r1 ",
      outcome: "Failure",
      from: "2026-01-01",
      to: "2026-01-31",
    });
    const url = apiMock.get.mock.calls[0][0] as string;
    expect(url).toContain("offset=40");
    expect(url).toContain("limit=10");
    expect(url).toContain("actor_id=a1");
    expect(url).toContain("action=login");
    expect(url).toContain("resource_id=r1");
    expect(url).toContain("outcome=Failure");
    expect(url).toContain("from=2026-01-01T00%3A00%3A00Z");
    expect(url).toContain("to=2026-01-31T23%3A59%3A59Z");
  });
  it("passes through already-RFC3339 from/to unchanged", async () => {
    apiMock.get.mockResolvedValue(res({ items: [], total: 0, offset: 0, limit: 20 }));
    await auditService.list({ from: "2026-01-01T05:00:00Z" });
    const url = apiMock.get.mock.calls[0][0] as string;
    expect(url).toContain("from=2026-01-01T05%3A00%3A00Z");
  });
});

// ─── certificates ─────────────────────────────────────────────────────────────

describe("certificateService", () => {
  it("list/generate/get/revoke", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "c1" }] }));
    expect(await certificateService.list()).toEqual([{ id: "c1" }]);
    apiMock.post.mockResolvedValue(res({ id: "c1", private_key_pem: "PK" }));
    const g = await certificateService.generate({
      issuer_ca_id: "ca1",
      subject: "s",
      cert_type: "User",
      key_algorithm: "Ed25519",
      validity_days: 30,
    });
    expect(g.private_key_pem).toBe("PK");
    apiMock.get.mockResolvedValue(res({ id: "c1" }));
    await certificateService.get("c1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/certificates/c1");
    apiMock.post.mockResolvedValue(res(undefined));
    await certificateService.revoke("c1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/certificates/c1/revoke");
  });

  it("listSigningCas resolves org by slug then filters Active CAs", async () => {
    apiMock.get
      .mockResolvedValueOnce(res([{ id: "o1", slug: "acme" }, { id: "o2", slug: "other" }]))
      .mockResolvedValueOnce(
        res([
          { id: "ca1", status: "Active" },
          { id: "ca2", status: "Revoked" },
        ])
      );
    const cas = await certificateService.listSigningCas("acme");
    expect(apiMock.get).toHaveBeenNthCalledWith(2, "/api/v1/organizations/o1/ca-certificates");
    expect(cas).toEqual([{ id: "ca1", status: "Active" }]);
  });

  it("listSigningCas falls back to the first org when no slug given", async () => {
    apiMock.get
      .mockResolvedValueOnce(res([{ id: "o1", slug: "acme" }]))
      .mockResolvedValueOnce(res({ items: [] }));
    await certificateService.listSigningCas();
    expect(apiMock.get).toHaveBeenNthCalledWith(2, "/api/v1/organizations/o1/ca-certificates");
  });

  it("listSigningCas returns [] when the org slug is unknown", async () => {
    apiMock.get.mockResolvedValueOnce(res([{ id: "o1", slug: "acme" }]));
    expect(await certificateService.listSigningCas("nope")).toEqual([]);
    expect(apiMock.get).toHaveBeenCalledTimes(1);
  });
});

// ─── federation ───────────────────────────────────────────────────────────────

describe("federationService", () => {
  it("covers all endpoints", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "f1" }] }));
    expect(await federationService.getAll()).toEqual([{ id: "f1" }]);
    apiMock.post.mockResolvedValue(res({ id: "f1" }));
    await federationService.create({ provider: "p", protocol: "Saml", client_id: "c", client_secret: "s" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/federation-configs", expect.objectContaining({ provider: "p" }));
    apiMock.get.mockResolvedValue(res({ id: "f1" }));
    await federationService.getById("f1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/federation-configs/f1");
    apiMock.put.mockResolvedValue(res({ id: "f1" }));
    await federationService.update("f1", { enabled: false });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/federation-configs/f1", { enabled: false });
    apiMock.delete.mockResolvedValue(res(undefined));
    await federationService.remove("f1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/federation-configs/f1");
  });
});

// ─── notification rules ─────────────────────────────────────────────────────

describe("notificationRuleService & helpers", () => {
  it("notificationEventLabel resolves known ids and falls back to raw id", () => {
    expect(notificationEventLabel("login_failure")).toBe("Login failure");
    expect(notificationEventLabel("unknown_event")).toBe("unknown_event");
    expect(NOTIFICATION_EVENTS.length).toBeGreaterThan(0);
  });
  it("CRUD endpoints", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "n1" }] }));
    expect(await notificationRuleService.list()).toEqual([{ id: "n1" }]);
    apiMock.post.mockResolvedValue(res({ id: "n1" }));
    await notificationRuleService.create({ name: "n", description: "d", events: [], recipient_emails: [] });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/notification-rules", expect.objectContaining({ name: "n" }));
    apiMock.get.mockResolvedValue(res({ id: "n1" }));
    await notificationRuleService.get("n1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/notification-rules/n1");
    apiMock.put.mockResolvedValue(res({ id: "n1" }));
    await notificationRuleService.update("n1", { enabled: true });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/notification-rules/n1", { enabled: true });
    apiMock.delete.mockResolvedValue(res(undefined));
    await notificationRuleService.remove("n1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/notification-rules/n1");
  });
});

// ─── oauth2 clients ───────────────────────────────────────────────────────────

describe("oauth2ClientService", () => {
  it("CRUD endpoints", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "oc1" }] }));
    expect(await oauth2ClientService.list()).toEqual([{ id: "oc1" }]);
    apiMock.post.mockResolvedValue(res({ id: "oc1", client_secret: "sec" }));
    const c = await oauth2ClientService.create({ name: "n", redirect_uris: [], grant_types: [] });
    expect(c.client_secret).toBe("sec");
    apiMock.get.mockResolvedValue(res({ id: "oc1" }));
    await oauth2ClientService.get("oc1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/oauth2-clients/oc1");
    apiMock.put.mockResolvedValue(res({ id: "oc1" }));
    await oauth2ClientService.update("oc1", { name: "x" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/oauth2-clients/oc1", { name: "x" });
    apiMock.delete.mockResolvedValue(res(undefined));
    await oauth2ClientService.remove("oc1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/oauth2-clients/oc1");
  });
});

// ─── permissions ────────────────────────────────────────────────────────────

describe("permissionService", () => {
  it("CRUD endpoints", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "p1" }] }));
    expect(await permissionService.list()).toEqual([{ id: "p1" }]);
    apiMock.get.mockResolvedValue(res({ id: "p1" }));
    await permissionService.get("p1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/permissions/p1");
    apiMock.post.mockResolvedValue(res({ id: "p1" }));
    await permissionService.create({ action: "read", description: "d" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/permissions", { action: "read", description: "d" });
    apiMock.put.mockResolvedValue(res({ id: "p1" }));
    await permissionService.update("p1", { description: "d2" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/permissions/p1", { description: "d2" });
    apiMock.delete.mockResolvedValue(res(undefined));
    await permissionService.remove("p1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/permissions/p1");
  });
});

// ─── pgp ────────────────────────────────────────────────────────────────────

describe("pgpService", () => {
  it("list/generate/get/revoke/encrypt/signAuditBatch", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "k1" }] }));
    expect(await pgpService.list()).toEqual([{ id: "k1" }]);
    apiMock.post.mockResolvedValue(res({ id: "k1", private_key_armored: "PRIV" }));
    const gen = await pgpService.generate({ name: "n", email: "e@x.io", purpose: "Export", algorithm: "Ed25519" });
    expect(gen.private_key_armored).toBe("PRIV");
    apiMock.get.mockResolvedValue(res({ id: "k1" }));
    await pgpService.get("k1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/pgp-keys/k1");
    apiMock.post.mockResolvedValue(res(undefined));
    await pgpService.revoke("k1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/pgp-keys/k1/revoke");
    apiMock.post.mockResolvedValue(res({ recipient_key_id: "k1", ciphertext_armored: "CT" }));
    const enc = await pgpService.encrypt("k1", { data_base64: "ZGF0YQ==" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/pgp-keys/k1/encrypt", { data_base64: "ZGF0YQ==" });
    expect(enc.ciphertext_armored).toBe("CT");
    apiMock.post.mockResolvedValue(res({ batch_id: "b1", entry_ids: ["e1"] }));
    const sig = await pgpService.signAuditBatch({ entry_ids: ["e1"] });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/pgp-keys/sign-audit-batch", { entry_ids: ["e1"] });
    expect(sig.batch_id).toBe("b1");
  });
});

// ─── resources ────────────────────────────────────────────────────────────────

describe("resourceService & resourceTypeLabel", () => {
  it("resourceTypeLabel humanizes iot_device and passes others through", () => {
    expect(resourceTypeLabel("iot_device")).toBe("IoT Device");
    expect(resourceTypeLabel("api")).toBe("api");
  });
  it("create folds description into metadata", async () => {
    apiMock.post.mockResolvedValue(res({ id: "r1" }));
    await resourceService.create({ name: "n", resource_type: "api", description: "d" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/resources", {
      name: "n",
      resource_type: "api",
      metadata: { description: "d" },
    });
  });
  it("create without description omits metadata", async () => {
    apiMock.post.mockResolvedValue(res({ id: "r1" }));
    await resourceService.create({ name: "n", resource_type: "api" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/resources", { name: "n", resource_type: "api" });
  });
  it("update supports clearing parent via null and folding description", async () => {
    apiMock.put.mockResolvedValue(res({ id: "r1" }));
    await resourceService.update("r1", { parent_id: null, description: "" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/resources/r1", {
      parent_id: null,
      metadata: { description: "" },
    });
  });
  it("list/get/remove/listChildren", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "r1" }] }));
    expect(await resourceService.list()).toEqual([{ id: "r1" }]);
    apiMock.get.mockResolvedValue(res({ id: "r1" }));
    await resourceService.get("r1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/resources/r1");
    apiMock.delete.mockResolvedValue(res(undefined));
    await resourceService.remove("r1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/resources/r1");
    apiMock.get.mockResolvedValue(res([{ id: "r2" }]));
    expect(await resourceService.listChildren("r1")).toEqual([{ id: "r2" }]);
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/resources/r1/children");
  });
});

// ─── roles ──────────────────────────────────────────────────────────────────

describe("roleService", () => {
  it("core CRUD", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "r1" }] }));
    expect(await roleService.list()).toEqual([{ id: "r1" }]);
    apiMock.get.mockResolvedValue(res({ id: "r1" }));
    await roleService.get("r1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/roles/r1");
    apiMock.post.mockResolvedValue(res({ id: "r1" }));
    await roleService.create({ name: "n", description: "" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles", { name: "n", description: "" });
    apiMock.put.mockResolvedValue(res({ id: "r1" }));
    await roleService.update("r1", { name: "x" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/roles/r1", { name: "x" });
    apiMock.delete.mockResolvedValue(res(undefined));
    await roleService.remove("r1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1");
  });
  it("permission grants", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ permission: { id: "p1" }, scope_ids: [] }] }));
    expect(await roleService.listPermissions("r1")).toHaveLength(1);
    apiMock.post.mockResolvedValue(res(undefined));
    await roleService.grantPermission("r1", "p1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles/r1/permissions", { permission_id: "p1" });
    apiMock.delete.mockResolvedValue(res(undefined));
    await roleService.revokePermission("r1", "p1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/permissions/p1");
  });
  it("user & group assignment", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "u1", metadata: {} }] }));
    await roleService.listUsers("r1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/roles/r1/users");
    apiMock.post.mockResolvedValue(res(undefined));
    await roleService.assignToUser("r1", "u1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles/r1/users", { user_id: "u1" });
    apiMock.delete.mockResolvedValue(res(undefined));
    await roleService.unassignFromUser("r1", "u1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/users/u1");
    apiMock.get.mockResolvedValue(res({ items: [{ id: "g1" }] }));
    await roleService.listGroups("r1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/roles/r1/groups");
    await roleService.listByGroup("g1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/groups/g1/roles");
    await roleService.assignToGroup("r1", "g1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/roles/r1/groups", { group_id: "g1" });
    await roleService.unassignFromGroup("r1", "g1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/roles/r1/groups/g1");
  });
});

// ─── service accounts ───────────────────────────────────────────────────────

describe("serviceAccountService", () => {
  it("covers all endpoints", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "sa1" }] }));
    expect(await serviceAccountService.getAll()).toEqual([{ id: "sa1" }]);
    apiMock.post.mockResolvedValue(res({ id: "sa1", client_secret: "sec" }));
    const created = await serviceAccountService.create({ name: "n" });
    expect(created.client_secret).toBe("sec");
    apiMock.get.mockResolvedValue(res({ id: "sa1" }));
    await serviceAccountService.getById("sa1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/service-accounts/sa1");
    apiMock.put.mockResolvedValue(res({ id: "sa1" }));
    await serviceAccountService.update("sa1", { status: "Inactive" });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/service-accounts/sa1", { status: "Inactive" });
    apiMock.delete.mockResolvedValue(res(undefined));
    await serviceAccountService.remove("sa1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/service-accounts/sa1");
    apiMock.post.mockResolvedValue(res({ client_secret: "new" }));
    const rot = await serviceAccountService.rotateSecret("sa1");
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/service-accounts/sa1/rotate-secret");
    expect(rot.client_secret).toBe("new");
  });
});

// ─── settings ───────────────────────────────────────────────────────────────

describe("settingsService", () => {
  it("getSettings / updateSettings", async () => {
    apiMock.get.mockResolvedValue(res({ id: "s" }));
    await settingsService.getSettings();
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/settings");
    apiMock.put.mockResolvedValue(res({ id: "s" }));
    await settingsService.updateSettings({ min_length: 12 });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/settings", { min_length: 12 });
  });
});

// ─── webhooks ───────────────────────────────────────────────────────────────

describe("webhookService", () => {
  it("covers all endpoints", async () => {
    apiMock.get.mockResolvedValue(res({ items: [{ id: "w1" }] }));
    expect(await webhookService.list()).toEqual([{ id: "w1" }]);
    apiMock.post.mockResolvedValue(res({ id: "w1" }));
    await webhookService.create({ url: "https://x", events: ["user.created"], secret: "s" });
    expect(apiMock.post).toHaveBeenCalledWith("/api/v1/webhooks", expect.objectContaining({ url: "https://x" }));
    apiMock.get.mockResolvedValue(res({ id: "w1" }));
    await webhookService.get("w1");
    expect(apiMock.get).toHaveBeenCalledWith("/api/v1/webhooks/w1");
    apiMock.put.mockResolvedValue(res({ id: "w1" }));
    await webhookService.update("w1", { enabled: false });
    expect(apiMock.put).toHaveBeenCalledWith("/api/v1/webhooks/w1", { enabled: false });
    apiMock.delete.mockResolvedValue(res(undefined));
    await webhookService.remove("w1");
    expect(apiMock.delete).toHaveBeenCalledWith("/api/v1/webhooks/w1");
  });
});

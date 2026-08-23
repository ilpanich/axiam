import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import { buildEnrollmentForUser } from "@/services/opaque";
import type { AuthUser } from "@/stores/auth";

// Stands in for the WebAssembly build of `crates/axiam-opaque`: a checkout that
// has not run the Rust toolchain has no artifact, and `lib/opaque` resolves it
// through a runtime specifier `vi.mock` cannot reach.
const opaqueModuleMock = {
  default: vi.fn(async () => undefined),
  opaqueAvailable: () => true,
  OpaqueKsf: {
    argon2id: (memoryKib: number, iterations: number, parallelism: number) => ({
      kind: "argon2id",
      memoryKib,
      iterations,
      parallelism,
    }),
    scrypt: (logN: number, r: number, p: number) => ({ kind: "scrypt", logN, r, p }),
  },
  OpaqueLogin: class {
    ke1 = "aa".repeat(96);
    constructor(_password: string) {}
    finish() {
      return { ke3: "bb".repeat(64), sessionKey: "cc".repeat(64), exportKey: "dd".repeat(64) };
    }
  },
  OpaqueRegistration: class {
    request = "ee".repeat(32);
    constructor(_password: string) {}
    finish() {
      return { record: "ff".repeat(192), exportKey: "dd".repeat(64) };
    }
  },
};

const OPTIONAL_POLICY = {
  opaque_mode: "optional",
  opaque_suite: "ristretto255_sha512",
  opaque_ksf: "argon2id",
};

function storeUser(overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    id: "u1",
    username: "alice",
    email: "alice@example.com",
    permissions: [],
    tenant_id: "t1",
    orgSlug: "acme",
    tenantSlug: "default",
    opaque: OPTIONAL_POLICY,
    ...overrides,
  };
}

function registerStarted() {
  return res({
    opaque_session: "sealed",
    registration_response: "aa".repeat(32),
    suite: "ristretto255_sha512",
    ksf: "argon2id",
    memory_kib: 19456,
    iterations: 2,
    parallelism: 1,
  });
}

beforeEach(async () => {
  vi.clearAllMocks();
  const { __setOpaqueModuleForTests } = await import("@/lib/opaque");
  __setOpaqueModuleForTests(opaqueModuleMock);
});

afterEach(async () => {
  const { __resetOpaqueModuleForTests } = await import("@/lib/opaque");
  __resetOpaqueModuleForTests();
});

describe("buildEnrollmentForUser", () => {
  it("sends the workspace identity the auth store actually holds", async () => {
    // The regression. The auth store spells these `orgSlug`/`tenantSlug`; this
    // function read only `org_slug`/`tenant_slug`, so both came out undefined,
    // `register/start` was posted with no workspace identity, the server
    // answered 400, and the catch-all turned that into `null` — the same value
    // that legitimately means "this tenant does not use OPAQUE". Every password
    // change silently omitted the record, so a tenant could run `optional`
    // indefinitely and never enrol anybody.
    apiMock.post.mockResolvedValue(registerStarted());

    const enrollment = await buildEnrollmentForUser(storeUser(), "Str0ng!Passw0rd");

    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/opaque/register/start",
      expect.objectContaining({ org_slug: "acme", tenant_slug: "default" })
    );
    expect(enrollment).toEqual({
      opaque_session: "sealed",
      registration_record: "ff".repeat(192),
    });
  });

  it("still accepts the wire spelling of the slugs", async () => {
    apiMock.post.mockResolvedValue(registerStarted());

    await buildEnrollmentForUser(
      { org_slug: "acme", tenant_slug: "default", opaque: OPTIONAL_POLICY },
      "Str0ng!Passw0rd"
    );

    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/opaque/register/start",
      expect.objectContaining({ org_slug: "acme", tenant_slug: "default" })
    );
  });

  it("never sends the plaintext password to register/start", async () => {
    apiMock.post.mockResolvedValue(registerStarted());
    await buildEnrollmentForUser(storeUser(), "Str0ng!Passw0rd");
    for (const call of apiMock.post.mock.calls) {
      expect(JSON.stringify(call[1] ?? {})).not.toContain("Str0ng!Passw0rd");
    }
  });

  it("returns null without a request when the tenant has OPAQUE disabled", async () => {
    const user = storeUser({
      opaque: { ...OPTIONAL_POLICY, opaque_mode: "disabled" },
    });
    expect(await buildEnrollmentForUser(user, "Str0ng!Passw0rd")).toBeNull();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("returns null without a request when there is no policy or no user", async () => {
    expect(await buildEnrollmentForUser(null, "pw")).toBeNull();
    expect(
      await buildEnrollmentForUser(storeUser({ opaque: undefined }), "pw")
    ).toBeNull();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("returns null without a request when the workspace identity is missing", async () => {
    // Rather than posting a request the server can only refuse. Reaching here
    // means the auth store was never hydrated from /auth/me, which is a
    // different problem and not one an OPAQUE round-trip diagnoses.
    const user = storeUser({ orgSlug: undefined, tenantSlug: undefined });
    expect(await buildEnrollmentForUser(user, "pw")).toBeNull();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("returns null when register/start fails, so the caller omits the field", async () => {
    apiMock.post.mockRejectedValue(new Error("boom"));
    expect(await buildEnrollmentForUser(storeUser(), "pw")).toBeNull();
  });
});

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { apiMock, res } from "@/test/apiMock";

vi.mock("@/lib/api", () => ({ default: apiMock }));

import {
  buildEnrollmentForReset,
  buildEnrollmentForTenant,
  buildEnrollmentForUser,
} from "@/services/opaque";

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

const ORG_TENANT = "11111111-1111-1111-1111-111111111111";
const CHILD_TENANT = "22222222-2222-2222-2222-222222222222";

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

/** An axios-shaped rejection carrying an HTTP status. */
function httpError(status: number) {
  return Object.assign(new Error(`HTTP ${status}`), { response: { status } });
}

const ENROLLED = {
  opaque_session: "sealed",
  registration_record: "ff".repeat(192),
};

/** The single request body the module posted, for assertions. */
function postedBody() {
  expect(apiMock.post).toHaveBeenCalledTimes(1);
  return apiMock.post.mock.calls[0][1] as Record<string, unknown>;
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

describe("buildEnrollmentForUser — the caller's own password", () => {
  it("seals against the tenant the caller LIVES in, not the one it is acting on", async () => {
    // The regression. An organization-level administrator with a child tenant
    // selected is still changing a password that belongs to the organization's
    // reserved scope, and that is where the server stores the record. Sealing it
    // against the selected tenant produced a session the server refuses with
    // "the OPAQUE session was issued for a different tenant".
    apiMock.post.mockResolvedValue(registerStarted());

    const enrollment = await buildEnrollmentForUser(
      { principal_tenant_id: ORG_TENANT, tenant_id: CHILD_TENANT },
      "Str0ng!Passw0rd"
    );

    expect(apiMock.post).toHaveBeenCalledWith(
      "/api/v1/auth/opaque/register/start",
      expect.objectContaining({ tenant_id: ORG_TENANT })
    );
    expect(postedBody()).not.toHaveProperty("org_slug");
    expect(enrollment).toEqual(ENROLLED);
  });

  it("falls back to tenant_id when the server does not report a principal tenant", async () => {
    // A server predating `principal_tenant_id` never lets the two diverge
    // anyway: without the field there is no tenant switching to disagree about.
    apiMock.post.mockResolvedValue(registerStarted());

    await buildEnrollmentForUser({ tenant_id: ORG_TENANT }, "Str0ng!Passw0rd");

    expect(postedBody()).toMatchObject({ tenant_id: ORG_TENANT });
  });

  it("asks the server instead of trusting a cached tenant policy", async () => {
    // This is what made enabling OPAQUE look like it did nothing. The auth store
    // caches the tenant's policy at login; an operator who switched the
    // organization to `optional` and then changed a password in the same session
    // still had `disabled` in the store, so the old code returned null WITHOUT
    // asking and no record was ever written. The tenant accumulated no coverage,
    // and switching to `required` then locked everybody out.
    apiMock.post.mockResolvedValue(registerStarted());

    const enrollment = await buildEnrollmentForUser(
      { principal_tenant_id: ORG_TENANT },
      "Str0ng!Passw0rd"
    );

    expect(apiMock.post).toHaveBeenCalledTimes(1);
    expect(enrollment).toEqual(ENROLLED);
  });

  it("returns null on 404, which is how the server says OPAQUE is disabled", async () => {
    apiMock.post.mockRejectedValue(httpError(404));

    expect(
      await buildEnrollmentForUser({ principal_tenant_id: ORG_TENANT }, "pw")
    ).toBeNull();
  });

  it("throws on any other failure rather than silently omitting the record", async () => {
    // Swallowing this produced an account that was unenrolled under `optional`,
    // or refused by the server under `required` with a message about a missing
    // record the operator had no way to act on. A thrown error reaches the form,
    // where "try again" is something the person in front of it can do.
    apiMock.post.mockRejectedValue(httpError(500));

    await expect(
      buildEnrollmentForUser({ principal_tenant_id: ORG_TENANT }, "pw")
    ).rejects.toThrow();
  });

  it("returns null without a request when there is no tenant at all", async () => {
    expect(await buildEnrollmentForUser(null, "pw")).toBeNull();
    expect(await buildEnrollmentForUser({}, "pw")).toBeNull();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("returns null without a request when this browser cannot do OPAQUE", async () => {
    // A checkout with no WebAssembly artifact, or a browser that cannot load
    // it. Nothing to enrol with and nothing a retry would fix — distinct from
    // the server saying the tenant has OPAQUE off, which is the 404 above, and
    // from a transient failure, which throws.
    const { __setOpaqueModuleForTests } = await import("@/lib/opaque");
    __setOpaqueModuleForTests(null);

    expect(
      await buildEnrollmentForUser({ principal_tenant_id: ORG_TENANT }, "pw")
    ).toBeNull();
    expect(apiMock.post).not.toHaveBeenCalled();
  });

  it("never sends the plaintext password to register/start", async () => {
    apiMock.post.mockResolvedValue(registerStarted());
    await buildEnrollmentForUser({ principal_tenant_id: ORG_TENANT }, "Str0ng!Passw0rd");
    for (const call of apiMock.post.mock.calls) {
      expect(JSON.stringify(call[1] ?? {})).not.toContain("Str0ng!Passw0rd");
    }
  });
});

describe("buildEnrollmentForTenant — creating somebody else's account", () => {
  it("seals against the tenant the account is created in", async () => {
    // The 400 in the bug report. `POST /api/v1/users` is scoped to the selected
    // tenant by the `X-Axiam-Tenant` header, so the record has to be sealed
    // against that tenant's key material — not the administrator's own.
    apiMock.post.mockResolvedValue(registerStarted());

    const enrollment = await buildEnrollmentForTenant({
      tenantId: CHILD_TENANT,
      password: "Str0ng!Passw0rd",
    });

    expect(postedBody()).toMatchObject({ tenant_id: CHILD_TENANT });
    expect(enrollment).toEqual(ENROLLED);
  });

  it("returns null when the target tenant has OPAQUE disabled", async () => {
    apiMock.post.mockRejectedValue(httpError(404));
    expect(
      await buildEnrollmentForTenant({ tenantId: CHILD_TENANT, password: "pw" })
    ).toBeNull();
  });
});

describe("buildEnrollmentForReset — the unauthenticated reset page", () => {
  it("names only the tenant, which is all the emailed link carries", async () => {
    // The link is `?token=…&tenant_id=…`; there is no organization in it and no
    // session to learn one from. This used to fetch `/auth/reset/context` first
    // just to read the policy, and skipped enrolment whenever that failed —
    // making reset the hole in OPAQUE coverage under `required`.
    apiMock.post.mockResolvedValue(registerStarted());

    const enrollment = await buildEnrollmentForReset({
      tenantId: CHILD_TENANT,
      password: "Str0ng!Passw0rd",
    });

    expect(apiMock.get).not.toHaveBeenCalled();
    expect(postedBody()).toEqual({
      tenant_id: CHILD_TENANT,
      registration_request: "ee".repeat(32),
    });
    expect(enrollment).toEqual(ENROLLED);
  });
});

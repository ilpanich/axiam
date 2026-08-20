/**
 * Tests for the OPAQUE loader.
 *
 * Deliberately short. Its predecessor, `srp.test.ts`, was 235 lines because
 * `lib/srp.ts` contained the protocol and had to be checked against the
 * cross-language vectors. `lib/opaque.ts` contains no cryptography — CONTRACT
 * §23.1 forbids it — so what is left to test is the loader's own decisions:
 * that a missing artifact degrades rather than throws, that the module is
 * instantiated once, and that the KSF the server names is honoured exactly.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import {
  OpaqueUnavailableError,
  OpaqueUnsupportedError,
  __resetOpaqueModuleForTests,
  __setOpaqueModuleForTests,
  opaqueAvailable,
  startLogin,
  startRegistration,
} from "@/lib/opaque";

/** Records which KSF it was handed, so the tests can assert on it. */
function moduleMock() {
  const seen: unknown[] = [];
  return {
    seen,
    mod: {
      default: vi.fn(async () => undefined),
      opaqueAvailable: () => true,
      OpaqueKsf: {
        argon2id: (memoryKib: number, iterations: number, parallelism: number) => {
          const ksf = { kind: "argon2id", memoryKib, iterations, parallelism };
          seen.push(ksf);
          return ksf;
        },
        scrypt: (logN: number, r: number, p: number) => {
          const ksf = { kind: "scrypt", logN, r, p };
          seen.push(ksf);
          return ksf;
        },
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
    },
  };
}

beforeEach(() => {
  __resetOpaqueModuleForTests();
});

afterEach(() => {
  __resetOpaqueModuleForTests();
});

describe("availability", () => {
  it("reports false rather than throwing when the artifact is absent", async () => {
    // The posture CONTRACT §23.1 requires: a build whose module did not load
    // must answer the capability question, not fail at login time. The
    // specifier is unresolvable in this checkout, so this is the real path.
    await expect(opaqueAvailable()).resolves.toBe(false);
  });

  it("reports true once a module is present", async () => {
    __setOpaqueModuleForTests(moduleMock().mod);
    await expect(opaqueAvailable()).resolves.toBe(true);
  });

  it("raises a distinguishable error when an exchange is started without a module", async () => {
    // Distinguishable so the caller can fall back to password login rather
    // than reporting a wrong password.
    await expect(startLogin("pw")).rejects.toBeInstanceOf(OpaqueUnavailableError);
    await expect(startRegistration("pw")).rejects.toBeInstanceOf(OpaqueUnavailableError);
  });
});

describe("KSF selection", () => {
  it("uses exactly the argon2id parameters the server named", async () => {
    const { mod, seen } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const exchange = await startLogin("pw");
    exchange.finish("12".repeat(320), {
      ksf: "argon2id",
      memory_kib: 65536,
      iterations: 3,
      parallelism: 2,
    });

    expect(seen).toEqual([
      { kind: "argon2id", memoryKib: 65536, iterations: 3, parallelism: 2 },
    ]);
  });

  it("uses exactly the scrypt parameters the server named", async () => {
    const { mod, seen } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const exchange = await startRegistration("pw");
    exchange.finish("34".repeat(64), { ksf: "scrypt", log_n: 15, r: 4, p: 2 });

    expect(seen).toEqual([{ kind: "scrypt", logN: 15, r: 4, p: 2 }]);
  });

  it("refuses an unknown KSF rather than substituting one", async () => {
    // Substituting produces a well-formed randomized password that no AXIAM
    // server agrees with, reported to the user as a wrong password.
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const exchange = await startLogin("pw");
    expect(() =>
      exchange.finish("12".repeat(320), { ksf: "pbkdf2_sha256", iterations: 600000 })
    ).toThrow(OpaqueUnsupportedError);
  });

  it("refuses a KSF whose cost parameters are missing", async () => {
    // Absent is not zero. Reading a missing `memory_kib` as 0 would stretch
    // with the wrong cost and fail against a record that is perfectly good.
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const exchange = await startLogin("pw");
    expect(() => exchange.finish("12".repeat(320), { ksf: "argon2id" })).toThrow(
      OpaqueUnsupportedError
    );
    const other = await startLogin("pw");
    expect(() => other.finish("12".repeat(320), { ksf: "scrypt", log_n: 15 })).toThrow(
      OpaqueUnsupportedError
    );
  });
});

describe("exchange shape", () => {
  it("surfaces the first message for the caller to post", async () => {
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    expect((await startLogin("pw")).ke1).toHaveLength(192);
    expect((await startRegistration("pw")).request).toHaveLength(64);
  });

  it("returns only the value the wire needs", async () => {
    // The session key and export key stay inside the module. AXIAM issues
    // ordinary session cookies, so surfacing them here would be handing the
    // application key material it has no use for and must not log.
    const { mod } = moduleMock();
    __setOpaqueModuleForTests(mod);

    const ke3 = (await startLogin("pw")).finish("12".repeat(320), {
      ksf: "argon2id",
      memory_kib: 19456,
      iterations: 2,
      parallelism: 1,
    });
    expect(ke3).toBe("bb".repeat(64));
  });
});

import { describe, it, expect } from "vitest";

import {
  DEFAULT_OPAQUE_POLICY,
  OPAQUE_KSFS,
  OPAQUE_MODES,
  opaqueKsfIsAtLeast,
  opaqueModeIsAtLeast,
  opaqueRelaxationWarning,
  opaqueSuiteIsAtLeast,
  readOpaquePolicy,
  type OpaquePolicy,
} from "./opaquePolicy";

const OPTIONAL: OpaquePolicy = {
  opaque_mode: "optional",
  opaque_suite: "ristretto255_sha512",
  opaque_ksf: "argon2id",
};

// The ladders these mirror live in crates/axiam-core/src/models/opaque.rs. They
// are what "a tenant may only be more restrictive" means for these three
// fields, so a drift here shows up as a form that lets an admin submit a
// payload the server will reject — or, worse, hides one it would accept.

describe("tighten-only ordering", () => {
  it("ranks modes disabled < optional < required", () => {
    expect(opaqueModeIsAtLeast("required", "optional")).toBe(true);
    expect(opaqueModeIsAtLeast("optional", "optional")).toBe(true);
    expect(opaqueModeIsAtLeast("disabled", "optional")).toBe(false);
    expect(opaqueModeIsAtLeast("optional", "required")).toBe(false);
  });

  it("ranks argon2id above scrypt", () => {
    expect(opaqueKsfIsAtLeast("argon2id", "scrypt")).toBe(true);
    expect(opaqueKsfIsAtLeast("scrypt", "argon2id")).toBe(false);
  });

  it("accepts the only defined suite against itself", () => {
    expect(
      opaqueSuiteIsAtLeast("ristretto255_sha512", "ristretto255_sha512")
    ).toBe(true);
  });

  it("lists selectable values weakest-first, matching the ladder", () => {
    expect(OPAQUE_MODES).toEqual(["disabled", "optional", "required"]);
    expect(OPAQUE_KSFS).toEqual(["scrypt", "argon2id"]);
  });
});

describe("readOpaquePolicy", () => {
  it("passes a present policy through unchanged", () => {
    expect(readOpaquePolicy({ opaque: OPTIONAL })).toEqual(OPTIONAL);
  });

  // A settings row written before the OPAQUE migration has no such column, and
  // the backend resolves that to `disabled`. Returning `undefined` instead
  // would drop the keys from the next PUT body, which is the same thing by a
  // longer route.
  it("resolves an absent policy to the disabled default", () => {
    expect(readOpaquePolicy({})).toEqual(DEFAULT_OPAQUE_POLICY);
    expect(readOpaquePolicy(undefined)).toEqual(DEFAULT_OPAQUE_POLICY);
    expect(readOpaquePolicy(null)).toEqual(DEFAULT_OPAQUE_POLICY);
  });

  it("fills in only the fields that are missing", () => {
    expect(readOpaquePolicy({ opaque: { opaque_mode: "required" } })).toEqual({
      opaque_mode: "required",
      opaque_suite: "ristretto255_sha512",
      opaque_ksf: "argon2id",
    });
  });
});

describe("opaqueRelaxationWarning", () => {
  it("stays silent when the candidate matches the effective policy", () => {
    expect(opaqueRelaxationWarning(OPTIONAL, OPTIONAL)).toBeNull();
  });

  it("stays silent when the candidate tightens", () => {
    expect(
      opaqueRelaxationWarning({ ...OPTIONAL, opaque_mode: "required" }, OPTIONAL)
    ).toBeNull();
  });

  it("names the weakened mode", () => {
    const warning = opaqueRelaxationWarning(
      { ...OPTIONAL, opaque_mode: "disabled" },
      OPTIONAL
    );
    expect(warning).toContain("Optional → Disabled");
    expect(warning).toContain("more restrictive");
  });

  it("names a weakened key-stretching function", () => {
    const warning = opaqueRelaxationWarning(
      { ...OPTIONAL, opaque_ksf: "scrypt" },
      OPTIONAL
    );
    expect(warning).toContain("argon2id → scrypt");
  });

  it("collects every weakened field into one advisory", () => {
    const warning = opaqueRelaxationWarning(
      { ...OPTIONAL, opaque_mode: "disabled", opaque_ksf: "scrypt" },
      OPTIONAL
    );
    expect(warning).toContain("mode");
    expect(warning).toContain("key-stretching function");
  });
});

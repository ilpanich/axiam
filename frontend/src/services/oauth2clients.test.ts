import { describe, it, expect } from "vitest";
import {
  DEVICE_CODE_GRANT,
  deviceGrantNeedsCredential,
  scopeCeilingMessage,
} from "./oauth2clients";

function failure(status: number, data: Record<string, unknown>) {
  return { response: { status, data } };
}

describe("deviceGrantNeedsCredential", () => {
  it("is true for a confidential client holding the device-code grant", () => {
    expect(deviceGrantNeedsCredential([DEVICE_CODE_GRANT], "client_secret_basic")).toBe(true);
    expect(deviceGrantNeedsCredential(["authorization_code", DEVICE_CODE_GRANT], "private_key_jwt")).toBe(
      true,
    );
    // No method sent: the backend's default, client_secret_post, is confidential.
    expect(deviceGrantNeedsCredential([DEVICE_CODE_GRANT], undefined)).toBe(true);
  });

  it("is false for a public client or one without the grant", () => {
    expect(deviceGrantNeedsCredential([DEVICE_CODE_GRANT], "none")).toBe(false);
    expect(deviceGrantNeedsCredential(["authorization_code"], "client_secret_post")).toBe(false);
    expect(deviceGrantNeedsCredential([], undefined)).toBe(false);
  });
});

describe("scopeCeilingMessage", () => {
  it("returns the server's sentence for a 422 scope_exceeds_ceiling", () => {
    expect(
      scopeCeilingMessage(
        failure(422, { error: "scope_exceeds_ceiling", message: "scope(s) x are outside dcr_allowed_scopes" }),
      ),
    ).toBe("scope(s) x are outside dcr_allowed_scopes");
  });

  it("returns null for any other status, slug or value", () => {
    expect(scopeCeilingMessage(failure(422, { error: "validation_error", message: "m" }))).toBeNull();
    expect(scopeCeilingMessage(failure(400, { error: "scope_exceeds_ceiling", message: "m" }))).toBeNull();
    expect(scopeCeilingMessage(new Error("boom"))).toBeNull();
    expect(scopeCeilingMessage(undefined)).toBeNull();
  });
});

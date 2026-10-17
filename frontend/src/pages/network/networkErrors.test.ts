import { describe, it, expect } from "vitest";
import { networkErrorMessage } from "./networkErrors";

function failure(status: number, data: Record<string, unknown>) {
  return { response: { status, data } };
}

const options = { fallback: "It failed." };

describe("networkErrorMessage", () => {
  it("names the permission and the node of a 403 from the body's members", () => {
    expect(
      networkErrorMessage(
        failure(403, {
          error: "authorization_denied",
          message: "Permission denied",
          action: "network:grant",
          resource_id: "n1",
        }),
        options,
      ),
    ).toBe("Permission denied Missing permission network:grant on n1.");
  });

  it("resolves the node when the page knows it", () => {
    const err = failure(403, { message: "Denied", action: "network:grant", resource_id: "n1" });
    expect(networkErrorMessage(err, { ...options, nodeName: () => "/network/zones/hq/corp" })).toBe(
      "Denied Missing permission network:grant on /network/zones/hq/corp.",
    );
    expect(networkErrorMessage(err, { ...options, nodeName: () => undefined })).toContain(" on n1.");
  });

  it("copes with a 403 that carries only some of the members", () => {
    expect(networkErrorMessage(failure(403, { message: "Denied", action: "network:read" }), options)).toBe(
      "Denied Missing permission network:read.",
    );
    expect(networkErrorMessage(failure(403, { message: "Denied" }), options)).toBe("Denied");
    expect(networkErrorMessage(failure(403, {}), options)).toBe("You are not allowed to do this.");
  });

  it("never reads the permission out of the message", () => {
    const text = networkErrorMessage(
      failure(403, { message: "needs network:grant on somewhere" }),
      options,
    );
    expect(text).toBe("needs network:grant on somewhere");
    expect(text).not.toContain("Missing permission");
  });

  it("words a stale_version 409 alone, whatever the message says", () => {
    const err = failure(409, {
      error: "conflict",
      reason_code: "stale_version",
      message: "the network segment changed since it was read; read it again and retry",
    });
    expect(networkErrorMessage(err, options)).toBe(
      "Changed by someone else — reload and try again.",
    );
  });

  it("shows the server's sentence alone for every other reason_code", () => {
    const strands = failure(409, {
      error: "conflict",
      reason_code: "strands_profile",
      message: "the segment's reply profile p1 uses filter_id 'a'; change or delete the profile first",
    });
    expect(networkErrorMessage(strands, options)).toBe(
      "the segment's reply profile p1 uses filter_id 'a'; change or delete the profile first",
    );
    const vlan = failure(409, {
      error: "already_exists",
      reason_code: "duplicate_vlan",
      message: "Entity already exists: network_segment: the site already has a segment with this vlan_id",
    });
    expect(networkErrorMessage(vlan, { ...options, staleOnly: true })).toMatch(/^Entity already exists/);
    expect(networkErrorMessage(vlan, options)).not.toContain("Changed by someone else");
    // A code the console does not know is still not someone else's write.
    expect(networkErrorMessage(failure(409, { reason_code: "something_new" }), options)).toBe(
      "This change conflicts with the current network settings.",
    );
  });

  it("without a reason_code, says a 409 is someone else's write and adds the sentence unless stale-only", () => {
    const err = failure(409, { error: "conflict", message: "VLAN 10 is taken at this site" });
    expect(networkErrorMessage(err, options)).toBe(
      "Changed by someone else — reload and try again. VLAN 10 is taken at this site",
    );
    expect(networkErrorMessage(err, { ...options, staleOnly: true })).toBe(
      "Changed by someone else — reload and try again.",
    );
    expect(networkErrorMessage(failure(409, {}), options)).toBe(
      "Changed by someone else — reload and try again.",
    );
  });

  it("explains a 429, and passes a 400 and anything else through the shared helper", () => {
    expect(networkErrorMessage(failure(429, { error: "rate_limited" }), options)).toMatch(
      /Too many network changes/,
    );
    expect(
      networkErrorMessage(failure(400, { error: "validation_error", message: "bad vlan" }), options),
    ).toBe("bad vlan");
    expect(networkErrorMessage({}, options)).toBe("It failed.");
  });
});

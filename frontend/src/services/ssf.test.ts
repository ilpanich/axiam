import { describe, it, expect } from "vitest";

import {
  SSF_BOUNDS,
  SSF_EVENT_TYPES,
  validateSsfStreamInput,
  type SsfStreamInput,
} from "./ssf";

const ALL_EVENTS = SSF_EVENT_TYPES.map((e) => e.uri);

/** A valid push stream — the baseline each case perturbs. */
function input(patch: Partial<SsfStreamInput> = {}): SsfStreamInput {
  return {
    receiver_client_id: "siem-receiver",
    audience: "https://siem.example.com/",
    description: "Corporate SIEM",
    delivery_method: "push",
    endpoint_url: "https://siem.example.com/events",
    events_allowed: ALL_EVENTS,
    subject_format: "iss_sub",
    status: "enabled",
    ...patch,
  } as SsfStreamInput;
}

describe("validateSsfStreamInput", () => {
  it("accepts a valid push stream and a valid poll stream", () => {
    expect(validateSsfStreamInput(input())).toBeNull();
    expect(
      validateSsfStreamInput(
        input({ delivery_method: "poll", endpoint_url: undefined }),
      ),
    ).toBeNull();
  });

  it("requires a receiver client id and an audience, ignoring whitespace", () => {
    expect(validateSsfStreamInput(input({ receiver_client_id: "  " }))).toBe(
      "Receiver client id is required.",
    );
    expect(validateSsfStreamInput(input({ audience: "   " }))).toBe(
      "Audience is required.",
    );
  });

  it("measures the bounds in UTF-8 bytes, not characters", () => {
    // 200 two-byte characters: 200 chars, 400 bytes — over the 256-byte bound.
    const wide = "é".repeat(200);
    expect(wide.length).toBeLessThan(SSF_BOUNDS.descriptionBytes);
    expect(validateSsfStreamInput(input({ description: wide }))).toBe(
      `Description must be at most ${SSF_BOUNDS.descriptionBytes} bytes.`,
    );
    expect(
      validateSsfStreamInput(
        input({ audience: "a".repeat(SSF_BOUNDS.audienceBytes + 1) }),
      ),
    ).toBe(`Audience must be at most ${SSF_BOUNDS.audienceBytes} bytes.`);
    expect(
      validateSsfStreamInput(
        input({ status_reason: "r".repeat(SSF_BOUNDS.statusReasonBytes + 1) }),
      ),
    ).toBe(
      `Status reason must be at most ${SSF_BOUNDS.statusReasonBytes} bytes.`,
    );
  });

  it("refuses a push stream with no endpoint, an oversize one, or a malformed one", () => {
    expect(validateSsfStreamInput(input({ endpoint_url: "  " }))).toBe(
      "A push stream needs an endpoint URL.",
    );
    expect(validateSsfStreamInput(input({ endpoint_url: undefined }))).toBe(
      "A push stream needs an endpoint URL.",
    );
    expect(
      validateSsfStreamInput(
        input({
          endpoint_url: `https://x.example.com/${"p".repeat(SSF_BOUNDS.endpointUrlBytes)}`,
        }),
      ),
    ).toBe(
      `Endpoint URL must be at most ${SSF_BOUNDS.endpointUrlBytes} bytes.`,
    );
    expect(validateSsfStreamInput(input({ endpoint_url: "not a url" }))).toBe(
      "Endpoint URL must be an absolute URL.",
    );
  });

  it("refuses a non-https endpoint and one that carries credentials", () => {
    expect(
      validateSsfStreamInput(input({ endpoint_url: "http://siem.example.com" })),
    ).toBe("Endpoint URL must use https.");
    expect(
      validateSsfStreamInput(
        input({ endpoint_url: "https://user:pw@siem.example.com/" }),
      ),
    ).toBe("Endpoint URL must not carry credentials.");
    expect(
      validateSsfStreamInput(
        input({ endpoint_url: "https://user@siem.example.com/" }),
      ),
    ).toBe("Endpoint URL must not carry credentials.");
  });

  it("does not look at the endpoint of a poll stream", () => {
    expect(
      validateSsfStreamInput(
        input({ delivery_method: "poll", endpoint_url: "http://ignored" }),
      ),
    ).toBeNull();
  });

  it("bounds the authorization header and requires at least one event", () => {
    expect(
      validateSsfStreamInput(
        input({
          authorization_header: "h".repeat(
            SSF_BOUNDS.authorizationHeaderBytes + 1,
          ),
        }),
      ),
    ).toBe(
      `The authorization header must be at most ${SSF_BOUNDS.authorizationHeaderBytes} bytes.`,
    );
    expect(validateSsfStreamInput(input({ events_allowed: [] }))).toBe(
      "Allow at least one event type.",
    );
  });
});

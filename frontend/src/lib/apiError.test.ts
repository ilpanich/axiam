import { describe, it, expect } from "vitest";
import { getApiErrorMessage, redactSecrets } from "./apiError";

// Minimal AxiosError shape — avoids importing axios in tests.
function makeAxiosError(data?: { error?: string; message?: string }): unknown {
  return {
    isAxiosError: true,
    response: data !== undefined ? { data } : undefined,
    message: "Network Error",
  };
}

describe("getApiErrorMessage", () => {
  it("returns response.data.error when present", () => {
    const err = makeAxiosError({ error: "Email already in use", message: "conflict" });
    expect(getApiErrorMessage(err)).toBe("Email already in use");
  });

  it("falls back to response.data.message when error field absent", () => {
    const err = makeAxiosError({ message: "Validation failed" });
    expect(getApiErrorMessage(err)).toBe("Validation failed");
  });

  it("returns error.message for a plain Error", () => {
    const err = new Error("Something went wrong");
    expect(getApiErrorMessage(err)).toBe("Something went wrong");
  });

  it("returns a non-empty generic fallback for null", () => {
    const result = getApiErrorMessage(null);
    expect(result.length).toBeGreaterThan(0);
  });

  it("returns a non-empty generic fallback for undefined", () => {
    const result = getApiErrorMessage(undefined);
    expect(result.length).toBeGreaterThan(0);
  });

  it("returns error.message from AxiosError when no response data", () => {
    const err = makeAxiosError(undefined);
    expect(getApiErrorMessage(err)).toBe("Network Error");
  });

  it("returns the generic fallback for a plain non-Error object", () => {
    const result = getApiErrorMessage({ some: "shape" });
    expect(result).toBe("An unexpected error occurred. Please try again.");
  });

  it("returns the generic fallback for a bare string", () => {
    expect(getApiErrorMessage("boom")).toBe(
      "An unexpected error occurred. Please try again."
    );
  });

  it("ignores empty error/message fields and falls back to the network message", () => {
    const err = makeAxiosError({ error: "", message: "" });
    expect(getApiErrorMessage(err)).toBe("Network Error");
  });

  it("returns the generic fallback for an Error with an empty message", () => {
    expect(getApiErrorMessage(new Error(""))).toBe(
      "An unexpected error occurred. Please try again."
    );
  });
});


// ─── Secret redaction ─────────────────────────────────────────────────────────
//
// The threat is not that AXIAM's handlers echo secrets — none of them do
// today. It is that this function renders whatever came back in the body, at
// ~38 call sites including every form that carries a credential, and the body
// is not always written by AXIAM: a proxy or gateway can answer instead, and
// those echo requests routinely.

describe("redactSecrets", () => {
  it("redacts an AXIAM SCIM provisioning handle", () => {
    const token = `axiam_scim_${"a".repeat(43)}`;
    const out = redactSecrets(`invalid token ${token} presented`);
    expect(out).not.toContain(token);
    expect(out).toContain("[redacted: scim token]");
  });

  it("redacts a JWT", () => {
    const jwt =
      "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJ1c2VyIiwiZXhwIjoxfQ.c2lnbmF0dXJlLWhlcmU";
    const out = redactSecrets(`token rejected: ${jwt}`);
    expect(out).not.toContain(jwt);
    expect(out).toContain("[redacted: jwt]");
  });

  it("redacts an echoed Authorization header", () => {
    const out = redactSecrets("upstream sent Bearer abcdef0123456789xyz");
    expect(out).not.toContain("abcdef0123456789xyz");
    expect(out).toContain("[redacted: bearer token]");
  });

  it("redacts PEM private key material", () => {
    const pem =
      "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIA\n-----END PRIVATE KEY-----";
    const out = redactSecrets(`could not parse ${pem}`);
    expect(out).not.toContain("MC4CAQAwBQYDK2VwBCIEIA");
    expect(out).toContain("[redacted: private key]");
  });

  it("redacts secret-named fields from an echoed request body", () => {
    const out = redactSecrets(
      'Json deserialize error: {"host":"smtp.example.com","password":"hunter2","port":"x"}'
    );
    expect(out).not.toContain("hunter2");
    // The non-secret context survives — an error nobody can act on is one
    // people work around by opening the network tab.
    expect(out).toContain("smtp.example.com");
  });

  it("redacts secret-named query parameters", () => {
    const out = redactSecrets("upstream: GET /cb?code=abc&client_secret=s3cr3t-value");
    expect(out).not.toContain("s3cr3t-value");
    expect(out).toContain("code=abc");
  });

  it("redacts api_key in either casing", () => {
    expect(redactSecrets('{"api_key":"sg-live-123"}')).not.toContain("sg-live-123");
    expect(redactSecrets('{"apiKey":"sg-live-456"}')).not.toContain("sg-live-456");
  });

  it("truncates a body long enough to be an echoed payload", () => {
    const out = redactSecrets("x".repeat(2000));
    expect(out.length).toBeLessThan(600);
    expect(out).toContain("(truncated)");
  });

  // Guarding against the failure mode that makes redactors useless: if it
  // mangles ordinary errors, people stop trusting the UI's messages.
  it("leaves ordinary AXIAM messages untouched", () => {
    const real = [
      "Email already in use",
      "expires_in_days must be between 1 and 365",
      "password too short: minimum 12, got 4",
      "the named user does not hold scim:provision, so a token bound to them could not provision anything. Grant the permission first.",
      "A deny rule overrides every allow for this action",
      "cannot read email configuration for a different organization",
      "Request failed with status code 500",
    ];
    for (const m of real) {
      expect(redactSecrets(m)).toBe(m);
    }
  });

  it("leaves a bare short string alone", () => {
    expect(redactSecrets("conflict")).toBe("conflict");
  });
});

describe("getApiErrorMessage redaction", () => {
  it("redacts a secret echoed in response.data.error", () => {
    const err = makeAxiosError({ error: `leaked axiam_scim_${"b".repeat(43)}` });
    expect(getApiErrorMessage(err)).toContain("[redacted: scim token]");
  });

  it("redacts a secret echoed in response.data.message", () => {
    const err = makeAxiosError({ message: 'rejected {"password":"hunter2"}' });
    expect(getApiErrorMessage(err)).not.toContain("hunter2");
  });

  it("redacts a secret in the axios network message", () => {
    const err = {
      isAxiosError: true,
      response: undefined,
      message: "timeout posting client_secret=s3cr3t",
    };
    expect(getApiErrorMessage(err)).not.toContain("s3cr3t");
  });

  it("redacts a secret in a plain Error message", () => {
    expect(
      getApiErrorMessage(new Error("failed with Bearer abcdef0123456789"))
    ).not.toContain("abcdef0123456789");
  });
});

import { describe, it, expect } from "vitest";
import {
  getApiErrorCode,
  getApiErrorMessage,
  getApiErrorStatus,
  redactSecrets,
} from "./apiError";

// Minimal rejected-request shape. `isAxiosError` is set here only because a
// real axios rejection carries it — the helpers read the shape structurally
// and never the brand, which is what lets a test double describe an error
// without importing the transport (see `makeBareError` below).
function makeAxiosError(
  data?: { error?: string; message?: string; error_description?: string },
  status?: number
): unknown {
  return {
    isAxiosError: true,
    response: data !== undefined ? { data, status } : undefined,
    message: "Network Error",
  };
}

// The same thing with no axios branding at all, as a fetch wrapper or a test
// double would throw it.
function makeBareError(data?: { error?: string; message?: string }): unknown {
  return { response: data !== undefined ? { data } : undefined };
}

describe("getApiErrorMessage", () => {
  // The shape axiam-api-rest's `ErrorBody` actually sends: `error` is a
  // machine slug and `message` is the sentence. Both are always present, so
  // whichever field this helper reads first is the one every caller renders.
  it("prefers response.data.message over the response.data.error slug", () => {
    const err = makeAxiosError({
      error: "already_exists",
      message: "Entity already exists: user",
    });
    expect(getApiErrorMessage(err)).toBe("Entity already exists: user");
  });

  it("reads error_description for an RFC 6749 OAuth2 error body", () => {
    const err = makeAxiosError({
      error: "invalid_grant",
      error_description: "The refresh token has been revoked.",
    });
    expect(getApiErrorMessage(err)).toBe("The refresh token has been revoked.");
  });

  it("renders the error slug only when it is the only field present", () => {
    const err = makeAxiosError({ error: "rate_limited" });
    expect(getApiErrorMessage(err)).toBe("rate_limited");
  });

  it("reads a rejection that carries no isAxiosError brand", () => {
    expect(getApiErrorMessage(makeBareError({ message: "Token expired" }))).toBe(
      "Token expired"
    );
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

describe("getApiErrorMessage fallback precedence", () => {
  // A page-authored fallback outranks a transport exception string, because
  // "Network Error" and "timeout of 0ms exceeded" are developer diagnostics
  // and the page has written something a person can act on.
  it("prefers a caller fallback over the transport message", () => {
    const err = { message: "Network Error" };
    expect(getApiErrorMessage(err, "This link has expired.")).toBe(
      "This link has expired."
    );
  });

  it("still reaches the transport message when no fallback is supplied", () => {
    expect(getApiErrorMessage({ message: "Network Error" })).toBe("Network Error");
  });

  it("prefers a server message over the caller fallback", () => {
    const err = makeAxiosError({ message: "Token already used", error: "conflict" });
    expect(getApiErrorMessage(err, "This link has expired.")).toBe(
      "Token already used"
    );
  });

  it("returns the caller fallback for null and undefined", () => {
    expect(getApiErrorMessage(null, "nope")).toBe("nope");
    expect(getApiErrorMessage(undefined, "nope")).toBe("nope");
  });
});

describe("getApiErrorStatus", () => {
  it("returns the HTTP status of a failed request", () => {
    expect(getApiErrorStatus(makeAxiosError({ error: "forbidden" }, 403))).toBe(403);
  });

  // undefined means "no HTTP response arrived", which is a different fact from
  // any status code and must not collapse into a falsy check.
  it("returns undefined when no response arrived", () => {
    expect(getApiErrorStatus(new Error("network down"))).toBeUndefined();
    expect(getApiErrorStatus(makeAxiosError(undefined))).toBeUndefined();
    expect(getApiErrorStatus(null)).toBeUndefined();
    expect(getApiErrorStatus("boom")).toBeUndefined();
  });
});

describe("getApiErrorCode", () => {
  it("returns the machine slug, which is the field to branch on", () => {
    const err = makeAxiosError({
      error: "password_policy_violation",
      message: "Password policy violation: too short",
    });
    expect(getApiErrorCode(err)).toBe("password_policy_violation");
  });

  it("returns undefined when there is no slug", () => {
    expect(getApiErrorCode(makeAxiosError({ message: "boom" }))).toBeUndefined();
    expect(getApiErrorCode(new Error("network down"))).toBeUndefined();
    expect(getApiErrorCode(null)).toBeUndefined();
  });
});

describe("getApiErrorMessage redaction", () => {
  // The regression that motivated routing every page through this helper:
  // ProfilePage, ChangePasswordPage and MfaManagementPage each extracted
  // `response.data.message` inline and rendered it with no redaction at all.
  it("redacts a secret echoed in response.data.message even with a fallback", () => {
    const err = makeAxiosError({
      message: `update rejected for eyJhbGciOiJFZERTQSJ9.${"c".repeat(20)}.${"d".repeat(20)}`,
    });
    const out = getApiErrorMessage(err, "Failed to update profile.");
    expect(out).toContain("[redacted: jwt]");
    expect(out).not.toContain("c".repeat(20));
  });

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

import { describe, expect, it } from "vitest";

import {
  ACR_MULTI_FACTOR,
  ACR_SINGLE_FACTOR,
  REAUTH_MAX_ATTEMPTS,
  REAUTH_WINDOW_MS,
  clearReauthAttempts,
  recordReauthAttempt,
  sanitizeRequiredAcr,
} from "@/lib/reauth";

const RETURN_TO =
  "/oauth2/authorize?response_type=code&client_id=oa_1&axiam_login_hop=1";

/** A `Storage` that lives in a `Map`, so the guard is tested without a DOM. */
function memoryStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (k: string) => map.get(k) ?? null,
    key: (i: number) => [...map.keys()][i] ?? null,
    removeItem: (k: string) => void map.delete(k),
    setItem: (k: string, v: string) => void map.set(k, v),
  } as Storage;
}

/** A `Storage` that throws on every access — a private window, or quota. */
function hostileStorage(): Storage {
  const boom = () => {
    throw new Error("storage is unavailable");
  };
  return {
    get length(): number {
      return boom();
    },
    clear: boom,
    getItem: boom,
    key: boom,
    removeItem: boom,
    setItem: boom,
  } as unknown as Storage;
}

describe("sanitizeRequiredAcr", () => {
  it("accepts exactly the two values AXIAM defines", () => {
    expect(sanitizeRequiredAcr(ACR_SINGLE_FACTOR)).toBe(ACR_SINGLE_FACTOR);
    expect(sanitizeRequiredAcr(ACR_MULTI_FACTOR)).toBe(ACR_MULTI_FACTOR);
  });

  /**
   * The allow-list is the whole point. This page must never be able to display
   * — or act on — an authentication context class chosen by whoever wrote the
   * URL, because the class the resulting session earns is derived on the server
   * from what the session proves, and a page that showed an arbitrary string
   * would be the first place the two could be confused.
   */
  it.each([
    ["absent", null],
    ["undefined", undefined],
    ["empty", ""],
    ["a class from another registry", "http://schemas.example/2fa"],
    ["a plausible invention", "urn:axiam:acr:god-mode"],
    ["the right value in the wrong case", "URN:AXIAM:ACR:MFA"],
    ["the right value with whitespace", " urn:axiam:acr:mfa "],
    ["markup", "<img src=x onerror=alert(1)>"],
  ])("refuses %s", (_label, raw) => {
    expect(sanitizeRequiredAcr(raw)).toBeNull();
  });
});

describe("recordReauthAttempt (T1.6)", () => {
  it("allows the first three hops to one destination and refuses the fourth", () => {
    const storage = memoryStorage();
    const now = 1_000_000;
    for (let i = 0; i < REAUTH_MAX_ATTEMPTS; i += 1) {
      expect(recordReauthAttempt(RETURN_TO, now + i * 100, storage)).toBe(true);
    }
    expect(recordReauthAttempt(RETURN_TO, now + 400, storage)).toBe(false);
    expect(recordReauthAttempt(RETURN_TO, now + 500, storage)).toBe(false);
  });

  it("counts per destination, because signing in to three applications is not a loop", () => {
    const storage = memoryStorage();
    const now = 1_000_000;
    for (let i = 0; i < REAUTH_MAX_ATTEMPTS; i += 1) {
      recordReauthAttempt(RETURN_TO, now + i, storage);
    }
    expect(recordReauthAttempt(RETURN_TO, now + 10, storage)).toBe(false);
    expect(
      recordReauthAttempt("/oauth2/authorize?client_id=oa_2", now + 11, storage),
    ).toBe(true);
  });

  it("forgets attempts once the window has passed", () => {
    const storage = memoryStorage();
    const now = 1_000_000;
    for (let i = 0; i < REAUTH_MAX_ATTEMPTS; i += 1) {
      recordReauthAttempt(RETURN_TO, now + i, storage);
    }
    expect(recordReauthAttempt(RETURN_TO, now + 10, storage)).toBe(false);
    expect(
      recordReauthAttempt(RETURN_TO, now + REAUTH_WINDOW_MS + 1, storage),
    ).toBe(true);
  });

  it("starts again once a completed sign-in clears the destination", () => {
    const storage = memoryStorage();
    const now = 1_000_000;
    for (let i = 0; i < REAUTH_MAX_ATTEMPTS; i += 1) {
      recordReauthAttempt(RETURN_TO, now + i, storage);
    }
    expect(recordReauthAttempt(RETURN_TO, now + 10, storage)).toBe(false);
    clearReauthAttempts(RETURN_TO, storage);
    expect(recordReauthAttempt(RETURN_TO, now + 11, storage)).toBe(true);
  });

  /**
   * The guard is a convenience for the end user, so a browser that refuses to
   * store anything must cost them a guard and never a sign-in.
   */
  it("permits the hop when there is no usable storage", () => {
    expect(recordReauthAttempt(RETURN_TO, 1, null)).toBe(true);
    for (let i = 0; i < REAUTH_MAX_ATTEMPTS + 2; i += 1) {
      expect(recordReauthAttempt(RETURN_TO, i, hostileStorage())).toBe(true);
    }
    expect(() => clearReauthAttempts(RETURN_TO, hostileStorage())).not.toThrow();
  });

  it("ignores a stored value somebody else wrote", () => {
    const storage = memoryStorage();
    storage.setItem("axiam.reauth.attempts", "not json at all");
    expect(recordReauthAttempt(RETURN_TO, 1, storage)).toBe(true);

    storage.setItem("axiam.reauth.attempts", JSON.stringify({ [RETURN_TO]: "3" }));
    expect(recordReauthAttempt(RETURN_TO, 2, storage)).toBe(true);
  });

  /** A timestamp from the future is not evidence of anything. */
  it("drops recorded times that are ahead of the clock", () => {
    const storage = memoryStorage();
    storage.setItem(
      "axiam.reauth.attempts",
      JSON.stringify({ [RETURN_TO]: [10_000, 10_001, 10_002] }),
    );
    expect(recordReauthAttempt(RETURN_TO, 5_000, storage)).toBe(true);
  });
});

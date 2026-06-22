import { describe, it, expect } from "vitest";
import { getApiErrorMessage } from "./apiError";

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
});

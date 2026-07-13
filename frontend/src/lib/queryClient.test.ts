import { describe, it, expect } from "vitest";
import { queryClient } from "./queryClient";

// Exercises the shared QueryClient's retry policy (D-14): 401/403 never retry,
// everything else retries up to 2 times.
describe("queryClient retry policy", () => {
  const retry = queryClient.getDefaultOptions().queries?.retry as (
    failureCount: number,
    error: unknown
  ) => boolean;

  it("is configured as a function", () => {
    expect(typeof retry).toBe("function");
  });

  it("never retries on 401 or 403", () => {
    expect(retry(0, { response: { status: 401 } })).toBe(false);
    expect(retry(0, { response: { status: 403 } })).toBe(false);
  });

  it("retries other errors up to twice then stops", () => {
    const err = { response: { status: 500 } };
    expect(retry(0, err)).toBe(true);
    expect(retry(1, err)).toBe(true);
    expect(retry(2, err)).toBe(false);
  });

  it("treats an error with no response as retryable", () => {
    expect(retry(0, new Error("network"))).toBe(true);
  });

  it("uses a 60s stale time", () => {
    expect(queryClient.getDefaultOptions().queries?.staleTime).toBe(60_000);
  });
});

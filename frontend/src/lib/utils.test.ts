import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { cn, formatRelativeTime, formatDate, formatDateTime, slugify } from "./utils";

describe("cn", () => {
  it("merges class names and dedupes conflicting tailwind utilities", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
    const off: boolean = false;
    expect(cn("a", off && "b", "c")).toBe("a c");
    expect(cn(["a", "b"], { c: true, d: false })).toBe("a b c");
  });
});

describe("formatRelativeTime", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-07-12T12:00:00Z"));
  });
  afterEach(() => vi.useRealTimers());

  const ago = (sec: number) =>
    new Date(Date.now() - sec * 1000).toISOString();

  it("returns 'just now' under a minute", () => {
    expect(formatRelativeTime(ago(30))).toBe("just now");
  });
  it("singular vs plural minutes", () => {
    expect(formatRelativeTime(ago(60))).toBe("1 minute ago");
    expect(formatRelativeTime(ago(120))).toBe("2 minutes ago");
  });
  it("singular vs plural hours", () => {
    expect(formatRelativeTime(ago(3600))).toBe("1 hour ago");
    expect(formatRelativeTime(ago(7200))).toBe("2 hours ago");
  });
  it("yesterday boundary", () => {
    expect(formatRelativeTime(ago(90000))).toBe("yesterday");
  });
  it("days / months / years", () => {
    expect(formatRelativeTime(ago(3 * 86400))).toBe("3 days ago");
    expect(formatRelativeTime(ago(60 * 86400))).toBe("2 months ago");
    expect(formatRelativeTime(ago(45 * 86400))).toBe("1 month ago");
    expect(formatRelativeTime(ago(400 * 86400))).toBe("1 year ago");
    expect(formatRelativeTime(ago(800 * 86400))).toBe("2 years ago");
  });
});

describe("formatDate / formatDateTime", () => {
  it("formatDate produces a non-empty medium date", () => {
    expect(formatDate("2026-01-15T10:30:00Z")).toMatch(/2026/);
  });
  it("formatDateTime includes a time component", () => {
    const out = formatDateTime("2026-01-15T10:30:00Z");
    expect(out).toMatch(/2026/);
    expect(out.length).toBeGreaterThan(formatDate("2026-01-15T10:30:00Z").length);
  });
});

describe("slugify", () => {
  it("lowercases, trims, and hyphenates non-alphanumerics", () => {
    expect(slugify("My Organization")).toBe("my-organization");
  });
  it("strips leading/trailing separators and collapses runs", () => {
    expect(slugify("  Hello   World!!  ")).toBe("hello-world");
    expect(slugify("--Acme_Co--")).toBe("acme-co");
  });
  it("returns empty string for all-symbol input", () => {
    expect(slugify("@@@")).toBe("");
  });
});

describe("formatDate — invalid input", () => {
  // `Intl.DateTimeFormat.format` throws `RangeError: Invalid time value` rather
  // than returning something useless. Thrown from a render that takes down the
  // whole page: a table of a hundred rows blanks to an error boundary because
  // one row has a malformed timestamp.
  it("renders a dash instead of throwing on an unparseable date", () => {
    expect(formatDate("not-a-date")).toBe("—");
    expect(formatDate("")).toBe("—");
  });

  it("renders a dash for a missing value rather than 'Invalid Date'", () => {
    // Reached when an API response omits an optional timestamp; the cast
    // mirrors what a `string | undefined` field does at runtime.
    expect(formatDate(undefined as unknown as string)).toBe("—");
  });

  it("still formats a real date", () => {
    expect(formatDate("2026-01-15T00:00:00Z")).not.toBe("—");
  });

  it("formatDateTime has the same guard", () => {
    expect(formatDateTime("not-a-date")).toBe("—");
    expect(formatDateTime("2026-01-15T10:30:00Z")).not.toBe("—");
  });

  it("formatRelativeTime renders a dash rather than 'NaN years ago'", () => {
    // This one never threw — NaN compares false against everything, so it fell
    // through every branch to the last. The quieter failure, and the one more
    // likely to reach a user.
    expect(formatRelativeTime("not-a-date")).toBe("—");
    expect(formatRelativeTime(new Date().toISOString())).toBe("just now");
  });
});

import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { cn, formatRelativeTime, formatDate, formatDateTime, slugify } from "./utils";

describe("cn", () => {
  it("merges class names and dedupes conflicting tailwind utilities", () => {
    expect(cn("px-2", "px-4")).toBe("px-4");
    expect(cn("a", false && "b", "c")).toBe("a c");
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

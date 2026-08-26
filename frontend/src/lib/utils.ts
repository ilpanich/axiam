import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

/**
 * Returns a human-readable relative time string for a given ISO date string.
 * E.g. "2 minutes ago", "3 hours ago", "yesterday"
 */
export function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  // An unparseable date makes every comparison below false — NaN compares false
  // against everything — so it falls all the way through and renders
  // "NaN years ago". It does not throw, which makes it the quieter of the two
  // failure modes and the easier one to ship.
  if (Number.isNaN(date.getTime())) return "—";
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffSec = Math.floor(diffMs / 1000);

  if (diffSec < 60) return "just now";
  if (diffSec < 3600) {
    const m = Math.floor(diffSec / 60);
    return `${m} ${m === 1 ? "minute" : "minutes"} ago`;
  }
  if (diffSec < 86400) {
    const h = Math.floor(diffSec / 3600);
    return `${h} ${h === 1 ? "hour" : "hours"} ago`;
  }
  if (diffSec < 172800) return "yesterday";
  const d = Math.floor(diffSec / 86400);
  if (d < 30) return `${d} days ago`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo} ${mo === 1 ? "month" : "months"} ago`;
  const yr = Math.floor(mo / 12);
  return `${yr} ${yr === 1 ? "year" : "years"} ago`;
}

/**
 * Formats an ISO date string as a medium-length date, e.g. "Jan 15, 2026"
 */
export function formatDate(iso: string): string {
  // `Intl.DateTimeFormat.format` THROWS `RangeError: Invalid time value` on an
  // unparseable date rather than returning something useless. Thrown from a
  // render, that takes down the whole page — a table of a hundred rows blanks
  // because one of them has a malformed timestamp, and the operator sees an
  // error boundary instead of the ninety-nine good rows.
  //
  // A dash is the right answer for a date that is not a date: it is what an
  // absent value renders as everywhere else in this UI, and the row stays
  // readable.
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}

/**
 * Formats an ISO date string as date + time, e.g. "Jan 15, 2026, 10:30 AM"
 */
export function formatDateTime(iso: string): string {
  // Same hazard as `formatDate` — see the note there.
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return "—";
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

/**
 * Converts a string to a URL/slug-safe format.
 * E.g. "My Organization" -> "my-organization"
 */
export function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
}

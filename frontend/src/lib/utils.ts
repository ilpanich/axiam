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
  return new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );
}

/**
 * Formats an ISO date string as date + time, e.g. "Jan 15, 2026, 10:30 AM"
 */
export function formatDateTime(iso: string): string {
  return new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(iso));
}

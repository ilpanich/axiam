export type Page =
  | "home"
  | "sdks"
  | "sdk"
  | "docs"
  | "news"
  | "post"
  | "bench"
  | "roadmap";

export interface Sdk {
  id: string;
  name: string;
  abbr: string;
  registry: string;
  registryUrl: string;
  /**
   * Canonical package-documentation host for this ecosystem (docs.rs, etc.).
   * Optional: a few ecosystems have no auto-generated API-doc host distinct
   * from the registry/repository, in which case these are omitted.
   */
  docsLabel?: string;
  docsUrl?: string;
  repoUrl: string;
  /** Link to the runnable examples folder inside the SDK repository. */
  examplesUrl: string;
  pkg: string;
  install: string;
  blurb: string;
  highlights: string[];
  quickstart: string;
  /**
   * A second example showing the declarative framework-guard style idiomatic
   * to the language — a macro (Rust), annotation (Java), attribute (C#/PHP),
   * decorator/dependency (TypeScript/Python) or middleware (Go).
   */
  guardLabel: string;
  guardExample: string;
}

export type PostBlockType = "p" | "h" | "quote";

export interface PostBlock {
  type: PostBlockType;
  text: string;
}

export interface Post {
  slug: string;
  date: string;
  dateShort: string;
  tag: string;
  author: string;
  title: string;
  excerpt: string;
  body: PostBlock[];
}

export interface Phase {
  n: number;
  title: string;
  focus: string;
  /** Approximate start date, e.g. "Feb 24, 2026" — derived from the issue tracker + commit history. */
  start: string;
  /** Approximate end date, e.g. "Feb 25, 2026", or "Ongoing" for the in-progress phase. */
  end: string;
  /** Delivery state — completed phases are "done"; the current hardening phase is "ongoing". */
  status: "done" | "ongoing";
}

/** One target's result within a benchmark scenario. */
export interface BenchBar {
  /** Target name — "AXIAM", "Keycloak", "Zitadel". */
  target: string;
  /** Numeric value used to size the bar. */
  value: number;
  /** Pre-formatted label shown at the end of the bar (e.g. "1,788"). */
  display: string;
  /** AXIAM bars get the brand gradient; competitors get muted slate. */
  axiam?: boolean;
}

/**
 * A single benchmark scenario rendered as a titled bar chart plus a short
 * takeaway. `higherIsBetter` flips the "leader" framing for cost-style metrics.
 */
export interface BenchScenario {
  id: string;
  title: string;
  /** Metric being charted, e.g. "throughput · requests/s (plaintext)". */
  unit: string;
  bars: BenchBar[];
  /** One-line, measured-tone takeaway shown under the chart. */
  takeaway: string;
}

/**
 * One row of the whole-stack efficiency comparison. Values are pre-formatted
 * strings; `[AXIAM, Keycloak, Zitadel]` order throughout.
 */
export interface BenchEfficiencyRow {
  scenario: string;
  /** Throughput per CPU core consumed (higher is better). */
  perCore: [string, string, string];
  /** CPU-milliseconds per request (lower is better). */
  cpuMs: [string, string, string];
}

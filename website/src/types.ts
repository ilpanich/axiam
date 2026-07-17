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
}

export interface BenchRow {
  name: string;
  value: string;
  width: string;
  fill: string;
}

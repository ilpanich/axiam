import { useEffect, useMemo, useState } from "react";
import type { Page } from "../types";
import {
  DOC_SECTIONS,
  DOC_PAGES,
  DOC_ORDER,
  findDocPage,
  docSectionsAreComplete,
  type DocPage,
  type DocBlock,
} from "../docs";
import { renderInline } from "../lib/render";
import Block from "../components/DocBlocks";

interface DocsProps {
  go: (page: Page) => void;
}

const DEFAULT_SLUG = "overview";

const scrollTop = () => {
  if (typeof window !== "undefined") window.scrollTo(0, 0);
};

/**
 * Read the doc slug out of the URL hash, or `null` if the hash is not a doc
 * link.
 *
 * Deep links matter more here than anywhere else on the site: documentation is
 * the thing people link each other to, and a docs section that always opens on
 * page one cannot be cited. The hash is used rather than the History API
 * because the site is served as static files with no server-side routing, so a
 * real path would 404 on refresh.
 *
 * The `null` return is load-bearing. The "On this page" links are ordinary
 * `#heading-id` anchors, so every one of them fires `hashchange` with a hash
 * this pattern does not match. Returning a default slug there would send a
 * reader who clicked a heading link back to the first page of the docs.
 */
function docSlugFromHash(): string | null {
  if (typeof window === "undefined") return null;
  const match = /^#\/docs\/([a-z0-9-]+)$/.exec(window.location.hash);
  const slug = match?.[1];
  return slug && findDocPage(slug) ? slug : null;
}

/** Flatten a block to the plain text the search index matches against. */
function blockText(block: DocBlock): string {
  switch (block.type) {
    case "h":
    case "p":
    case "note":
    case "warn":
      return block.text;
    case "list":
      return block.items.join(" ");
    case "code":
      return `${block.caption ?? ""} ${block.code}`;
    case "table":
      return `${block.headers.join(" ")} ${block.rows.flat().join(" ")}`;
    case "cards":
      return block.cards.map((c) => `${c.title} ${c.body}`).join(" ");
    case "links":
      return block.links.map((l) => `${l.label} ${l.note ?? ""}`).join(" ");
    case "steps":
      return block.steps.map((s) => `${s.title} ${s.body} ${s.code ?? ""}`).join(" ");
    case "api":
      return block.endpoints
        .map((e) => `${e.method} ${e.path} ${e.summary}`)
        .join(" ");
    case "codegroup":
      return block.tabs.map((t) => `${t.label} ${t.code}`).join(" ");
  }
}

interface SearchEntry {
  slug: string;
  navLabel: string;
  section: string;
  title: string;
  intro: string;
  haystack: string;
}

/**
 * The search index, built once from the content itself.
 *
 * Deliberately a substring match over lower-cased text rather than anything
 * cleverer: the corpus is a few hundred KB, it runs in well under a frame, and
 * a fuzzy matcher would return the kind of near-miss that makes a reader doubt
 * the result they wanted was found at all.
 */
const SEARCH_INDEX: SearchEntry[] = DOC_PAGES.map((p) => ({
  slug: p.slug,
  navLabel: p.navLabel,
  section: p.section,
  title: p.title,
  intro: p.intro,
  haystack: [p.title, p.navLabel, p.section, p.intro, ...p.blocks.map(blockText)]
    .join(" ")
    .toLowerCase(),
}));

function search(query: string): SearchEntry[] {
  const q = query.trim().toLowerCase();
  if (q.length < 2) return [];
  const terms = q.split(/\s+/);
  return SEARCH_INDEX.filter((e) => terms.every((t) => e.haystack.includes(t)))
    .sort((a, b) => {
      // A hit in the title outranks one buried in the body.
      const aTitle = a.title.toLowerCase().includes(q) ? 0 : 1;
      const bTitle = b.title.toLowerCase().includes(q) ? 0 : 1;
      return aTitle - bTitle;
    })
    .slice(0, 8);
}

export default function Docs({ go }: DocsProps) {
  const [slug, setSlug] = useState<string>(() => docSlugFromHash() ?? DEFAULT_SLUG);
  const [query, setQuery] = useState("");

  // Keep the view in step with the browser's back/forward buttons.
  useEffect(() => {
    const onHashChange = () => {
      const next = docSlugFromHash();
      // Ignore heading anchors — they are not page navigations.
      if (next) setSlug(next);
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  // Surface a navigation/content mismatch to whoever is editing the docs,
  // in development only. Rendering anyway beats refusing to.
  useEffect(() => {
    if (!import.meta.env.DEV) return;
    for (const problem of docSectionsAreComplete()) {
      console.warn(`[docs] ${problem}`);
    }
  }, []);

  const page: DocPage = findDocPage(slug) ?? DOC_PAGES[0];

  const toc = useMemo(
    () =>
      page.blocks
        .filter((b): b is Extract<DocBlock, { type: "h" }> => b.type === "h")
        .map((b) => ({ id: b.id, text: b.text })),
    [page],
  );

  const results = useMemo(() => search(query), [query]);

  const index = DOC_ORDER.indexOf(page.slug);
  const prev = index > 0 ? findDocPage(DOC_ORDER[index - 1]) : undefined;
  const next =
    index >= 0 && index < DOC_ORDER.length - 1
      ? findDocPage(DOC_ORDER[index + 1])
      : undefined;

  const openDoc = (nextSlug: string) => {
    setSlug(nextSlug);
    setQuery("");
    if (typeof window !== "undefined") {
      window.location.hash = `#/docs/${nextSlug}`;
    }
    scrollTop();
  };

  return (
    <div className="ax-docs">
      {/* Left nav */}
      <aside className="ax-docs-side">
        <div style={{ margin: "0 0 18px", padding: "0 12px" }}>
          <input
            type="search"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search the docs…"
            aria-label="Search the documentation"
            style={{
              width: "100%",
              boxSizing: "border-box",
              padding: "8px 11px",
              borderRadius: 9,
              border: "1px solid rgba(0,212,255,.2)",
              background: "rgba(0,0,0,.28)",
              color: "#e2e8f0",
              fontSize: 13.5,
              outline: "none",
            }}
          />
          {query.trim().length >= 2 && (
            <div style={{ marginTop: 8 }}>
              {results.length === 0 ? (
                <div style={{ fontSize: 12.5, color: "#64748b", padding: "6px 2px" }}>
                  No matches for “{query.trim()}”.
                </div>
              ) : (
                results.map((r) => (
                  <button
                    key={r.slug}
                    className="ax-side"
                    onClick={() => openDoc(r.slug)}
                    style={{ textAlign: "left" }}
                  >
                    <span style={{ display: "block" }}>{r.navLabel}</span>
                    <span style={{ display: "block", fontSize: 11, color: "#64748b" }}>
                      {r.section}
                    </span>
                  </button>
                ))
              )}
            </div>
          )}
        </div>

        {DOC_SECTIONS.map((section, si) => (
          <div key={section.label}>
            <div
              style={{
                fontSize: 11,
                textTransform: "uppercase",
                letterSpacing: ".14em",
                color: "#64748b",
                margin: si === 0 ? "0 0 10px 14px" : "22px 0 10px 14px",
              }}
            >
              {section.label}
            </div>
            {section.slugs.map((s) => {
              const doc = findDocPage(s);
              if (!doc) return null;
              return (
                <button
                  key={s}
                  className={`ax-side${s === slug ? " ax-side-active" : ""}`}
                  aria-current={s === slug ? "page" : undefined}
                  onClick={() => openDoc(s)}
                >
                  {doc.navLabel}
                </button>
              );
            })}
          </div>
        ))}
      </aside>

      {/* Article */}
      <article style={{ minWidth: 0 }}>
        <div style={{ fontSize: 13, color: "#64748b", marginBottom: 10 }}>
          {page.section} /{" "}
          <span style={{ color: "#94a3b8" }}>{page.navLabel}</span>
        </div>
        <h1
          style={{
            margin: "0 0 8px",
            fontSize: "clamp(30px, 5vw, 40px)",
            fontWeight: 800,
            letterSpacing: "-.02em",
          }}
        >
          {page.title}
        </h1>
        <p style={{ fontSize: 17, color: "#94a3b8", margin: "0 0 30px" }}>
          {renderInline(page.intro)}
        </p>
        {page.blocks.map((block, i) => (
          <Block key={i} block={block} go={go} />
        ))}

        {/* Verification stamp — rendered only for a page that carries one */}
        {page.verifiedRelease && (
          <p
            style={{
              fontSize: 12,
              color: "#64748b",
              marginTop: 32,
              paddingTop: 16,
              borderTop: "1px solid rgba(0,212,255,.10)",
            }}
          >
            Verified against AXIAM {page.verifiedRelease}.
          </p>
        )}

        {/* Previous / next pager */}
        {(prev || next) && (
          <nav
            aria-label="Documentation pages"
            style={{
              display: "flex",
              gap: 14,
              marginTop: 44,
              paddingTop: 24,
              borderTop: "1px solid rgba(255,255,255,.08)",
            }}
          >
            {prev && (
              <button
                className="glass-card ax-lift"
                onClick={() => openDoc(prev.slug)}
                style={{
                  flex: 1,
                  padding: 16,
                  textAlign: "left",
                  cursor: "pointer",
                  border: "1px solid rgba(0,212,255,.14)",
                  color: "inherit",
                }}
              >
                <div style={{ fontSize: 12, color: "#64748b", marginBottom: 4 }}>
                  ← Previous
                </div>
                <div style={{ fontWeight: 700, color: "#e2e8f0" }}>{prev.navLabel}</div>
              </button>
            )}
            {next && (
              <button
                className="glass-card ax-lift"
                onClick={() => openDoc(next.slug)}
                style={{
                  flex: 1,
                  padding: 16,
                  textAlign: "right",
                  cursor: "pointer",
                  border: "1px solid rgba(0,212,255,.14)",
                  color: "inherit",
                }}
              >
                <div style={{ fontSize: 12, color: "#64748b", marginBottom: 4 }}>
                  Next →
                </div>
                <div style={{ fontWeight: 700, color: "#e2e8f0" }}>{next.navLabel}</div>
              </button>
            )}
          </nav>
        )}
      </article>

      {/* Right ToC */}
      <aside className="ax-docs-toc">
        <div
          style={{
            textTransform: "uppercase",
            letterSpacing: ".12em",
            color: "#64748b",
            marginBottom: 12,
            fontSize: 11,
          }}
        >
          On this page
        </div>
        {toc.map((h, i) => (
          <a
            key={h.id}
            href={`#${h.id}`}
            style={{
              display: "block",
              color: i === 0 ? "#67e8f9" : "#94a3b8",
              padding: "5px 0",
              ...(i === 0
                ? {
                    borderLeft: "2px solid #00d4ff",
                    paddingLeft: 10,
                    marginLeft: -12,
                  }
                : {}),
            }}
          >
            {h.text}
          </a>
        ))}
      </aside>
    </div>
  );
}

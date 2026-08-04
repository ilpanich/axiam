import { useMemo, useState } from "react";
import type { Page } from "../types";
import { DOC_SECTIONS, DOC_PAGES, type DocPage, type DocBlock } from "../docs";
import { renderInline } from "../lib/render";
import Block from "../components/DocBlocks";

interface DocsProps {
  go: (page: Page) => void;
}

const scrollTop = () => {
  if (typeof window !== "undefined") window.scrollTo(0, 0);
};

export default function Docs({ go }: DocsProps) {
  const [slug, setSlug] = useState("quickstart");
  const page: DocPage =
    DOC_PAGES.find((p) => p.slug === slug) ?? DOC_PAGES[0];

  const toc = useMemo(
    () =>
      page.blocks
        .filter((b): b is Extract<DocBlock, { type: "h" }> => b.type === "h")
        .map((b) => ({ id: b.id, text: b.text })),
    [page],
  );

  const openDoc = (next: string) => {
    setSlug(next);
    scrollTop();
  };

  return (
    <div className="ax-docs">
      {/* Left nav */}
      <aside className="ax-docs-side">
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
              const doc = DOC_PAGES.find((p) => p.slug === s);
              if (!doc) return null;
              return (
                <button
                  key={s}
                  className={`ax-side${s === slug ? " ax-side-active" : ""}`}
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

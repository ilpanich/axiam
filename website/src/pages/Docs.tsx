import { useMemo, useState } from "react";
import type { Page } from "../types";
import { DOC_SECTIONS, DOC_PAGES, type DocPage, type DocBlock } from "../docs";
import { renderInline, highlightCode } from "../lib/render";

interface DocsProps {
  go: (page: Page) => void;
}

const scrollTop = () => {
  if (typeof window !== "undefined") window.scrollTo(0, 0);
};

const headingStyle = {
  fontSize: 22,
  fontWeight: 700,
  margin: "34px 0 12px",
  scrollMarginTop: 90,
} as const;

function CodeBlock({ block }: { block: Extract<DocBlock, { type: "code" }> }) {
  return (
    <div
      className="glass-card"
      style={{ borderRadius: 12, overflow: "hidden", margin: "0 0 16px" }}
    >
      {block.caption && (
        <div
          style={{
            padding: "10px 16px",
            borderBottom: "1px solid rgba(0,212,255,.12)",
            background: "rgba(255,255,255,.03)",
            font: "12px ui-monospace,Menlo,monospace",
            color: "#94a3b8",
          }}
        >
          {block.caption}
        </div>
      )}
      <pre
        style={{
          margin: 0,
          padding: 20,
          fontSize: 13.5,
          lineHeight: 1.7,
          color: "#cbd5e1",
          overflow: "auto",
        }}
      >
        {highlightCode(block.code)}
      </pre>
    </div>
  );
}

function Callout({
  kind,
  text,
}: {
  kind: "note" | "warn";
  text: string;
}) {
  const styles =
    kind === "warn"
      ? { border: "rgba(255,189,46,.4)", bg: "rgba(255,189,46,.08)", icon: "⚠️", iconColor: "#ffd98a" }
      : { border: "rgba(168,85,247,.3)", bg: "rgba(168,85,247,.06)", icon: "ℹ", iconColor: "#c084fc" };
  return (
    <div
      className="glass-card"
      style={{
        padding: "16px 20px",
        borderColor: styles.border,
        background: styles.bg,
        display: "flex",
        gap: 12,
        alignItems: "flex-start",
        margin: "0 0 20px",
      }}
    >
      <span style={{ color: styles.iconColor, fontSize: 18, lineHeight: 1 }}>
        {styles.icon}
      </span>
      <p style={{ margin: 0, fontSize: 14, color: "#cbd5e1", lineHeight: 1.6 }}>
        {renderInline(text)}
      </p>
    </div>
  );
}

function Block({ block, go }: { block: DocBlock; go: (p: Page) => void }) {
  switch (block.type) {
    case "h":
      return (
        <h2 id={block.id} style={headingStyle}>
          {block.text}
        </h2>
      );
    case "p":
      return (
        <p style={{ color: "#cbd5e1", lineHeight: 1.7, margin: "0 0 16px" }}>
          {renderInline(block.text)}
        </p>
      );
    case "list":
      return (
        <ul
          style={{
            margin: "0 0 16px",
            paddingLeft: 22,
            color: "#cbd5e1",
            lineHeight: 1.7,
          }}
        >
          {block.items.map((item, i) => (
            <li key={i} style={{ marginBottom: 6 }}>
              {renderInline(item)}
            </li>
          ))}
        </ul>
      );
    case "code":
      return <CodeBlock block={block} />;
    case "note":
      return <Callout kind="note" text={block.text} />;
    case "warn":
      return <Callout kind="warn" text={block.text} />;
    case "cards":
      return (
        <div className="ax-grid-2" style={{ gap: 14 }}>
          {block.cards.map((c, i) => (
            <div
              key={i}
              className="glass-card ax-lift"
              style={{ padding: 18, cursor: "pointer" }}
              onClick={() => go(c.to)}
            >
              <div style={{ fontWeight: 700, marginBottom: 4 }}>{c.title}</div>
              <div style={{ fontSize: 13, color: "#94a3b8" }}>{c.body}</div>
            </div>
          ))}
        </div>
      );
  }
}

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

import { useState } from "react";
import type { Page } from "../types";
import type { DocBlock } from "../docs";
import { renderInline, highlightCode } from "../lib/render";

/**
 * Renderer for the shared `DocBlock` content model.
 *
 * Both the documentation site (`pages/Docs.tsx`) and the Security section
 * (`pages/Security.tsx`) author their prose as block arrays and render it
 * through `Block`, so headings, tables, callouts and code samples look the same
 * wherever they appear.
 */

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

function Table({ block }: { block: Extract<DocBlock, { type: "table" }> }) {
  return (
    <div
      className="glass-card"
      style={{
        borderRadius: 12,
        overflowX: "auto",
        margin: "0 0 20px",
      }}
    >
      <table
        style={{
          width: "100%",
          borderCollapse: "collapse",
          fontSize: 13.5,
          minWidth: 520,
        }}
      >
        <thead>
          <tr>
            {block.headers.map((h, i) => (
              <th
                key={i}
                style={{
                  textAlign: "left",
                  padding: "12px 16px",
                  borderBottom: "1px solid rgba(0,212,255,.18)",
                  color: "#67e8f9",
                  fontWeight: 700,
                  whiteSpace: "nowrap",
                }}
              >
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {block.rows.map((row, ri) => (
            <tr key={ri}>
              {row.map((cell, ci) => (
                <td
                  key={ci}
                  style={{
                    padding: "11px 16px",
                    borderBottom: "1px solid rgba(255,255,255,.06)",
                    color: ci === 0 ? "#e2e8f0" : "#cbd5e1",
                    verticalAlign: "top",
                    lineHeight: 1.55,
                    fontFamily:
                      ci === 0 && !block.proseFirstCol
                        ? "ui-monospace,Menlo,monospace"
                        : undefined,
                    fontWeight: ci === 0 && block.proseFirstCol ? 600 : undefined,
                    whiteSpace:
                      ci === 0 && !block.proseFirstCol ? "nowrap" : "normal",
                  }}
                >
                  {renderInline(cell)}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
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

/**
 * A numbered procedure. Steps are rendered with an explicit ordinal rather than
 * an `<ol>` marker so the number can sit in the gutter at a fixed width — a
 * two-digit step must not reflow the prose column relative to a one-digit one.
 */
function Steps({ block }: { block: Extract<DocBlock, { type: "steps" }> }) {
  return (
    <ol
      style={{
        listStyle: "none",
        margin: "0 0 22px",
        padding: 0,
        counterReset: "ax-step",
      }}
    >
      {block.steps.map((step, i) => (
        <li
          key={i}
          style={{
            display: "flex",
            gap: 14,
            alignItems: "flex-start",
            marginBottom: 18,
          }}
        >
          <span
            aria-hidden="true"
            style={{
              flex: "0 0 26px",
              width: 26,
              height: 26,
              borderRadius: "50%",
              border: "1px solid rgba(0,212,255,.35)",
              background: "rgba(0,212,255,.08)",
              color: "#67e8f9",
              font: "600 13px/26px ui-monospace,Menlo,monospace",
              textAlign: "center",
            }}
          >
            {i + 1}
          </span>
          <div style={{ minWidth: 0, flex: 1 }}>
            <div style={{ fontWeight: 700, color: "#e2e8f0", marginBottom: 4 }}>
              {renderInline(step.title)}
            </div>
            <div style={{ color: "#cbd5e1", lineHeight: 1.7, fontSize: 14.5 }}>
              {renderInline(step.body)}
            </div>
            {step.code && (
              <pre
                style={{
                  margin: "10px 0 0",
                  padding: "12px 14px",
                  borderRadius: 10,
                  border: "1px solid rgba(0,212,255,.12)",
                  background: "rgba(0,0,0,.28)",
                  fontSize: 12.5,
                  lineHeight: 1.65,
                  color: "#cbd5e1",
                  overflowX: "auto",
                }}
              >
                {highlightCode(step.code)}
              </pre>
            )}
          </div>
        </li>
      ))}
    </ol>
  );
}

/** Method-badge colours. GET reads, POST creates, DELETE destroys — the badge
 *  is the fastest way to scan an endpoint table, so the palette is by risk. */
const METHOD_COLORS: Record<string, { fg: string; bg: string; border: string }> = {
  GET: { fg: "#67e8f9", bg: "rgba(0,212,255,.10)", border: "rgba(0,212,255,.35)" },
  POST: { fg: "#86efac", bg: "rgba(34,197,94,.10)", border: "rgba(34,197,94,.35)" },
  PUT: { fg: "#fcd34d", bg: "rgba(251,191,36,.10)", border: "rgba(251,191,36,.35)" },
  PATCH: { fg: "#fcd34d", bg: "rgba(251,191,36,.10)", border: "rgba(251,191,36,.35)" },
  DELETE: { fg: "#fca5a5", bg: "rgba(248,113,113,.10)", border: "rgba(248,113,113,.35)" },
};

/** An HTTP endpoint reference list. */
function ApiList({ block }: { block: Extract<DocBlock, { type: "api" }> }) {
  return (
    <div
      className="glass-card"
      style={{ borderRadius: 12, overflow: "hidden", margin: "0 0 20px" }}
    >
      {block.endpoints.map((ep, i) => {
        const c = METHOD_COLORS[ep.method] ?? METHOD_COLORS.GET;
        return (
          <div
            key={i}
            style={{
              display: "flex",
              gap: 12,
              alignItems: "baseline",
              flexWrap: "wrap",
              padding: "11px 16px",
              borderTop: i === 0 ? undefined : "1px solid rgba(255,255,255,.06)",
            }}
          >
            <span
              style={{
                flex: "0 0 auto",
                minWidth: 58,
                textAlign: "center",
                padding: "2px 7px",
                borderRadius: 5,
                border: `1px solid ${c.border}`,
                background: c.bg,
                color: c.fg,
                font: "700 11px ui-monospace,Menlo,monospace",
                letterSpacing: ".04em",
              }}
            >
              {ep.method}
            </span>
            <code
              style={{
                font: "13px ui-monospace,Menlo,monospace",
                color: "#e2e8f0",
                wordBreak: "break-word",
              }}
            >
              {ep.path}
            </code>
            {ep.public && (
              <span
                title="Reachable without an access token"
                style={{
                  padding: "1px 6px",
                  borderRadius: 4,
                  border: "1px solid rgba(168,85,247,.35)",
                  background: "rgba(168,85,247,.08)",
                  color: "#c084fc",
                  font: "600 10px ui-monospace,Menlo,monospace",
                  letterSpacing: ".06em",
                }}
              >
                PUBLIC
              </span>
            )}
            <span
              style={{
                flex: "1 1 240px",
                minWidth: 0,
                fontSize: 13.5,
                color: "#94a3b8",
                lineHeight: 1.55,
              }}
            >
              {renderInline(ep.summary)}
            </span>
          </div>
        );
      })}
    </div>
  );
}

/** One sample in several languages, shown as tabs. */
function CodeGroup({ block }: { block: Extract<DocBlock, { type: "codegroup" }> }) {
  const [active, setActive] = useState(0);
  const tab = block.tabs[active] ?? block.tabs[0];
  return (
    <div
      className="glass-card"
      style={{ borderRadius: 12, overflow: "hidden", margin: "0 0 16px" }}
    >
      <div
        role="tablist"
        aria-label={block.caption ?? "Code samples"}
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 2,
          padding: "6px 8px",
          borderBottom: "1px solid rgba(0,212,255,.12)",
          background: "rgba(255,255,255,.03)",
        }}
      >
        {block.tabs.map((t, i) => (
          <button
            key={t.label}
            role="tab"
            type="button"
            aria-selected={i === active}
            onClick={() => setActive(i)}
            style={{
              padding: "5px 12px",
              borderRadius: 7,
              border: "1px solid transparent",
              background: i === active ? "rgba(0,212,255,.12)" : "transparent",
              borderColor: i === active ? "rgba(0,212,255,.3)" : "transparent",
              color: i === active ? "#67e8f9" : "#94a3b8",
              font: "600 12px ui-monospace,Menlo,monospace",
              cursor: "pointer",
            }}
          >
            {t.label}
          </button>
        ))}
        {block.caption && (
          <span
            style={{
              marginLeft: "auto",
              alignSelf: "center",
              font: "12px ui-monospace,Menlo,monospace",
              color: "#64748b",
            }}
          >
            {block.caption}
          </span>
        )}
      </div>
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
        {highlightCode(tab.code)}
      </pre>
    </div>
  );
}

export default function Block({
  block,
  go,
}: {
  block: DocBlock;
  go: (p: Page) => void;
}) {
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
    case "table":
      return <Table block={block} />;
    case "note":
      return <Callout kind="note" text={block.text} />;
    case "warn":
      return <Callout kind="warn" text={block.text} />;
    case "links":
      return (
        <ul
          style={{
            margin: "0 0 16px",
            paddingLeft: 22,
            color: "#94a3b8",
            lineHeight: 1.7,
            fontSize: 14,
          }}
        >
          {block.links.map((link) => (
            <li key={link.href} style={{ marginBottom: 6 }}>
              <a href={link.href} target="_blank" rel="noreferrer">
                {renderInline(link.label)}
              </a>
              {link.note && <span> — {renderInline(link.note)}</span>}
            </li>
          ))}
        </ul>
      );
    case "steps":
      return <Steps block={block} />;
    case "api":
      return <ApiList block={block} />;
    case "codegroup":
      return <CodeGroup block={block} />;
    case "cards":
      return (
        <div className="ax-grid-2" style={{ gap: 14 }}>
          {block.cards.map((c, i) => (
            <div
              key={i}
              className="glass-card ax-lift"
              style={{ padding: 18, cursor: "pointer" }}
              onClick={() => {
                // Set the hash first: the docs section is hash-routed, so this
                // is what selects the page once the section is on screen.
                if (c.doc) window.location.hash = `#/docs/${c.doc}`;
                go(c.to);
              }}
            >
              <div style={{ fontWeight: 700, marginBottom: 4 }}>{c.title}</div>
              <div style={{ fontSize: 13, color: "#94a3b8" }}>{c.body}</div>
            </div>
          ))}
        </div>
      );
  }
}

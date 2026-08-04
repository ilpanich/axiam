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

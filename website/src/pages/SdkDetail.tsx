import type { Page, Sdk } from "../types";

interface SdkDetailProps {
  sdk: Sdk;
  go: (page: Page) => void;
}

const dot = (background: string) => (
  <span style={{ width: 11, height: 11, borderRadius: "50%", background }} />
);

/** A macOS-style "terminal" card with a labelled title bar and a code body. */
function TerminalCard({ label, code }: { label: string; code: string }) {
  return (
    <div
      className="glass-card"
      style={{
        borderRadius: 14,
        overflow: "hidden",
        border: "1px solid rgba(0,212,255,.2)",
      }}
    >
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          padding: "13px 18px",
          borderBottom: "1px solid rgba(0,212,255,.12)",
          background: "rgba(255,255,255,.03)",
        }}
      >
        {dot("#ff5f56")}
        {dot("#ffbd2e")}
        {dot("#27c93f")}
        <span
          style={{
            marginLeft: 8,
            font: "12px ui-monospace,Menlo,monospace",
            color: "#94a3b8",
          }}
        >
          {label}
        </span>
      </div>
      <pre
        style={{
          margin: 0,
          padding: 22,
          fontSize: 13.5,
          lineHeight: 1.75,
          color: "#cbd5e1",
          overflow: "auto",
        }}
      >
        {code}
      </pre>
    </div>
  );
}

export default function SdkDetail({ sdk, go }: SdkDetailProps) {
  return (
    <div style={{ maxWidth: 1000, margin: "0 auto", padding: "40px 40px 90px" }}>
      <button
        className="ax-navlink"
        onClick={() => go("sdks")}
        style={{
          marginBottom: 22,
          display: "inline-flex",
          alignItems: "center",
          gap: 6,
          background: "none",
          border: "none",
        }}
      >
        ← All SDKs
      </button>

      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 16,
          marginBottom: 12,
        }}
      >
        <div
          style={{
            width: 52,
            height: 52,
            borderRadius: 12,
            background: "rgba(0,212,255,.1)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontWeight: 800,
            color: "#00d4ff",
            fontSize: 19,
          }}
        >
          {sdk.abbr}
        </div>
        <div>
          <h1
            style={{
              margin: 0,
              fontSize: "clamp(28px, 6vw, 38px)",
              fontWeight: 800,
            }}
          >
            {sdk.name} SDK
          </h1>
          <div
            style={{
              fontSize: 14,
              color: "#64748b",
              fontFamily: "ui-monospace,Menlo,monospace",
            }}
          >
            {sdk.pkg}
          </div>
        </div>
      </div>

      <p
        style={{
          fontSize: 17,
          color: "#94a3b8",
          maxWidth: 660,
          margin: "0 0 22px",
        }}
      >
        {sdk.blurb}
      </p>

      <div
        style={{ display: "flex", gap: 12, marginBottom: 40, flexWrap: "wrap" }}
      >
        <a
          className="ax-ghost"
          href={sdk.registryUrl}
          target="_blank"
          rel="noreferrer"
        >
          {sdk.registry} ↗
        </a>
        {sdk.docsUrl && (
          <a
            className="ax-ghost"
            href={sdk.docsUrl}
            target="_blank"
            rel="noreferrer"
          >
            {sdk.docsLabel} docs ↗
          </a>
        )}
        <a
          className="ax-ghost"
          href={sdk.repoUrl}
          target="_blank"
          rel="noreferrer"
        >
          Repository ↗
        </a>
        <a
          className="ax-ghost"
          href={sdk.examplesUrl}
          target="_blank"
          rel="noreferrer"
        >
          Examples ↗
        </a>
      </div>

      <div style={{ marginBottom: 24 }} className="ax-grid-2">
        <div className="glass-card" style={{ padding: 24 }}>
          <h3
            style={{
              margin: "0 0 14px",
              fontSize: 15,
              textTransform: "uppercase",
              letterSpacing: ".1em",
              color: "#67e8f9",
            }}
          >
            Install
          </h3>
          <code
            style={{
              display: "block",
              fontSize: 13.5,
              color: "#e2e8f0",
              background: "rgba(0,0,0,.3)",
              border: "1px solid rgba(0,212,255,.14)",
              borderRadius: 8,
              padding: 14,
              fontFamily: "ui-monospace,Menlo,monospace",
              overflow: "auto",
            }}
          >
            {sdk.install}
          </code>
        </div>
        <div className="glass-card" style={{ padding: 24 }}>
          <h3
            style={{
              margin: "0 0 14px",
              fontSize: 15,
              textTransform: "uppercase",
              letterSpacing: ".1em",
              color: "#67e8f9",
            }}
          >
            Highlights
          </h3>
          <div
            style={{ display: "flex", flexDirection: "column", gap: 10 }}
          >
            {sdk.highlights.map((h) => (
              <div
                key={h}
                style={{
                  display: "flex",
                  gap: 9,
                  alignItems: "flex-start",
                  fontSize: 14,
                  color: "#cbd5e1",
                }}
              >
                <span style={{ color: "#00d4ff", marginTop: 1 }}>✓</span>
                {h}
              </div>
            ))}
          </div>
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
        <TerminalCard label={`quickstart · ${sdk.name}`} code={sdk.quickstart} />
        <TerminalCard
          label={`${sdk.guardLabel} · ${sdk.name}`}
          code={sdk.guardExample}
        />
      </div>
    </div>
  );
}

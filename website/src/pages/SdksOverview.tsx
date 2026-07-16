import { SDKS } from "../data";

interface SdksOverviewProps {
  openSdk: (id: string) => void;
}

export default function SdksOverview({ openSdk }: SdksOverviewProps) {
  return (
    <div style={{ maxWidth: 1180, margin: "0 auto", padding: "56px 40px 90px" }}>
      <div style={{ marginBottom: 38 }}>
        <span
          className="ax-pill"
          style={{
            border: "1px solid rgba(0,212,255,.3)",
            color: "#67e8f9",
            padding: "5px 13px",
          }}
        >
          Client SDKs
        </span>
        <h1
          style={{
            margin: "16px 0 10px",
            fontSize: "clamp(32px, 6vw, 46px)",
            fontWeight: 800,
            letterSpacing: "-.02em",
          }}
        >
          Talk to AXIAM in your language
        </h1>
        <p style={{ margin: 0, fontSize: 17, color: "#94a3b8", maxWidth: 680 }}>
          Seven official SDKs conform to a single behavioral contract (§1–§11) —
          login &amp; MFA, REST/gRPC/AMQP authorization, and framework guards.
          Pick a language to see the quickstart.
        </p>
      </div>
      <div className="ax-grid-3">
        {SDKS.map((s) => (
          <div
            key={s.id}
            className="glass-card ax-lift"
            style={{
              padding: 24,
              display: "flex",
              flexDirection: "column",
              gap: 14,
              cursor: "pointer",
            }}
            onClick={() => openSdk(s.id)}
          >
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
              }}
            >
              <div
                style={{ display: "flex", alignItems: "center", gap: 11 }}
              >
                <div
                  style={{
                    width: 38,
                    height: 38,
                    borderRadius: 9,
                    background: "rgba(0,212,255,.1)",
                    display: "flex",
                    alignItems: "center",
                    justifyContent: "center",
                    fontWeight: 800,
                    color: "#00d4ff",
                    fontSize: 15,
                  }}
                >
                  {s.abbr}
                </div>
                <span style={{ fontSize: 19, fontWeight: 700 }}>{s.name}</span>
              </div>
              <span
                className="ax-pill"
                style={{
                  background: "rgba(168,85,247,.12)",
                  border: "1px solid rgba(168,85,247,.3)",
                  color: "#c084fc",
                  padding: "3px 10px",
                  fontSize: 11,
                }}
              >
                {s.registry}
              </span>
            </div>
            <p
              style={{
                margin: 0,
                fontSize: 13.5,
                lineHeight: 1.5,
                color: "#94a3b8",
                minHeight: 40,
              }}
            >
              {s.blurb}
            </p>
            <code
              style={{
                fontSize: 12.5,
                color: "#67e8f9",
                background: "rgba(0,0,0,.28)",
                border: "1px solid rgba(0,212,255,.14)",
                borderRadius: 8,
                padding: "9px 12px",
                fontFamily: "ui-monospace,Menlo,monospace",
                overflow: "auto",
              }}
            >
              {s.install}
            </code>
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                marginTop: 2,
              }}
            >
              <span
                style={{
                  fontSize: 12.5,
                  color: "#64748b",
                  fontFamily: "ui-monospace,Menlo,monospace",
                }}
              >
                {s.pkg}
              </span>
              <span
                style={{ color: "#67e8f9", fontSize: 13, fontWeight: 600 }}
              >
                View SDK →
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

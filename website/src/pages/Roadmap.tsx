import { PHASES } from "../data";

export default function Roadmap() {
  return (
    <div style={{ maxWidth: 900, margin: "0 auto", padding: "56px 40px 90px" }}>
      <span
        className="ax-pill"
        style={{
          border: "1px solid rgba(0,212,255,.3)",
          color: "#67e8f9",
          padding: "5px 13px",
        }}
      >
        Roadmap
      </span>
      <h1
        style={{
          margin: "16px 0 10px",
          fontSize: "clamp(32px, 6vw, 46px)",
          fontWeight: 800,
          letterSpacing: "-.02em",
        }}
      >
        64 tasks. 19 phases.
      </h1>
      <p style={{ margin: "0 0 14px", fontSize: 17, color: "#94a3b8", maxWidth: 640 }}>
        A structured path from project foundation to a security-audited,
        SDK-complete platform. AXIAM remains a work in progress until a stable
        release.
      </p>
      <div style={{ display: "flex", gap: 22, marginBottom: 40 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 8,
            fontSize: 14,
            color: "#94a3b8",
          }}
        >
          <span
            style={{
              width: 10,
              height: 10,
              borderRadius: "50%",
              background: "#27c93f",
              boxShadow: "0 0 8px #27c93f",
            }}
          />
          Done
        </div>
      </div>
      <div style={{ position: "relative", paddingLeft: 26 }}>
        <div
          style={{
            position: "absolute",
            left: 5,
            top: 6,
            bottom: 6,
            width: 2,
            background: "linear-gradient(#00d4ff,#a855f7)",
          }}
        />
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {PHASES.map((ph) => (
            <div key={ph.n} style={{ position: "relative" }}>
              <div
                style={{
                  position: "absolute",
                  left: -25,
                  top: 20,
                  width: 12,
                  height: 12,
                  borderRadius: "50%",
                  background: "#0d0d2b",
                  border: "2px solid #27c93f",
                  boxShadow: "0 0 8px rgba(39,201,63,.6)",
                }}
              />
              <div
                className="glass-card ax-lift"
                style={{
                  padding: "16px 22px",
                  display: "flex",
                  alignItems: "center",
                  gap: 18,
                }}
              >
                <div
                  style={{
                    flex: "none",
                    fontSize: 12,
                    fontWeight: 700,
                    color: "#64748b",
                    width: 64,
                    fontFamily: "ui-monospace,Menlo,monospace",
                  }}
                >
                  Phase {ph.n}
                </div>
                <div style={{ flex: 1 }}>
                  <div
                    style={{ fontSize: 15.5, fontWeight: 700, color: "#f8fafc" }}
                  >
                    {ph.title}
                  </div>
                  <div style={{ fontSize: 13, color: "#94a3b8", marginTop: 2 }}>
                    {ph.focus}
                  </div>
                </div>
                <span
                  className="ax-pill"
                  style={{
                    flex: "none",
                    background: "rgba(39,201,63,.12)",
                    border: "1px solid rgba(39,201,63,.35)",
                    color: "#5ee688",
                    padding: "4px 12px",
                    fontSize: 11.5,
                  }}
                >
                  Done
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

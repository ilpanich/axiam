import { BENCH } from "../data";

const CARDS = [
  {
    label: "Performance",
    labelColor: "#67e8f9",
    value: "<1 ms",
    valueColor: "#00d4ff",
    sub: "authz decision p99",
    body: "Throughput and latency under sustained load.",
  },
  {
    label: "Efficiency",
    labelColor: "#67e8f9",
    value: "per core",
    valueColor: "#00d4ff",
    sub: "throughput / CPU & / GiB",
    body: "Competitor-level performance at a smaller footprint?",
  },
  {
    label: "Security posture",
    labelColor: "#c084fc",
    value: "HTTP → mTLS",
    valueColor: "#a855f7",
    sub: "same workload, replayed",
    body: "Quantifying what each security tier costs.",
  },
];

export default function Benchmarks() {
  return (
    <div style={{ maxWidth: 1100, margin: "0 auto", padding: "56px 40px 90px" }}>
      <span
        className="ax-pill"
        style={{
          border: "1px solid rgba(0,212,255,.3)",
          color: "#67e8f9",
          padding: "5px 13px",
        }}
      >
        Benchmarks
      </span>
      <h1
        style={{
          margin: "16px 0 10px",
          fontSize: "clamp(32px, 6vw, 46px)",
          fontWeight: 800,
          letterSpacing: "-.02em",
        }}
      >
        Measured on equal footing
      </h1>
      <p style={{ margin: "0 0 24px", fontSize: 17, color: "#94a3b8", maxWidth: 720 }}>
        A vendor-neutral framework drives standard OAuth2/OIDC flows through a
        per-target adapter, comparing AXIAM against other open-source IAM systems
        across three axes.
      </p>

      {/* ---- Draft notice ---- */}
      <div
        className="glass-card"
        style={{
          padding: "18px 22px",
          borderColor: "rgba(255,189,46,.4)",
          background: "rgba(255,189,46,.08)",
          display: "flex",
          gap: 14,
          alignItems: "flex-start",
          marginBottom: 44,
        }}
      >
        <span style={{ fontSize: 20, lineHeight: 1 }} aria-hidden="true">
          ⚠️
        </span>
        <div>
          <div
            style={{
              fontSize: 15,
              fontWeight: 700,
              color: "#ffd98a",
              marginBottom: 4,
            }}
          >
            Draft — placeholder figures
          </div>
          <p style={{ margin: 0, fontSize: 14, lineHeight: 1.65, color: "#e2e8f0" }}>
            This section is currently a <strong>draft</strong>. The numbers below
            are illustrative placeholders for layout only — they are{" "}
            <strong>not measured results</strong>. Real benchmark results will be
            published here once the benchmarks have been performed.
          </p>
        </div>
      </div>

      <div style={{ marginBottom: 44 }} className="ax-grid-3">

        {CARDS.map((c) => (
          <div key={c.label} className="glass-card ax-lift" style={{ padding: 26 }}>
            <div
              style={{
                fontSize: 13,
                textTransform: "uppercase",
                letterSpacing: ".12em",
                color: c.labelColor,
                marginBottom: 14,
              }}
            >
              {c.label}
            </div>
            <div style={{ fontSize: 34, fontWeight: 800, color: c.valueColor }}>
              {c.value}
            </div>
            <div style={{ fontSize: 13, color: "#94a3b8", marginTop: 2 }}>
              {c.sub}
            </div>
            <p
              style={{
                margin: "14px 0 0",
                fontSize: 13.5,
                lineHeight: 1.55,
                color: "#94a3b8",
              }}
            >
              {c.body}
            </p>
          </div>
        ))}
      </div>

      <div className="glass-card" style={{ padding: 32 }}>
        <div
          style={{
            display: "flex",
            alignItems: "baseline",
            justifyContent: "space-between",
            marginBottom: 24,
            gap: 12,
            flexWrap: "wrap",
          }}
        >
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 700 }}>
            Relative throughput per CPU core
          </h2>
          <span
            className="ax-pill"
            style={{
              border: "1px solid rgba(255,189,46,.4)",
              background: "rgba(255,189,46,.08)",
              color: "#ffd98a",
              padding: "4px 12px",
              fontSize: 12,
            }}
          >
            Draft · placeholder data
          </span>
        </div>
        <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
          {BENCH.map((row) => (
            <div
              key={row.name}
              style={{ display: "flex", alignItems: "center", gap: 16 }}
            >
              <div
                style={{
                  width: 110,
                  flex: "none",
                  fontSize: 14,
                  color: "#e2e8f0",
                  fontWeight: 600,
                }}
              >
                {row.name}
              </div>
              <div
                style={{
                  flex: 1,
                  height: 22,
                  background: "rgba(255,255,255,.05)",
                  borderRadius: 6,
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: row.width,
                    background: row.fill,
                    borderRadius: 6,
                  }}
                />
              </div>
              <div
                style={{
                  width: 70,
                  flex: "none",
                  textAlign: "right",
                  fontSize: 14,
                  color: "#94a3b8",
                  fontFamily: "ui-monospace,Menlo,monospace",
                }}
              >
                {row.value}
              </div>
            </div>
          ))}
        </div>
        <p
          style={{
            margin: "24px 0 0",
            fontSize: 13,
            color: "#64748b",
            lineHeight: 1.6,
            borderTop: "1px solid rgba(0,212,255,.1)",
            paddingTop: 18,
          }}
        >
          Numbers shown are placeholders for layout and will be replaced with
          measured results after the benchmark runs. The real harness reports
          throughput/latency, throughput-per-core and throughput-per-GiB, plus
          the plaintext-HTTP-to-mTLS security cost ladder. See{" "}
          <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
            benchmarks/docs/methodology.md
          </code>
          .
        </p>
      </div>
    </div>
  );
}

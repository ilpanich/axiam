import type { ReactNode } from "react";
import type { BenchScenario } from "../types";
import {
  BENCH_SCENARIOS,
  BENCH_AUTHZ,
  BENCH_EFFICIENCY,
} from "../data";

/* ---- shared bits ------------------------------------------------------- */

const AXIAM_FILL = "linear-gradient(90deg,#00d4ff,#a855f7)";
const OTHER_FILL = "rgba(148,163,184,.4)";

function Pill({
  color,
  border,
  bg,
  children,
}: {
  color: string;
  border: string;
  bg?: string;
  children: ReactNode;
}) {
  return (
    <span
      className="ax-pill"
      style={{
        border: `1px solid ${border}`,
        background: bg,
        color,
        padding: "4px 12px",
        fontSize: 12,
      }}
    >
      {children}
    </span>
  );
}

function SectionTitle({ kicker, title }: { kicker: string; title: string }) {
  return (
    <div style={{ marginBottom: 18 }}>
      <div
        style={{
          fontSize: 12,
          textTransform: "uppercase",
          letterSpacing: ".14em",
          color: "#67e8f9",
          marginBottom: 8,
        }}
      >
        {kicker}
      </div>
      <h2 style={{ margin: 0, fontSize: 24, fontWeight: 800, letterSpacing: "-.01em" }}>
        {title}
      </h2>
    </div>
  );
}

/** Horizontal bar chart for one scenario; bar length ∝ throughput. */
function BarChart({ scenario }: { scenario: BenchScenario }) {
  const max = Math.max(...scenario.bars.map((b) => b.value));
  return (
    <div className="glass-card" style={{ padding: 26 }}>
      <div
        style={{
          display: "flex",
          alignItems: "baseline",
          justifyContent: "space-between",
          gap: 12,
          flexWrap: "wrap",
          marginBottom: 4,
        }}
      >
        <h3 style={{ margin: 0, fontSize: 17, fontWeight: 700 }}>{scenario.title}</h3>
      </div>
      <div style={{ fontSize: 12.5, color: "#64748b", marginBottom: 20 }}>
        {scenario.unit}
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {scenario.bars.map((bar) => (
          <div key={bar.target} style={{ display: "flex", alignItems: "center", gap: 14 }}>
            <div
              style={{
                width: 116,
                flex: "none",
                fontSize: 13.5,
                color: bar.axiam ? "#e2e8f0" : "#94a3b8",
                fontWeight: bar.axiam ? 700 : 500,
              }}
            >
              {bar.target}
            </div>
            <div
              style={{
                flex: 1,
                height: 24,
                background: "rgba(255,255,255,.05)",
                borderRadius: 6,
                overflow: "hidden",
                minWidth: 40,
              }}
            >
              <div
                style={{
                  height: "100%",
                  width: `${Math.max((bar.value / max) * 100, 2)}%`,
                  background: bar.axiam ? AXIAM_FILL : OTHER_FILL,
                  borderRadius: 6,
                  transition: "width .3s",
                }}
              />
            </div>
            <div
              style={{
                width: 74,
                flex: "none",
                textAlign: "right",
                fontSize: 14,
                color: bar.axiam ? "#67e8f9" : "#94a3b8",
                fontWeight: bar.axiam ? 700 : 500,
                fontFamily: "ui-monospace,Menlo,monospace",
              }}
            >
              {bar.display}
            </div>
          </div>
        ))}
      </div>
      <p
        style={{
          margin: "20px 0 0",
          fontSize: 13,
          color: "#94a3b8",
          lineHeight: 1.6,
          borderTop: "1px solid rgba(0,212,255,.1)",
          paddingTop: 16,
        }}
      >
        {scenario.takeaway}
      </p>
    </div>
  );
}

/* ---- headline stat cards ---------------------------------------------- */

const HEADLINES = [
  {
    label: "Token issuance",
    value: "4.3–5.2×",
    sub: "more tokens/s than Zitadel / Keycloak — median of 3 runs, ±0.1%",
  },
  {
    label: "JWKS fetch",
    value: "27,784",
    sub: "req/s — 7–13× the field (server not even saturated)",
  },
  {
    label: "Native mTLS",
    value: "≈ 0 cost",
    sub: "client-certificate TLS 1.3 verified in-process, at parity with plain TLS on every scenario",
  },
];

/* ---- environment facts ------------------------------------------------- */

const TARGETS = [
  ["AXIAM", "axiam-server 1.0.0-alpha19 (Rust, pulled release image, digest-recorded)", "SurrealDB v3 + RabbitMQ 4"],
  ["Keycloak", "Keycloak 26.7.0 (JVM)", "PostgreSQL 16 (uniformly tuned)"],
  ["Zitadel", "Zitadel v4.15.2 (Go)", "PostgreSQL 16 (uniformly tuned)"],
];

/* ---- sensitivity highlights -------------------------------------------- */

const SENSITIVITY = [
  {
    title: "Native mTLS is free",
    body: "The p3 profile terminates client-certificate TLS 1.3 inside the server process — no proxy in front, the verified peer certificate is the identity source — and lands at parity with plain TLS 1.3 across the entire matrix (token issuance 903.6 vs 903 req/s, userinfo 4,826 vs 4,822, …). For IoT and service-mesh fleets, certificate verification costs nothing measurable on top of TLS.",
  },
  {
    title: "The decision cache is worth 3×",
    body: "With the optional per-tenant authorization decision cache enabled (5 s TTL, event-driven invalidation), single checks go from 737 to 2,322 req/s over REST and 603 to 1,822 req/s over gRPC on the same capped hardware, and the database stops being saturated. The benchmark's hit rate is favorable; a hit-rate sweep is queued before the default changes.",
  },
  {
    title: "Where each product hits its wall",
    body: "With every database uncapped to 4 CPUs: Keycloak doesn't move at all (its server is the wall in every cell), Zitadel gains 70–85% on reads (Postgres saturates even at 4 cores), and AXIAM's authz/userinfo paths scale with DB CPU (+37% / +49%) while its token endpoints don't need the DB at all. AXIAM's server saturated for the first time at 7,457 userinfo req/s.",
  },
  {
    title: "Shipped rate limits, measured",
    body: "One pass ran AXIAM with its production per-IP rate limits active: a 50-user single-IP load generator is throttled to near-zero on every limited endpoint — the defaults do exactly what they ship for (blunting single-source abuse), and the competitors ship no equivalent defaults. It also showed those defaults must be re-keyed and resized for machine-to-machine fleets — see the new sizing guide in the docs.",
  },
];

const CAVEATS = [
  {
    title: "TLS 1.3 still halves token issuance",
    body: "Client-credentials throughput drops 50.5% at p2 (introspection −0.2%, userinfo −3.7%, login ~0%). Telemetry shows the handshake is ~free (resumption works); everything points at a connection-level ceiling — 50 users funnelled through multiplexed HTTP/2 — not crypto. The HTTP/1.1 isolation cell we queued for this run was invalidated by the measurement artifact below and is re-queued. Even with the penalty, AXIAM's TLS token numbers lead the field 2.2–2.6×.",
  },
  {
    title: "Correction: the batch verdict was a measurement artifact",
    body: "Earlier drafts reported the authz batch endpoints as slower than single checks. Run 3 found why: for ~5–7 minutes after a stack is seeded, the database serves everything through a ~45 req/s serialization window — and the batch cells had always run first. A batch cell measured on a settled stack reaches 852 batches/s (≈4,260 checks/s), i.e. batch outperforms singles as designed. All batch numbers are withdrawn until the corrected protocol re-measures them; the transient itself is under investigation, including whether it can affect production cold-starts.",
  },
  {
    title: "The refresh comparison is partially restored",
    body: "Keycloak's refresh cells now measure real single-use rotation (379 req/s at p0). AXIAM's own refresh cells still measure a fallback — a harness cookie-handling bug the fallback tagging keeps catching, fix queued — and stay excluded. Zitadel's refresh needs an offline_access flow the harness doesn't implement yet.",
  },
  {
    title: "Median-of-3 now, but still a laptop",
    body: "Every matrix cell is the median of three runs (observed spread ±0.1–2.8%, so deltas above ~5% are signal), on a digest-pinned release image. The hardware is still a consumer laptop (Dell XPS 15, i7-8750H) with per-cell CPU-frequency and temperature telemetry published; the thermal envelope was identical for all targets, so cross-target fairness holds and absolute numbers are, if anything, conservative. Memory figures for cells after the login burst include ~360 MiB of retained allocator memory (a scripted allocator experiment is scheduled).",
  },
];

const NEXT = [
  "A post-seed settle gate + rotated cell order in the harness",
  "Clean batch A/B (concurrent vs coalesced) under the corrected protocol",
  "The TLS + HTTP/1.1 isolation cell, re-run on a settled stack",
  "The AXIAM refresh-scenario harness fix",
  "The allocator (jemalloc) A/B for post-burst memory retention",
  "SDK client-side overhead tables (all 7 primary SDKs)",
  "A server-class re-run to replace the laptop numbers",
];

/* ---- page -------------------------------------------------------------- */

export default function Benchmarks() {
  return (
    <div style={{ maxWidth: 1000, margin: "0 auto", padding: "56px 40px 90px" }}>
      <Pill color="#67e8f9" border="rgba(0,212,255,.3)">
        Benchmarks
      </Pill>
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
        A vendor-neutral harness drives the identical logical workload through a
        per-target adapter, comparing AXIAM against Keycloak and Zitadel across
        OAuth2/OIDC flows. Below are the run-3 results — the first median-of-3
        figures, on the digest-pinned release image.
      </p>

      {/* ---- Preliminary banner ---- */}
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
            style={{ fontSize: 15, fontWeight: 700, color: "#ffd98a", marginBottom: 4 }}
          >
            Temporary results — the benchmark is still being improved
          </div>
          <p style={{ margin: 0, fontSize: 14, lineHeight: 1.65, color: "#e2e8f0" }}>
            These numbers come from run 3 (2026-07-25/26, AXIAM&nbsp;1.0.0-alpha19,
            digest-pinned release image) and are the first{" "}
            <strong>median-of-3</strong> figures — run-to-run spread was
            ±0.1–2.8% per cell, so they are statistically solid. They are still
            temporary: the harness is being improved (a measurement-order
            artifact found this run forced us to withdraw the batch and one TLS
            diagnosis cell — see the honesty section), and everything still runs
            on a consumer laptop rather than server-class hardware. Treat them as
            a strong, reproducible signal, not a final verdict; this page is
            updated as each improved run lands.
          </p>
        </div>
      </div>

      {/* ---- Headline numbers ---- */}
      <div style={{ marginBottom: 52 }} className="ax-grid-3">
        {HEADLINES.map((h) => (
          <div key={h.label} className="glass-card ax-lift" style={{ padding: 24 }}>
            <div
              style={{
                fontSize: 12,
                textTransform: "uppercase",
                letterSpacing: ".12em",
                color: "#67e8f9",
                marginBottom: 12,
              }}
            >
              {h.label}
            </div>
            <div style={{ fontSize: 30, fontWeight: 800, color: "#00d4ff" }}>
              {h.value}
            </div>
            <p style={{ margin: "8px 0 0", fontSize: 13, lineHeight: 1.5, color: "#94a3b8" }}>
              {h.sub}
            </p>
          </div>
        ))}
      </div>

      {/* ---- How it's designed ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Method" title="How the benchmark is designed" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760 }}>
          Three open-source IAM servers are driven with the <em>identical logical
          workload</em> through a vendor-neutral{" "}
          <a
            href="https://k6.io"
            target="_blank"
            rel="noreferrer"
            style={{ color: "#67e8f9" }}
          >
            k6
          </a>{" "}
          harness. A thin adapter layer per target isolates the only thing that
          legitimately differs between vendors — the exact endpoint paths and
          request shapes — so the work each server performs for a given scenario
          is the same. Scenarios cover the OAuth2/OIDC surface: machine-to-machine
          token issuance, introspection, JWKS, userinfo and password login.
        </p>
        <div className="glass-card" style={{ padding: 4, marginTop: 20, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5, minWidth: 480 }}>
            <thead>
              <tr>
                {["Target", "Server", "Datastore"].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "12px 16px",
                      borderBottom: "1px solid rgba(0,212,255,.18)",
                      color: "#67e8f9",
                      fontWeight: 700,
                    }}
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {TARGETS.map((row) => (
                <tr key={row[0]}>
                  {row.map((cell, ci) => (
                    <td
                      key={ci}
                      style={{
                        padding: "11px 16px",
                        borderBottom: "1px solid rgba(255,255,255,.06)",
                        color: ci === 0 ? "#e2e8f0" : "#cbd5e1",
                        fontWeight: ci === 0 ? 700 : 400,
                      }}
                    >
                      {cell}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* ---- How it's run ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Setup" title="How it was run — on a PC" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760 }}>
          Everything ran on a single consumer laptop (Dell XPS 15 9570 — Intel
          i7-8750H, 12 logical CPUs, ~31&nbsp;GiB RAM), with the CPU governor
          pinned to <code style={{ color: "#67e8f9" }}>performance</code> and the
          targets benchmarked sequentially, never concurrently. Each server and
          its database run in containers capped identically at 2 CPUs and
          1024&nbsp;MiB, so no target can buy throughput with extra hardware.
        </p>
        <div className="ax-grid-2" style={{ marginTop: 20, gap: 14 }}>
          {[
            ["Load model", "Closed-loop, 50 virtual users. 30 s warm-up + 120 s measured window per scenario — repeated 3×, median reported."],
            ["Profiles", "p0-plaintext and p2-tls13 (TLS 1.3, terminated in-process by all three targets, gRPC included) — plus a labeled p3-mTLS pass for AXIAM."],
            ["Validity gates", "A cell counts only if error rate ≤ 1% and p95 < 2000 ms. Failing cells are labelled, never charted as a head-to-head."],
            ["Container caps", "IAM server 2 CPU / 1 GiB · database 2 CPU / 1 GiB · RabbitMQ (AXIAM only) 1 CPU / 512 MiB."],
          ].map(([t, b]) => (
            <div key={t} className="glass-card" style={{ padding: 20 }}>
              <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 6, color: "#e2e8f0" }}>
                {t}
              </div>
              <div style={{ fontSize: 13.5, color: "#94a3b8", lineHeight: 1.6 }}>{b}</div>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Fairness ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Fairness" title="Keeping it fair" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760, marginBottom: 16 }}>
          Comparing different systems fairly is the hard part, so the data is
          collected to remove every advantage we can find:
        </p>
        <ul style={{ margin: 0, paddingLeft: 22, color: "#cbd5e1", lineHeight: 1.75, maxWidth: 760 }}>
          <li style={{ marginBottom: 8 }}>
            <strong>Identical envelope.</strong> Same host, same container caps,
            same 50-VU closed loop and measurement window for every target —
            and every matrix cell is the median of three runs.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Provenance recorded.</strong> Every container in every cell
            records its image digest; AXIAM ran from the published, digest-pinned
            release image — so improvements between runs are attributable to a
            known binary.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Competitors tuned, not hobbled.</strong> PostgreSQL is
            minimally and <em>uniformly</em> tuned for both Keycloak and Zitadel;
            SurrealDB runs stock. AXIAM's own per-IP rate limits are neutralized so
            they don't cap the load generator.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Telemetry recorded.</strong> Every cell logs host CPU
            frequency, package temperature and load-generator CPU at 1-second
            resolution, published with the raw data — so thermal throttling and a
            saturated generator are visible rather than hidden.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Only valid cells count.</strong> Fallback operations and cells
            that breach a validity gate are labelled and excluded from every
            head-to-head claim — including AXIAM's own.
          </li>
        </ul>
      </section>

      {/* ---- Headline results ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Results" title="Head-to-head throughput" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 22 }}>
          Plaintext (p0) profile, capped matrix, median of three runs. Higher is
          better. Each chart is a valid, comparable cell from the full result
          matrix.
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {BENCH_SCENARIOS.map((s) => (
            <BarChart key={s.id} scenario={s} />
          ))}
        </div>
      </section>

      {/* ---- Efficiency ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Efficiency" title="Throughput per core & CPU cost" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 20 }}>
          Whole-stack, plaintext. AXIAM's figures still carry its audit broker and,
          on some cells, a saturated database — which is exactly why Keycloak edges
          it on userinfo CPU cost. Reported plainly.
        </p>
        <div className="glass-card" style={{ padding: 4, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5, minWidth: 560 }}>
            <thead>
              <tr>
                {["Scenario", "req/s per core (higher better)", "cpu·ms/req (lower better)"].map(
                  (h) => (
                    <th
                      key={h}
                      style={{
                        textAlign: "left",
                        padding: "12px 16px",
                        borderBottom: "1px solid rgba(0,212,255,.18)",
                        color: "#67e8f9",
                        fontWeight: 700,
                      }}
                    >
                      {h}
                    </th>
                  ),
                )}
              </tr>
            </thead>
            <tbody>
              {BENCH_EFFICIENCY.map((row) => (
                <tr key={row.scenario}>
                  <td
                    style={{
                      padding: "11px 16px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      color: "#e2e8f0",
                      fontWeight: 600,
                    }}
                  >
                    {row.scenario}
                  </td>
                  <td
                    style={{
                      padding: "11px 16px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      color: "#cbd5e1",
                      fontFamily: "ui-monospace,Menlo,monospace",
                    }}
                  >
                    <span style={{ color: "#67e8f9", fontWeight: 700 }}>{row.perCore[0]}</span>
                    {" · "}
                    {row.perCore[1]} · {row.perCore[2]}
                  </td>
                  <td
                    style={{
                      padding: "11px 16px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      color: "#cbd5e1",
                      fontFamily: "ui-monospace,Menlo,monospace",
                    }}
                  >
                    <span style={{ color: "#67e8f9", fontWeight: 700 }}>{row.cpuMs[0]}</span>
                    {" · "}
                    {row.cpuMs[1]} · {row.cpuMs[2]}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p style={{ margin: "12px 4px 0", fontSize: 12.5, color: "#64748b" }}>
          Each cell reads <span style={{ color: "#67e8f9" }}>AXIAM</span> · Keycloak · Zitadel.
        </p>
      </section>

      {/* ---- AXIAM-only authz ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="AXIAM-only" title="Authorization decisions" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 22 }}>
          No head-to-head here — Keycloak and Zitadel expose no equivalent decision
          endpoint. Each check is a full RBAC evaluation (tenant-scoped roles,
          resource hierarchy, scopes) against live data, over REST and gRPC. The
          cache-ON rows are a labeled sensitivity pass, not the default
          configuration; batch numbers are withdrawn pending re-measurement (see
          the honesty section).
        </p>
        <BarChart scenario={BENCH_AUTHZ} />
      </section>

      {/* ---- Sensitivity ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Sensitivity" title="What the labeled passes showed" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 20 }}>
          Beyond the head-to-head matrix, run 3 added labeled single-variable
          passes — never mixed into the comparison tables — to find each
          system's walls and AXIAM's tuning levers.
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {SENSITIVITY.map((s) => (
            <div key={s.title} className="glass-card" style={{ padding: 22 }}>
              <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 6, color: "#67e8f9" }}>
                {s.title}
              </div>
              <p style={{ margin: 0, fontSize: 13.5, color: "#94a3b8", lineHeight: 1.65 }}>
                {s.body}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Caveats ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Honesty" title="Weaknesses & caveats" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760, marginBottom: 20 }}>
          The results are encouraging, but still temporary — and where a
          measurement was wrong, we say so and withdraw it, including when the
          error was in our favor. Stated plainly:
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {CAVEATS.map((c) => (
            <div key={c.title} className="glass-card" style={{ padding: 22 }}>
              <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 6, color: "#ffd98a" }}>
                {c.title}
              </div>
              <p style={{ margin: 0, fontSize: 13.5, color: "#94a3b8", lineHeight: 1.65 }}>
                {c.body}
              </p>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Next ---- */}
      <section>
        <SectionTitle kicker="Roadmap" title="What happens next" />
        <div className="glass-card" style={{ padding: 26 }}>
          <div style={{ display: "flex", flexWrap: "wrap", gap: 10 }}>
            {NEXT.map((n) => (
              <span
                key={n}
                className="ax-pill"
                style={{
                  background: "rgba(0,212,255,.06)",
                  border: "1px solid rgba(0,212,255,.2)",
                  color: "#cbd5e1",
                  padding: "7px 14px",
                  fontSize: 13,
                }}
              >
                {n}
              </span>
            ))}
          </div>
          <p
            style={{
              margin: "22px 0 0",
              fontSize: 13,
              color: "#64748b",
              lineHeight: 1.6,
              borderTop: "1px solid rgba(0,212,255,.1)",
              paddingTop: 18,
            }}
          >
            Full data, metric definitions and the raw per-cell telemetry live in
            the repository under{" "}
            <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
              benchmarks/PUBLIC_BENCH_ANALYSIS.md
            </code>{" "}
            and{" "}
            <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
              benchmarks/docs/methodology.md
            </code>
            . Sources: benchmark runs of 2026-07-25/26 (median-of-3 matrix +
            labeled sensitivity passes).
          </p>
        </div>
      </section>
    </div>
  );
}

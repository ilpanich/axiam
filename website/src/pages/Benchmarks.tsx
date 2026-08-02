import type { ReactNode } from "react";
import type { BenchResourceRow, BenchScenario } from "../types";
import {
  BENCH_SCENARIOS,
  BENCH_AUTHZ,
  BENCH_EFFICIENCY,
  BENCH_MEMORY_PEAK,
  BENCH_MEMORY_WORST,
  BENCH_MEMORY_CAP,
  BENCH_STACK_MEMORY,
  BENCH_CPU_PER_REQ,
  BENCH_RPS_PER_GIB,
} from "../data";

/* ---- shared bits ------------------------------------------------------- */

const AXIAM_FILL = "linear-gradient(90deg,#00d4ff,#a855f7)";
const OTHER_FILL = "rgba(148,163,184,.4)";

/**
 * Categorical series colours for the three-target resource charts, in
 * `[AXIAM, Keycloak, Zitadel]` order. Fixed assignment — a target keeps its
 * colour in every chart, and the order is never cycled. The triple is
 * validated against the dark chart surface for the lightness band, chroma
 * floor, colour-vision-deficiency separation (worst adjacent pair ΔE 18.4)
 * and ≥ 3:1 contrast; every bar is also directly labelled, so identity is
 * never carried by colour alone.
 */
const TARGET_SERIES = [
  { label: "AXIAM", color: "#00a3bf" },
  { label: "Keycloak", color: "#c9761b" },
  { label: "Zitadel", color: "#8b5ce8" },
] as const;

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
        {scenario.note && (
          <Pill color="#ffd98a" border="rgba(255,189,46,.4)" bg="rgba(255,189,46,.08)">
            ⚠ {scenario.note}
          </Pill>
        )}
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

/* ---- resource-usage charts --------------------------------------------- */

function SeriesLegend() {
  return (
    <div
      style={{
        display: "flex",
        flexWrap: "wrap",
        gap: 16,
        marginBottom: 18,
        fontSize: 12.5,
        color: "#94a3b8",
      }}
    >
      {TARGET_SERIES.map((s) => (
        <span key={s.label} style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
          <span
            aria-hidden="true"
            style={{
              width: 11,
              height: 11,
              borderRadius: 3,
              background: s.color,
              flex: "none",
            }}
          />
          {s.label}
        </span>
      ))}
    </div>
  );
}

/** One target's bar inside a resource-chart row. */
function ResourceBar({
  label,
  color,
  value,
  max,
  text,
}: {
  label: string;
  color: string;
  value: number | null;
  max: number;
  text: string;
}) {
  return (
    <div
      style={{ display: "flex", alignItems: "center", gap: 10 }}
      title={`${label}: ${text}`}
    >
      <div
        style={{
          flex: 1,
          height: 12,
          background: "rgba(255,255,255,.05)",
          borderRadius: 4,
          overflow: "hidden",
          minWidth: 40,
        }}
      >
        {value !== null && (
          <div
            style={{
              height: "100%",
              width: `${Math.max((value / max) * 100, 1.5)}%`,
              background: color,
              borderRadius: 4,
            }}
          />
        )}
      </div>
      <div
        style={{
          width: 76,
          flex: "none",
          textAlign: "right",
          fontSize: 12.5,
          color: value === null ? "#64748b" : "#cbd5e1",
          fontFamily: "ui-monospace,Menlo,monospace",
        }}
      >
        {text}
      </div>
    </div>
  );
}

/**
 * Grouped bars: one group per scenario, one bar per target, in fixed series
 * order. `scale: "row"` normalises each group to its own maximum — used where
 * the values span three orders of magnitude and a shared axis would flatten
 * every small group into nothing; every bar is labelled with its absolute
 * value, and the caption says so.
 */
function ResourceChart({
  title,
  unit,
  rows,
  format,
  scale = "shared",
  footnote,
}: {
  title: string;
  unit: string;
  rows: BenchResourceRow[];
  format: (n: number) => string;
  scale?: "shared" | "row";
  footnote?: string;
}) {
  const allValues = rows.flatMap((r) => r.values.filter((v): v is number => v !== null));
  const sharedMax = Math.max(...allValues);
  return (
    <div className="glass-card" style={{ padding: 26 }}>
      <h3 style={{ margin: 0, fontSize: 17, fontWeight: 700 }}>{title}</h3>
      <div style={{ fontSize: 12.5, color: "#64748b", margin: "4px 0 20px" }}>{unit}</div>
      <SeriesLegend />
      <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
        {rows.map((row) => {
          const rowMax =
            scale === "row"
              ? Math.max(...row.values.filter((v): v is number => v !== null))
              : sharedMax;
          return (
            <div key={row.scenario}>
              <div
                style={{
                  fontSize: 13,
                  color: "#e2e8f0",
                  fontWeight: 600,
                  marginBottom: 7,
                }}
              >
                {row.scenario}
                {row.marker && <span style={{ color: "#ffd98a" }}>{row.marker}</span>}
              </div>
              <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
                {TARGET_SERIES.map((s, i) => (
                  <ResourceBar
                    key={s.label}
                    label={s.label}
                    color={s.color}
                    value={row.values[i]}
                    max={rowMax}
                    text={row.values[i] === null ? "—" : format(row.values[i] as number)}
                  />
                ))}
              </div>
            </div>
          );
        })}
      </div>
      <p
        style={{
          margin: "20px 0 0",
          fontSize: 12.5,
          color: "#64748b",
          lineHeight: 1.6,
          borderTop: "1px solid rgba(0,212,255,.1)",
          paddingTop: 16,
        }}
      >
        {scale === "row"
          ? "Bars are scaled within each scenario — the absolute values differ by orders of magnitude between scenarios, so the numbers, not the bar lengths, compare across groups. "
          : "All bars share one scale. "}
        {footnote}
      </p>
    </div>
  );
}

/** Peak server memory drawn against the identical 2,048 MiB container cap. */
function MemoryCapChart() {
  return (
    <div className="glass-card" style={{ padding: 26 }}>
      <h3 style={{ margin: 0, fontSize: 17, fontWeight: 700 }}>
        Peak server memory vs the container cap
      </h3>
      <div style={{ fontSize: 12.5, color: "#64748b", margin: "4px 0 22px" }}>
        worst case over the whole run · MiB · the full track is the identical{" "}
        {BENCH_MEMORY_CAP.toLocaleString("en-US")} MiB cap every server got
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
        {TARGET_SERIES.map((s, i) => {
          const value = BENCH_MEMORY_WORST.values[i] as number;
          const pct = (value / BENCH_MEMORY_CAP) * 100;
          return (
            <div
              key={s.label}
              style={{ display: "flex", alignItems: "center", gap: 14 }}
              title={`${s.label}: ${value} MiB of ${BENCH_MEMORY_CAP} MiB`}
            >
              <div
                style={{
                  width: 92,
                  flex: "none",
                  fontSize: 13.5,
                  color: "#e2e8f0",
                  fontWeight: 600,
                }}
              >
                {s.label}
              </div>
              <div
                style={{
                  flex: 1,
                  height: 22,
                  background: "rgba(255,255,255,.05)",
                  border: "1px dashed rgba(148,163,184,.28)",
                  borderRadius: 6,
                  overflow: "hidden",
                  minWidth: 40,
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: `${pct}%`,
                    background: s.color,
                    borderRadius: 5,
                  }}
                />
              </div>
              <div
                style={{
                  width: 148,
                  flex: "none",
                  textAlign: "right",
                  fontSize: 13,
                  color: "#cbd5e1",
                  fontFamily: "ui-monospace,Menlo,monospace",
                }}
              >
                {value.toLocaleString("en-US")} MiB · {pct.toFixed(0)}%
              </div>
            </div>
          );
        })}
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
        The cap was <em>raised</em> from 1 GiB to 2 GiB for this run — for all
        three targets equally — because Keycloak could not reliably survive
        sustained password-login load at 1 GiB, and peaked at 1,070 MiB here.
        AXIAM peaked at 172 MiB, 8% of the same allowance, while delivering the
        throughput numbers above.
      </p>
    </div>
  );
}

/* ---- headline stat cards ---------------------------------------------- */

const HEADLINES = [
  {
    label: "Token issuance",
    value: "6.4–7.7×",
    sub: "more tokens/s than Zitadel / Keycloak — median of 3 runs, ±0.4%",
  },
  {
    label: "Identity reads over gRPC",
    value: "12,665",
    sub: "req/s at a 6 ms p95 — 3.3× Keycloak's best userinfo number",
  },
  {
    label: "Peak server memory",
    value: "172 MiB",
    sub: "8% of the 2 GiB the same envelope gave every target — Keycloak peaked at 1,070 MiB",
  },
];

/* ---- environment facts ------------------------------------------------- */

const TARGETS = [
  ["AXIAM", "axiam-server, post-fix build (Rust, build_ref recorded per cell)", "SurrealDB v3 + RabbitMQ 4"],
  ["Keycloak", "Keycloak 26.7.0 (JVM)", "PostgreSQL 16 (uniformly tuned)"],
  ["Zitadel", "Zitadel v4.15.2 (Go)", "PostgreSQL 16 (uniformly tuned)"],
];

/* ---- sensitivity highlights -------------------------------------------- */

const SENSITIVITY = [
  {
    title: "The defect we published, then fixed, then re-measured",
    body: "The previous draft's most important finding was a bug in our own product: six hot endpoints paid one synchronous datastore write — the shared rate-limit counter — before the handler even ran, and on the gRPC listener every single call paid it. The fix (a write-behind counter: decisions in memory, one coalesced write per bucket per interval) shipped, and this run is the end-to-end re-measurement: token issuance +50%, introspection +97%, gRPC authz checks +47%, gRPC userinfo +284%, and no regression anywhere else. The trade is stated plainly: cross-replica rate-limit enforcement is now eventual rather than synchronous, with a bounded overshoot that is zero on a single replica.",
  },
  {
    title: "Native mTLS is still free",
    body: "The p3 profile terminates client-certificate TLS 1.3 inside the server process — no proxy in front, the verified peer certificate is the identity source — and again lands at parity with plain TLS 1.3 on every scenario. For IoT and service-mesh fleets, certificate verification costs nothing measurable on top of TLS. It remains, as far as we can measure, unique in this field.",
  },
  {
    title: "Give the database cores first",
    body: "Uncapping only the database from 2 to 4 CPUs (servers untouched) moves authz checks +90% / +89% (REST/gRPC), client credentials +64%, introspection +42% and userinfo +59%, while JWKS, login and gRPC userinfo don't move at all. Post-fix, database CPU is the product's main ceiling — so if your workload is authz- or identity-read heavy, that is where the next core belongs.",
  },
  {
    title: "The decision cache, at its best case and its worst",
    body: "With the optional decision cache on (5 s TTL, opt-in), gRPC checks reach 11,598 req/s — 13.1× — at the bench's favourable keyspace, and batch reaches 26,000–45,000 checks/s. REST checks gain only 5%: their per-request session-cookie validation is a database read the decision cache deliberately does not cover, and it becomes the new limiter. Read 13× as a ceiling at ~100% hit rate, not an expectation; the realistic-keyspace measurement is +32%. The default stays off, the server logs its live hit rate, and the REST session cost is now a tracked optimisation target.",
  },
  {
    title: "Shipped rate limits, measured — and a second bug found",
    body: "One pass ran AXIAM with its production per-IP limits active: a 50-user single-IP flood is throttled to the configured trickle on every limited endpoint while unlimited paths run at full speed beside it, so the 429 path is cheap and the defaults do their abuse-stopping job. The same pass caught a real bug — the gRPC limiter admits about 1/60th of its configured rate, a per-second limit enforced against a per-minute window — found here, root-caused in code, fix tracked. Until it ships, treat the gRPC authz limit as per-minute, or limit at the mesh/gateway layer instead.",
  },
];

const CAVEATS = [
  {
    title: "The TLS client-credentials drop (−57%) is still unexplained",
    body: "Client-credentials throughput falls 56.7% at p2, while introspection loses 1.6%, userinfo 2.4% and authz checks nothing at all under identical TLS — so this is not a crypto cost. New post-fix evidence narrows it: under TLS the endpoint shows a flat ~43 ms per request with nothing saturated, which is a serialization plateau, and the old prime suspect (the rate-limit write) is now gone. A dedicated VU-sweep is the next round's task. Even with the penalty, AXIAM's TLS token issuance leads the field 2.8–3.4×.",
  },
  {
    title: "This run's batch cells measured the wrong strategy",
    body: "A benchmark compose file still pinned the pre-decision default, so the batch cells accidentally exercised the non-default `concurrent` strategy (199 batch ops/s = 995 checks/s, ~1.3× singles). The shipped default is `coalesced`, whose settled measurement remains the previous draft's verdict — 744 batch ops/s = 3,721 checks/s = 4.98× singles over REST, ~4,330 checks/s over gRPC. The harness pin is fixed; run 5 re-measures the default at full matrix scale.",
  },
  {
    title: "Keycloak's login cells are excluded — by memory, not by function",
    body: "Even at the raised 2 GiB cap, Keycloak completed only 1 of 3 password-login runs cleanly per profile, so our own validity gate excludes those cells (the single clean run is published in parentheses, not charted). Prior diagnostics show it wants ~3.5–4 GiB under sustained hashing load; the next run gives its login cells exactly that, clearly labeled. Zitadel's login exclusion is its default bcrypt cost — expected, and tunable — and its refresh exclusion is a flow our harness doesn't implement yet.",
  },
  {
    title: "Median-of-3, fully labeled — but still a laptop",
    body: "42 of 48 matrix cells are valid and every invalid cell is listed with its reason; every cell is the median of three runs (spread ±0.2–2.8% on AXIAM cells, so deltas above ~5% are signal). The hardware is still a consumer laptop (Dell XPS 15, i7-8750H): package temperatures hit 96–100 °C on hot cells and the clock varied 3.2–3.9 GHz. The thermal envelope was identical for all targets, so cross-target fairness holds and absolute numbers are, if anything, conservative — but a server-class re-run remains the standing caveat.",
  },
  {
    title: "The SDK pass is a first pass",
    body: "All eleven SDKs ran the same four operations at all three profiles with zero errors in 132 op-cells — but it is a single pass, not a median-of-3, and no matched-concurrency wire baseline was captured, so we are not publishing an 'SDK overhead vs raw HTTP' number yet. The C and PHP harnesses run serially, so their rows aren't comparable with the concurrency-16 ones; the C# refresh row measures its auth helper's (correct) token cache rather than the wire; and one C++ tail anomaly is under investigation.",
  },
];

const NEXT = [
  "Re-measure the batch default (`coalesced`) at full matrix scale",
  "Fix the ×60 gRPC rate-limiter units bug, then re-run the posture pass",
  "A 4 GiB, clearly-labeled Keycloak password-login cell",
  "The VU-sweep that explains the TLS client-credentials plateau",
  "SDK median-of-3 repeats plus the missing wire baseline",
  "Cut the REST session-validation database read the decision cache can't cover",
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
        OAuth2/OIDC flows. Below are the run-4 results — the first complete
        matrix measured on a build with no known measurement-distorting defect
        in it, and the first with a resource-usage profile to match.
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
            These numbers come from run 4 (2026-08-01/02) — a full{" "}
            <strong>median-of-3</strong> matrix, three targets, two TLS
            profiles, 42 of 48 cells valid with every invalid cell listed and
            explained. It is the re-measurement on the build that fixes the
            rate-limit defect the previous run found in AXIAM itself, so the
            gains on the six affected endpoints (+47% to +284%) are the story of
            this draft. They are still temporary: this run's batch cells
            measured the wrong strategy through a harness slip, Keycloak's login
            cells need a larger labeled memory envelope to be fair, and
            everything still runs on a consumer laptop rather than server-class
            hardware. Treat them as a strong, reproducible signal, not a final
            verdict; this page is updated as each improved run lands.
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
          token issuance, introspection, JWKS, userinfo over both REST and gRPC,
          session/token refresh and password login.
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
          targets benchmarked sequentially, never concurrently. Each server runs
          in a container capped identically at 2 CPUs and 2048&nbsp;MiB, so no
          target can buy throughput with extra hardware.
        </p>
        <div className="ax-grid-2" style={{ marginTop: 20, gap: 14 }}>
          {[
            ["Load model", "Closed-loop, 50 virtual users. 30 s warm-up + 120 s measured window per scenario — repeated 3×, median reported."],
            ["Profiles", "p0-plaintext and p2-tls13 (TLS 1.3, terminated in-process by all three targets, gRPC included) — plus a labeled p3-mTLS pass for AXIAM."],
            ["Validity gates", "A cell counts only if error rate ≤ 1% and p95 < 2000 ms. Failing cells are labelled, never charted as a head-to-head — 42 of 48 cells passed this run."],
            ["Container caps", "IAM server 2 CPU / 2 GiB · database 2 CPU / 1 GiB · RabbitMQ (AXIAM only) 1 CPU / 512 MiB. The server cap was raised from 1 GiB — for every target equally — because Keycloak could not reliably survive login load below it."],
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
            records its image digest, and every AXIAM cell records the build ref
            it ran — so improvements between runs are attributable to a known
            binary. This run used a post-fix build rather than a published
            release image; run 5 returns to a release image whose build ref is a
            commit on <code>main</code>.
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
          better. Each chart is a valid cell from the full result matrix; where
          a cell is not a like-for-like race, the chart carries the label that
          says so.
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

      {/* ---- Resource usage ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Resource usage" title="What it costs to run" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760 }}>
          New in this run: memory and CPU were sampled per container, every
          second, throughout every cell — so the throughput numbers above come
          with the bill for producing them. Same load, same 2-CPU /
          2&nbsp;GiB envelope for every server. All figures are the p0-plaintext
          profile, median of three runs.
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: 20, marginTop: 22 }}>
          <MemoryCapChart />

          <ResourceChart
            title="Server memory by scenario"
            unit="peak resident memory · MiB · lower is better"
            rows={BENCH_MEMORY_PEAK}
            format={(n) => `${n.toLocaleString("en-US")} MiB`}
            footnote="* On the partially valid password-login cells the peak medians and average medians diverge across runs, so the worst-case-over-the-whole-run figures in the chart above are the honest summary for that scenario. Zitadel has no refresh cell — its flow is excluded from this run."
          />

          <ResourceChart
            title="CPU cost per request"
            unit="cpu·ms per request · whole stack unless noted · lower is better"
            rows={BENCH_CPU_PER_REQ}
            format={(n) => n.toFixed(2)}
            scale="row"
            footnote="Whole-stack userinfo is the single efficiency cell Keycloak wins — AXIAM's figure there carries a pegged SurrealDB plus RabbitMQ. Measured server-only, the same request costs AXIAM 0.25 cpu·ms against Keycloak's 0.53. Both are published; neither is hidden."
          />

          <ResourceChart
            title="Throughput per GiB of stack memory"
            unit="requests/s per GiB of whole-stack RAM · higher is better"
            rows={BENCH_RPS_PER_GIB}
            format={(n) => n.toLocaleString("en-US")}
            scale="row"
            footnote="Whole-stack means server + database + broker: AXIAM's denominator includes SurrealDB and RabbitMQ, Keycloak's and Zitadel's include PostgreSQL."
          />
        </div>

        <div className="glass-card" style={{ padding: 4, marginTop: 20, overflowX: "auto" }}>
          <table
            style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5, minWidth: 480 }}
          >
            <thead>
              <tr>
                {["Target", "Whole-stack memory", "What's in it"].map((h) => (
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
              {BENCH_STACK_MEMORY.map((row) => (
                <tr key={row[0]}>
                  {row.map((cell, ci) => (
                    <td
                      key={ci}
                      style={{
                        padding: "11px 16px",
                        borderBottom: "1px solid rgba(255,255,255,.06)",
                        color: ci === 0 ? "#e2e8f0" : "#cbd5e1",
                        fontWeight: ci === 0 ? 700 : 400,
                        fontFamily: ci === 1 ? "ui-monospace,Menlo,monospace" : undefined,
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

        <p
          style={{
            margin: "18px 0 0",
            fontSize: 14,
            color: "#94a3b8",
            lineHeight: 1.7,
            maxWidth: 760,
          }}
        >
          Read plainly: <strong style={{ color: "#e2e8f0" }}>Zitadel's stack is the
          smallest of the three</strong> — its Go server is respectably compact and its
          costs surface as CPU per request instead. AXIAM's stack is not the
          smallest, but it does the most work per byte and per core, by 1.6× to
          17× on every cell except one. And where Keycloak needed its memory cap
          doubled just to run the login scenario, AXIAM's server never exceeded
          172 MiB of the same 2 GiB allowance.
        </p>
      </section>

      {/* ---- AXIAM-only authz ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="AXIAM-only" title="Authorization decisions" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 22 }}>
          No head-to-head here — Keycloak and Zitadel expose no equivalent decision
          endpoint. Each check is a full RBAC evaluation (tenant-scoped roles,
          resource hierarchy, scopes) against live data, over REST and gRPC. The
          cache-ON rows are a labeled best-case sensitivity pass, not the default
          configuration; the batch figure quoted below is carried over from the
          previous run, because this run's batch cells measured the wrong
          strategy (see the honesty section).
        </p>
        <BarChart scenario={BENCH_AUTHZ} />
      </section>

      {/* ---- Sensitivity ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Sensitivity" title="What the labeled passes showed" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 20 }}>
          Beyond the head-to-head matrix, run 4 ran five labeled single-variable
          passes — never mixed into the comparison tables — to verify the fix,
          find each system's walls, and size AXIAM's tuning levers.
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
            . Sources: benchmark run 4 of 2026-08-01/02 (median-of-3 capped
            matrix × two TLS profiles × three targets; labeled sensitivity
            passes for DB-uncapped, decision-cache, native mTLS, production
            rate-limit posture and batch strategy; an 11-language SDK pass;
            per-cell k6 summaries with 1-second container and host telemetry).
          </p>
        </div>
      </section>
    </div>
  );
}

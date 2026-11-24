import type { ReactNode } from "react";
import type { BenchResourceRow, BenchScenario } from "../types";
import {
  BENCH_SCENARIOS,
  BENCH_AUTHZ,
  BENCH_EFFICIENCY,
  BENCH_MEMORY_AVG,
  BENCH_MEMORY_WORST,
  BENCH_MEMORY_CAP,
  BENCH_STACK_MEMORY,
  BENCH_CPU_PER_REQ,
  BENCH_RPS_PER_GIB,
  BENCH_TLS_COST,
  BENCH_SDK_LATENCY,
  BENCH_SDK_FOOTPRINT,
  BENCH_CAPS,
  BENCH_SURREAL,
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

/** Server memory drawn against the identical 2,048 MiB container cap. */
function MemoryCapChart() {
  return (
    <div className="glass-card" style={{ padding: 26 }}>
      <h3 style={{ margin: 0, fontSize: 17, fontWeight: 700 }}>
        Server memory vs the container cap
      </h3>
      <div style={{ fontSize: 12.5, color: "#64748b", margin: "4px 0 22px" }}>
        highest per-scenario average over the whole run · MiB · the full track is
        the identical {BENCH_MEMORY_CAP.toLocaleString("en-US")} MiB cap every
        server got
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
        The cap is 2 GiB for every target — raised from 1 GiB in earlier runs,
        equally for all, because Keycloak could not reliably survive sustained
        password-login load below it. Across this entire matrix AXIAM's server
        averaged 54–75 MiB, under 4% of the same allowance; Keycloak 26.8.1's
        averaged 708–941 MiB, which is no visible reduction against the
        710–853 MiB Keycloak 26.7.0 averaged in run 5 (a different host, so a
        direction rather than a measurement of the release-note claim);
        Zitadel's averaged 127–137 MiB.
      </p>
    </div>
  );
}

/** Open upstream issues in the pinned SurrealDB 4.0.1 build (runs 6 and 6b). */
const SURREALDB_BUG_URL = "https://github.com/surrealdb/surrealdb/issues/7667";
const SURREALDB_EVENT_BUG_URL = "https://github.com/surrealdb/surrealdb/issues/7716";

/* ---- headline stat cards ---------------------------------------------- */

const HEADLINES = [
  {
    label: "Token issuance",
    value: "3.5–4.6×",
    sub: "the tokens/s of Keycloak and Zitadel with 4 CPUs per container (3.8–3.9× at 2), held within 2% under TLS 1.3 and mTLS",
  },
  {
    label: "Server memory under load",
    value: "54–75 MiB",
    sub: "AXIAM's server across the whole run-6 matrix (89–133 MiB at 4 CPUs), against 708–941 MiB for Keycloak and 127–137 MiB for Zitadel",
  },
  {
    label: "Cost of the SurrealDB 4.0.1 server",
    value: "13–39%",
    sub: "of AXIAM's throughput on database-bound cells, measured against the same image on SurrealDB 3.3.5 (run 6c, 2 CPUs)",
  },
];

/* ---- environment facts ------------------------------------------------- */

const TARGETS = [
  [
    "AXIAM",
    "AXIAM 1.3.0 — the published release image, pinned by digest",
    "SurrealDB v4.0.1 + RabbitMQ 4 (TLS)",
  ],
  ["Keycloak", "Keycloak 26.8.1 (JVM)", "PostgreSQL 16 (uniformly tuned)"],
  ["Zitadel", "Zitadel v4.19.5 (Go)", "PostgreSQL 16 (uniformly tuned)"],
  ["authentik", "authentik 2026.8.5 (Python) — server + worker", "PostgreSQL 16 (uniformly tuned), no Redis"],
];

/* ---- what this run found ----------------------------------------------- */

const FINDINGS = [
  {
    title: "Run 6b: double the cores, double the throughput — the 2-CPU caps were the limit",
    body: "With 4 CPUs per server and per database, AXIAM gained 2.02–2.32× on every cell it could gain on and stayed bound in SurrealDB (4.0–4.1 of 4 cores, server at 0.6–1.9). Keycloak gained 1.96–2.27× and stayed bound in its own server. Zitadel gained 1.66–1.95×, and on token issuance and introspection none of its containers reached 95% of the cap (server 3.65–3.70, PostgreSQL 3.38–3.63 of 4), so part of its limit is not CPU. The run-6 ordering survives the doubling: AXIAM still leads token issuance (3,234 vs 934 and 704 req/s), Keycloak still leads introspection (3,952 vs 3,272) and REST userinfo (7,807 vs 2,963), and login is a draw (98 vs 93 logins/s, inside Keycloak's ±4.3% spread).",
  },
  {
    title: "SurrealDB's per-statement cost parallelises — and the shared p95 band was CPU-quota throttling",
    body: "If surrealdb/surrealdb#7667's per-statement CPU cost could not run in parallel, more database cores would not help. They do: AXIAM's database-bound cells more than doubled. At the same time AXIAM's p95 collapsed — 69 → 20 ms on token issuance, 69 → 20 ms on introspection, 59 → 11 ms on gRPC userinfo — while its p50 barely moved (14.9 → 13.7 ms). Keycloak shows the same signature (JWKS p95 73.5 → 5.6 ms). A tail that shrinks when a container stops hitting its quota, while the median stays put, is what CFS throttling looks like; run 6's 65–90 ms band was that, not any product. The bug still costs CPU on every write: it is now known to cost cores, not to serialise.",
  },
  {
    title: "Run 6c: the SurrealDB 4.0.1 server costs AXIAM 13–39% at 2 CPUs, 6–40% at 4",
    body: "The same AXIAM 1.3.1 image against a SurrealDB 3.3.5 server, at equal caps on the same VM, raised every database-bound cell by 1.15–1.64× at 2 CPUs and 1.07–1.66× at 4, with SurrealDB still at its cap — the database simply spends less per request (13–39% fewer database cores per 1,000 requests at 2 CPUs). surrealdb/surrealdb#7716 contributes nothing here, since AXIAM defines no events; #7667 is the known candidate, but at 4 CPUs the losses are largest on read-heavy cells (authorization checks and userinfo, 20–40%, against 6–14% for token issuance, introspection and refresh), which #7667's write-only description does not predict. With 3.3.5, Keycloak would still lead introspection and REST userinfo at both cap levels.",
  },
  {
    title: "AXIAM 1.3.1 measured 5–12% below 1.3.0 at equal caps — unexplained so far",
    body: "Run 6b's control pass ran AXIAM 1.3.1 at run 6's 2/2 caps on the same VM a day later, against the same SurrealDB digest: client credentials 1,610 → 1,448 (−10%), introspection −9%, userinfo −6%, gRPC userinfo −9%, refresh −12%, authorization −7 to −11%, JWKS −5%. That is outside run 6's ±0.3–4.5% run-to-run spread. 1.3.1's changelog lists dependency bumps and test fixes and no performance change, and the control pass had no competitor alongside it, so release and day-to-day host drift cannot be separated yet. We report it rather than absorb it; the run-6b cap factors use 1.3.1 at 2/2 as AXIAM's baseline, so they measure the caps alone.",
  },
  {
    title: "AXIAM's ceiling is now its database tier",
    body: "On every AXIAM cell that reads or writes data, SurrealDB averaged 2.00–2.04 of its 2-core cap while the AXIAM server used 0.27–0.84 of its own 2 cores. The report's bottleneck column names `bench-axiam-surrealdb` on 27 of AXIAM's 33 cells; the six others are JWKS, which never touches the database, and password login, where the server is busy hashing. The server process has headroom it cannot use, so these cells measure SurrealDB under AXIAM's query load, not AXIAM's request handling.",
  },
  {
    title: "Database-bound cells fell 43–75% against run 5; the database-free cell rose 64%",
    body: "Run 6, at 2/2. Against run 5 on the laptop: client credentials 2,804 → 1,610, introspection 4,504 → 1,582, userinfo 4,752 → 1,411, gRPC userinfo 12,307 → 3,078, single authorization checks 1,032 → 492 — while JWKS went from 26,680 to 43,640. The competitors are the control for the change of host: Keycloak moved +3% to +21% on the same cells and Zitadel −14% to −1%. A host effect cannot produce opposite movements on AXIAM's database-bound and database-free cells; something in the database tier changed. Run 6 is the first on SurrealDB 4.0 (AXIAM 1.3.0 requires it), and SurrealDB has an open upstream bug (surrealdb/surrealdb#7667, highlighted at the top of this page): write statements cost 10–17× more CPU than in 3.3.5, unchanged in 4.0.1. Run 6c has since measured the server's share: the same AXIAM on SurrealDB 3.3.5 is 13–39% faster at the same caps — a real part of the drop, not all of it.",
  },
  {
    title: "Native mTLS still costs nothing measurable — partly because the server is not the ceiling",
    body: "Mutual TLS terminated in the server process, with the verified client certificate as the identity source, stays within ±2% of plaintext on every database-bound AXIAM cell. Read that with care: TLS work lands on the AXIAM server, which has headroom, while the ceiling is SurrealDB. The one cell where the server works hardest, JWKS, shows the real handshake-and-record cost: −16.0% under TLS 1.3 and −12.7% under mTLS, against −5.6% / −17.0% for Keycloak.",
  },
  {
    title: "Login: a draw with Keycloak, both CPU-bound on hashing",
    body: "AXIAM serves 49 logins/s at a 1,046 ms p95 with its server at 1.81 of 2 cores; Keycloak serves 47 at 1,213 ms with its server pegged. For the first time in this series Keycloak's login cell is valid at every profile, and it was measured at the same 2 GiB cap as everyone else. Zitadel's default bcrypt cost keeps it at a ~29 s p50, which is expected and tunable.",
  },
  {
    title: "The SDK picture is cleaner than run 5's",
    body: "C++'s reconnect-shaped p95 tail is gone (72 ms against a 71 ms wire baseline), and TypeScript's negative overhead — flagged in run 5 as a comparability problem — is now a coherent +3.2 ms. Eight of the nine concurrent SDKs sit within +0.5 to +3.2 ms of raw k6 at p95; Python remains the outlier at +21 ms.",
  },
];

const CAVEATS = [
  {
    title: "Run 6c is an unsupported pairing, measured only to size the bug",
    body: "AXIAM 1.3 requires SurrealDB 4.0, and its 4.0.0 client talking to a 3.3.5 server is a pairing SurrealDB declares supported but that AXIAM's CI never runs (CI last ran these queries against 3.3.4). The dry runs passed at both caps and every cell is valid, which shows that the benchmarked paths work — not that the whole product does. SurrealDB 3.3.5 also carries two advisories that 4.0 fixed (RUSTSEC-2026-0452 and RUSTSEC-2026-0454), which is one reason AXIAM moved. Run 6c cells are a labelled sensitivity pass: never medianed with runs 6 and 6b, never in a head-to-head, and not a recommendation to deploy on 3.x.",
  },
  {
    title: "Not comparable with run 5 — the box, the engine and the release all changed",
    body: "Run 5 measured AXIAM 1.0.0-alpha24 on SurrealDB 3 on a consumer laptop. Run 6 measures AXIAM 1.3.0 on SurrealDB 4.0.1 on a cloud VM. Any run-5 figure quoted on this page is context for a finding, not a like-for-like delta, and no number here should be read against an older page or comparison document without that sentence attached.",
  },
  {
    title: "AXIAM lost two head-to-head cells it used to win",
    body: "Keycloak now leads token introspection (1,940 vs 1,582 req/s) and REST userinfo (3,862 vs 1,411), and on whole-stack CPU per request it wins both. AXIAM still leads token issuance by 3.8–3.9×, JWKS by 7.9×, and is the cheapest server-only on every cell — but we publish the losses as plainly as the wins, and we do not claim the database tier will recover until it has been measured doing so.",
  },
  {
    title: "A narrower run than run 5",
    body: "This was a comparison pass: the dry run, resting footprints, the core matrix (median of 3) and the SDK pass. Deferred: the new-feature cells, the production rate-limit table, the minimal profile and every investigation pass (refresh stage timings, database ceiling, strict revocation, decision-cache sensitivity). The rate-limiter enforcement gaps published with run 5 have therefore been neither confirmed fixed nor re-measured, and nothing on this page should be read as saying they were.",
  },
  {
    title: "authentik produced no valid cell",
    body: "Every authentik cell failed the validity gate (p95 well above 2 s) with its PostgreSQL pegged, at the same per-container caps as everyone else — which, with the worker carrying its own 2-CPU / 2 GiB cap, is a 6-CPU / 5 GiB stack against Keycloak's 4 / 3. Its p2 profile is its own TLS listener over HTTP/1.1, it has no p3, its login is protocol-variant and its refresh a fallback operation. We make no performance statement about authentik from this run; an uncapped pass would be needed to say whether that is the envelope or the product.",
  },
  {
    title: "One cloud VM, qualified, still shared tenancy",
    body: "A 16-vCPU AMD EPYC Genoa instance (Infomaniak Public Cloud) passed a pre-run qualification: sysbench spread 0.32% over three runs, 0.00% steal under load, and no period above 5% steal during the matrix. Its vCPUs are SMT threads on shared hardware, so absolute figures describe this instance class. The harness carried local changes to the SDK bench manifests and the AXIAM target compose file, recorded in the provenance; the C# SDK bench was retargeted to .NET 10 for the SDK pass only. The server image itself is the published 1.3.0, by digest.",
  },
  {
    title: "Run 6b is a sensitivity pass, at plaintext only",
    body: "Run 6b moved one variable — CPU, from 2 to 4 per server and per database for every target (memory unchanged; RabbitMQ unchanged at 1 CPU), giving stack ceilings of 8 CPUs for Keycloak and Zitadel, 9 for AXIAM and 12 for authentik (its worker carries the server cap). It measured p0-plaintext only, its cells are never medianed with run 6's, and the TLS, mTLS, resource, efficiency and SDK figures on this page remain run 6's at 2/2. Efficiency stays per core actually used, so the different ceilings favour nobody. AXIAM's JWKS cell at 4/4 saturated the load generator (k6 at 7.3 cores) and is not quoted as a capacity.",
  },
];

const NEXT = [
  "Re-run the database-bound cells on this VM once surrealdb/surrealdb#7667 is fixed in a SurrealDB release",
  "Explain AXIAM 1.3.1's 5–12% at equal caps: a same-day 1.3.0 / 1.3.1 control with a competitor alongside",
  "Find which of AXIAM's queries got more expensive on 4.0.1 — reads included, per run 6c — and report them upstream with #7667",
  "Find Zitadel's non-CPU limit and its fixed 200 ms gRPC userinfo floor before quoting either as a product ceiling",
  "The deferred passes: production rate-limit table, minimal profile, new-feature cells",
  "Refresh stage timings",
  "authentik: still no valid cell at 4/4 (it roughly doubled, still above the 2 s gate) — a larger envelope, or an explanation",
  "Profile the Python SDK gap",
  "The seventh draft of PUBLIC_BENCH_ANALYSIS.md from runs 6 and 6b",
];

/* ---- why build AXIAM at all? ------------------------------------------- */

/**
 * The question the field invites — Keycloak is mature and ubiquitous,
 * Zitadel is modern and well-engineered — answered from run 6's
 * measurements, with the cons attached.
 */
const WHY_AXIAM = [
  {
    n: "1",
    title: "The server is efficient; the database tier is the work in front of us",
    body: "Server-only, AXIAM spends the least CPU per request on every cell measured — 0.44 cpu·ms per token against Keycloak's 4.89 and Zitadel's 4.61, 0.42 on introspection and userinfo — and serves 43,640 JWKS reads/s from 54 MiB. IAM is infrastructure that runs in front of everything, and a server whose cost floor is an order of magnitude lower is a real capability. Run 6 also says, plainly, that the stack is only as fast as its slowest tier: with SurrealDB 4.0.1 pegged, Keycloak wins two head-to-head cells, and run 6c measured 13–39% of that ceiling as the 4.0.1 server's own regression. Making the database tier match the server is now the measured priority, not a footnote.",
  },
  {
    n: "2",
    title: "Nobody else treats the machine/IoT edge as the main stage",
    body: "Authorization decisions as a first-class, benchmarked hot path (2,425–3,100 hierarchy-aware RBAC checks/s in batches at the shipped default, cache off); a gRPC data plane that serves 12.6× Zitadel's gRPC userinfo (the competitors' gRPC surfaces are management APIs, and it shows); and in-process mutual TLS with no sidecar, which makes per-device client certificates the cheap option for IoT fleets rather than an architecture project. If your workload is humans logging into web apps, Keycloak serves you well today. If it is services and devices asking “may I?” many times a second, that workload is what AXIAM is shaped around.",
  },
  {
    n: "3",
    title: "Security posture as measured defaults, not documentation",
    body: "AXIAM ships abuse rate-limits on by default, with human endpoints locked strictly regardless of posture. Argon2id, EdDSA short-lived tokens, single-use rotating refresh tokens, append-only audit and encrypted-at-rest secrets are defaults, not options. And the process is part of the posture: this series has found, published and fixed a synchronous rate-limit write, a ×60 limiter units bug, a Nagle-induced TLS latency cliff and two authorization table scans — and now publishes a database-tier regression on its own release, in public view, before it is understood.",
  },
  {
    n: "4",
    title: "Deny-override RBAC and a real device flow, not just device-shaped marketing",
    body: "The RBAC engine is default-deny with deny-override: an explicit deny grant beats every allow, at any depth of the resource hierarchy and at equal specificity — the semantic gap incumbent additive-only engines leave open. And the OAuth2 Device Authorization Grant ships end to end — enter a code, authenticate, consent, approve or deny — for the headless devices and CLIs a browser-redirect flow can't reach.",
  },
];

const WHY_AXIAM_CONS =
  "AXIAM is young: it has a fraction of Keycloak's protocol surface, extension ecosystem, hosting options and community. On runs 6 and 6b alike Keycloak beats it on introspection and REST userinfo throughput, and on whole-stack CPU for both; AXIAM's stack carries SurrealDB and RabbitMQ in every full deployment, and by cgroup working set Zitadel's stack is smaller at rest; SurrealDB is a younger storage engine than PostgreSQL by a decade, and its 4.0 line is the tier this run found pegged. Choosing AXIAM today means choosing a young system whose server efficiency, machine-first design and measurement culture you value over incumbent breadth — with its database tier as the open item. That trade is exactly the niche the incumbents leave open, and the measurements above are why we believe it is worth serving.";


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
        per-target adapter, comparing AXIAM against Keycloak, Zitadel and — new
        this run — authentik across OAuth2/OIDC flows. Below are the run-6
        results of 2026-11-20/21: the first measured on a qualified{" "}
        <strong style={{ color: "#e2e8f0" }}>server-class cloud VM</strong>{" "}
        rather than a laptop, against the published{" "}
        <code style={{ color: "#67e8f9" }}>1.3.0</code> release image pulled by
        digest, median of three runs across plaintext, TLS&nbsp;1.3 and native
        mutual TLS — and{" "}
        <a href="#run-6b" style={{ color: "#67e8f9" }}>run 6b</a> of
        2026-11-21/22, the same comparison on the same VM with every server
        and every database given 4 CPUs instead of 2 — and{" "}
        <a href="#run-6c" style={{ color: "#67e8f9" }}>run 6c</a> of
        2026-11-23/24, the same AXIAM image on a SurrealDB 3.3.5 server, which
        measures what the 4.0.1 server costs it.
      </p>
      <p style={{ margin: "0 0 44px", fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 720 }}>
        Read one fact before any number: run 6 is{" "}
        <strong style={{ color: "#e2e8f0" }}>not comparable with run 5</strong>.
        The host changed, AXIAM moved from 1.0.0-alpha24 to 1.3.0, and its
        database from SurrealDB 3 to 4.0.1. The headline finding follows from
        the last of these: on every cell that touches data, SurrealDB is pegged
        at its cap while the AXIAM server uses well under half of its own, and
        AXIAM's lead narrowed — it now loses two head-to-head cells to
        Keycloak. Doubling the caps in run 6b doubled AXIAM and Keycloak alike
        and changed no winner. Both are shown below, with the reasons.
      </p>

      {/* ---- Upstream SurrealDB 4 bug ---- */}
      <div
        className="glass-card"
        style={{
          padding: "18px 22px",
          borderColor: "rgba(255,189,46,.4)",
          background: "rgba(255,189,46,.08)",
          marginBottom: 44,
          marginTop: -20,
        }}
      >
        <div style={{ fontSize: 15, fontWeight: 700, color: "#ffd98a", marginBottom: 6 }}>
          Known upstream bugs in SurrealDB 4.0.1 — and what the 4.0.1 server costs AXIAM
        </div>
        <p style={{ margin: "0 0 10px", fontSize: 14, lineHeight: 1.65, color: "#e2e8f0" }}>
          Both issues are open, with no fix merged upstream, and both report
          4.0.x as a regression from 3.3.x.{" "}
          <a
            href={SURREALDB_BUG_URL}
            target="_blank"
            rel="noreferrer"
            style={{ color: "#67e8f9" }}
          >
            surrealdb/surrealdb#7667
          </a>{" "}
          reports that every write statement costs about 350&nbsp;µs of CPU in
          the query executor, 10–17× more than in 3.3.5, unchanged in 4.0.1; it
          sits on AXIAM's request path.{" "}
          <a
            href={SURREALDB_EVENT_BUG_URL}
            target="_blank"
            rel="noreferrer"
            style={{ color: "#67e8f9" }}
          >
            surrealdb/surrealdb#7716
          </a>{" "}
          reports that every CREATE firing a <code>DEFINE EVENT</code>{" "}
          re-plans the whole event body. AXIAM's shipped schema defines no
          events, so <strong>#7716 has no measurable effect on AXIAM</strong>;
          it is listed because it is a regression of the exact build pinned.
        </p>
        <p style={{ margin: 0, fontSize: 14, lineHeight: 1.65, color: "#e2e8f0" }}>
          <strong>How much, measured.</strong> Run 6c ran the same AXIAM 1.3.1
          image against a SurrealDB 3.3.5 server, on the same VM at equal caps.
          On the database-bound cells 4.0.1 delivered{" "}
          <strong>13–39% less throughput at 2 CPUs</strong> (median of the
          nine cells: 31%) and <strong>6–40% less at 4 CPUs</strong> (median
          27%); on 3.3.5 the database needed 13–39% less CPU per request. That is the
          whole 4.0.1 server against 3.3.5 — #7667 plus anything else that
          changed in 4.0 — and it does not follow #7667's shape alone: the
          largest losses at 4 CPUs are on the read-heavy authorization and
          userinfo cells (20–40%), not on token issuance, introspection and
          refresh (6–14%). It
          explains part of the drop since run 5, not all of it. The run-6
          charts below carry the measured cost per cell; the head-to-head
          figures stay on 4.0.1, the only supported server.{" "}
          <strong>
            The database-bound cells will be re-measured once a fixed SurrealDB
            release ships
          </strong>
          , and this page will be updated with the result.
        </p>
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
          Four open-source IAM servers are driven with the <em>identical logical
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
        <SectionTitle kicker="Setup" title="How it was run — on a cloud VM" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760 }}>
          Everything ran on one Infomaniak Public Cloud instance — AMD EPYC
          Genoa, 16 vCPUs, 64&nbsp;GiB RAM, local disk, Ubuntu 24.04 with kernel
          6.8 — created for the run and qualified before it: three sysbench
          passes within 0.32% of each other, 0.00% CPU steal under load, and no
          period above 5% steal during the matrix. The targets were benchmarked
          sequentially, never concurrently. Each server runs in a container
          capped identically at 2 CPUs and 2048&nbsp;MiB, so no target can buy
          throughput with extra hardware.
        </p>
        <div className="ax-grid-2" style={{ marginTop: 20, gap: 14 }}>
          {[
            ["Load model", "Closed-loop, 50 virtual users, k6 2.3. 30 s warm-up + 120 s measured window per scenario — repeated 3×, median reported."],
            ["Profiles", "Three, all median-of-3: p0-plaintext, p2-tls13 (TLS 1.3 terminated in-process, gRPC included; authentik's is its own TLS listener over HTTP/1.1) and p3-mtls (in-process mutual TLS; authentik has none)."],
            ["Validity gates", "A cell counts only if error rate ≤ 1% and p95 < 2000 ms. Failing cells are labelled, never charted as a head-to-head — 66 of 84 cells passed this run (the 18 others: all 12 of authentik's, and Zitadel's login and fallback refresh), and the settle gate cleared first-probe on every cell."],
            ["Container caps", "IAM server 2 CPU / 2 GiB · database 2 CPU / 1 GiB · RabbitMQ (AXIAM only) 1 CPU / 512 MiB · authentik's worker 2 CPU / 2 GiB, like its server. Unchanged from run 5."],
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
            and every matrix cell is the median of three runs, on a VM whose
            steal time was checked before and during the run.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Provenance recorded.</strong> Every container in every cell
            records its image digest, and this run benchmarks a{" "}
            <em>published</em> artifact —{" "}
            <code style={{ overflowWrap: "anywhere" }}>ghcr.io/ilpanich/axiam/server:1.3.0</code>, pinned by
            digest and pulled exactly as any reader would pull it — so the
            numbers describe a release anyone can fetch rather than a working
            tree only we can build.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Competitors tuned, not hobbled.</strong> PostgreSQL is
            minimally and <em>uniformly</em> tuned for Keycloak, Zitadel and
            authentik;
            SurrealDB runs stock. AXIAM's own per-IP rate limits are neutralized so
            they don't cap the load generator.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Telemetry recorded.</strong> Every cell logs per-container
            CPU and memory, host statistics and load-generator CPU at 1-second
            resolution, with CPU steal sampled throughout — so a saturated
            container, a noisy neighbour or a saturated generator is visible
            rather than hidden.
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
          says so. A value in parentheses failed the validity gate and is shown
          only so that a target is not silently missing.
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: 20 }}>
          {BENCH_SCENARIOS.map((s) => (
            <BarChart key={s.id} scenario={s} />
          ))}
        </div>
      </section>

      {/* ---- Run 6b: raised caps ---- */}
      <section id="run-6b" style={{ marginBottom: 52, scrollMarginTop: 90 }}>
        <SectionTitle kicker="Run 6b" title="Twice the cores: was it the caps?" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760 }}>
          In run 6 nearly every cell stopped at the 2-CPU cap of one container
          while the host had more than half its CPU free. Run 6b re-ran the
          plaintext comparison on the same VM with{" "}
          <strong style={{ color: "#e2e8f0" }}>4 CPUs for every server and every
          database</strong> — the same step for every target and role, memory
          unchanged — against the same competitor and SurrealDB images, by
          digest. AXIAM's 2/2 baseline is a control pass of 1.3.1 at run 6's
          caps, so its factor measures the caps alone. Median of three runs;
          22 of 30 cells valid (authentik's six, and Zitadel's login and
          fallback refresh, are invalid as in run 6).
        </p>
        <div className="glass-card" style={{ padding: 4, marginTop: 20, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 720 }}>
            <thead>
              <tr>
                {["Scenario", "AXIAM", "Keycloak", "Zitadel"].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "12px 14px",
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
              {BENCH_CAPS.map((row) => (
                <tr key={row.scenario}>
                  <td
                    style={{
                      padding: "11px 14px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      color: "#e2e8f0",
                      fontWeight: 600,
                    }}
                  >
                    {row.scenario}
                  </td>
                  {row.cells.map((cell, ci) => (
                    <td
                      key={ci}
                      style={{
                        padding: "11px 14px",
                        borderBottom: "1px solid rgba(255,255,255,.06)",
                        verticalAlign: "top",
                      }}
                    >
                      {cell === null ? (
                        <span style={{ color: "#64748b" }}>—</span>
                      ) : (
                        <>
                          <div
                            style={{
                              fontFamily: "ui-monospace,Menlo,monospace",
                              color: ci === 0 ? "#67e8f9" : "#cbd5e1",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {cell.from} → {cell.to}
                          </div>
                          <div style={{ fontSize: 11.5, color: "#94a3b8", marginTop: 2 }}>
                            {cell.factor} · bound: {cell.bound}
                          </div>
                        </>
                      )}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p style={{ margin: "12px 4px 0", fontSize: 12.5, color: "#64748b", lineHeight: 1.6 }}>
          Requests/s at 2 → 4 CPUs per server and per database, p0-plaintext.
          “Bound” names the container at ≥ 95% of its cap at 4/4. AXIAM's JWKS
          at 4/4 saturated the load generator and is not a capacity figure.
          Zitadel's login and refresh, and every authentik cell, failed the
          validity gate at both cap levels.
        </p>
        <ul style={{ margin: "20px 0 0", paddingLeft: 22, color: "#cbd5e1", lineHeight: 1.75, maxWidth: 760 }}>
          <li style={{ marginBottom: 8 }}>
            <strong>AXIAM and Keycloak scale cleanly.</strong> Both roughly
            double and stay bound in the same container (AXIAM's login excepted: its server hashed at 3.7 of 4 cores, just under the 95% mark) — SurrealDB for AXIAM,
            the JVM server for Keycloak. Run 6 measured their 2-CPU caps, not
            their limits.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Zitadel has a limit that is not CPU.</strong> On token
            issuance and introspection no container reached 95% of its cap, and
            its gRPC userinfo held a flat 200 ms p50 with both containers near
            one core.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>No winner changed.</strong> Token issuance: AXIAM 3,234,
            Keycloak 934, Zitadel 704 req/s. Introspection: Keycloak 3,952,
            AXIAM 3,272, Zitadel 1,522. REST userinfo: Keycloak 7,807, AXIAM
            2,963, Zitadel 1,677. gRPC userinfo: AXIAM 6,369, Zitadel 226.
            Login: Keycloak 98, AXIAM 93 — a draw within spread.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>The tails shrank more than the medians.</strong> AXIAM's
            token-issuance p95 fell from 69 to 20 ms with its p50 almost
            unchanged; Keycloak's JWKS p95 from 73.5 to 5.6 ms. Run 6's shared
            65–90 ms p95 band was CPU-quota throttling of the pegged container.
          </li>
        </ul>
      </section>

      {/* ---- Run 6c: SurrealDB 3.3.5 ---- */}
      <section id="run-6c" style={{ marginBottom: 52, scrollMarginTop: 90 }}>
        <SectionTitle kicker="Run 6c" title="The same AXIAM on SurrealDB 3.3.5" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760 }}>
          One variable: the database server. The same AXIAM 1.3.1 image, by
          digest, ran the plaintext matrix against a{" "}
          <strong style={{ color: "#e2e8f0" }}>SurrealDB 3.3.5 server</strong>{" "}
          instead of 4.0.1, at both cap levels, on the same VM, on a freshly
          created database volume for every block, and is compared cell by
          cell with run 6b's AXIAM on 4.0.1. Median of three runs, 33 of 33
          cells valid in each pass. Every figure here is labelled{" "}
          <em>SurrealDB 3.3.5 server, unsupported, benchmark-only</em>: AXIAM
          1.3 requires 4.0, and run 6c never enters a head-to-head table.
        </p>
        <div className="glass-card" style={{ padding: 4, marginTop: 20, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 720 }}>
            <thead>
              <tr>
                {["Scenario", "2 CPUs · 4.0.1 → 3.3.5", "4 CPUs · 4.0.1 → 3.3.5", "DB cores / 1k req (2 CPUs)"].map((h) => (
                  <th
                    key={h}
                    style={{
                      textAlign: "left",
                      padding: "12px 14px",
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
              {BENCH_SURREAL.map((row) => (
                <tr key={row.scenario}>
                  <td
                    style={{
                      padding: "11px 14px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      color: "#e2e8f0",
                      fontWeight: 600,
                    }}
                  >
                    {row.scenario}
                  </td>
                  {[row.caps2, row.caps4, row.dbCost].map((cell, ci) => (
                    <td
                      key={ci}
                      style={{
                        padding: "11px 14px",
                        borderBottom: "1px solid rgba(255,255,255,.06)",
                        color: ci === 2 ? "#94a3b8" : "#cbd5e1",
                        fontFamily: "ui-monospace,Menlo,monospace",
                        whiteSpace: "nowrap",
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
        <p style={{ margin: "12px 4px 0", fontSize: 12.5, color: "#64748b", lineHeight: 1.6 }}>
          Requests/s on 4.0.1 → on 3.3.5, the ratio, and how much less
          throughput 4.0.1 delivers. Batch rows are operations/s (five checks
          each). The last column is SurrealDB's CPU per 1,000 requests.
        </p>
        <ul style={{ margin: "20px 0 0", paddingLeft: 22, color: "#cbd5e1", lineHeight: 1.75, maxWidth: 760 }}>
          <li style={{ marginBottom: 8 }}>
            <strong>The 4.0.1 server costs AXIAM up to 40%.</strong> Every
            database-bound cell is faster on 3.3.5, and SurrealDB stays at its
            cap in all of them but one — so each request costs the database
            less, rather than the bottleneck moving. The exception is refresh
            at 4 CPUs (+7%, database at 3.7 of 4 cores): its limit there is no
            longer database CPU.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>The shape is not #7667's alone.</strong> #7667 describes a
            cost on write statements with reads almost unchanged, so the
            write-heavy token and refresh cells should gain most. At 4 CPUs they
            gain least (4.0.1 costs them 6–14%), and the authorization checks
            and userinfo reads gain most (20–40%).
            Either those cells write more per request than their labels
            suggest, or 4.0.1's extra cost is not only on writes. We report
            that as found; finding which queries got more expensive is the next
            step, and goes upstream.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Password login and JWKS do not move with the database.</strong>{" "}
            Login stays bound on Argon2id (within ±4%). JWKS, which never
            queries the database, read 16–17% lower with the load generator at
            7.5 cores in both passes; it is a generator-bound cell and we do not
            attribute that difference to the server version.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Part of the story since run 5, not all of it.</strong> On
            3.3.5, AXIAM's token issuance at 2 CPUs is 1,922 req/s against run
            5's 2,804 on a different host; the 4.0.1 server accounts for a
            share of the run-5 → run-6 drop, and the rest is still to explain.
          </li>
        </ul>
      </section>

      {/* ---- Efficiency ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Efficiency" title="Throughput per core & CPU cost" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 20 }}>
          Whole-stack, plaintext. AXIAM's figures carry its audit broker and a
          saturated database on every cell except JWKS, and Keycloak now wins
          introspection and userinfo on both measures. Server-only, AXIAM is the
          cheapest on all four — see the CPU chart below. Reported plainly.
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
          Memory and CPU are sampled per container, every second, throughout
          every cell — so the throughput numbers above come with the bill for
          producing them. Same load, same 2-CPU / 2&nbsp;GiB envelope for every
          server. All figures are the p0-plaintext profile, median of three
          runs.
        </p>

        <div style={{ display: "flex", flexDirection: "column", gap: 20, marginTop: 22 }}>
          <MemoryCapChart />

          <ResourceChart
            title="Server memory by scenario"
            unit="average resident memory of the server container · MiB · lower is better"
            rows={BENCH_MEMORY_AVG}
            format={(n) => `${n.toLocaleString("en-US")} MiB`}
            footnote="† Authorization checks and batches have no competitor equivalent; AXIAM's server ran them in 57 MiB. Zitadel has no valid login or refresh cell (its default bcrypt cost, and a fallback operation), and authentik no valid cell at all, so neither is charted here."
          />

          <ResourceChart
            title="CPU cost per request"
            unit="cpu·ms per request · whole stack unless noted · lower is better"
            rows={BENCH_CPU_PER_REQ}
            format={(n) => n.toFixed(2)}
            scale="row"
            footnote="Whole-stack, Keycloak wins introspection and userinfo — AXIAM's figures there carry a pegged SurrealDB plus RabbitMQ. Server-only, AXIAM is the cheapest on every row: 0.42 cpu·ms per userinfo against Keycloak's 0.52, 0.44 per token against 4.89. Both views are published; neither is hidden."
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
            style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5, minWidth: 640 }}
          >
            <thead>
              <tr>
                {["Target", "Under load (avg)", "At rest · RSS", "At rest · working set", "What's in it"].map((h) => (
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
                        fontFamily: ci >= 1 && ci <= 3 ? "ui-monospace,Menlo,monospace" : undefined,
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
          Whole-stack MiB. Under load is the range of per-cell averages over
          every valid cell; at rest is the median of a freshly started stack.
          Read plainly: <strong style={{ color: "#e2e8f0" }}>which stack is
          smallest at rest depends on the measure</strong>. By resident memory
          AXIAM's is (373 MiB against Zitadel's 593), by cgroup working set
          Zitadel's is (172 against 216) — PostgreSQL's shared buffers count in
          its resident set. Under load AXIAM's server averaged 54–75 MiB
          across the entire matrix, of the same 2 GiB allowance that Keycloak's
          filled to 941.
        </p>
      </section>

      {/* ---- AXIAM-only authz ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="AXIAM-only" title="Authorization decisions" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 22 }}>
          No head-to-head here — no other target exposes an equivalent decision
          endpoint. Each check is a full RBAC evaluation (tenant-scoped roles,
          resource hierarchy, scopes) against live data, over REST and gRPC,
          with the decision cache off. Batch bars are checks/s at the shipped{" "}
          <code style={{ color: "#67e8f9" }}>coalesced</code> default, five
          checks per batch. The cache-on sensitivity pass of run 5 was not
          repeated.
        </p>
        <BarChart scenario={BENCH_AUTHZ} />
      </section>

      {/* ---- TLS / mTLS cost ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Security cost" title="What TLS 1.3 and mutual TLS cost" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760, marginBottom: 20 }}>
          Throughput delta against the plaintext cell of the same scenario, from
          the run of record at median-of-3. Both encrypted profiles terminate
          in-process — no proxy, no sidecar — and on p3 the verified client
          certificate is the identity source. Most REST rows measure TLS{" "}
          <em>plus</em> an HTTP/1.1→2 protocol change together, and are labelled
          as such in the raw report.
        </p>
        <div className="glass-card" style={{ padding: 4, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5, minWidth: 480 }}>
            <thead>
              <tr>
                {["Scenario", "TLS 1.3 (p2)", "Mutual TLS (p3)"].map((h) => (
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
              {BENCH_TLS_COST.map((row) => (
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
                  {[row.tls, row.mtls].map((cell, ci) => (
                    <td
                      key={ci}
                      style={{
                        padding: "11px 16px",
                        borderBottom: "1px solid rgba(255,255,255,.06)",
                        color: "#cbd5e1",
                        fontFamily: "ui-monospace,Menlo,monospace",
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
        <p style={{ margin: "16px 4px 0", fontSize: 13.5, color: "#94a3b8", lineHeight: 1.7, maxWidth: 760 }}>
          The headline holds a fourth time, with a qualifier:{" "}
          <strong style={{ color: "#e2e8f0" }}>
            native mutual TLS costs AXIAM within ±2% of plaintext on every
            database-bound scenario
          </strong>
          , because the TLS work lands on a server with spare cores while the
          ceiling is the database. JWKS, where the server works hardest, shows
          the cost of the cryptography itself: −16.0% under TLS&nbsp;1.3 and
          −12.7% under mTLS. For comparison, Keycloak pays −9.8% to −17.0%
          under mTLS on introspection, userinfo and JWKS, and is valid at every
          profile this run; Zitadel's valid cells sit between −2.1% and +2.6%.
        </p>
      </section>

      {/* ---- SDK benchmarks ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="SDKs" title="What the client libraries cost" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760 }}>
          All eleven official SDKs (1.3.1) run the same four operations against
          the same seeded AXIAM at plaintext —{" "}
          <strong>three passes each, medianed</strong> — with a
          matched-concurrency k6 wire baseline measured on the same host. That
          baseline is what makes the last column meaningful: it is the
          authorization-check p95 an SDK adds over raw HTTP at the same
          concurrency. Every SDK ran clean, all three passes, zero errors.
        </p>

        <div className="glass-card" style={{ padding: 4, marginTop: 22, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13, minWidth: 720 }}>
            <thead>
              <tr>
                {[
                  "SDK",
                  "login p50",
                  "refresh p50",
                  "check p50",
                  "check p95",
                  "check thr",
                  "p95 overhead vs wire",
                ].map((h, i) => (
                  <th
                    key={h}
                    style={{
                      textAlign: i === 0 ? "left" : "right",
                      padding: "12px 14px",
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
              {BENCH_SDK_LATENCY.map((row) => (
                <tr key={row.sdk}>
                  <td
                    style={{
                      padding: "11px 14px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      color: "#e2e8f0",
                      fontWeight: 700,
                    }}
                  >
                    {row.sdk}
                    {row.serial && (
                      <span style={{ color: "#64748b", fontWeight: 500 }}> · serial</span>
                    )}
                    {row.flag && (
                      <div style={{ fontSize: 11.5, color: "#ffd98a", fontWeight: 500, marginTop: 2 }}>
                        ⚠ {row.flag}
                      </div>
                    )}
                  </td>
                  {[row.login, row.refresh, row.checkP50, row.checkP95, row.thr, row.overhead].map(
                    (cell, ci) => (
                      <td
                        key={ci}
                        style={{
                          padding: "11px 14px",
                          borderBottom: "1px solid rgba(255,255,255,.06)",
                          textAlign: "right",
                          whiteSpace: "nowrap",
                          fontFamily: "ui-monospace,Menlo,monospace",
                          color:
                            ci === 5 && row.best
                              ? "#67e8f9"
                              : cell === "—"
                                ? "#64748b"
                                : "#cbd5e1",
                          fontWeight: ci === 5 && row.best ? 700 : 400,
                        }}
                      >
                        {cell}
                      </td>
                    ),
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p style={{ margin: "12px 4px 0", fontSize: 12.5, color: "#64748b", lineHeight: 1.6 }}>
          Milliseconds unless noted; throughput in requests/s; concurrency 16.
          The two <em>serial</em> harnesses (C and PHP) drive a single worker by
          their own design, so their throughput and latencies — login
          included, which never queues behind other hashes — are not
          comparable with the others, and no overhead is computed for them.
        </p>

        <ul style={{ margin: "20px 0 0", paddingLeft: 22, color: "#cbd5e1", lineHeight: 1.75, maxWidth: 760 }}>
          <li style={{ marginBottom: 8 }}>
            <strong>The server, not the SDKs, sets the floor.</strong> All nine
            concurrent SDKs measure login at 324–336 ms p50 and refresh at
            10.3–12.1 ms — server-side Argon2id and the database dominate
            identically from every language, and check throughput is bounded by
            the same pegged SurrealDB as the matrix.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Hot-path overhead is under 3.5 ms</strong> at p95 for eight
            of the nine concurrent SDKs (+0.5 to +3.2 ms over raw k6 at the
            same concurrency).
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Python is still the outlier</strong> (check p50 39 ms, +21 ms
            p95 overhead) on a uvloop event loop with one worker thread; the gap
            belongs to the SDK/runtime and is being profiled.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Two run-5 flags are cleared.</strong> C++'s
            reconnect-shaped tail is gone (p95 72.0 ms), and TypeScript's
            negative overhead is now a coherent +3.2 ms.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Some login overheads read negative</strong> (by up to
            −7.9 ms), which is why the table carries no login overhead:
            login latency is dominated by queuing behind server-side hashing,
            so a few milliseconds either side of the baseline is noise, not SDK
            cost.
          </li>
        </ul>

        <h3 style={{ margin: "34px 0 6px", fontSize: 17, fontWeight: 700 }}>
          Client-side footprint
        </h3>
        <p style={{ fontSize: 14, color: "#94a3b8", lineHeight: 1.7, maxWidth: 760, margin: "0 0 18px" }}>
          Each SDK's own process CPU over the whole bench and its peak resident
          memory, median of three passes — half the story for IoT and sidecar
          deployments, where the client is the constrained side.
        </p>
        <div className="glass-card" style={{ padding: 4, overflowX: "auto" }}>
          <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 13.5, minWidth: 480 }}>
            <thead>
              <tr>
                {["SDK", "Runtime", "Client CPU (s)", "Peak RSS (MiB)"].map((h, i) => (
                  <th
                    key={h}
                    style={{
                      textAlign: i > 1 ? "right" : "left",
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
              {BENCH_SDK_FOOTPRINT.map((row) => (
                <tr key={row.sdk}>
                  <td
                    style={{
                      padding: "11px 16px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      color: "#e2e8f0",
                      fontWeight: 700,
                    }}
                  >
                    {row.sdk}
                    {row.serial && (
                      <span style={{ color: "#64748b", fontWeight: 500 }}> · serial</span>
                    )}
                  </td>
                  <td
                    style={{
                      padding: "11px 16px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      color: "#94a3b8",
                    }}
                  >
                    {row.runtime}
                  </td>
                  <td
                    style={{
                      padding: "11px 16px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      textAlign: "right",
                      fontFamily: "ui-monospace,Menlo,monospace",
                      color: row.cpu <= 4.4 ? "#67e8f9" : "#cbd5e1",
                      fontWeight: row.cpu <= 4.4 ? 700 : 400,
                    }}
                  >
                    {row.cpu.toFixed(1)}
                  </td>
                  <td
                    style={{
                      padding: "11px 16px",
                      borderBottom: "1px solid rgba(255,255,255,.06)",
                      textAlign: "right",
                      fontFamily: "ui-monospace,Menlo,monospace",
                      color: row.rss <= 23 ? "#67e8f9" : "#cbd5e1",
                      fontWeight: row.rss <= 23 ? 700 : 400,
                    }}
                  >
                    {row.rss}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <p style={{ margin: "16px 4px 0", fontSize: 13.5, color: "#94a3b8", lineHeight: 1.7, maxWidth: 760 }}>
          C++ is now the cheapest concurrent client on both CPU and memory (3.0
          s, 15 MiB), with Go close on CPU; C, C++ and Rust are the smallest on
          memory (10, 15 and 23 MiB — the embedded/IoT lane); the JVM SDKs pay
          the expected 335–623 MiB runtime tax at equal wire performance;
          Python is the most expensive on CPU <em>and</em> the slowest, a
          consistent picture. One number we flag for the second run in a row
          rather than explain: Rust's client CPU (22 s) reads high against its
          memory footprint and its latency profile, and is on the list to be
          traced.
        </p>
      </section>

      {/* ---- Sensitivity ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Findings" title="What run 6 found" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 20 }}>
          Run 6 ran the comparison only — no investigation passes — so these
          are readings of the matrix, each with the evidence behind it. The
          first two are the story of this run, and they are not flattering.
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {FINDINGS.map((s) => (
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

      {/* ---- §10 excerpt: why build AXIAM at all? ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Reading the numbers" title="Why build AXIAM at all?" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760, marginBottom: 20 }}>
          A fair question given this field: Keycloak is mature and ubiquitous,
          Zitadel is modern and well-engineered, Auth0 and Okta are excellent
          managed products. Six runs of measurements into this project, and
          with this run's losses on the table, the answer is:
        </p>
        <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
          {WHY_AXIAM.map((w) => (
            <div key={w.n} className="glass-card" style={{ padding: 22, display: "flex", gap: 16 }}>
              <div
                aria-hidden="true"
                style={{
                  flex: "none",
                  width: 30,
                  height: 30,
                  borderRadius: 8,
                  display: "grid",
                  placeItems: "center",
                  background: "rgba(0,212,255,.08)",
                  border: "1px solid rgba(0,212,255,.25)",
                  color: "#67e8f9",
                  fontWeight: 800,
                  fontSize: 14,
                }}
              >
                {w.n}
              </div>
              <div>
                <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 6, color: "#67e8f9" }}>
                  {w.title}
                </div>
                <p style={{ margin: 0, fontSize: 13.5, color: "#94a3b8", lineHeight: 1.65 }}>
                  {w.body}
                </p>
              </div>
            </div>
          ))}
          <div
            className="glass-card"
            style={{
              padding: 22,
              borderColor: "rgba(255,189,46,.35)",
              background: "rgba(255,189,46,.06)",
            }}
          >
            <div style={{ fontWeight: 700, fontSize: 15, marginBottom: 6, color: "#ffd98a" }}>
              And the honest cons, in the same breath
            </div>
            <p style={{ margin: 0, fontSize: 13.5, color: "#e2e8f0", lineHeight: 1.7 }}>
              {WHY_AXIAM_CONS}
            </p>
          </div>
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
            Metric definitions live in the repository under{" "}
            <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
              benchmarks/docs/methodology.md
            </code>
            ;{" "}
            <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
              benchmarks/PUBLIC_BENCH_ANALYSIS.md
            </code>{" "}
            is still the run-5 analysis until its seventh draft is written from
            this run. Sources: benchmark run 6 of 2026-11-20/21 (median-of-3
            capped matrix × three profiles × four targets, 66 of 84 cells
            valid, against the digest-pinned{" "}
            <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
              1.3.0
            </code>{" "}
            release image; resting footprints of the four stacks; an
            11-language SDK median-of-3 pass with a matched-VU wire baseline and
            client CPU/RSS telemetry; per-cell k6 summaries with 1-second
            container and host telemetry). Target versions: AXIAM 1.3.0,
            Keycloak 26.8.1, Zitadel v4.19.5, authentik 2026.8.5, SurrealDB
            v4.0.1, PostgreSQL 16. Host: Infomaniak Public Cloud, AMD EPYC
            Genoa, 16 vCPUs, 64 GiB. Run 6b of 2026-11-21/22 on the same VM:
            p0-plaintext, median of 3, a 2/2 control pass of AXIAM 1.3.1
            (image digest recorded) and a 4/4 pass of all four targets on the
            run-6 competitor and SurrealDB digests, 22 of 30 cells valid. Run
            6c of 2026-11-23/24 on the same VM: the same AXIAM 1.3.1 image
            against a SurrealDB 3.3.5 server (digest recorded; unsupported,
            benchmark-only), p0-plaintext at 2/2 and 4/4, median of 3, 66 of 66
            cells valid.
          </p>
        </div>
      </section>
    </div>
  );
}

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
        The cap is 2 GiB for every target — raised from 1 GiB two runs ago,
        equally for all three, because Keycloak could not reliably survive
        sustained password-login load below it. Across this entire matrix
        AXIAM's server averaged 86–120 MiB, under 6% of the same allowance,
        while delivering the throughput numbers above; Keycloak's heaviest
        scenario averaged 853 MiB, and raising its cap to 4 GiB for a labelled
        login attempt made it slower rather than faster.
      </p>
    </div>
  );
}

/* ---- headline stat cards ---------------------------------------------- */

const HEADLINES = [
  {
    label: "Token issuance",
    value: "6.5–7.9×",
    sub: "more tokens/s than Zitadel / Keycloak — and now the same ~8× under TLS 1.3 and mutual TLS",
  },
  {
    label: "Identity reads over gRPC",
    value: "12,307",
    sub: "req/s at a 6 ms p95 — 3.3× Keycloak's best userinfo number; Zitadel's gRPC measures 191/s",
  },
  {
    label: "Native mutual TLS",
    value: "≈1%",
    sub: "cost over plain TLS 1.3, in-process, no sidecar — in the run of record at median-of-3",
  },
];

/* ---- environment facts ------------------------------------------------- */

const TARGETS = [
  [
    "AXIAM",
    "AXIAM 1.0.0-alpha24 — the published release image, pinned by digest",
    "SurrealDB v3 (digest-pinned) + RabbitMQ 4",
  ],
  ["Keycloak", "Keycloak 26.7.0 (JVM)", "PostgreSQL 16 (uniformly tuned)"],
  ["Zitadel", "Zitadel v4.16.2 (Go)", "PostgreSQL 16 (uniformly tuned)"],
];

/* ---- sensitivity highlights -------------------------------------------- */

const SENSITIVITY = [
  {
    title: "Mystery 1 closed — the TLS plateau was Nagle's algorithm",
    body: "The previous draft published a −57% TLS drop on token issuance as an open question with a named suspect: actix-web never set TCP_NODELAY, so Nagle's algorithm held the second TLS record of each HTTP/2 response until the peer's 40 ms delayed-ACK timer fired. The controlled A/B settles it — 1,172 req/s with the old behaviour (a flat 42.8 / 44.1 ms plateau, reproduced exactly), 2,642 req/s with TCP_NODELAY, against a 2,757 req/s plaintext control. The wire-level photograph confirms the mechanism: an `ss -ti` snapshot inside the server's network namespace caught 18 of 20 connections frozen with bytes in the send queue behind a single unacked segment, versus zero in the control. TCP_NODELAY now ships on by default, and the TLS penalty is −2.0%.",
  },
  {
    title: "Mystery 2 closed — REST's authz deficit was one database read",
    body: "With the decision cache on, gRPC checks used to reach 13× while REST barely moved. A 2×2 (decision cache × session-validation cache) confirms the cause: REST validates session revocation on every request, gRPC validates the JWT and stops. Turning both caches on lifts REST from 5,597 to 11,647 checks/s — parity with gRPC's 11,172 — while the session cache does nothing at all for gRPC, which never did the read. Both caches remain OFF by default: these are hot-key ceilings, not expectations. The flip side is stated with the same candour — part of gRPC's speed is that it does not re-check revocation per call, so token expiry (15 min max) is its revocation bound, a documented posture choice with a strict mode on the roadmap.",
  },
  {
    title: "Caching and revocation, measured rather than assumed",
    body: "The obvious objection to any decision cache is that it delays revocation, so this run measured it twice over with caching on at a 5 s TTL. Revoke a role through the API and the invalidation hook fires end to end: a deny is served 262 ms after the revocation call. Delete the grant behind the server's back — directly in the database, suppressing every hook — and stale allows persist to 5.2 s, inside the promised TTL-plus-slack bound. Revocation through the API is immediate even with caches on; only out-of-band database surgery waits out the TTL, which is exactly the documented contract.",
  },
  {
    title: "Mystery 3 closed — per-query waste removed, concurrency remains",
    body: "EXPLAIN on the live schema found two full-table scans on the hot authorization read path. Removing them (no schema change needed) took cache-off capped checks from 753 to 1,010–1,032 req/s, past the pre-registered 1,000 bar, and CI tests now fail if any hot authorization query ever regresses to a table scan. The capped→uncapped delta (2→4 database cores) narrowed from ~+90% to +75–79%, which reframes the ceiling: per-query cost is no longer the dominant waste, database concurrency is. Read-scaling now outranks further per-query tuning on the roadmap, and \"give the database cores first\" remains the operative sizing guidance for authz-heavy workloads.",
  },
  {
    title: "Native mTLS is still free — now in the run of record",
    body: "The p3 profile terminates client-certificate TLS 1.3 inside the server process — no proxy in front, the verified peer certificate is the identity source. This run promotes it from a sensitivity pass to a full matrix profile at median-of-3, and it holds: mutual TLS costs about 1% over plain TLS 1.3 on every scenario. For an IoT or zero-trust fleet that needs client certificates on every connection, AXIAM is the only one of the three offering this in-process, and it is effectively free — where Keycloak pays −17% on its hottest read under mTLS and could not produce a valid login cell under it at all.",
  },
];

const CAVEATS = [
  {
    title: "Session/token refresh regressed 35% — and it is our own doing",
    body: "AXIAM's refresh cell fell from 839 to 545 req/s (p50 47.5 → 88.8 ms) between the two runs, on tight medians, with no harness change anywhere on that path. The suspects are our own post-run-4 security-hardening commits and/or database version drift, and a stage-timed bisection is queued. The cross-vendor position is unchanged — AXIAM still leads Keycloak on this cell, under its protocol-variant label — but we would rather flag our own regression than let a favourable ratio hide it.",
  },
  {
    title: "The rate limiter fails our own enforcement assertions — in both directions",
    body: "This run added an automated check comparing configured limits against admitted rates under a single-IP flood, with a ±10% bar. Login passes exactly (11/min admitted against 10 configured). The REST machine endpoints over-admit — +12% on token, +48% on introspect, +50% on authz check — as token-bucket burst bleeds into the sustained window. The gRPC families under-admit by ×20–33 (181/min admitted against 6,000 configured on authz): the ×60 units bug of the previous draft is genuinely fixed, but two cooperating limiter layers with mismatched windows appear to compound under overload, which is a real availability bug under attack. Three limiter families (revoke, gRPC admin, gRPC infra) still have no test scenario. Compliant clients under the limit are unaffected by any of this — but until it is fixed and re-measured we do not advertise gRPC throughput under the abuse posture, and we publish the failing table rather than the passing subset.",
  },
  {
    title: "Keycloak's login story is genuinely hard to measure fairly",
    body: "We raised Keycloak's cap to 4 GiB as promised, and it got slower: ~21 req/s at a ~2.5 s p95, still failing the validity gate and below its 2 GiB survivor runs. Its login behaviour looks memory-sensitive rather than simply memory-starved, so we will say that rather than keep raising its cap. Credit where it is due — it produced its first valid login cell of this series at p2 (51 req/s), and that is charted. Zitadel's login exclusion remains its default bcrypt cost, which is expected and tunable, and its refresh exclusion is a flow our harness still doesn't implement.",
  },
  {
    title: "Median-of-3 on a release image — but still a laptop",
    body: "64 of 72 matrix cells are valid and every invalid cell is listed with its reason; every cell is the median of three runs (spread ≤ ±2% on AXIAM cells, ±13–17% on the batch cells, where coalescing is phase-sensitive). The hardware is still a consumer laptop (Dell XPS 15, i7-8750H): package temperatures hit 95–100 °C on hot cells and the clock varied 3.1–3.9 GHz. The thermal envelope was identical for all targets, so cross-target fairness holds and absolute numbers are, if anything, conservative — but the server-class re-run remains the standing caveat, and the biggest single upgrade this series can still make.",
  },
  {
    title: "Not a like-for-like re-run of the previous draft",
    body: "Between the two runs, two authorization table scans were removed, Nagle was disabled on the REST listener, the gRPC rate-limiter units bug was fixed, the shipped rate-limit defaults were revised, and the batch default the harness measures finally matches the batch default the product ships. Treat this run as the new baseline; where a controlled comparison was wanted, a one-variable A/B was run and is reported as such. The investigation passes are single labelled runs by design — only the matrix cells are median-of-3.",
  },
];

const NEXT = [
  "The refresh-regression bisection, stage-timed",
  "Fix the gRPC limiter starvation and the REST over-admission, re-verified by the same assertion script that failed them here",
  "Scenario coverage for the three untested limiter families",
  "The TypeScript wire-baseline audit before any TS overhead claim is published",
  "Profile the Python SDK gap that survived the async-driver fix",
  "Chase the C++ reconnect tail into server-side idle-timeout suspects",
  "A server-class re-run to replace the laptop numbers",
];

/* ---- §10 excerpt: why build AXIAM at all? ------------------------------ */

/**
 * Excerpted from §10 of `benchmarks/PUBLIC_BENCH_ANALYSIS.md`. The report
 * answers the fair question the field invites — Keycloak is mature and
 * ubiquitous, Zitadel is modern and well-engineered — from the measurements
 * rather than from ambition, and it answers it with the cons attached. Both
 * halves are reproduced here.
 */
const WHY_AXIAM = [
  {
    n: "1",
    title: "The efficiency gap is real, large, and it is the product",
    body: "These are not micro-optimizations: on identical hardware, identical caps and identical scenarios, AXIAM issues ~8× the tokens, introspects ~2.4–4.8× the tokens, and serves ~6–13× the JWKS reads of the incumbents — in 86–120 MiB of server RSS, under 8% of what Keycloak uses for less throughput. IAM is infrastructure that runs 24/7 in front of everything; its cost floor and its p95 are a tax every request in the system pays. Rust with no GC pauses, no JVM warm-up, and CPU-shaped-per-request economics moves that floor by close to an order of magnitude — that is a capability difference, not a benchmark trophy.",
  },
  {
    n: "2",
    title: "Nobody else treats the machine/IoT edge as the main stage",
    body: "Authorization decisions as a first-class, benchmarked hot path (5,100+ hierarchy-aware RBAC checks/s on 2+2 cores, batch API at the shipped default); a gRPC data plane that does 12,000+ identity reads/s at a 6 ms p95 (the competitors' gRPC surfaces are management APIs, and it shows — Zitadel's measures 200/s); and in-process mutual TLS at ~1% cost, no sidecar — which makes per-device client certificates the cheap option for IoT fleets rather than an architecture project. If your workload is humans logging into web apps, Keycloak serves you well today. If it is services and devices asking “may I?” tens of thousands of times a second, that workload is what AXIAM is shaped around.",
  },
  {
    n: "3",
    title: "Security posture as measured defaults, not documentation",
    body: "AXIAM is the only target here that ships abuse rate-limits on by default — sized from these measurements, with human endpoints locked strictly regardless of posture (and login enforcement measured exact under flood; the machine-endpoint enforcement gaps above are published, tracked bugs, not fine print). Argon2id, EdDSA short-lived tokens, single-use rotating refresh tokens, append-only audit and encrypted-at-rest secrets are defaults, not options. And the process is part of the posture: this benchmark series has now found, published and fixed a synchronous rate-limit write, a ×60 limiter units bug, a Nagle-induced TLS latency cliff and two authorization table scans — and currently carries an open refresh regression and a gRPC flood-behaviour bug in public view. We think an IAM vendor that measures itself adversarially and publishes the misses is itself a security feature.",
  },
];

const WHY_AXIAM_CONS =
  "AXIAM is alpha: it has a fraction of Keycloak's protocol surface, extension ecosystem, hosting options and community; Zitadel's resting stack is smaller than ours (SurrealDB + RabbitMQ ride along in every AXIAM deployment); Keycloak wins one whole-stack efficiency cell outright; our RBAC engine is additive-only in v1.0-beta (no deny-override); SurrealDB is a younger storage engine than Postgres by a decade; and every number in this document comes from one consumer laptop until the server-class re-run lands. Choosing AXIAM today means choosing a young system whose performance-per-watt, machine-first design and measurement culture you value over incumbent breadth. That trade is exactly the niche the incumbents leave open — and the measurements above are why we believe the niche is worth serving.";

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
        OAuth2/OIDC flows. Below are the run-5 results — the first measured
        against a <strong style={{ color: "#e2e8f0" }}>published release image</strong>{" "}
        rather than a working tree, pulled by digest exactly as any reader would
        pull it, and the first with the full three-profile matrix (plaintext,
        TLS&nbsp;1.3, native mutual TLS) in the run of record.
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
            Preliminary results — the benchmark is still being improved
          </div>
          <p style={{ margin: 0, fontSize: 14, lineHeight: 1.65, color: "#e2e8f0" }}>
            These numbers come from run 5 (2026-08-05/06) — a full{" "}
            <strong>median-of-3</strong> matrix, three targets, three profiles
            (plaintext, TLS 1.3, native mTLS), 64 of 72 cells valid with every
            invalid cell listed and explained, measured against the released,
            digest-pinned <code>1.0.0-alpha24</code> image. The story of this
            draft is that all three of the previous draft's open mysteries were
            closed with controlled experiments — the TLS plateau, the REST/gRPC
            authorization asymmetry and the database ceiling. It also found two
            new problems, published here with the same candour: a refresh
            regression we introduced ourselves, and a rate limiter that fails
            our own enforcement assertions. Everything still runs on a consumer
            laptop rather than server-class hardware. Treat these as a strong,
            reproducible signal, not a final verdict; this page is updated as
            each improved run lands.
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
            ["Profiles", "Three, all median-of-3 in the run of record: p0-plaintext, p2-tls13 (TLS 1.3 terminated in-process by all three targets, gRPC included) and p3-mtls (in-process mutual TLS), now a full matrix profile rather than a sensitivity pass."],
            ["Validity gates", "A cell counts only if error rate ≤ 1% and p95 < 2000 ms. Failing cells are labelled, never charted as a head-to-head — 64 of 72 cells passed this run, and the settle gate cleared first-probe on every session."],
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
            records its image digest, and this run benchmarks a{" "}
            <em>published</em> artifact —{" "}
            <code>ghcr.io/ilpanich/axiam/server:1.0.0-alpha24</code>, pinned by
            digest and pulled exactly as any reader would pull it — so the
            numbers describe a release anyone can fetch rather than a working
            tree only we can build.
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
            footnote="* Keycloak's login cells are only partially valid, and its 4 GiB labelled attempt is excluded from this chart entirely — it is reported in the caveats instead. † Authorization checks and batches have no competitor equivalent; AXIAM's server ran them in 86–94 MiB. Zitadel has no refresh cell — its flow is excluded from this run."
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
          smallest at rest</strong> — its Go server is respectably compact and its
          costs surface as CPU per request instead. AXIAM's stack is not the
          smallest, but it does the most work per byte and per core, by 1.6× to
          24× on every cell except one. And where Keycloak needed its memory cap
          doubled just to run the login scenario — then got slower when we
          doubled it again — AXIAM's server averaged 86–120 MiB across the
          entire matrix, of the same 2 GiB allowance.
        </p>
      </section>

      {/* ---- AXIAM-only authz ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="AXIAM-only" title="Authorization decisions" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 22 }}>
          No head-to-head here — Keycloak and Zitadel expose no equivalent decision
          endpoint. Each check is a full RBAC evaluation (tenant-scoped roles,
          resource hierarchy, scopes) against live data, over REST and gRPC,
          with the decision cache off. Batch bars are checks/s at the shipped{" "}
          <code style={{ color: "#67e8f9" }}>coalesced</code> default — measured
          at full matrix scale this time, after the previous run's harness pin
          accidentally exercised a non-default strategy. The two cache-ON bars
          are a labelled best-case sensitivity pass, not the default
          configuration.
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
          The headline stands its third and strongest re-measurement:{" "}
          <strong style={{ color: "#e2e8f0" }}>
            native mutual TLS costs AXIAM about 1% over plain TLS 1.3 on every
            scenario
          </strong>
          . For comparison, Keycloak pays up to −17.2% under mTLS on its hottest
          read and could not produce a valid login cell under it; Zitadel's
          valid cells sit between −1.7% and −3.9%.
        </p>
      </section>

      {/* ---- SDK benchmarks ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="SDKs" title="What the client libraries cost" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760 }}>
          All eleven official SDKs run the same four operations against the same
          seeded AXIAM at plaintext — <strong>three passes each, medianed</strong>{" "}
          — with a matched-concurrency k6 wire baseline measured on the same host
          first. That baseline is what makes the last column meaningful: it is
          the authorization-check p95 an SDK adds over raw HTTP at the same
          concurrency, and this is the first run of this series that can publish
          it honestly.
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
          their own design, so their throughput is not comparable with the
          others and they run no login/refresh op-cell.
        </p>

        <ul style={{ margin: "20px 0 0", paddingLeft: 22, color: "#cbd5e1", lineHeight: 1.75, maxWidth: 760 }}>
          <li style={{ marginBottom: 8 }}>
            <strong>The server, not the SDKs, sets the floor.</strong> Ten SDKs
            measure refresh at 16.7–17.3 ms p50 and login at 232–257 ms —
            server-side Argon2id dominates identically from every language.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Hot-path overhead is single-digit milliseconds</strong> at
            p95 for seven of the nine concurrent SDKs (+2.7 to +4.6 ms over raw
            k6 at the same concurrency) — the headline the wire baseline was
            built to establish.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>Python is still the outlier</strong> after moving to a
            genuinely async driver (p50 40 ms, +60 ms p95 overhead). The previous
            draft blamed the harness; the harness is now clean, so the remaining
            gap belongs to the SDK/runtime and is being profiled.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>C++ keeps its reconnect-shaped tail</strong> (p50 3.2 ms,
            p95 280 ms) despite the connection-age fix — the investigation has
            moved to server-side idle-timeout suspects.
          </li>
          <li style={{ marginBottom: 8 }}>
            <strong>TypeScript's negative “overhead” is flagged, not
            celebrated.</strong> A client should not beat the wire baseline on
            the same box, so its baseline comparability is under audit before we
            publish any TS overhead claim.
          </li>
        </ul>

        <h3 style={{ margin: "34px 0 6px", fontSize: 17, fontWeight: 700 }}>
          Client-side footprint
        </h3>
        <p style={{ fontSize: 14, color: "#94a3b8", lineHeight: 1.7, maxWidth: 760, margin: "0 0 18px" }}>
          New this run: each SDK's own process CPU over the whole bench and its
          peak resident memory — half the story for IoT and sidecar deployments,
          where the client is the constrained side. First pass of this telemetry.
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
                      color: row.cpu <= 3.3 ? "#67e8f9" : "#cbd5e1",
                      fontWeight: row.cpu <= 3.3 ? 700 : 400,
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
          Go is by far the cheapest concurrent client on CPU; C and Rust are the
          smallest on memory (13 and 23 MiB — the embedded/IoT lane); the JVM
          SDKs pay the expected 300–460 MiB runtime tax at equal wire
          performance; Python is the most expensive on CPU <em>and</em> the
          slowest, a consistent picture. One number we flag rather than explain:
          Rust's client CPU reads high relative to its excellent latency
          profile, and since this is the first run of this telemetry, that figure
          gets a second look before we draw conclusions from it.
        </p>
      </section>

      {/* ---- Sensitivity ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="Investigation" title="Three mysteries, closed" />
        <p style={{ fontSize: 14, color: "#64748b", lineHeight: 1.6, maxWidth: 760, marginBottom: 20 }}>
          The previous draft published three unexplained results as open
          questions with named hypotheses. Run 5 tested all three with labeled
          single-variable passes — never mixed into the comparison tables — and
          closed all three with data. This is why we benchmark in the open: the
          benchmark is also a debugger.
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

      {/* ---- §10 excerpt: why build AXIAM at all? ---- */}
      <section style={{ marginBottom: 52 }}>
        <SectionTitle kicker="From the report · §10" title="Why build AXIAM at all?" />
        <p style={{ fontSize: 15, color: "#cbd5e1", lineHeight: 1.7, maxWidth: 760, marginBottom: 20 }}>
          A fair question given this field: Keycloak is mature and ubiquitous,
          Zitadel is modern and well-engineered, Auth0 and Okta are excellent
          managed products. Five drafts of measurements into this project, the
          answer has sharpened rather than softened. Excerpted from §10 of the
          analysis:
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
            Full data, metric definitions and the raw per-cell telemetry live in
            the repository under{" "}
            <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
              benchmarks/PUBLIC_BENCH_ANALYSIS.md
            </code>{" "}
            and{" "}
            <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
              benchmarks/docs/methodology.md
            </code>
            . Sources: benchmark run 5 of 2026-08-05/06 (median-of-3 capped
            matrix × three profiles × three targets, against the digest-pinned{" "}
            <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
              1.0.0-alpha24
            </code>{" "}
            release image; labeled investigation passes for the TCP_NODELAY A/B
            with VU sweep and in-namespace socket captures, the session/decision
            cache 2×2, the cache-on revocation cell, DB capped/uncapped, the
            4 GiB Keycloak login attempt and the production rate-limit posture;
            an 11-language SDK median-of-3 pass with a matched-VU wire baseline
            and client CPU/RSS telemetry; per-cell k6 summaries with 1-second
            container and host telemetry). Target versions: AXIAM 1.0.0-alpha24,
            Keycloak 26.7.0, Zitadel v4.16.2, SurrealDB v3, PostgreSQL 16.
          </p>
        </div>
      </section>
    </div>
  );
}

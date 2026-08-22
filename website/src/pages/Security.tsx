import { Suspense, lazy, useEffect, useState } from "react";
import type { Page } from "../types";
import { SEC_GROUPS, SEC_SECTIONS } from "../security";
import { SECURITY_VERIFIED_DATE, SECURITY_VERIFIED_RELEASE } from "../version";
import { THREAT_MODEL_SUMMARY } from "../threatModelSummary";
import Block from "../components/DocBlocks";

/**
 * The Security section — AXIAM's public threat-modeling and security write-up.
 *
 * One long, linkable document with a sticky section index: the narrative is the
 * point, so the sections scroll rather than swap. The interactive Threat Dragon
 * browser is code-split, because the generated model data is much larger than
 * the prose around it and most visitors read the summary without opening it.
 */

const ThreatModelExplorer = lazy(
  () => import("../components/ThreatModelExplorer"),
);

interface SecurityProps {
  go: (page: Page) => void;
}

const STATS = [
  { value: String(THREAT_MODEL_SUMMARY.total), label: "STRIDE threats modelled" },
  { value: String(THREAT_MODEL_SUMMARY.mitigated), label: "Mitigated" },
  { value: String(THREAT_MODEL_SUMMARY.open), label: "Open — with guidance" },
  { value: String(THREAT_MODEL_SUMMARY.diagramCount), label: "Data-flow diagrams" },
];

/** Highlight the section currently under the header as the reader scrolls. */
function useActiveSection(ids: string[]): string {
  const [active, setActive] = useState(ids[0]);

  useEffect(() => {
    if (typeof IntersectionObserver === "undefined") return;
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries
          .filter((e) => e.isIntersecting)
          .sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top);
        if (visible[0]) setActive(visible[0].target.id);
      },
      // Only count a section as current once its heading is under the sticky
      // header and it still occupies the upper part of the viewport.
      { rootMargin: "-88px 0px -70% 0px", threshold: 0 },
    );
    for (const id of ids) {
      const el = document.getElementById(id);
      if (el) observer.observe(el);
    }
    return () => observer.disconnect();
  }, [ids]);

  return active;
}

const SECTION_IDS = SEC_SECTIONS.map((s) => s.id);

export default function Security({ go }: SecurityProps) {
  const active = useActiveSection(SECTION_IDS);

  return (
    <div>
      {/* Hero */}
      <div className="ax-sec-hero">
        <span
          className="ax-pill"
          style={{
            border: "1px solid rgba(0,212,255,.3)",
            color: "#67e8f9",
            padding: "5px 13px",
          }}
        >
          Threat modeling &amp; security
        </span>
        <h1
          style={{
            margin: "16px 0 12px",
            fontSize: "clamp(32px, 6vw, 46px)",
            fontWeight: 800,
            letterSpacing: "-.02em",
            maxWidth: 820,
          }}
        >
          Security infrastructure has to show its work.
        </h1>
        <p
          style={{
            margin: "0 0 26px",
            fontSize: 17,
            color: "#94a3b8",
            maxWidth: 720,
            lineHeight: 1.65,
          }}
        >
          How AXIAM is designed to be secure, what it defends against, and where
          responsibility passes to whoever deploys it — backed by a public STRIDE
          threat model you can read here, element by element.
        </p>

        <div
          className="ax-sec-stats"
          style={{ display: "flex", flexWrap: "wrap", gap: 14, marginBottom: 8 }}
        >
          {STATS.map((s) => (
            <div
              key={s.label}
              className="glass-card"
              style={{ padding: "14px 20px", minWidth: 160, flex: "1 1 160px" }}
            >
              <div
                style={{
                  fontSize: 26,
                  fontWeight: 800,
                  color: "#67e8f9",
                  letterSpacing: "-.02em",
                }}
              >
                {s.value}
              </div>
              <div style={{ fontSize: 12.5, color: "#94a3b8" }}>{s.label}</div>
            </div>
          ))}
        </div>

        {/* Which release the claims on this page were checked against. Silent
            staleness is the failure mode a security page cannot afford. */}
        <p style={{ margin: "14px 0 0", fontSize: 13, color: "#64748b" }}>
          Verified against{" "}
          <code style={{ color: "#94a3b8", fontFamily: "ui-monospace,Menlo,monospace" }}>
            {SECURITY_VERIFIED_RELEASE}
          </code>{" "}
          · last re-derived from source on {SECURITY_VERIFIED_DATE}
        </p>
      </div>

      {/* Section index + document */}
      <div className="ax-sec">
        <aside className="ax-sec-side">
          {SEC_GROUPS.map((group, gi) => (
            <div key={group.label}>
              <div
                style={{
                  fontSize: 11,
                  textTransform: "uppercase",
                  letterSpacing: ".14em",
                  color: "#64748b",
                  margin: gi === 0 ? "0 0 10px 14px" : "22px 0 10px 14px",
                }}
              >
                {group.label}
              </div>
              {group.ids.map((id) => {
                const section = SEC_SECTIONS.find((s) => s.id === id);
                if (!section) return null;
                return (
                  <a
                    key={id}
                    href={`#${id}`}
                    className={`ax-side${id === active ? " ax-side-active" : ""}`}
                    style={{ textDecoration: "none" }}
                  >
                    {section.navLabel}
                  </a>
                );
              })}
            </div>
          ))}
        </aside>

        <article style={{ minWidth: 0 }}>
          {SEC_SECTIONS.map((section) => (
            <section
              key={section.id}
              id={section.id}
              style={{ scrollMarginTop: 88, marginBottom: 52 }}
            >
              <h2
                style={{
                  fontSize: "clamp(24px, 3.4vw, 30px)",
                  fontWeight: 800,
                  letterSpacing: "-.02em",
                  margin: "0 0 18px",
                  paddingBottom: 12,
                  borderBottom: "1px solid rgba(0,212,255,.14)",
                }}
              >
                {section.title}
              </h2>

              <div style={{ maxWidth: section.explorer ? "none" : 860 }}>
                {section.blocks.map((block, i) => (
                  <Block key={i} block={block} go={go} />
                ))}
              </div>

              {section.explorer && (
                <Suspense
                  fallback={
                    <p style={{ color: "#64748b", fontSize: 14 }}>
                      Loading the threat model…
                    </p>
                  }
                >
                  <ThreatModelExplorer />
                </Suspense>
              )}
            </section>
          ))}
        </article>
      </div>
    </div>
  );
}

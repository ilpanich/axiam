import type { Page } from "../types";
import { SDKS, GITHUB_URL } from "../data";
import {
  ShieldIcon,
  KeyholeIcon,
  LockIcon,
  NodesIcon,
  ListIcon,
  LayersIcon,
} from "../components/icons";
import { logoMark } from "../assets";
import type { JSX } from "react";

interface HomeProps {
  go: (page: Page) => void;
  openSdk: (id: string) => void;
}

interface Feature {
  icon: JSX.Element;
  accent: "cyan" | "purple";
  title: string;
  body: string;
}

const FEATURES: Feature[] = [
  {
    icon: <ShieldIcon />,
    accent: "cyan",
    title: "Multi-tenant RBAC",
    body: "Organizations contain tenants for full data isolation. Roles, permissions and groups cascade through a scoped resource hierarchy.",
  },
  {
    icon: <KeyholeIcon />,
    accent: "purple",
    title: "OAuth2 & OpenID Connect",
    body: "A full authorization server — PKCE, client credentials and refresh-token rotation — with SAML & OIDC federation for cross-domain SSO.",
  },
  {
    icon: <LockIcon />,
    accent: "cyan",
    title: "PKI & certificates",
    body: "Hierarchical X.509 certificates and mTLS for IoT devices, with GnuPG-backed audit-log signing and encrypted data exports.",
  },
  {
    icon: <NodesIcon />,
    accent: "purple",
    title: "Webhooks",
    body: "Real-time event delivery with HMAC-SHA256 signatures, so downstream systems can trust every payload they receive.",
  },
  {
    icon: <ListIcon />,
    accent: "cyan",
    title: "Tamper-evident audit",
    body: "An append-only, cryptographically chained audit trail — every privileged action logged, signed and verifiable after the fact.",
  },
  {
    icon: <LayersIcon />,
    accent: "purple",
    title: "Three protocols",
    body: "REST over Actix-Web, gRPC over Tonic and AMQP over RabbitMQ — synchronous and asynchronous authorization from one core.",
  },
];

const ACCENTS = {
  cyan: { bg: "rgba(0,212,255,.12)", color: "#00d4ff" },
  purple: { bg: "rgba(168,85,247,.14)", color: "#c084fc" },
} as const;

const HERO_STATS = [
  { value: "64", label: "tasks" },
  { value: "19", label: "phases" },
  { value: "11", label: "SDKs" },
  { value: "100%", label: "Rust" },
];

const COMPLIANCE = ["OWASP ASVS", "GDPR", "ISO 27001", "CyberSecurity Act"];

function clientPill(label: string) {
  return (
    <span
      key={label}
      className="ax-pill"
      style={{
        background: "rgba(255,255,255,.05)",
        border: "1px solid rgba(0,212,255,.18)",
        color: "#cbd5e1",
        padding: "5px 12px",
      }}
    >
      {label}
    </span>
  );
}

export default function Home({ go, openSdk }: HomeProps) {
  return (
    <div>
      {/* ---- Hero ---- */}
      <section
        style={{
          position: "relative",
          overflow: "hidden",
          padding: "clamp(72px,12vw,104px) clamp(20px,5vw,40px) clamp(56px,9vw,84px)",
          textAlign: "center",
          borderBottom: "1px solid rgba(0,212,255,.08)",
        }}
      >
        <img
          src={logoMark}
          alt=""
          aria-hidden="true"
          style={{
            position: "absolute",
            top: 30,
            left: "50%",
            transform: "translateX(-50%)",
            width: 520,
            opacity: 0.15,
            filter: "blur(1px)",
            pointerEvents: "none",
            animation: "floaty 7s ease-in-out infinite",
          }}
        />
        <div
          style={{
            position: "relative",
            maxWidth: 900,
            margin: "0 auto",
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 26,
          }}
        >
          <span
            className="ax-pill"
            style={{
              border: "1px solid rgba(0,212,255,.35)",
              background: "rgba(0,212,255,.06)",
              color: "#67e8f9",
              padding: "7px 15px",
            }}
          >
            <span
              style={{
                width: 7,
                height: 7,
                borderRadius: "50%",
                background: "#00d4ff",
                boxShadow: "0 0 8px #00d4ff",
              }}
            />
            Open source · Apache-2.0 · Built in Rust 2024
          </span>
          <h1
            style={{
              maxWidth: 880,
              margin: 0,
              fontSize: "clamp(34px, 8vw, 64px)",
              lineHeight: 1.05,
              fontWeight: 800,
              letterSpacing: "-.025em",
            }}
          >
            Identity &amp; access management,{" "}
            <span
              style={{
                background: "linear-gradient(120deg,#00d4ff,#a855f7)",
                WebkitBackgroundClip: "text",
                backgroundClip: "text",
                WebkitTextFillColor: "transparent",
              }}
            >
              designed by a human, built with AI.
            </span>
          </h1>
          <p
            style={{
              maxWidth: 680,
              margin: 0,
              fontSize: 19,
              lineHeight: 1.6,
              color: "#94a3b8",
            }}
          >
            AXIAM is an enterprise-grade, open-source IAM platform — a
            vibe-coding experiment proving that one architect, pairing with
            Claude Code, can ship a Rust system that stands next to Keycloak,
            Okta and Auth0.
          </p>
          <div style={{ display: "flex", gap: 14, marginTop: 6 }}>
            <button className="ax-cta btn-primary" onClick={() => go("docs")}>
              Read the quickstart <span style={{ fontSize: 17 }}>→</span>
            </button>
            <a
              className="ax-ghost"
              href={GITHUB_URL}
              target="_blank"
              rel="noreferrer"
            >
              View on GitHub
            </a>
          </div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 34,
              marginTop: 34,
              flexWrap: "wrap",
              justifyContent: "center",
            }}
          >
            <span
              style={{
                fontSize: 12,
                textTransform: "uppercase",
                letterSpacing: ".16em",
                color: "#64748b",
              }}
            >
              Every commit, human + AI
            </span>
            <div style={{ display: "flex", gap: 36 }}>
              {HERO_STATS.map((s) => (
                <div key={s.label} style={{ textAlign: "center" }}>
                  <div
                    style={{ fontSize: 26, fontWeight: 800, color: "#00d4ff" }}
                  >
                    {s.value}
                  </div>
                  <div
                    style={{
                      fontSize: 11,
                      letterSpacing: ".1em",
                      textTransform: "uppercase",
                      color: "#64748b",
                    }}
                  >
                    {s.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* ---- Features ---- */}
      <section className="ax-section">
        <div style={{ textAlign: "center", marginBottom: 44 }}>
          <h2 className="ax-h2">One platform, every access primitive</h2>
          <p style={{ margin: "14px 0 0", fontSize: 17, color: "#94a3b8" }}>
            Authentication, authorization, federation and PKI — behind REST,
            gRPC and AMQP.
          </p>
        </div>
        <div className="ax-grid-3">
          {FEATURES.map((f) => (
            <div
              key={f.title}
              className="glass-card ax-lift ax-feat"
              style={{ padding: 26 }}
            >
              <div
                style={{
                  width: 44,
                  height: 44,
                  borderRadius: 11,
                  background: ACCENTS[f.accent].bg,
                  display: "flex",
                  alignItems: "center",
                  justifyContent: "center",
                  color: ACCENTS[f.accent].color,
                }}
              >
                {f.icon}
              </div>
              <h3>{f.title}</h3>
              <p>{f.body}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ---- Architecture ---- */}
      <section style={{ maxWidth: 1180, margin: "0 auto", padding: "70px 40px" }}>
        <div style={{ textAlign: "center", marginBottom: 40 }}>
          <h2 className="ax-h2">Layered by design</h2>
          <p style={{ margin: "14px 0 0", fontSize: 17, color: "#94a3b8" }}>
            A clean path from any client to the graph store.
          </p>
        </div>
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
            gap: 14,
            maxWidth: 820,
            margin: "0 auto",
          }}
        >
          <div
            className="glass-card"
            style={{ width: "100%", padding: "18px 22px", textAlign: "center" }}
          >
            <div
              style={{
                fontSize: 12,
                textTransform: "uppercase",
                letterSpacing: ".14em",
                color: "#64748b",
                marginBottom: 8,
              }}
            >
              Clients
            </div>
            <div
              style={{
                display: "flex",
                gap: 10,
                justifyContent: "center",
                flexWrap: "wrap",
              }}
            >
              {["Browser", "Mobile", "IoT", "Services", "SDKs"].map(clientPill)}
            </div>
          </div>
          <div style={{ color: "#00d4ff", fontSize: 12, letterSpacing: ".3em" }}>
            REST · gRPC · AMQP ▼
          </div>
          <div
            className="glass-card"
            style={{
              width: "100%",
              padding: "18px 22px",
              textAlign: "center",
              borderColor: "rgba(0,212,255,.3)",
            }}
          >
            <div
              style={{
                fontSize: 12,
                textTransform: "uppercase",
                letterSpacing: ".14em",
                color: "#67e8f9",
                marginBottom: 6,
              }}
            >
              API Gateway
            </div>
            <div
              style={{
                color: "#cbd5e1",
                fontSize: 14,
                fontFamily: "ui-monospace,Menlo,monospace",
              }}
            >
              Actix-Web&nbsp;&nbsp;|&nbsp;&nbsp;Tonic&nbsp;&nbsp;|&nbsp;&nbsp;Lapin
            </div>
          </div>
          <div style={{ color: "#00d4ff", fontSize: 14 }}>▼</div>
          <div
            className="glass-card"
            style={{
              width: "100%",
              padding: "18px 22px",
              textAlign: "center",
              borderColor: "rgba(168,85,247,.3)",
            }}
          >
            <div
              style={{
                fontSize: 12,
                textTransform: "uppercase",
                letterSpacing: ".14em",
                color: "#c084fc",
                marginBottom: 6,
              }}
            >
              Service layer
            </div>
            <div
              style={{
                color: "#cbd5e1",
                fontSize: 14,
                fontFamily: "ui-monospace,Menlo,monospace",
              }}
            >
              AuthN · AuthZ · Users · Federation · Roles · PKI · Audit · OAuth2
            </div>
          </div>
          <div style={{ color: "#00d4ff", fontSize: 14 }}>▼</div>
          <div
            className="glass-card"
            style={{
              width: "100%",
              padding: "16px 22px",
              textAlign: "center",
              color: "#94a3b8",
              fontSize: 14,
            }}
          >
            Repository abstractions
          </div>
          <div style={{ color: "#00d4ff", fontSize: 14 }}>▼</div>
          <div
            className="glass-card"
            style={{
              width: "100%",
              padding: "18px 22px",
              textAlign: "center",
              borderColor: "rgba(168,85,247,.3)",
            }}
          >
            <span style={{ fontWeight: 700, color: "#c084fc", fontSize: 16 }}>
              SurrealDB Cluster
            </span>
            <span
              style={{ color: "#64748b", fontSize: 13, marginLeft: 10 }}
            >
              document + graph hybrid
            </span>
          </div>
        </div>
      </section>

      {/* ---- Vibe-coding ---- */}
      <section
        style={{
          borderTop: "1px solid rgba(0,212,255,.08)",
          borderBottom: "1px solid rgba(0,212,255,.08)",
          background: "rgba(168,85,247,.05)",
        }}
      >
        <div
          style={{
            maxWidth: 1000,
            margin: "0 auto",
            padding: "70px clamp(20px,5vw,40px)",
            gap: 48,
            alignItems: "center",
          }}
          className="ax-grid-2"
        >
          <div>
            <span
              className="ax-pill"
              style={{
                border: "1px solid rgba(168,85,247,.4)",
                background: "rgba(168,85,247,.1)",
                color: "#c084fc",
                padding: "6px 14px",
              }}
            >
              A vibe-coding experiment
            </span>
            <h2
              className="ax-h2"
              style={{ margin: "18px 0 16px", fontSize: 34 }}
            >
              Human vision, AI at implementation scale
            </h2>
            <p
              style={{
                fontSize: 16,
                lineHeight: 1.7,
                color: "#94a3b8",
                margin: "0 0 14px",
              }}
            >
              Every line of code, every test, every commit was produced through
              human-AI pair programming with Claude Code (Opus 4.6). The
              architect provides vision, constraints and review; the AI provides
              implementation at scale.
            </p>
            <p style={{ fontSize: 16, lineHeight: 1.7, color: "#94a3b8", margin: 0 }}>
              The deeper goal is to explore the future of software itself — where
              human creativity and generative AI produce software neither could
              build alone.
            </p>
          </div>
          <div
            className="glass-card"
            style={{ padding: 30, borderColor: "rgba(168,85,247,.25)" }}
          >
            <div
              style={{
                fontSize: 15,
                lineHeight: 1.7,
                color: "#e2e8f0",
                fontStyle: "italic",
              }}
            >
              "Prove that a single architect, collaborating with an AI coding
              agent, can produce a production-quality IAM system that competes
              with Keycloak, Okta and Auth0 — built in Rust for maximum
              performance, safety and security."
            </div>
            <div
              style={{
                marginTop: 20,
                display: "flex",
                alignItems: "center",
                gap: 10,
              }}
            >
              <div
                style={{
                  width: 34,
                  height: 34,
                  borderRadius: 8,
                  background: "linear-gradient(135deg,#00d4ff,#a855f7)",
                }}
              />
              <div>
                <div
                  style={{ fontSize: 13, fontWeight: 600, color: "#f8fafc" }}
                >
                  The AXIAM project goal
                </div>
                <div style={{ fontSize: 12, color: "#64748b" }}>
                  from the project README
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ---- SDK pills ---- */}
      <section
        style={{
          maxWidth: 1180,
          margin: "0 auto",
          padding: "74px 40px 30px",
          textAlign: "center",
        }}
      >
        <h2 className="ax-h2">Eleven SDKs, one behavioral contract</h2>
        <p style={{ margin: "14px 0 30px", fontSize: 17, color: "#94a3b8" }}>
          Every client library vendors the same cross-language contract, OpenAPI
          spec and protobufs.
        </p>
        <div
          style={{
            display: "flex",
            gap: 12,
            justifyContent: "center",
            flexWrap: "wrap",
            marginBottom: 30,
          }}
        >
          {SDKS.map((s) => (
            <button
              key={s.id}
              className="ax-pill ax-lift"
              onClick={() => openSdk(s.id)}
              style={{
                background: "rgba(255,255,255,.05)",
                border: "1px solid rgba(0,212,255,.2)",
                color: "#e2e8f0",
                padding: "9px 18px",
                fontSize: 14,
                cursor: "pointer",
              }}
            >
              {s.name}
            </button>
          ))}
        </div>
        <button className="ax-ghost" onClick={() => go("sdks")}>
          Explore the SDKs →
        </button>
      </section>

      {/* ---- Compliance ---- */}
      <section
        style={{ maxWidth: 1180, margin: "0 auto", padding: "40px 40px 90px" }}
      >
        <div className="glass-card" style={{ padding: 40, textAlign: "center" }}>
          <div
            style={{
              fontSize: 12,
              textTransform: "uppercase",
              letterSpacing: ".16em",
              color: "#64748b",
              marginBottom: 20,
            }}
          >
            Secure &amp; compliant by design
          </div>
          <div
            style={{
              display: "flex",
              gap: 14,
              justifyContent: "center",
              flexWrap: "wrap",
            }}
          >
            {COMPLIANCE.map((c) => (
              <span
                key={c}
                className="ax-pill"
                style={{
                  border: "1px solid rgba(0,212,255,.3)",
                  color: "#67e8f9",
                  padding: "10px 20px",
                  fontSize: 14,
                }}
              >
                {c}
              </span>
            ))}
          </div>
          <p
            style={{
              margin: "22px auto 0",
              maxWidth: 600,
              fontSize: 14,
              color: "#94a3b8",
            }}
          >
            Argon2id, EdDSA (Ed25519) and AES-256-GCM under the hood — with data
            export/deletion, consent tracking and access control built in.
          </p>
        </div>
      </section>
    </div>
  );
}

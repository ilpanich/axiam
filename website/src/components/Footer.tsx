import type { Page } from "../types";
import { GITHUB_URL } from "../data";
import { logoMark } from "../assets";

interface FooterProps {
  go: (page: Page) => void;
}

export default function Footer({ go }: FooterProps) {
  return (
    <footer className="ax-footer">
      <div className="ax-footer-grid">
        <div>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 11,
              marginBottom: 14,
            }}
          >
            <img
              src={logoMark}
              width={32}
              height={32}
              alt="AXIAM"
              style={{ borderRadius: 8 }}
            />
            <span
              style={{ fontWeight: 800, fontSize: 18, letterSpacing: ".12em" }}
            >
              AXIAM
            </span>
          </div>
          <p
            style={{
              margin: 0,
              fontSize: 13.5,
              lineHeight: 1.6,
              color: "#94a3b8",
              maxWidth: 280,
            }}
          >
            Access eXtended Identity and Authorization Management — an
            open-source IAM platform built in Rust.
          </p>
        </div>

        <div>
          <div className="ax-footer-head">Product</div>
          <div className="ax-footer-col">
            <button className="ax-navlink" onClick={() => go("home")}>
              Features
            </button>
            <button className="ax-navlink" onClick={() => go("bench")}>
              Benchmarks
            </button>
            <button className="ax-navlink" onClick={() => go("roadmap")}>
              Roadmap
            </button>
          </div>
        </div>

        <div>
          <div className="ax-footer-head">Developers</div>
          <div className="ax-footer-col">
            <button className="ax-navlink" onClick={() => go("docs")}>
              Documentation
            </button>
            <button className="ax-navlink" onClick={() => go("sdks")}>
              SDKs
            </button>
            <a
              className="ax-navlink"
              href={GITHUB_URL}
              target="_blank"
              rel="noreferrer"
              style={{ color: "#cbd5e1" }}
            >
              GitHub
            </a>
          </div>
        </div>

        <div>
          <div className="ax-footer-head">Project</div>
          <div className="ax-footer-col">
            <button className="ax-navlink" onClick={() => go("news")}>
              News
            </button>
            <a
              className="ax-navlink"
              href={GITHUB_URL}
              target="_blank"
              rel="noreferrer"
              style={{ color: "#cbd5e1" }}
            >
              License · Apache-2.0
            </a>
          </div>
        </div>
      </div>

      <div
        style={{
          maxWidth: 1180,
          margin: "0 auto",
          padding: "18px 40px 34px",
          borderTop: "1px solid rgba(0,212,255,.08)",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          fontSize: 12.5,
          color: "#64748b",
          flexWrap: "wrap",
          gap: 10,
        }}
      >
        <span>© 2026 AXIAM · Apache License 2.0</span>
        <span>
          Designed by a human, built with Claude Code · a vibe-coding experiment
        </span>
      </div>
    </footer>
  );
}

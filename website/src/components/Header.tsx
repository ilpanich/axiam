import type { Page } from "../types";
import { GITHUB_URL } from "../data";
import { GithubIcon } from "./icons";
import { logoMark } from "../assets";

interface HeaderProps {
  page: Page;
  go: (page: Page) => void;
}

interface NavItem {
  label: string;
  page: Page;
  active: (p: Page) => boolean;
}

const NAV_ITEMS: NavItem[] = [
  { label: "Home", page: "home", active: (p) => p === "home" },
  { label: "SDKs", page: "sdks", active: (p) => p === "sdks" || p === "sdk" },
  { label: "Docs", page: "docs", active: (p) => p === "docs" },
  { label: "Benchmarks", page: "bench", active: (p) => p === "bench" },
  { label: "Roadmap", page: "roadmap", active: (p) => p === "roadmap" },
  { label: "News", page: "news", active: (p) => p === "news" || p === "post" },
];

export default function Header({ page, go }: HeaderProps) {
  return (
    <header className="ax-header">
      <button className="ax-brand" onClick={() => go("home")}>
        <img
          src={logoMark}
          width={36}
          height={36}
          alt="AXIAM"
          style={{ borderRadius: 9, boxShadow: "0 0 16px rgba(0,212,255,.45)" }}
        />
        <span className="ax-brand-name">AXIAM</span>
      </button>

      <nav className="ax-nav">
        {NAV_ITEMS.map((item) => (
          <button
            key={item.page}
            className="ax-navlink"
            onClick={() => go(item.page)}
          >
            {item.label}
            {item.active(page) && <span className="ax-navdash" />}
          </button>
        ))}
      </nav>

      <div style={{ display: "flex", gap: 14, alignItems: "center" }}>
        <a
          className="ax-navlink"
          href={GITHUB_URL}
          target="_blank"
          rel="noreferrer"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: 7,
            color: "#cbd5e1",
          }}
        >
          <GithubIcon />
          Star
        </a>
        <button className="ax-cta btn-primary" onClick={() => go("docs")}>
          Get started
        </button>
      </div>
    </header>
  );
}

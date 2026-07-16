import { POSTS } from "../data";

interface NewsIndexProps {
  openPost: (slug: string) => void;
}

export default function NewsIndex({ openPost }: NewsIndexProps) {
  return (
    <div style={{ maxWidth: 1000, margin: "0 auto", padding: "56px 40px 90px" }}>
      <span
        className="ax-pill"
        style={{
          border: "1px solid rgba(0,212,255,.3)",
          color: "#67e8f9",
          padding: "5px 13px",
        }}
      >
        News &amp; updates
      </span>
      <h1
        style={{
          margin: "16px 0 10px",
          fontSize: "clamp(32px, 6vw, 46px)",
          fontWeight: 800,
          letterSpacing: "-.02em",
        }}
      >
        From the AXIAM project
      </h1>
      <p style={{ margin: "0 0 40px", fontSize: 17, color: "#94a3b8", maxWidth: 640 }}>
        Milestones, engineering notes and releases. Each post is a Markdown file
        with a metadata header — drop a new one in{" "}
        <code style={{ color: "#67e8f9", fontFamily: "ui-monospace,Menlo,monospace" }}>
          content/news/
        </code>{" "}
        and it appears here.
      </p>
      <div style={{ display: "flex", flexDirection: "column", gap: 18 }}>
        {POSTS.map((p) => (
          <div
            key={p.slug}
            className="glass-card ax-lift"
            style={{
              padding: "26px 28px",
              cursor: "pointer",
              display: "flex",
              gap: 24,
              alignItems: "flex-start",
            }}
            onClick={() => openPost(p.slug)}
          >
            <div
              style={{
                flex: "none",
                width: 96,
                textAlign: "center",
                paddingTop: 2,
              }}
            >
              <div
                style={{
                  fontSize: 12,
                  color: "#64748b",
                  textTransform: "uppercase",
                  letterSpacing: ".1em",
                }}
              >
                {p.dateShort}
              </div>
            </div>
            <div style={{ flex: 1, minWidth: 0 }}>
              <span
                className="ax-pill"
                style={{
                  background: "rgba(168,85,247,.12)",
                  border: "1px solid rgba(168,85,247,.3)",
                  color: "#c084fc",
                  padding: "3px 11px",
                  fontSize: 11,
                  marginBottom: 10,
                }}
              >
                {p.tag}
              </span>
              <h2 style={{ margin: "8px 0 8px", fontSize: 22, fontWeight: 700 }}>
                {p.title}
              </h2>
              <p
                style={{
                  margin: "0 0 12px",
                  fontSize: 14.5,
                  lineHeight: 1.6,
                  color: "#94a3b8",
                }}
              >
                {p.excerpt}
              </p>
              <span
                style={{ fontSize: 13, color: "#67e8f9", fontWeight: 600 }}
              >
                Read more →
              </span>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

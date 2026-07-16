import type { Page, Post } from "../types";

interface NewsPostProps {
  post: Post;
  go: (page: Page) => void;
}

export default function NewsPost({ post, go }: NewsPostProps) {
  return (
    <div style={{ maxWidth: 760, margin: "0 auto", padding: "40px 40px 90px" }}>
      <button
        className="ax-navlink"
        onClick={() => go("news")}
        style={{ marginBottom: 26, background: "none", border: "none" }}
      >
        ← All news
      </button>
      <span
        className="ax-pill"
        style={{
          background: "rgba(168,85,247,.12)",
          border: "1px solid rgba(168,85,247,.3)",
          color: "#c084fc",
          padding: "4px 12px",
          fontSize: 12,
        }}
      >
        {post.tag}
      </span>
      <h1
        style={{
          margin: "18px 0 14px",
          fontSize: "clamp(28px, 6vw, 40px)",
          fontWeight: 800,
          letterSpacing: "-.02em",
          lineHeight: 1.12,
        }}
      >
        {post.title}
      </h1>
      <div
        style={{
          display: "flex",
          gap: 14,
          alignItems: "center",
          color: "#64748b",
          fontSize: 14,
          marginBottom: 32,
          paddingBottom: 22,
          borderBottom: "1px solid rgba(0,212,255,.12)",
        }}
      >
        <span>{post.date}</span>
        <span>·</span>
        <span>{post.author}</span>
      </div>
      <div>
        {post.body.map((b, i) => {
          if (b.type === "h") {
            return (
              <h2
                key={i}
                style={{ fontSize: 23, fontWeight: 700, margin: "32px 0 12px" }}
              >
                {b.text}
              </h2>
            );
          }
          if (b.type === "quote") {
            return (
              <div
                key={i}
                className="glass-card"
                style={{
                  padding: "20px 24px",
                  borderLeft: "3px solid #00d4ff",
                  margin: "0 0 18px",
                  fontStyle: "italic",
                  color: "#e2e8f0",
                  fontSize: 16,
                }}
              >
                {b.text}
              </div>
            );
          }
          return (
            <p
              key={i}
              style={{
                fontSize: 16.5,
                lineHeight: 1.8,
                color: "#cbd5e1",
                margin: "0 0 18px",
              }}
            >
              {b.text}
            </p>
          );
        })}
      </div>
    </div>
  );
}

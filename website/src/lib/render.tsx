import { Fragment, type ReactNode } from "react";

const inlineCodeStyle = {
  color: "#67e8f9",
  fontFamily: "ui-monospace,Menlo,monospace",
  fontSize: "0.92em",
  background: "rgba(0,0,0,.28)",
  border: "1px solid rgba(0,212,255,.14)",
  borderRadius: 5,
  padding: "1px 5px",
} as const;

/**
 * Render prose text, turning `backtick` spans into inline <code>,
 * `**double-asterisk**` spans into bold, `*single-asterisk*` spans into
 * italics and `[label](#/docs/slug)` into a link. Code wins: asterisks and
 * brackets inside a backtick span are left alone, so a code sample never gets
 * reinterpreted as markup.
 */
export function renderInline(text: string): ReactNode {
  const parts = text.split("`");
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <code key={i} style={inlineCodeStyle}>
        {part}
      </code>
    ) : (
      <Fragment key={i}>{renderLinks(part)}</Fragment>
    ),
  );
}

const linkStyle = {
  color: "#67e8f9",
  textDecoration: "none",
  borderBottom: "1px solid rgba(0,212,255,.35)",
} as const;

/**
 * Turn `[label](href)` into an anchor.
 *
 * Cross-references between doc pages are written as ordinary hash links
 * (`#/docs/opaque`) rather than as click handlers, because the docs section is
 * hash-routed: a plain `<a href>` therefore navigates correctly, is
 * middle-clickable, and can be copied out of the page — none of which is true
 * of a `<span onClick>`. External links are opened in a new tab.
 */
function renderLinks(text: string): ReactNode {
  if (!text.includes("](")) return renderBold(text);

  const tokens: ReactNode[] = [];
  const re = /\[([^\]]+)\]\(([^)]+)\)/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let key = 0;
  while ((match = re.exec(text)) !== null) {
    if (match.index > last) {
      tokens.push(
        <Fragment key={key++}>{renderBold(text.slice(last, match.index))}</Fragment>,
      );
    }
    const [, label, href] = match;
    const external = /^https?:/.test(href);
    tokens.push(
      <a
        key={key++}
        href={href}
        style={linkStyle}
        {...(external ? { target: "_blank", rel: "noreferrer" } : {})}
      >
        {renderBold(label)}
      </a>,
    );
    last = match.index + match[0].length;
  }
  if (last < text.length) {
    tokens.push(<Fragment key={key++}>{renderBold(text.slice(last))}</Fragment>);
  }
  return tokens;
}

function renderBold(text: string): ReactNode {
  if (!text.includes("*")) return text;
  const parts = text.split("**");
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <strong key={i} style={{ color: "#e2e8f0", fontWeight: 700 }}>
        {part}
      </strong>
    ) : (
      <Fragment key={i}>{renderItalic(part)}</Fragment>
    ),
  );
}

function renderItalic(text: string): ReactNode {
  if (!text.includes("*")) return text;
  const parts = text.split("*");
  return parts.map((part, i) =>
    i % 2 === 1 ? <em key={i}>{part}</em> : <Fragment key={i}>{part}</Fragment>,
  );
}

const KEYWORDS = new Set([
  "import",
  "from",
  "export",
  "const",
  "let",
  "var",
  "new",
  "await",
  "async",
  "function",
  "return",
  "if",
  "else",
  "for",
  "while",
  "use",
  "fn",
  "pub",
  "let",
  "def",
  "with",
  "class",
  "public",
  "bool",
  "boolean",
  "true",
  "false",
]);

const COMMENT_COLOR = "#64748b";
const STRING_COLOR = "#67e8f9";
const KEYWORD_COLOR = "#c084fc";

/**
 * Lightweight, language-agnostic highlighter for the docs code samples.
 * Colors whole-line comments (# or //), quoted strings and a small set of
 * common keywords. Deliberately conservative — it never mangles code, it
 * just adds a little colour.
 */
export function highlightCode(code: string): ReactNode {
  return code.split("\n").map((line, lineIdx) => {
    const trimmed = line.trimStart();
    const isComment = trimmed.startsWith("#") || trimmed.startsWith("//");
    return (
      <Fragment key={lineIdx}>
        {isComment ? (
          <span style={{ color: COMMENT_COLOR }}>{line}</span>
        ) : (
          highlightLine(line)
        )}
        {"\n"}
      </Fragment>
    );
  });
}

// Split a line into string literals and non-string runs, coloring each.
function highlightLine(line: string): ReactNode {
  const tokens: ReactNode[] = [];
  const re = /(["'`])(?:\\.|(?!\1).)*\1/g;
  let last = 0;
  let match: RegExpExecArray | null;
  let key = 0;
  while ((match = re.exec(line)) !== null) {
    if (match.index > last) {
      tokens.push(
        <Fragment key={key++}>{highlightWords(line.slice(last, match.index))}</Fragment>,
      );
    }
    tokens.push(
      <span key={key++} style={{ color: STRING_COLOR }}>
        {match[0]}
      </span>,
    );
    last = match.index + match[0].length;
  }
  if (last < line.length) {
    tokens.push(<Fragment key={key++}>{highlightWords(line.slice(last))}</Fragment>);
  }
  return tokens;
}

function highlightWords(text: string): ReactNode {
  const parts = text.split(/(\b\w+\b)/);
  return parts.map((part, i) =>
    KEYWORDS.has(part) ? (
      <span key={i} style={{ color: KEYWORD_COLOR }}>
        {part}
      </span>
    ) : (
      <Fragment key={i}>{part}</Fragment>
    ),
  );
}

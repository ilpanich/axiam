import { useEffect, useMemo, useRef, useState } from "react";
import { THREAT_MODEL } from "../threatModel";
import type { TmDiagram, TmEdge, TmNode, TmThreat } from "../threatModelTypes";
import {
  SECURITY_DEEP_LINK_RE,
  diagramHash,
  elementHash,
  threatHash,
} from "../securityLinks";

/**
 * Interactive browser for the OWASP Threat Dragon model.
 *
 * Renders each data-flow diagram straight from the generated model data — the
 * same JSON the project maintains in `ThreatDragonModels/` — and lets a reader
 * click any element or flow to see the threats recorded against it, with the
 * control that answers each one. Nothing here is hand-written prose: the
 * diagrams, the counts and the mitigations all come from the model, so the page
 * cannot claim more than the model does.
 */

const CYAN = "#00d4ff";
const CYAN_SOFT = "#67e8f9";
const PURPLE = "#c084fc";
const AMBER = "#ffbd2e";
const SLATE = "#94a3b8";

const SEVERITY_COLOR: Record<string, string> = {
  Critical: "#ff6b6b",
  High: "#ffbd2e",
  Medium: "#67e8f9",
  Low: "#94a3b8",
};

const STATUS_COLOR: Record<string, string> = {
  Mitigated: "#27c93f",
  Open: "#ffbd2e",
};

const KIND_LABEL: Record<TmNode["kind"], string> = {
  actor: "External actor",
  process: "Process",
  store: "Data store",
};

/** A diagram element or flow, in the flattened form the threat list uses. */
interface Selectable {
  id: string;
  name: string;
  description: string;
  kindLabel: string;
  threats: TmThreat[];
  open: number;
}

function Chip({ text, color }: { text: string; color: string }) {
  return (
    <span
      className="ax-pill"
      style={{
        border: `1px solid ${color}55`,
        background: `${color}14`,
        color,
        padding: "2px 9px",
        fontSize: 11.5,
        whiteSpace: "nowrap",
      }}
    >
      {text}
    </span>
  );
}

/* ---- Diagram ------------------------------------------------------------- */

function NodeShape({
  node,
  selected,
  onSelect,
}: {
  node: TmNode;
  selected: boolean;
  onSelect: (id: string) => void;
}) {
  const stroke = node.open > 0 ? AMBER : node.kind === "actor" ? CYAN : CYAN_SOFT;
  const fill = node.open > 0 ? "rgba(255,189,46,.07)" : "rgba(0,212,255,.07)";
  const cx = node.x + node.w / 2;
  const cy = node.y + node.h / 2;
  // Shrink the type on the few elements whose label runs to many lines, so a
  // long name stays inside its shape instead of spilling over the outline.
  const fontSize = node.lines.length > 4 ? 10 : 11.5;
  const lineHeight = fontSize + 2;
  const textTop = cy - ((node.lines.length - 1) * lineHeight) / 2;

  return (
    <g
      role="button"
      tabIndex={0}
      aria-label={`${KIND_LABEL[node.kind]}: ${node.name}`}
      onClick={() => onSelect(node.id)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(node.id);
        }
      }}
      style={{ cursor: "pointer" }}
      opacity={node.outOfScope ? 0.55 : 1}
    >
      <title>{`${KIND_LABEL[node.kind]} — ${node.name} · ${node.threats.length} threat(s)`}</title>

      {node.kind === "process" ? (
        <circle
          cx={cx}
          cy={cy}
          r={Math.min(node.w, node.h) / 2}
          fill={fill}
          stroke={stroke}
          strokeWidth={selected ? 3 : 1.6}
          strokeDasharray={node.outOfScope ? "6 4" : undefined}
        />
      ) : node.kind === "store" ? (
        <>
          <rect x={node.x} y={node.y} width={node.w} height={node.h} fill={fill} />
          <line
            x1={node.x}
            y1={node.y}
            x2={node.x + node.w}
            y2={node.y}
            stroke={stroke}
            strokeWidth={selected ? 3 : 1.8}
          />
          <line
            x1={node.x}
            y1={node.y + node.h}
            x2={node.x + node.w}
            y2={node.y + node.h}
            stroke={stroke}
            strokeWidth={selected ? 3 : 1.8}
          />
        </>
      ) : (
        <rect
          x={node.x}
          y={node.y}
          width={node.w}
          height={node.h}
          rx={6}
          fill={fill}
          stroke={stroke}
          strokeWidth={selected ? 3 : 1.6}
          strokeDasharray={node.outOfScope ? "6 4" : undefined}
        />
      )}

      {selected && (
        <rect
          x={node.x - 8}
          y={node.y - 8}
          width={node.w + 16}
          height={node.h + 16}
          rx={10}
          fill="none"
          stroke={CYAN}
          strokeWidth={1}
          strokeDasharray="4 4"
        />
      )}

      <text
        x={cx}
        y={textTop}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize={fontSize}
        fill="#e2e8f0"
        style={{ pointerEvents: "none", userSelect: "none" }}
      >
        {node.lines.map((line, i) => (
          <tspan key={i} x={cx} dy={i === 0 ? 0 : lineHeight}>
            {line}
          </tspan>
        ))}
      </text>

      {node.open > 0 && (
        <>
          <circle cx={node.x + node.w - 4} cy={node.y + 4} r={8} fill={AMBER} />
          <text
            x={node.x + node.w - 4}
            y={node.y + 5}
            textAnchor="middle"
            dominantBaseline="middle"
            fontSize={10}
            fontWeight={700}
            fill="#0d0d2b"
            style={{ pointerEvents: "none" }}
          >
            {node.open}
          </text>
        </>
      )}
    </g>
  );
}

function EdgeShape({
  edge,
  active,
  onSelect,
  onHover,
}: {
  edge: TmEdge;
  /** Selected or hovered — drawn brighter and thicker. */
  active: boolean;
  onSelect: (id: string) => void;
  onHover: (id: string | null) => void;
}) {
  const stroke = active ? CYAN : edge.encrypted ? "rgba(148,163,184,.7)" : AMBER;

  return (
    <g
      role="button"
      tabIndex={0}
      aria-label={`Data flow: ${edge.name}`}
      onClick={() => onSelect(edge.id)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onSelect(edge.id);
        }
      }}
      onMouseEnter={() => onHover(edge.id)}
      onMouseLeave={() => onHover(null)}
      onFocus={() => onHover(edge.id)}
      onBlur={() => onHover(null)}
      style={{ cursor: "pointer" }}
    >
      <title>{`${edge.name}${edge.protocol ? ` (${edge.protocol})` : ""} · ${
        edge.encrypted ? "encrypted" : "not marked encrypted"
      } · ${edge.threats.length} threat(s)`}</title>

      {/* Invisible fat stroke widens the click/hover target. */}
      <path d={edge.path} fill="none" stroke="transparent" strokeWidth={14} />
      <path
        d={edge.path}
        fill="none"
        stroke={stroke}
        strokeWidth={active ? 2.4 : 1.4}
        strokeDasharray={edge.encrypted ? undefined : "7 5"}
        markerEnd="url(#tm-arrow)"
        markerStart={edge.bidirectional ? "url(#tm-arrow-start)" : undefined}
      />
    </g>
  );
}

/**
 * A flow's caption, drawn in its own layer above the elements.
 *
 * Flows converge on the busiest processes, so showing every caption at once
 * turns the middle of a diagram into overlapping text. Captions are therefore
 * off by default and appear on hover, selection, or when the reader asks for
 * all of them.
 */
function EdgeLabel({ edge, active }: { edge: TmEdge; active: boolean }) {
  if (!edge.label || edge.labelLines.length === 0) return null;
  const height = edge.labelLines.length * 12;
  return (
    <g style={{ pointerEvents: "none" }}>
      <rect
        x={edge.lx - 104}
        y={edge.ly - height / 2 - 3}
        width={208}
        height={height + 6}
        rx={5}
        fill="rgba(13,13,43,.92)"
        stroke={active ? `${CYAN}88` : "rgba(148,163,184,.22)"}
      />
      <text
        x={edge.lx}
        y={edge.ly - height / 2 + 6}
        textAnchor="middle"
        fontSize={10.5}
        fill={active ? CYAN_SOFT : "#cbd5e1"}
        style={{ userSelect: "none" }}
      >
        {edge.labelLines.map((line, i) => (
          <tspan key={i} x={edge.lx} dy={i === 0 ? 0 : 12}>
            {line}
          </tspan>
        ))}
      </text>
    </g>
  );
}

function Diagram({
  diagram,
  selectedId,
  onSelect,
  fit,
  showLabels,
}: {
  diagram: TmDiagram;
  selectedId: string | null;
  onSelect: (id: string) => void;
  fit: boolean;
  showLabels: boolean;
}) {
  const [hoveredId, setHoveredId] = useState<string | null>(null);
  const isActive = (id: string) => id === selectedId || id === hoveredId;

  return (
    <div
      className="glass-card"
      style={{
        overflowX: "auto",
        padding: 10,
        background: "rgba(8,8,28,.55)",
      }}
    >
      <svg
        viewBox={`0 0 ${diagram.width} ${diagram.height}`}
        role="img"
        aria-label={`${diagram.title} data-flow diagram`}
        style={{
          display: "block",
          width: fit ? "100%" : diagram.width,
          minWidth: fit ? undefined : diagram.width,
          height: "auto",
        }}
      >
        <defs>
          <marker
            id="tm-arrow"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0,1 L10,5 L0,9 z" fill="rgba(203,213,225,.85)" />
          </marker>
          <marker
            id="tm-arrow-start"
            viewBox="0 0 10 10"
            refX="9"
            refY="5"
            markerWidth="7"
            markerHeight="7"
            orient="auto-start-reverse"
          >
            <path d="M0,1 L10,5 L0,9 z" fill="rgba(203,213,225,.85)" />
          </marker>
        </defs>

        {diagram.boundaries.map((b) => (
          <g key={b.id}>
            <rect
              x={b.x}
              y={b.y}
              width={b.w}
              height={b.h}
              rx={14}
              fill="rgba(168,85,247,.045)"
              stroke="rgba(192,132,252,.5)"
              strokeWidth={1.6}
              strokeDasharray="10 6"
            />
            <text x={b.x + 14} y={b.y + 20} fontSize={12} fill={PURPLE} fontWeight={600}>
              {b.label}
            </text>
          </g>
        ))}

        {diagram.edges.map((e) => (
          <EdgeShape
            key={e.id}
            edge={e}
            active={isActive(e.id)}
            onSelect={onSelect}
            onHover={setHoveredId}
          />
        ))}

        {diagram.nodes.map((n) => (
          <NodeShape
            key={n.id}
            node={n}
            selected={n.id === selectedId}
            onSelect={onSelect}
          />
        ))}

        {/* Flow captions ride above the elements so they stay legible. */}
        {diagram.edges
          .filter((e) => showLabels || isActive(e.id))
          .map((e) => (
            <EdgeLabel key={e.id} edge={e} active={isActive(e.id)} />
          ))}
      </svg>
    </div>
  );
}

/* ---- Deep links ---------------------------------------------------------- */

/**
 * Which diagram, element and threat the explorer is showing.
 *
 * Kept in the URL rather than in component state alone, because the point of a
 * threat model is being able to cite it: the STRIDE document, the open risk
 * register, commit messages and the SDK contract all refer to threats by
 * number, and none of those references is useful if the reader cannot be sent
 * to the thing itself.
 */
interface View {
  diagramId: number;
  selectedId: string | null;
  focusThreat: number | null;
}

const FIRST_DIAGRAM = THREAT_MODEL.diagrams[0].id;
const DEFAULT_VIEW: View = {
  diagramId: FIRST_DIAGRAM,
  selectedId: null,
  focusThreat: null,
};

function buildHash(view: View): string {
  if (view.focusThreat !== null) return threatHash(view.diagramId, view.focusThreat);
  if (view.selectedId) return elementHash(view.diagramId, view.selectedId);
  return diagramHash(view.diagramId);
}

/** The diagram and element a threat number lives on, or `null` if unknown. */
function locate(number: number): { diagramId: number; elementId: string } | null {
  for (const diagram of THREAT_MODEL.diagrams) {
    for (const el of [...diagram.nodes, ...diagram.edges]) {
      if (el.threats.some((t) => t.number === number)) {
        return { diagramId: diagram.id, elementId: el.id };
      }
    }
  }
  return null;
}

/**
 * Read the view out of the current URL.
 *
 * A threat number wins over the diagram in the link: threat numbers are unique
 * across the whole model, so `T-186` resolves to the right diagram even if the
 * rest of the link is stale — which is exactly the case where a citation would
 * otherwise quietly land on the wrong page.
 */
function readHash(): View {
  if (typeof window === "undefined") return DEFAULT_VIEW;
  const match = SECURITY_DEEP_LINK_RE.exec(window.location.hash);
  if (!match) return DEFAULT_VIEW;

  const diagramId = Number(match[1]);
  const known = THREAT_MODEL.diagrams.some((d) => d.id === diagramId);
  const view: View = {
    diagramId: known ? diagramId : FIRST_DIAGRAM,
    selectedId: null,
    focusThreat: null,
  };

  const target = match[2];
  if (!target) return view;

  const asThreat = /^T-(\d+)$/.exec(target);
  if (asThreat) {
    const number = Number(asThreat[1]);
    const found = locate(number);
    if (!found) return view;
    return { diagramId: found.diagramId, selectedId: found.elementId, focusThreat: number };
  }
  return { ...view, selectedId: target };
}

/* ---- Filtering ----------------------------------------------------------- */

const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];
const CATEGORY_ORDER = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information disclosure",
  "Denial of service",
  "Elevation of privilege",
];

const ALL_THREATS = THREAT_MODEL.diagrams.flatMap((d) =>
  [...d.nodes, ...d.edges].flatMap((el) => el.threats),
);

/** Values the model actually uses, in canonical order, unknowns last. */
function present(order: string[], values: string[]): string[] {
  const seen = new Set(values);
  return [
    ...order.filter((v) => seen.has(v)),
    ...[...seen].filter((v) => !order.includes(v)).sort(),
  ];
}

const SEVERITIES = present(SEVERITY_ORDER, ALL_THREATS.map((t) => t.severity));
const CATEGORIES = present(CATEGORY_ORDER, ALL_THREATS.map((t) => t.type));

/**
 * One lowercased haystack per threat, built once.
 *
 * The search runs on every keystroke over every threat in the model, whose
 * mitigation text can run to several paragraphs; concatenating and lowercasing
 * that on each pass is work that never changes, so it is done here instead.
 */
const HAYSTACK = new Map<number, string>(
  ALL_THREATS.map((t) => [
    t.number,
    `t-${t.number} ${t.title} ${t.description} ${t.mitigation}`.toLowerCase(),
  ]),
);

interface Filters {
  query: string;
  severities: string[];
  categories: string[];
  openOnly: boolean;
}

const NO_FILTERS: Filters = {
  query: "",
  severities: [],
  categories: [],
  openOnly: false,
};

const filtersActive = (f: Filters) =>
  f.openOnly || f.query.trim() !== "" || f.severities.length > 0 || f.categories.length > 0;

function matches(threat: TmThreat, f: Filters, query: string): boolean {
  if (f.openOnly && threat.status === "Mitigated") return false;
  if (f.severities.length > 0 && !f.severities.includes(threat.severity)) return false;
  if (f.categories.length > 0 && !f.categories.includes(threat.type)) return false;
  if (query && !(HAYSTACK.get(threat.number) ?? "").includes(query)) return false;
  return true;
}

/** Toggle `value` in a filter list. */
const toggle = (list: string[], value: string) =>
  list.includes(value) ? list.filter((v) => v !== value) : [...list, value];

/* ---- Threat list --------------------------------------------------------- */

/** A filter chip. Selected chips carry their own colour so severity reads at a glance. */
function FilterChip({
  label,
  active,
  color,
  onClick,
}: {
  label: string;
  active: boolean;
  color: string;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      className="ax-pill"
      aria-pressed={active}
      onClick={onClick}
      style={{
        padding: "4px 11px",
        fontSize: 12,
        cursor: "pointer",
        fontFamily: "inherit",
        border: `1px solid ${active ? `${color}88` : "rgba(148,163,184,.25)"}`,
        background: active ? `${color}1a` : "transparent",
        color: active ? color : SLATE,
      }}
    >
      {label}
    </button>
  );
}

/**
 * The threat's identifier, as a copyable anchor.
 *
 * Everything else in the project cites threats as `T-186`; until the card
 * carried the number, nothing on the website could be cited back.
 */
function ThreatAnchor({ diagramId, number }: { diagramId: number; number: number }) {
  const [copied, setCopied] = useState(false);
  const href = threatHash(diagramId, number);

  const copy = () => {
    const url =
      typeof window === "undefined"
        ? href
        : `${window.location.origin}${window.location.pathname}${window.location.search}${href}`;
    // Clipboard access is permission-gated and absent over plain HTTP, so a
    // failure here is expected rather than exceptional: the anchor beside the
    // button is still copyable by hand.
    navigator.clipboard?.writeText(url).then(
      () => {
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1400);
      },
      () => undefined,
    );
  };

  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
      <a
        href={href}
        style={{
          font: "700 12.5px ui-monospace,Menlo,monospace",
          color: CYAN_SOFT,
          textDecoration: "none",
          borderBottom: `1px solid ${CYAN}44`,
        }}
      >
        T-{number}
      </a>
      <button
        type="button"
        onClick={copy}
        title={`Copy a link to T-${number}`}
        aria-label={`Copy a link to T-${number}`}
        style={{
          border: "1px solid rgba(148,163,184,.25)",
          background: "transparent",
          borderRadius: 5,
          color: copied ? "#27c93f" : SLATE,
          font: "10.5px ui-monospace,Menlo,monospace",
          padding: "1px 5px",
          cursor: "pointer",
        }}
      >
        {copied ? "copied" : "link"}
      </button>
    </span>
  );
}

function ThreatCard({
  threat,
  diagramId,
  focused,
}: {
  threat: TmThreat;
  diagramId: number;
  /** Deep-linked: highlighted and scrolled to. */
  focused: boolean;
}) {
  return (
    <div
      id={`tm-threat-${threat.number}`}
      className="glass-card"
      style={{
        padding: "14px 16px",
        scrollMarginTop: 100,
        borderColor: focused
          ? "rgba(0,212,255,.75)"
          : threat.status === "Mitigated"
            ? "rgba(0,212,255,.14)"
            : "rgba(255,189,46,.34)",
        background:
          threat.status === "Mitigated"
            ? "rgba(255,255,255,.035)"
            : "rgba(255,189,46,.05)",
        boxShadow: focused ? "0 0 0 1px rgba(0,212,255,.35)" : undefined,
      }}
    >
      <div
        style={{
          display: "flex",
          gap: 10,
          alignItems: "baseline",
          flexWrap: "wrap",
          marginBottom: 8,
        }}
      >
        <ThreatAnchor diagramId={diagramId} number={threat.number} />
        <span style={{ fontWeight: 700, fontSize: 14.5, color: "#e2e8f0" }}>
          {threat.title}
        </span>
        <Chip text={threat.type} color={PURPLE} />
        <Chip
          text={threat.severity}
          color={SEVERITY_COLOR[threat.severity] ?? SLATE}
        />
        <Chip
          text={threat.status}
          color={STATUS_COLOR[threat.status] ?? SLATE}
        />
      </div>
      <p style={{ margin: "0 0 8px", fontSize: 13.5, color: "#cbd5e1", lineHeight: 1.6 }}>
        {threat.description}
      </p>
      {/* `pre-line`: a few mitigations are written as several paragraphs in the
          model and carry the blank lines to prove it; without this they render
          as one wall of text. */}
      <p
        style={{
          margin: 0,
          fontSize: 13.5,
          color: "#94a3b8",
          lineHeight: 1.6,
          whiteSpace: "pre-line",
        }}
      >
        <span
          style={{
            color: threat.status === "Mitigated" ? "#27c93f" : AMBER,
            fontWeight: 700,
          }}
        >
          {threat.status === "Mitigated" ? "Mitigation · " : "Residual risk · "}
        </span>
        {threat.mitigation}
      </p>
    </div>
  );
}

/* ---- Explorer ------------------------------------------------------------ */

export default function ThreatModelExplorer() {
  const [view, setView] = useState<View>(readHash);
  const [filters, setFilters] = useState<Filters>(NO_FILTERS);
  const [fit, setFit] = useState(true);
  const [showLabels, setShowLabels] = useState(false);

  const diagram =
    THREAT_MODEL.diagrams.find((d) => d.id === view.diagramId) ?? THREAT_MODEL.diagrams[0];

  // Follow the URL. A link into the explorer clears the filters with it: a
  // citation that lands on "no threats match" would be worse than no link.
  useEffect(() => {
    const onHashChange = () => {
      if (!SECURITY_DEEP_LINK_RE.test(window.location.hash)) return;
      const next = readHash();
      setView(next);
      setFilters(NO_FILTERS);
      // Canonicalise here as well as on mount: a link that names the wrong
      // diagram for its threat resolves to the right one, and if the reader was
      // already looking at that threat the view does not change, so the effect
      // below would never fire to correct the address bar.
      const canonical = buildHash(next);
      if (window.location.hash !== canonical) {
        window.history.replaceState(null, "", canonical);
      }
    };
    window.addEventListener("hashchange", onHashChange);
    return () => window.removeEventListener("hashchange", onHashChange);
  }, []);

  // Publish the view back to the URL. On mount this only *canonicalises* a link
  // that was already an explorer link — a citation naming the wrong diagram for
  // its threat is rewritten to the one the threat is really on — because
  // writing unconditionally would replace an in-page anchor (`#responsibility`)
  // with a diagram link nobody asked for. `replaceState` keeps selections out
  // of the back stack, so Back leaves the page rather than unwinding clicks.
  const hash = buildHash(view);
  const mounted = useRef(false);
  useEffect(() => {
    const first = !mounted.current;
    mounted.current = true;
    if (first && !SECURITY_DEEP_LINK_RE.test(window.location.hash)) return;
    if (window.location.hash !== hash) {
      window.history.replaceState(null, "", hash);
    }
  }, [hash]);

  // Bring a deep-linked threat into view once its card has rendered.
  useEffect(() => {
    if (view.focusThreat === null) return;
    document
      .getElementById(`tm-threat-${view.focusThreat}`)
      ?.scrollIntoView({ behavior: "smooth", block: "center" });
  }, [view.focusThreat]);

  const elements: Selectable[] = useMemo(
    () => [
      ...diagram.nodes.map((n) => ({
        id: n.id,
        name: n.name,
        description: n.description,
        kindLabel: KIND_LABEL[n.kind],
        threats: n.threats,
        open: n.open,
      })),
      ...diagram.edges.map((e) => ({
        id: e.id,
        name: e.name,
        description: e.description,
        kindLabel: "Data flow",
        threats: e.threats,
        open: e.open,
      })),
    ],
    [diagram],
  );

  const selected = elements.find((el) => el.id === view.selectedId) ?? null;
  const query = filters.query.trim().toLowerCase();
  const active = filtersActive(filters);

  const shown = useMemo(() => {
    const base = selected ? [selected] : elements;
    return base
      .map((el) => ({ ...el, threats: el.threats.filter((t) => matches(t, filters, query)) }))
      .filter((el) => el.threats.length > 0);
  }, [elements, selected, filters, query]);

  const shownCount = shown.reduce((n, el) => n + el.threats.length, 0);

  // How many threats the filters match on each *other* diagram, so an empty
  // result says where the matches actually are instead of just "none".
  const elsewhere = useMemo(() => {
    if (shownCount > 0 || !active) return [];
    return THREAT_MODEL.diagrams
      .filter((d) => d.id !== diagram.id)
      .map((d) => ({
        id: d.id,
        title: d.title,
        count: [...d.nodes, ...d.edges]
          .flatMap((el) => el.threats)
          .filter((t) => matches(t, filters, query)).length,
      }))
      .filter((d) => d.count > 0);
  }, [shownCount, active, diagram.id, filters, query]);

  const pick = (id: string) =>
    setView((cur) => ({
      ...cur,
      selectedId: cur.selectedId === id ? null : id,
      focusThreat: null,
    }));

  const switchDiagram = (id: number) =>
    setView({ diagramId: id, selectedId: null, focusThreat: null });

  return (
    <div>
      {/* Diagram picker */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 16 }}>
        {THREAT_MODEL.diagrams.map((d) => (
          <button
            key={d.id}
            onClick={() => switchDiagram(d.id)}
            className="ax-pill"
            style={{
              padding: "6px 13px",
              cursor: "pointer",
              fontFamily: "inherit",
              border:
                d.id === diagram.id
                  ? `1px solid ${CYAN}`
                  : "1px solid rgba(148,163,184,.28)",
              background: d.id === diagram.id ? "rgba(0,212,255,.14)" : "transparent",
              color: d.id === diagram.id ? CYAN_SOFT : SLATE,
            }}
          >
            {d.title}
            <span style={{ opacity: 0.65, fontWeight: 500 }}>
              {d.open > 0 ? `${d.total} · ${d.open} open` : `${d.total}`}
            </span>
          </button>
        ))}
      </div>

      <p style={{ color: "#94a3b8", fontSize: 14, lineHeight: 1.65, margin: "0 0 14px" }}>
        {diagram.description}
      </p>

      {/* Legend + controls */}
      <div
        style={{
          display: "flex",
          flexWrap: "wrap",
          gap: 14,
          alignItems: "center",
          marginBottom: 12,
          fontSize: 12.5,
          color: SLATE,
        }}
      >
        <LegendSwatch color={CYAN} label="Actor / process / store" />
        <LegendSwatch color={PURPLE} label="Trust boundary" dashed />
        <LegendSwatch color={AMBER} label="Open threat · unencrypted flow" dashed />
        <span style={{ flex: 1 }} />
        <button
          className="ax-pill"
          onClick={() => setShowLabels((v) => !v)}
          style={{
            padding: "5px 12px",
            cursor: "pointer",
            fontFamily: "inherit",
            border: showLabels
              ? "1px solid rgba(0,212,255,.45)"
              : "1px solid rgba(148,163,184,.28)",
            background: showLabels ? "rgba(0,212,255,.1)" : "transparent",
            color: showLabels ? CYAN_SOFT : SLATE,
          }}
        >
          {showLabels ? "Hide flow labels" : "Show all flow labels"}
        </button>
        <button
          className="ax-pill"
          onClick={() => setFit((v) => !v)}
          style={{
            padding: "5px 12px",
            cursor: "pointer",
            fontFamily: "inherit",
            border: "1px solid rgba(0,212,255,.3)",
            background: "rgba(0,212,255,.06)",
            color: CYAN_SOFT,
          }}
        >
          {fit ? "Full size" : "Fit width"}
        </button>
      </div>

      <Diagram
        diagram={diagram}
        selectedId={view.selectedId}
        onSelect={pick}
        fit={fit}
        showLabels={showLabels}
      />

      <p style={{ color: "#64748b", fontSize: 12.5, margin: "10px 0 22px" }}>
        Hover a flow to read its label; click any element or flow to see the
        threats recorded against it. Badged elements carry an open item. Every
        threat has a copyable <code>T-nnn</code> link.
      </p>

      {/* Filters */}
      <div
        className="glass-card"
        style={{ padding: "12px 14px", margin: "0 0 16px", background: "rgba(8,8,28,.4)" }}
      >
        <div
          style={{
            display: "flex",
            gap: 10,
            alignItems: "center",
            flexWrap: "wrap",
            marginBottom: 10,
          }}
        >
          <input
            type="search"
            value={filters.query}
            onChange={(e) => setFilters((f) => ({ ...f, query: e.target.value }))}
            placeholder="Search title, description, mitigation or T-number…"
            aria-label="Search threats"
            style={{
              flex: "1 1 260px",
              minWidth: 0,
              padding: "7px 11px",
              borderRadius: 8,
              border: "1px solid rgba(148,163,184,.28)",
              background: "rgba(0,0,0,.28)",
              color: "#e2e8f0",
              font: "13px inherit",
            }}
          />
          <FilterChip
            label="Open only"
            active={filters.openOnly}
            color={AMBER}
            onClick={() => setFilters((f) => ({ ...f, openOnly: !f.openOnly }))}
          />
          {active && (
            <button
              className="ax-pill"
              onClick={() => setFilters(NO_FILTERS)}
              style={{
                padding: "4px 11px",
                fontSize: 12,
                cursor: "pointer",
                fontFamily: "inherit",
                border: "1px solid rgba(148,163,184,.28)",
                background: "transparent",
                color: SLATE,
              }}
            >
              Clear filters
            </button>
          )}
        </div>

        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
          <span style={{ fontSize: 11.5, color: "#64748b", minWidth: 62 }}>Severity</span>
          {SEVERITIES.map((s) => (
            <FilterChip
              key={s}
              label={s}
              active={filters.severities.includes(s)}
              color={SEVERITY_COLOR[s] ?? SLATE}
              onClick={() =>
                setFilters((f) => ({ ...f, severities: toggle(f.severities, s) }))
              }
            />
          ))}
        </div>
        <div
          style={{
            display: "flex",
            gap: 8,
            flexWrap: "wrap",
            alignItems: "center",
            marginTop: 8,
          }}
        >
          <span style={{ fontSize: 11.5, color: "#64748b", minWidth: 62 }}>STRIDE</span>
          {CATEGORIES.map((c) => (
            <FilterChip
              key={c}
              label={c}
              active={filters.categories.includes(c)}
              color={PURPLE}
              onClick={() =>
                setFilters((f) => ({ ...f, categories: toggle(f.categories, c) }))
              }
            />
          ))}
        </div>
      </div>

      {/* Threat list */}
      <div
        style={{
          display: "flex",
          gap: 10,
          alignItems: "center",
          flexWrap: "wrap",
          marginBottom: 14,
        }}
      >
        <span style={{ fontWeight: 700, fontSize: 15 }}>
          {selected ? selected.name : diagram.title} —{" "}
          <span style={{ color: SLATE, fontWeight: 500 }}>
            {shownCount} threat{shownCount === 1 ? "" : "s"}
            {active || selected ? ` of ${diagram.total} in this diagram` : ""}
          </span>
        </span>
        <span style={{ flex: 1 }} />
        {selected && (
          <button
            className="ax-pill"
            onClick={() => setView((cur) => ({ ...cur, selectedId: null, focusThreat: null }))}
            style={{
              padding: "5px 12px",
              cursor: "pointer",
              fontFamily: "inherit",
              border: "1px solid rgba(148,163,184,.28)",
              background: "transparent",
              color: SLATE,
            }}
          >
            Clear selection
          </button>
        )}
      </div>

      {shownCount === 0 && (
        <div style={{ marginBottom: 18 }}>
          <p style={{ color: SLATE, fontSize: 14, margin: "0 0 8px" }}>
            {selected
              ? `No threat on ${selected.name} matches the current filters.`
              : `No threat in ${diagram.title} matches the current filters.`}
          </p>
          {elsewhere.length > 0 && (
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
              <span style={{ fontSize: 12.5, color: "#64748b" }}>Matches elsewhere:</span>
              {elsewhere.map((d) => (
                <button
                  key={d.id}
                  className="ax-pill"
                  onClick={() => switchDiagram(d.id)}
                  style={{
                    padding: "4px 11px",
                    fontSize: 12,
                    cursor: "pointer",
                    fontFamily: "inherit",
                    border: "1px solid rgba(0,212,255,.3)",
                    background: "rgba(0,212,255,.06)",
                    color: CYAN_SOFT,
                  }}
                >
                  {d.title}
                  <span style={{ opacity: 0.7, fontWeight: 500 }}>{d.count}</span>
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{ display: "flex", flexDirection: "column", gap: 22 }}>
        {shown.map((el) => (
          <div key={el.id}>
            <div
              style={{
                display: "flex",
                gap: 10,
                alignItems: "baseline",
                flexWrap: "wrap",
                marginBottom: 4,
              }}
            >
              <span style={{ fontWeight: 700, fontSize: 14.5, color: CYAN_SOFT }}>
                {el.name}
              </span>
              <Chip text={el.kindLabel} color={SLATE} />
            </div>
            {el.description && (
              <p
                style={{
                  margin: "0 0 10px",
                  fontSize: 13,
                  color: "#64748b",
                  lineHeight: 1.6,
                }}
              >
                {el.description}
              </p>
            )}
            <div style={{ display: "flex", flexDirection: "column", gap: 10 }}>
              {el.threats.map((t) => (
                <ThreatCard
                  key={t.number}
                  threat={t}
                  diagramId={diagram.id}
                  focused={t.number === view.focusThreat}
                />
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function LegendSwatch({
  color,
  label,
  dashed,
}: {
  color: string;
  label: string;
  dashed?: boolean;
}) {
  return (
    <span style={{ display: "inline-flex", alignItems: "center", gap: 7 }}>
      <span
        style={{
          width: 20,
          height: 0,
          borderTop: `2px ${dashed ? "dashed" : "solid"} ${color}`,
          display: "inline-block",
        }}
      />
      {label}
    </span>
  );
}

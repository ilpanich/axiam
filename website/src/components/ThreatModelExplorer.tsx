import { useMemo, useState } from "react";
import { THREAT_MODEL } from "../threatModel";
import type { TmDiagram, TmEdge, TmNode, TmThreat } from "../threatModelTypes";

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

/* ---- Threat list --------------------------------------------------------- */

function ThreatCard({ threat }: { threat: TmThreat }) {
  return (
    <div
      className="glass-card"
      style={{
        padding: "14px 16px",
        borderColor:
          threat.status === "Mitigated"
            ? "rgba(0,212,255,.14)"
            : "rgba(255,189,46,.34)",
        background:
          threat.status === "Mitigated"
            ? "rgba(255,255,255,.035)"
            : "rgba(255,189,46,.05)",
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
      <p style={{ margin: 0, fontSize: 13.5, color: "#94a3b8", lineHeight: 1.6 }}>
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
  const [index, setIndex] = useState(0);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [openOnly, setOpenOnly] = useState(false);
  const [fit, setFit] = useState(true);
  const [showLabels, setShowLabels] = useState(false);

  const diagram = THREAT_MODEL.diagrams[index];

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

  const selected = elements.find((el) => el.id === selectedId) ?? null;

  const shown = useMemo(() => {
    const base = selected ? [selected] : elements;
    return base
      .map((el) => ({
        ...el,
        threats: openOnly
          ? el.threats.filter((t) => t.status !== "Mitigated")
          : el.threats,
      }))
      .filter((el) => el.threats.length > 0);
  }, [elements, selected, openOnly]);

  const shownCount = shown.reduce((n, el) => n + el.threats.length, 0);

  const pick = (id: string) => setSelectedId((cur) => (cur === id ? null : id));
  const switchDiagram = (next: number) => {
    setIndex(next);
    setSelectedId(null);
  };

  return (
    <div>
      {/* Diagram picker */}
      <div style={{ display: "flex", flexWrap: "wrap", gap: 8, marginBottom: 16 }}>
        {THREAT_MODEL.diagrams.map((d, i) => (
          <button
            key={d.id}
            onClick={() => switchDiagram(i)}
            className="ax-pill"
            style={{
              padding: "6px 13px",
              cursor: "pointer",
              fontFamily: "inherit",
              border:
                i === index
                  ? `1px solid ${CYAN}`
                  : "1px solid rgba(148,163,184,.28)",
              background: i === index ? "rgba(0,212,255,.14)" : "transparent",
              color: i === index ? CYAN_SOFT : SLATE,
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
        selectedId={selectedId}
        onSelect={pick}
        fit={fit}
        showLabels={showLabels}
      />

      <p style={{ color: "#64748b", fontSize: 12.5, margin: "10px 0 22px" }}>
        Hover a flow to read its label; click any element or flow to see the
        threats recorded against it. Badged elements carry an open item.
      </p>

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
          </span>
        </span>
        <span style={{ flex: 1 }} />
        <button
          className="ax-pill"
          onClick={() => setOpenOnly((v) => !v)}
          style={{
            padding: "5px 12px",
            cursor: "pointer",
            fontFamily: "inherit",
            border: openOnly
              ? `1px solid ${AMBER}88`
              : "1px solid rgba(148,163,184,.28)",
            background: openOnly ? "rgba(255,189,46,.1)" : "transparent",
            color: openOnly ? AMBER : SLATE,
          }}
        >
          {openOnly ? "Showing open only" : "Show open only"}
        </button>
        {selected && (
          <button
            className="ax-pill"
            onClick={() => setSelectedId(null)}
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
        <p style={{ color: SLATE, fontSize: 14 }}>
          No threats match the current filter.
        </p>
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
                <ThreatCard key={t.number} threat={t} />
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

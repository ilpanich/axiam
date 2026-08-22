/**
 * Generate `src/threatModel.ts` from the OWASP Threat Dragon model.
 *
 * The Threat Dragon JSON (`ThreatDragonModels/Axiam/Axiam.json`) is the single
 * source of truth for the Security section: the diagrams, the trust boundaries
 * and every threat with its severity, status and mitigation. This script turns
 * that editor-oriented model into a small, render-ready data module — nodes and
 * boundaries with laid-out label lines, flows pre-routed into SVG path strings,
 * and per-diagram counts — so the website component stays a pure renderer and
 * the page cannot drift from the model.
 *
 * Run it after editing the model:
 *
 *   npm run gen:threat-model
 *
 * The generated file is committed; CI does not regenerate it.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const MODEL = resolve(here, "../../ThreatDragonModels/Axiam/Axiam.json");
const OUT = resolve(here, "../src/threatModel.ts");
// The full model is a few hundred kilobytes, so the Security page lazy-loads
// it and imports only these headline counts eagerly.
const OUT_SUMMARY = resolve(here, "../src/threatModelSummary.ts");

/** Padding added around the model's bounding box, in model units. */
const MARGIN = 24;
/** Font size used for element labels when wrapping them into lines. */
const NODE_FONT = 12;
/** Font size used for flow labels. */
const EDGE_FONT = 10.5;

/**
 * Canonical orders for the coverage tables the summary emits.
 *
 * Counting is driven by the model, but the *order* of the rows is not — a
 * severity table sorted by whatever the first diagram happened to contain reads
 * as noise. Anything the model carries that is not listed here is appended
 * rather than dropped, so a new category shows up on the page instead of
 * vanishing from the totals.
 */
const CATEGORY_ORDER = [
  "Spoofing",
  "Tampering",
  "Repudiation",
  "Information disclosure",
  "Denial of service",
  "Elevation of privilege",
];
const SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"];

/** Rough advance width of a character at `size`, used for greedy wrapping. */
const charWidth = (size) => size * 0.54;

/**
 * Wrap `text` into lines that fit `width` (minus padding), honouring the
 * explicit newlines the model author already put in the label.
 */
function wrap(text, width, size, pad = 12) {
  const max = Math.max(width - pad * 2, 40);
  const perLine = Math.max(Math.floor(max / charWidth(size)), 6);
  const lines = [];
  for (const paragraph of String(text ?? "").split("\n")) {
    const words = paragraph.trim().split(/\s+/).filter(Boolean);
    if (words.length === 0) {
      lines.push("");
      continue;
    }
    let line = "";
    for (const word of words) {
      const candidate = line ? `${line} ${word}` : word;
      if (candidate.length <= perLine || !line) {
        line = candidate;
      } else {
        lines.push(line);
        line = word;
      }
    }
    lines.push(line);
  }
  return lines;
}

const centerOf = (cell) => ({
  x: cell.position.x + cell.size.width / 2,
  y: cell.position.y + cell.size.height / 2,
});

/**
 * Clip the segment running from a cell's centre towards `to` at the cell's
 * outline, so flows start and end on the shape's edge rather than under it.
 * Processes are circles in Threat Dragon; actors and stores are rectangles.
 */
function anchor(cell, to, kind) {
  const c = centerOf(cell);
  const dx = to.x - c.x;
  const dy = to.y - c.y;
  if (dx === 0 && dy === 0) return c;

  if (kind === "process") {
    const r = Math.min(cell.size.width, cell.size.height) / 2;
    const len = Math.hypot(dx, dy);
    return { x: c.x + (dx / len) * r, y: c.y + (dy / len) * r };
  }

  const hw = cell.size.width / 2;
  const hh = cell.size.height / 2;
  // Scale the direction vector until it first touches a rectangle edge.
  const t = Math.min(
    dx === 0 ? Infinity : hw / Math.abs(dx),
    dy === 0 ? Infinity : hh / Math.abs(dy),
  );
  return { x: c.x + dx * t, y: c.y + dy * t };
}

/** Build an SVG path through `points`, rounding the corners at each vertex. */
function pathThrough(points) {
  if (points.length < 2) return "";
  if (points.length === 2) {
    return `M${round(points[0].x)},${round(points[0].y)} L${round(points[1].x)},${round(points[1].y)}`;
  }
  const RADIUS = 16;
  let d = `M${round(points[0].x)},${round(points[0].y)}`;
  for (let i = 1; i < points.length - 1; i++) {
    const prev = points[i - 1];
    const cur = points[i];
    const next = points[i + 1];
    const inLen = Math.hypot(cur.x - prev.x, cur.y - prev.y) || 1;
    const outLen = Math.hypot(next.x - cur.x, next.y - cur.y) || 1;
    const r = Math.min(RADIUS, inLen / 2, outLen / 2);
    const a = {
      x: cur.x - ((cur.x - prev.x) / inLen) * r,
      y: cur.y - ((cur.y - prev.y) / inLen) * r,
    };
    const b = {
      x: cur.x + ((next.x - cur.x) / outLen) * r,
      y: cur.y + ((next.y - cur.y) / outLen) * r,
    };
    d += ` L${round(a.x)},${round(a.y)} Q${round(cur.x)},${round(cur.y)} ${round(b.x)},${round(b.y)}`;
  }
  const last = points[points.length - 1];
  d += ` L${round(last.x)},${round(last.y)}`;
  return d;
}

const round = (n) => Math.round(n * 10) / 10;

/** Midpoint of the polyline, used to place the flow label. */
function midpoint(points) {
  const lengths = [];
  let total = 0;
  for (let i = 1; i < points.length; i++) {
    const len = Math.hypot(points[i].x - points[i - 1].x, points[i].y - points[i - 1].y);
    lengths.push(len);
    total += len;
  }
  let walked = 0;
  for (let i = 0; i < lengths.length; i++) {
    if (walked + lengths[i] >= total / 2) {
      const t = lengths[i] === 0 ? 0 : (total / 2 - walked) / lengths[i];
      return {
        x: points[i].x + (points[i + 1].x - points[i].x) * t,
        y: points[i].y + (points[i + 1].y - points[i].y) * t,
      };
    }
    walked += lengths[i];
  }
  return points[Math.floor(points.length / 2)];
}

const threatsOf = (cell) =>
  (cell.data?.threats ?? []).map((t) => ({
    number: t.number,
    title: t.title,
    type: t.type,
    severity: t.severity,
    status: t.status,
    description: t.description,
    mitigation: t.mitigation,
  }));

const SHAPE_KIND = { actor: "actor", process: "process", store: "store" };

function buildDiagram(diagram) {
  const cells = diagram.cells.filter((c) => c.visible !== false || c.shape === "flow");
  const boundaries = cells.filter((c) => c.shape === "trust-boundary-box");
  const nodeCells = cells.filter((c) => SHAPE_KIND[c.shape]);
  const flowCells = cells.filter((c) => c.shape === "flow");
  const byId = new Map(nodeCells.map((c) => [c.id, c]));

  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  for (const cell of [...boundaries, ...nodeCells]) {
    minX = Math.min(minX, cell.position.x);
    minY = Math.min(minY, cell.position.y);
    maxX = Math.max(maxX, cell.position.x + cell.size.width);
    maxY = Math.max(maxY, cell.position.y + cell.size.height);
  }
  const ox = minX - MARGIN;
  const oy = minY - MARGIN;

  const shift = (cell) => ({
    x: cell.position.x - ox,
    y: cell.position.y - oy,
    w: cell.size.width,
    h: cell.size.height,
  });

  const nodes = nodeCells.map((cell) => {
    const kind = SHAPE_KIND[cell.shape];
    const box = shift(cell);
    const name = cell.data?.name ?? cell.attrs?.text?.text ?? "";
    const threats = threatsOf(cell);
    return {
      id: cell.id,
      kind,
      ...box,
      name: name.replace(/\n/g, " "),
      // A circle is narrower than its bounding box everywhere but the centre,
      // so process labels wrap tighter than actors and stores.
      lines: wrap(name, kind === "process" ? box.w * 0.66 : box.w, NODE_FONT, 8),
      description: cell.data?.description ?? "",
      outOfScope: Boolean(cell.data?.outOfScope),
      threats,
      open: threats.filter((t) => t.status !== "Mitigated").length,
    };
  });

  const edges = flowCells.flatMap((cell) => {
    const source = byId.get(cell.source?.cell);
    const target = byId.get(cell.target?.cell);
    if (!source || !target) return [];

    const vertices = (cell.vertices ?? []).map((v) => ({ x: v.x, y: v.y }));
    const start = anchor(source, vertices[0] ?? centerOf(target), SHAPE_KIND[source.shape]);
    const end = anchor(
      target,
      vertices[vertices.length - 1] ?? centerOf(source),
      SHAPE_KIND[target.shape],
    );
    const points = [start, ...vertices, end].map((p) => ({ x: p.x - ox, y: p.y - oy }));
    const mid = midpoint(points);
    const label = cell.labels?.[0]?.attrs?.label?.text ?? cell.data?.name ?? "";
    const threats = threatsOf(cell);

    return [
      {
        id: cell.id,
        path: pathThrough(points),
        name: cell.data?.name ?? label,
        description: cell.data?.description ?? "",
        label,
        labelLines: wrap(label, 210, EDGE_FONT, 2),
        lx: round(mid.x),
        ly: round(mid.y),
        bidirectional: Boolean(cell.data?.isBidirectional),
        encrypted: Boolean(cell.data?.isEncrypted),
        publicNetwork: Boolean(cell.data?.isPublicNetwork),
        protocol: cell.data?.protocol ?? "",
        threats,
        open: threats.filter((t) => t.status !== "Mitigated").length,
      },
    ];
  });

  const allThreats = [...nodes, ...edges].flatMap((el) => el.threats);
  const bySeverity = {};
  for (const t of allThreats) bySeverity[t.severity] = (bySeverity[t.severity] ?? 0) + 1;

  return {
    id: diagram.id,
    title: diagram.title,
    description: diagram.description ?? "",
    width: round(maxX - ox + MARGIN),
    height: round(maxY - oy + MARGIN),
    boundaries: boundaries.map((cell) => ({
      id: cell.id,
      ...shift(cell),
      label: cell.data?.name ?? cell.attrs?.label?.text ?? "",
    })),
    nodes,
    edges,
    total: allThreats.length,
    open: allThreats.filter((t) => t.status !== "Mitigated").length,
    bySeverity,
  };
}

const model = JSON.parse(readFileSync(MODEL, "utf8"));
const diagrams = model.detail.diagrams.map(buildDiagram);
const total = diagrams.reduce((n, d) => n + d.total, 0);
const open = diagrams.reduce((n, d) => n + d.open, 0);

const header = `// AUTO-GENERATED — do not edit by hand.
//
// Produced by \`npm run gen:threat-model\` from the OWASP Threat Dragon model at
// \`ThreatDragonModels/Axiam/Axiam.json\`, which is the source of truth for the
// Security section. Re-run the generator whenever the model changes.

import type {
  ThreatModel,
  TmDiagram,
} from "./threatModelTypes";

export type { ThreatModel, TmDiagram };

`;

const body = `export const THREAT_MODEL: ThreatModel = ${JSON.stringify(
  {
    title: model.summary.title,
    owner: model.summary.owner,
    description: model.summary.description,
    version: model.version,
    diagramCount: diagrams.length,
    total,
    open,
    mitigated: total - open,
    diagrams,
  },
  null,
  1,
)};
`;

writeFileSync(OUT, header + body);

/**
 * Tally `key(threat)` across every threat in the model, emitting the buckets in
 * `order` first and any unrecognised bucket after them.
 */
function tally(order, key) {
  const counts = new Map(order.map((name) => [name, { total: 0, open: 0 }]));
  for (const diagram of diagrams) {
    for (const el of [...diagram.nodes, ...diagram.edges]) {
      for (const threat of el.threats) {
        const name = key(threat);
        if (!counts.has(name)) counts.set(name, { total: 0, open: 0 });
        const bucket = counts.get(name);
        bucket.total += 1;
        if (threat.status !== "Mitigated") bucket.open += 1;
      }
    }
  }
  return [...counts].map(([name, bucket]) => ({ name, ...bucket }));
}

const SEVERITY_RANK = new Map(SEVERITY_ORDER.map((s, i) => [s, i]));

/**
 * Every threat the model does not record as mitigated, most severe first.
 *
 * The Security page renders this as the open risk register. Each entry carries
 * the element and the diagram it sits on because "who owns it" is only legible
 * with that context — an open item on the Kubernetes diagram is a deployment
 * responsibility; the same words against a request-path process would not be.
 */
const openRisks = diagrams
  .flatMap((diagram) =>
    [...diagram.nodes, ...diagram.edges].flatMap((el) =>
      el.threats
        .filter((t) => t.status !== "Mitigated")
        .map((t) => ({
          number: t.number,
          title: t.title,
          category: t.type,
          severity: t.severity,
          diagramId: diagram.id,
          area: diagram.title,
          element: el.name.replace(/\n/g, " "),
          residualRisk: t.mitigation,
        })),
    ),
  )
  .sort(
    (a, b) =>
      (SEVERITY_RANK.get(a.severity) ?? SEVERITY_ORDER.length) -
        (SEVERITY_RANK.get(b.severity) ?? SEVERITY_ORDER.length) ||
      a.number - b.number,
  );

const summary = {
  version: model.version,
  diagramCount: diagrams.length,
  total,
  open,
  mitigated: total - open,
  areas: diagrams.map((d) => ({
    id: d.id,
    title: d.title,
    total: d.total,
    open: d.open,
  })),
  categories: tally(CATEGORY_ORDER, (t) => t.type),
  severities: tally(SEVERITY_ORDER, (t) => t.severity),
  openRisks,
};

writeFileSync(
  OUT_SUMMARY,
  `// AUTO-GENERATED — do not edit by hand.
//
// Headline counts from the OWASP Threat Dragon model, emitted by
// \`npm run gen:threat-model\` alongside \`threatModel.ts\`. Kept as a separate,
// tiny module so pages can quote the numbers without pulling in the whole model.

export interface ThreatModelArea {
  id: number;
  title: string;
  total: number;
  open: number;
}

/** One row of a coverage table — a STRIDE category, or a severity. */
export interface ThreatModelBucket {
  name: string;
  total: number;
  open: number;
}

/** One entry of the open risk register. */
export interface ThreatModelOpenRisk {
  number: number;
  title: string;
  category: string;
  severity: string;
  /** Diagram the threat sits on, for deep-linking into the explorer. */
  diagramId: number;
  area: string;
  element: string;
  /**
   * The model's mitigation field. For an open item it states the residual risk
   * and where responsibility for it lands.
   */
  residualRisk: string;
}

export interface ThreatModelSummary {
  /** Threat Dragon model schema version. */
  version: string;
  diagramCount: number;
  total: number;
  open: number;
  mitigated: number;
  /** Per-diagram counts, in model order. */
  areas: ThreatModelArea[];
  /** Counts per STRIDE category, in STRIDE order. */
  categories: ThreatModelBucket[];
  /** Counts per severity, most severe first. */
  severities: ThreatModelBucket[];
  /** Every threat not recorded as mitigated, most severe first. */
  openRisks: ThreatModelOpenRisk[];
}

export const THREAT_MODEL_SUMMARY: ThreatModelSummary = ${JSON.stringify(summary, null, 1)};
`,
);

console.log(
  `threatModel.ts: ${diagrams.length} diagrams, ${total} threats (${total - open} mitigated, ${open} open)`,
);

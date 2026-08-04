/**
 * Types for the generated threat-model data module (`threatModel.ts`).
 *
 * The data itself is produced from the OWASP Threat Dragon model by
 * `scripts/gen-threat-model.mjs`; these types describe the render-ready shape
 * that generator emits — geometry already resolved into SVG coordinates, flows
 * already routed into path strings, labels already wrapped into lines.
 */

/** STRIDE category of a threat, as recorded in the Threat Dragon model. */
export type TmCategory =
  | "Spoofing"
  | "Tampering"
  | "Repudiation"
  | "Information disclosure"
  | "Denial of service"
  | "Elevation of privilege";

export type TmSeverity = "Critical" | "High" | "Medium" | "Low";

export type TmStatus = "Mitigated" | "Open" | "NotApplicable";

export interface TmThreat {
  /** Author-assigned threat number within the model. */
  number: number;
  title: string;
  type: TmCategory | string;
  severity: TmSeverity | string;
  status: TmStatus | string;
  description: string;
  /** The control that answers the threat, or why the residual risk is accepted. */
  mitigation: string;
}

/** Anything in a diagram that can carry threats — an element or a flow. */
interface TmThreatBearing {
  id: string;
  name: string;
  description: string;
  threats: TmThreat[];
  /** Number of threats whose status is not `Mitigated`. */
  open: number;
}

/** A dashed trust-boundary box. Purely decorative — it carries no threats. */
export interface TmBoundary {
  id: string;
  x: number;
  y: number;
  w: number;
  h: number;
  label: string;
}

/** An actor, process or data store. */
export interface TmNode extends TmThreatBearing {
  kind: "actor" | "process" | "store";
  x: number;
  y: number;
  w: number;
  h: number;
  /** Label pre-wrapped to the shape's width. */
  lines: string[];
  outOfScope: boolean;
}

/** A data flow between two elements. */
export interface TmEdge extends TmThreatBearing {
  /** SVG path, clipped to both endpoints' outlines and rounded at vertices. */
  path: string;
  label: string;
  /** Label pre-wrapped for the small on-diagram caption. */
  labelLines: string[];
  /** Label anchor — the midpoint of the routed path. */
  lx: number;
  ly: number;
  bidirectional: boolean;
  encrypted: boolean;
  publicNetwork: boolean;
  protocol: string;
}

export interface TmDiagram {
  id: number;
  title: string;
  description: string;
  /** Diagram extents, used as the SVG `viewBox`. */
  width: number;
  height: number;
  boundaries: TmBoundary[];
  nodes: TmNode[];
  edges: TmEdge[];
  total: number;
  open: number;
  bySeverity: Record<string, number>;
}

export interface ThreatModel {
  title: string;
  owner: string;
  description: string;
  /** Threat Dragon model schema version. */
  version: string;
  diagramCount: number;
  total: number;
  open: number;
  mitigated: number;
  diagrams: TmDiagram[];
}

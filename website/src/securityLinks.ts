/**
 * The shape of a deep link into the Security section's threat-model explorer.
 *
 * Two modules build these links — the explorer itself, and the open risk
 * register in `security.ts`, which cannot import the explorer without dragging
 * the whole generated model into the eagerly-loaded bundle. The format lives
 * here so the two cannot drift apart.
 *
 * `#/security/diagram/8` selects a diagram; a third segment selects either a
 * threat (`T-186`) or an element by its model id. `App.tsx` matches the broader
 * `#/security…` prefix to decide which page is on screen; only the explorer
 * interprets what follows.
 */

export const SECURITY_DEEP_LINK_RE = /^#\/security\/diagram\/(\d+)(?:\/([^/]+))?$/;

export const diagramHash = (diagramId: number) => `#/security/diagram/${diagramId}`;

export const elementHash = (diagramId: number, elementId: string) =>
  `${diagramHash(diagramId)}/${elementId}`;

export const threatHash = (diagramId: number, number: number) =>
  `${diagramHash(diagramId)}/T-${number}`;

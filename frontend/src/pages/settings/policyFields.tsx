/**
 * Primitives the settings policy cards are built from.
 *
 * Extracted from `SettingsPage.tsx` together with `dcrPolicy.tsx`: once a card
 * lives in its own module it can no longer reach the page's local helpers, and
 * two cards rendering the same read-mode row through two copies of it is how
 * the DCR and CIMD summaries would drift. Nothing here has any policy in it —
 * these are two labelled displays; the words and the list parser are in
 * `policyText.ts`.
 */

import { Badge } from "@/components/ui/badge";

export interface NumberDisplayProps {
  label: string;
  value: number;
  unit?: string;
}

export function NumberDisplay({ label, value, unit }: NumberDisplayProps) {
  return (
    <div>
      <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
        {label}
      </p>
      <p className="text-sm text-foreground font-medium">
        {value}
        {unit ? ` ${unit}` : ""}
      </p>
    </div>
  );
}

export interface BooleanDisplayProps {
  label: string;
  enabled: boolean;
}

export function BooleanDisplay({ label, enabled }: BooleanDisplayProps) {
  return (
    <div className="flex items-center gap-2">
      <p className="text-xs text-muted-foreground uppercase tracking-wide">
        {label}
      </p>
      <Badge variant={enabled ? "default" : "secondary"}>
        {enabled ? "Enabled" : "Disabled"}
      </Badge>
    </div>
  );
}

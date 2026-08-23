import { AlertTriangle } from "lucide-react";

import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import {
  OPAQUE_KSFS,
  OPAQUE_KSF_LABEL,
  OPAQUE_MODES,
  OPAQUE_MODE_DESCRIPTION,
  OPAQUE_MODE_LABEL,
  OPAQUE_SUITES,
  OPAQUE_SUITE_LABEL,
  type OpaqueKsf,
  type OpaqueMode,
  type OpaquePolicy,
  type OpaqueSuite,
} from "@/services/opaquePolicy";

// The OPAQUE policy editor, shared by the organization baseline (Organizations
// → Settings) and the tenant override (Settings). Both write the same three
// fields to the same shapes, and a second copy of the `required` warning is a
// second copy that can go stale.

const SELECT_CLASS =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40 disabled:opacity-50";

interface OpaquePolicyFieldsProps {
  /** Prefixes every control id, so both pages can host this without collisions. */
  idPrefix: string;
  value: OpaquePolicy;
  onChange: (next: OpaquePolicy) => void;
  disabled?: boolean;
  /**
   * Scope-specific advisory rendered under the mode select — the tenant page
   * passes its tighten-only warning here. `null` renders nothing.
   */
  warning?: string | null;
}

export function OpaquePolicyFields({
  idPrefix,
  value,
  onChange,
  disabled,
  warning,
}: OpaquePolicyFieldsProps) {
  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-opaque-mode`}>Mode</Label>
        <select
          id={`${idPrefix}-opaque-mode`}
          value={value.opaque_mode}
          disabled={disabled}
          onChange={(e) =>
            onChange({ ...value, opaque_mode: e.target.value as OpaqueMode })
          }
          className={SELECT_CLASS}
        >
          {OPAQUE_MODES.map((mode) => (
            <option key={mode} value={mode}>
              {OPAQUE_MODE_LABEL[mode]}
            </option>
          ))}
        </select>
        <p className="text-xs text-muted-foreground">
          {OPAQUE_MODE_DESCRIPTION[value.opaque_mode]}
        </p>
      </div>

      {value.opaque_mode === "required" && (
        <div
          role="alert"
          className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/8 p-3 text-xs text-amber-400"
        >
          <AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>
            <strong>Required locks out anyone without a registration
            record.</strong>{" "}
            Password login is refused for the whole tenant before any credential
            is examined — including yours. Users enrol as they next set a
            password, so move to Optional first and give that time to spread.
            OPAQUE also needs the server started with an OPAQUE session key and
            setup key; without them these endpoints cannot answer.
          </span>
        </div>
      )}

      {warning && (
        <p role="alert" className="text-xs text-amber-400">
          {warning}
        </p>
      )}

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-opaque-suite`}>Ciphersuite</Label>
        <select
          id={`${idPrefix}-opaque-suite`}
          value={value.opaque_suite}
          disabled={disabled}
          onChange={(e) =>
            onChange({ ...value, opaque_suite: e.target.value as OpaqueSuite })
          }
          className={SELECT_CLASS}
        >
          {OPAQUE_SUITES.map((suite) => (
            <option key={suite} value={suite}>
              {OPAQUE_SUITE_LABEL[suite]}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-opaque-ksf`}>Key-stretching function</Label>
        <select
          id={`${idPrefix}-opaque-ksf`}
          value={value.opaque_ksf}
          disabled={disabled}
          onChange={(e) =>
            onChange({ ...value, opaque_ksf: e.target.value as OpaqueKsf })
          }
          className={SELECT_CLASS}
        >
          {OPAQUE_KSFS.map((ksf) => (
            <option key={ksf} value={ksf}>
              {OPAQUE_KSF_LABEL[ksf]}
            </option>
          ))}
        </select>
      </div>

      <p className="text-xs text-muted-foreground">
        The ciphersuite and key-stretching function apply to records created
        from now on. Existing records keep the parameters they were enrolled
        with, so tightening these takes effect as users next set a password
        rather than invalidating everyone at once.
      </p>
    </div>
  );
}

/** Read-only rendering of the same three fields. */
export function OpaquePolicySummary({ value }: { value: OpaquePolicy }) {
  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <div className="flex items-center gap-2">
        <p className="text-xs text-muted-foreground uppercase tracking-wide">
          Mode
        </p>
        <Badge variant={value.opaque_mode === "disabled" ? "secondary" : "default"}>
          {OPAQUE_MODE_LABEL[value.opaque_mode]}
        </Badge>
      </div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
          Ciphersuite
        </p>
        <p className="text-sm text-foreground font-medium">
          {OPAQUE_SUITE_LABEL[value.opaque_suite]}
        </p>
      </div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
          Key-stretching function
        </p>
        <p className="text-sm text-foreground font-medium">
          {OPAQUE_KSF_LABEL[value.opaque_ksf]}
        </p>
      </div>
    </div>
  );
}

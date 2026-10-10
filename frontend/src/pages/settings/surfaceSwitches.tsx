/**
 * P23W4-07 — the two switches of the identity and event surfaces, as an edit
 * form and a read-only summary.
 *
 * `saml_idp_enabled` (D-20) and `ssf_enabled` (D-45) are **disable-only**
 * layered settings: an organization turns a surface on for its tenants, and a
 * tenant may switch it off for itself and never on. Until this card existed the
 * only way to see which third parties receive security events about a tenant's
 * users, or to turn either surface off during an incident, was the settings API.
 *
 * What the form does not do is decide anything the server decides. At tenant
 * level it shows the layer an effective `false` comes from
 * (`surfaceLayer`) and refuses to offer a switch-on the organization has
 * withheld; the ordering itself is enforced by the server, which answers `400`
 * naming the field.
 */

import { Badge } from "@/components/ui/badge";
import { BooleanDisplay } from "./policyFields";
import type { SurfaceKey, SurfaceLayer } from "@/services/settings";

export interface SurfaceValue {
  saml_idp_enabled: boolean;
  ssf_enabled: boolean;
}

export interface SurfaceSwitchesProps {
  idPrefix: string;
  scope: "organization" | "tenant";
  value: SurfaceValue;
  /** Edit form when true, read-only summary otherwise. */
  editing: boolean;
  onChange?: (patch: Partial<SurfaceValue>) => void;
  /** Tenant scope: where each effective `false` comes from. */
  layers?: Partial<Record<SurfaceKey, SurfaceLayer>>;
  /** D-55: `ssf_enabled` is on but the transmitter is inactive, and why. */
  ssfInactiveReason?: string | null;
  disabled?: boolean;
}

const SURFACES: {
  key: SurfaceKey;
  label: string;
  help: string;
}[] = [
  {
    key: "saml_idp_enabled",
    label: "SAML 2.0 identity provider",
    help: "AXIAM signs people in to other applications over SAML. Off, the IdP endpoints answer 404 and no assertion is issued; the registered service providers and the signing credential are kept.",
  },
  {
    key: "ssf_enabled",
    label: "Shared Signals Framework transmitter",
    help: "AXIAM sends security events about this tenant's users (session revoked, credential change, account state) to the receivers registered as SSF streams. Off, nothing is signed or transmitted; the streams are kept.",
  },
];

/** What to say about a surface that is off, at tenant scope. */
function layerNote(layer: SurfaceLayer | undefined): string | null {
  switch (layer) {
    case "organization":
      return "Disabled by the organization. A tenant cannot enable it; an organization administrator has to turn it on first.";
    case "tenant":
      return "Turned off for this tenant. It can be turned back on only while the organization has it on.";
    case "unknown":
      return "Off. If the organization has switched it off, this tenant cannot turn it on and the server refuses the save.";
    default:
      return null;
  }
}

export function SurfaceSwitches({
  idPrefix,
  scope,
  value,
  editing,
  onChange,
  layers,
  ssfInactiveReason,
  disabled,
}: SurfaceSwitchesProps) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        {scope === "organization"
          ? "Off by default. These are the baseline every tenant inherits: a tenant may switch a surface off for itself and never on, so a surface off here is off everywhere."
          : "Off by default. The organization decides whether a tenant may use a surface; this tenant can only switch it off for itself."}
      </p>
      {SURFACES.map(({ key, label, help }) => {
        const layer = scope === "tenant" ? layers?.[key] : undefined;
        const note = value[key] ? null : layerNote(layer);
        const locked = layer === "organization";
        const id = `${idPrefix}-${key}`;
        const inactive = key === "ssf_enabled" && value[key] && ssfInactiveReason;
        return (
          <div key={key} className="space-y-1">
            {editing ? (
              <label
                htmlFor={id}
                className="flex items-start gap-3 cursor-pointer select-none"
              >
                <input
                  id={id}
                  type="checkbox"
                  checked={value[key]}
                  disabled={disabled || locked}
                  onChange={(e) => onChange?.({ [key]: e.target.checked })}
                  className="mt-0.5 h-4 w-4 rounded border-primary/40 bg-white/5 text-primary focus:ring-primary/40 disabled:opacity-50 disabled:cursor-not-allowed"
                />
                <div className="min-w-0">
                  <span className="text-sm text-foreground">{label}</span>
                  <p className="text-xs text-muted-foreground mt-0.5">{help}</p>
                </div>
              </label>
            ) : (
              <>
                <BooleanDisplay label={label} enabled={value[key]} />
                <p className="text-xs text-muted-foreground">{help}</p>
              </>
            )}
            {note && (
              <p className="pl-7 text-xs text-muted-foreground">
                {locked && <Badge variant="secondary">Disabled above</Badge>}{" "}
                {note}
              </p>
            )}
            {inactive && (
              <p role="status" className="pl-7 text-xs text-amber-400">
                On, but the transmitter is not active: {ssfInactiveReason}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}

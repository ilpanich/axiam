/**
 * S-7b — `server_cert_allowed_names`, as an edit form and a read-only summary.
 *
 * One module for the three places the list is written — the organization
 * baseline (organization Settings tab), a tenant's own settings page, and an
 * organization administrator's override panel on the tenant detail page — so
 * the three explain the list in the same words.
 *
 * Nothing here decides anything. The list is the fence T-288 describes, and the
 * server is its only judge: whether an entry parses, is canonical, and — for a
 * tenant — is covered by an organization entry is answered by a `400` naming
 * the entry, which each page shows as it comes. The summary renders the list
 * the server read back, never one computed here.
 */

import { Plus, Trash2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export type ServerNamesScope = "organization" | "tenant";

/** The three entry forms, the rule for an empty list, and who may widen it. */
function ServerNamesHelp({ scope, id }: { scope: ServerNamesScope; id?: string }) {
  return (
    <div id={id} className="space-y-2 text-xs text-muted-foreground">
      <p>
        The names a <strong>Server</strong> (TLS) certificate may carry. Every
        subject alternative name on the request, and its common name, must be
        admitted by an entry. Three forms:
      </p>
      <ul className="list-disc space-y-1 pl-5">
        <li>
          <code>api.lakeside.internal</code> — that host, and nothing below it.
        </li>
        <li>
          <code>.lakeside.internal</code> — every name <em>strictly below</em>{" "}
          it, <code>*.lakeside.internal</code> included, but not{" "}
          <code>lakeside.internal</code> itself: list the apex without the dot
          when it is meant.
        </li>
        <li>
          <code>10.0.0.0/8</code>, <code>fd00::/8</code> or a single address —
          IP names inside that prefix, of the same family.
        </li>
      </ul>
      <p>
        <strong>An empty list refuses every Server certificate request.</strong>{" "}
        That is the default: nothing is issued for a name until somebody lists
        it here.
      </p>
      {scope === "organization" ? (
        <p>
          Every tenant inherits this list and may only <em>remove</em> an entry
          or <em>narrow</em> one (<code>.plant.lakeside.internal</code> under{" "}
          <code>.lakeside.internal</code>, <code>10.1.0.0/16</code> under{" "}
          <code>10.0.0.0/8</code>). Removing an entry here narrows every
          tenant&rsquo;s effective list to what is left.
        </p>
      ) : (
        <p>
          A tenant may only <em>remove</em> an entry or <em>narrow</em> one
          within its organization&rsquo;s list; the server refuses anything
          wider and names the entry. The organization baseline is set on the
          organization&rsquo;s Settings tab.
        </p>
      )}
    </div>
  );
}

export interface ServerNamesFieldsProps {
  /** Distinguishes this list's DOM ids when a page renders more than one. */
  idPrefix: string;
  /** Rows as typed, blank ones included; cleaned by `cleanAllowedNames` on save. */
  value: string[];
  onChange: (next: string[]) => void;
  scope: ServerNamesScope;
  disabled?: boolean;
}

/** Edit mode: one row per entry, with add and remove. */
export function ServerNamesFields({
  idPrefix,
  value,
  onChange,
  scope,
  disabled,
}: ServerNamesFieldsProps) {
  const helpId = `${idPrefix}-server-names-help`;
  return (
    <fieldset className="space-y-3" aria-describedby={helpId} disabled={disabled}>
      <legend className="text-sm font-medium text-foreground">
        Server certificate names
      </legend>
      <ServerNamesHelp scope={scope} id={helpId} />
      {value.length === 0 ? (
        <p className="text-sm text-amber-400" role="note">
          Empty — every Server certificate request is refused.
        </p>
      ) : (
        <ul className="space-y-2">
          {value.map((entry, i) => (
            <li key={i} className="flex items-center gap-2">
              <Input
                aria-label={`Allowed name ${i + 1}`}
                value={entry}
                onChange={(e) =>
                  onChange(value.map((v, j) => (j === i ? e.target.value : v)))
                }
                placeholder=".lakeside.internal"
                autoComplete="off"
                spellCheck={false}
                className="font-mono text-xs"
              />
              <button
                type="button"
                aria-label={`Remove allowed name ${i + 1}`}
                onClick={() => onChange(value.filter((_, j) => j !== i))}
                className="p-1.5 rounded text-muted-foreground hover:text-destructive hover:bg-destructive/10 focus:outline-hidden focus:ring-2 focus:ring-primary/40"
              >
                <Trash2 size={14} aria-hidden="true" />
              </button>
            </li>
          ))}
        </ul>
      )}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => onChange([...value, ""])}
      >
        <Plus size={14} aria-hidden="true" />
        Add entry
      </Button>
    </fieldset>
  );
}

/**
 * Read mode: the list as the server read it back. For a tenant that is the
 * effective list — its override intersected with the organization baseline —
 * so an entry the organization has since withdrawn is already gone from it.
 */
export function ServerNamesSummary({
  value,
  scope,
  caption,
  help = true,
}: {
  value: string[];
  scope: ServerNamesScope;
  /** Replaces the default caption, e.g. to say whose list this is. */
  caption?: string;
  /** Off where the edit form beside it already explains the list. */
  help?: boolean;
}) {
  return (
    <div className="space-y-2">
      <p className="text-xs text-muted-foreground uppercase tracking-wide">
        {caption ??
          (scope === "organization"
            ? "Organization baseline"
            : "Effective for this tenant")}
      </p>
      {value.length === 0 ? (
        <p className="text-sm text-amber-400">
          Empty — every Server certificate request is refused.
        </p>
      ) : (
        <ul className="flex flex-wrap gap-1.5" aria-label="Allowed server names">
          {value.map((entry) => (
            <li key={entry}>
              <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-foreground/90">
                {entry}
              </code>
            </li>
          ))}
        </ul>
      )}
      {help && <ServerNamesHelp scope={scope} />}
    </div>
  );
}

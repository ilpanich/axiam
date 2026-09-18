/**
 * T21.4 — the Dynamic Client Registration card, as an edit form and a
 * read-only summary.
 *
 * Extracted verbatim from `SettingsPage.tsx` so that the organization Settings
 * tab can mount the same two components: `dynamic_registration` is tighten-only
 * against an organization baseline that defaults to `disabled`, so the tenant
 * page these were written for can only ever move *down* a ladder nothing in the
 * UI could put a tenant on. `validate_dcr_policy` runs at both settings doors
 * (`crates/axiam-core/src/models/settings.rs:1360`, `:2114`), so the D3 alert
 * below fires on the organization baseline exactly as it does on a tenant
 * override.
 */

import { AlertCircle } from "lucide-react";

import type { DynamicRegistrationMode } from "@/services/settings";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { NumberDisplay } from "./policyFields";
import {
  DYNAMIC_REGISTRATION_HELP,
  DYNAMIC_REGISTRATION_LABELS,
  parseLines,
} from "./policyText";

export interface DcrPolicyValue {
  dynamic_registration: DynamicRegistrationMode;
  dcr_allowed_scopes: string[];
  dcr_allowed_redirect_hosts: string[];
  external_client_allowed_resources: string[];
  dcr_max_clients: number;
  dcr_unused_client_ttl_days: number;
}

/**
 * Edit-mode fields for the T21.4 policy.
 *
 * `dcr_allowed_scopes`, `dcr_allowed_redirect_hosts` and
 * `external_client_allowed_resources` are free-text lists rather than
 * checkbox groups — unlike `OAUTH2_SCOPES` on the OAuth2 Clients page, this
 * policy is not bounded to a fixed catalog (a redirect host glob or a
 * resource URL is never one of a known few), so a textarea is the only
 * faithful editor, matching the "one per line" convention `redirect_uris` and
 * `allowed_resources` already use there.
 */
export function DcrPolicyFields({
  value,
  onChange,
}: {
  value: DcrPolicyValue;
  onChange: (patch: Partial<DcrPolicyValue>) => void;
}) {
  const d3Empty =
    value.dynamic_registration === "anonymous" &&
    value.external_client_allowed_resources.length === 0;

  return (
    <div className="space-y-4">
      <div className="space-y-2">
        <Label htmlFor="dcr-mode">Self-registration mode</Label>
        <select
          id="dcr-mode"
          className="w-full rounded border border-white/20 bg-transparent px-3 py-2 text-sm"
          value={value.dynamic_registration}
          onChange={(e) =>
            onChange({
              dynamic_registration: e.target.value as DynamicRegistrationMode,
            })
          }
        >
          <option value="disabled">{DYNAMIC_REGISTRATION_LABELS.disabled}</option>
          <option value="initial_access_token">
            {DYNAMIC_REGISTRATION_LABELS.initial_access_token}
          </option>
          <option value="anonymous">{DYNAMIC_REGISTRATION_LABELS.anonymous}</option>
        </select>
        <p className="text-xs text-muted-foreground">
          {DYNAMIC_REGISTRATION_HELP[value.dynamic_registration]}
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="dcr-allowed-scopes">Allowed scopes</Label>
        <Textarea
          id="dcr-allowed-scopes"
          value={value.dcr_allowed_scopes.join("\n")}
          onChange={(e) =>
            onChange({ dcr_allowed_scopes: parseLines(e.target.value) })
          }
          placeholder={"openid\nprofile\nemail"}
          rows={3}
          className="font-mono"
          aria-label="Allowed scopes (one per line)"
        />
        <p className="text-xs text-muted-foreground">
          Scopes a self-registered client may ask for. One per line; empty
          means it gets none.{" "}
          <strong>
            <code>address</code> and <code>phone</code> may never appear
            here
          </strong>{" "}
          — both release personal data under a per-client consent record
          (W7), and a self-registered client already carries a forced consent
          record of its own (D4); two records in one namespace is a state
          this policy refuses to create. Register a client that needs them
          through <code>POST /oauth2-clients</code> instead.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="dcr-allowed-redirect-hosts">
          Allowed redirect hosts
        </Label>
        <Textarea
          id="dcr-allowed-redirect-hosts"
          value={value.dcr_allowed_redirect_hosts.join("\n")}
          onChange={(e) =>
            onChange({
              dcr_allowed_redirect_hosts: parseLines(e.target.value),
            })
          }
          placeholder={"mcp.example.com\n*.example.com"}
          rows={2}
          className="font-mono"
          aria-label="Allowed redirect hosts (one per line)"
        />
        <p className="text-xs text-muted-foreground">
          Host globs a self-registered <code>redirect_uri</code> may point at
          (<code>*.example.com</code>, or <code>*</code> for any). Empty is
          fine: <code>127.0.0.1</code>, <code>localhost</code> and{" "}
          <code>[::1]</code> are always allowed regardless, since RFC 8252
          §7.3 loopback callbacks are how every desktop MCP client receives
          its callback.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="dcr-allowed-resources">
          Allowed audiences (resource servers)
        </Label>
        <Textarea
          id="dcr-allowed-resources"
          value={value.external_client_allowed_resources.join("\n")}
          onChange={(e) =>
            onChange({
              external_client_allowed_resources: parseLines(e.target.value),
            })
          }
          placeholder="https://mcp.example.com/mcp"
          rows={2}
          className="font-mono"
          aria-label="Allowed audiences (one per line)"
        />
        <p className="text-xs text-muted-foreground">
          <strong>D3.</strong> The MCP servers (or other resource servers)
          this tenant fronts. A self-registered client cannot choose its own
          audiences — it inherits this list verbatim, so what a stranger can
          mint a token <em>for</em> is decided here, in advance, rather than
          by the registration request.
        </p>
        {d3Empty && (
          <p
            role="alert"
            className="flex items-center gap-2 p-2.5 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-xs"
          >
            <AlertCircle size={14} className="shrink-0" aria-hidden="true" />
            Anonymous registration cannot be saved while this list is empty:
            an empty list would leave a self-registered client able to obtain
            only the <code>axiam:user</code> tokens AXIAM's own APIs accept —
            an unauthenticated endpoint that mints clients able to ask for
            tokens against AXIAM itself. Name the MCP servers this tenant
            fronts first.
          </p>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor="dcr-max-clients">Max self-registered clients</Label>
          <Input
            id="dcr-max-clients"
            type="number"
            min={1}
            value={value.dcr_max_clients}
            onChange={(e) =>
              onChange({ dcr_max_clients: Number(e.target.value) })
            }
          />
          <p className="text-xs text-muted-foreground">
            <strong>Governs client ID metadata documents too</strong>, counted
            separately and against the same value: a tenant running both
            mechanisms gets this many self-registered clients{" "}
            <em>and</em> this many CIMD shadow rows, so neither can exhaust the
            other&rsquo;s allowance.
          </p>
        </div>
        <div className="space-y-2">
          <Label htmlFor="dcr-unused-ttl">
            Unused-client sweep (days)
          </Label>
          <Input
            id="dcr-unused-ttl"
            type="number"
            min={0}
            value={value.dcr_unused_client_ttl_days}
            onChange={(e) =>
              onChange({ dcr_unused_client_ttl_days: Number(e.target.value) })
            }
          />
          <p className="text-xs text-muted-foreground">
            A self-registered client with no authorization for this many days
            is deleted, and a <code>managed_by: cimd</code> shadow row is swept
            against the same value under its own clock and health counter.{" "}
            <code>0</code> disables both sweeps for this tenant. A registration
            in <code>anonymous</code> mode that has <em>never</em> been
            authorized is measured against one hour from creation instead —
            fixed, and not switched off by <code>0</code>.
          </p>
        </div>
      </div>
    </div>
  );
}

/**
 * Read-mode summary. **I1** — while `dynamic_registration` is `disabled`
 * (the default), nothing beyond that fact is shown: an empty scopes/hosts
 * list and default counters would still be true, but rendering them invites
 * an operator to read significance into a policy that does nothing.
 */
export function DcrPolicySummary({ value }: { value: DcrPolicyValue }) {
  if (value.dynamic_registration === "disabled") {
    return (
      <div className="flex items-center gap-2">
        <p className="text-xs text-muted-foreground uppercase tracking-wide">
          Self-registration
        </p>
        <Badge variant="secondary">Disabled</Badge>
      </div>
    );
  }

  const listOrNone = (items: string[]) =>
    items.length > 0 ? items.join(", ") : "none configured";

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <p className="text-xs text-muted-foreground uppercase tracking-wide">
          Self-registration
        </p>
        <Badge>{DYNAMIC_REGISTRATION_LABELS[value.dynamic_registration]}</Badge>
      </div>
      <div className="grid gap-4 sm:grid-cols-2">
        <NumberDisplay
          label="Max self-registered clients"
          value={value.dcr_max_clients}
        />
        <NumberDisplay
          label="Unused-client sweep"
          value={value.dcr_unused_client_ttl_days}
          unit={value.dcr_unused_client_ttl_days === 0 ? "(disabled)" : "days"}
        />
      </div>
      <div className="space-y-2 text-sm">
        <p>
          <span className="text-muted-foreground">Allowed scopes: </span>
          {listOrNone(value.dcr_allowed_scopes)}
        </p>
        <p>
          <span className="text-muted-foreground">
            Allowed redirect hosts:{" "}
          </span>
          <span>{listOrNone(value.dcr_allowed_redirect_hosts)}</span>
          <span className="text-muted-foreground"> (loopback always allowed)</span>
        </p>
        <p>
          <span className="text-muted-foreground">
            Allowed audiences (D3):{" "}
          </span>
          {listOrNone(value.external_client_allowed_resources)}
        </p>
      </div>
    </div>
  );
}

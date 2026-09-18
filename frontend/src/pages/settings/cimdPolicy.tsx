/**
 * T21.5 — the Client ID Metadata Documents card, as an edit form and a
 * read-only summary.
 *
 * The sibling of `dcrPolicy.tsx`, and the answer to a mechanism that shipped
 * with an operator page, two server-side interlocks and no form. CIMD is the
 * one thing in AXIAM that makes an outbound request on an unauthenticated
 * caller's word; until this card existed the only place an operator met the
 * refusals that bound it was a `400` body after a `curl`.
 *
 * The posture is edited **whole**. `CimdPolicy` is one nested object on the
 * backend and `Option<CimdPolicy>` on a tenant override, because every field
 * here is a term of a single decision — do we fetch a stranger's URL and make
 * a client out of what comes back — and none of them means anything without
 * `enabled`.
 *
 * What the form does *not* do is decide anything the server decides. Every
 * refusal below is `validateCimdPolicy`'s, which is `validate_cimd_policy`'s,
 * word for word; the ordering rules (`enabled` and `allow_http` may be turned
 * off by a tenant and never on) are stated next to the control and left to the
 * server, because the organization baseline is not readable from either tenant
 * surface.
 */

import { useMemo } from "react";
import { AlertCircle } from "lucide-react";

import {
  CIMD_MAX_CACHE_CEILING_SECS,
  CIMD_MAX_METADATA_BYTES_CEILING,
  CIMD_MIN_CACHE_FLOOR_SECS,
  validateCimdPolicy,
  type CimdPolicy,
  type CimdPolicyField,
} from "@/services/settings";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { BooleanDisplay, NumberDisplay } from "./policyFields";
import { parseLines } from "./policyText";

export interface CimdPolicyFieldsProps {
  /** Distinguishes the control ids where two policy cards share a page. */
  idPrefix: string;
  value: CimdPolicy;
  /**
   * `external_client_allowed_resources`, which lives on the DCR card and which
   * the D3 interlock is stated against. Passed in rather than read here because
   * it is one list serving two mechanisms, edited in one place.
   */
  externalResources: string[];
  onChange: (next: CimdPolicy) => void;
  /** Shown under `enabled` where the surface can only tighten (tenant level). */
  orderingNote?: React.ReactNode;
}

/**
 * A switch, its explanation and any refusal that lands on it.
 *
 * Local rather than `components/shared`'s `ToggleField` because every switch on
 * this card can carry a `role="alert"`, and an alert rendered outside the
 * control's own block is one a screen reader announces detached from the thing
 * it refuses.
 */
function CimdSwitch({
  id,
  label,
  checked,
  disabled,
  onChange,
  description,
  children,
}: {
  id: string;
  label: string;
  checked: boolean;
  disabled?: boolean;
  onChange: (checked: boolean) => void;
  description: React.ReactNode;
  children?: React.ReactNode;
}) {
  const describedBy = `${id}-description`;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-3">
        <input
          id={id}
          type="checkbox"
          checked={checked}
          disabled={disabled}
          aria-describedby={describedBy}
          onChange={(e) => onChange(e.target.checked)}
          className="focus-ring h-4 w-4 rounded border-primary/40 bg-white/5 text-primary disabled:opacity-50 disabled:cursor-not-allowed"
        />
        <Label htmlFor={id} className="cursor-pointer py-1.5 flex-1">
          {label}
        </Label>
      </div>
      <p id={describedBy} className="pl-7 text-xs text-muted-foreground">
        {description}
      </p>
      {children}
    </div>
  );
}

/** The server's refusals for one field, each as its own alert. */
function Refusals({
  field,
  violations,
}: {
  field: CimdPolicyField;
  violations: { field: CimdPolicyField; message: string }[];
}) {
  const mine = violations.filter((v) => v.field === field);
  if (mine.length === 0) return null;
  return (
    <>
      {mine.map((v) => (
        <p
          key={v.message}
          role="alert"
          className="flex items-start gap-2 p-2.5 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-xs"
        >
          <AlertCircle size={14} className="shrink-0 mt-0.5" aria-hidden="true" />
          {v.message}
        </p>
      ))}
    </>
  );
}

/** Edit-mode fields for the whole T21.5 posture. */
export function CimdPolicyFields({
  idPrefix,
  value,
  externalResources,
  onChange,
  orderingNote,
}: CimdPolicyFieldsProps) {
  const violations = useMemo(
    () =>
      validateCimdPolicy({
        external_client_allowed_resources: externalResources,
        cimd: value,
      }),
    [externalResources, value]
  );

  const patch = (next: Partial<CimdPolicy>) => onChange({ ...value, ...next });

  return (
    <div className="space-y-4">
      <CimdSwitch
        id={`${idPrefix}-cimd-enabled`}
        label="Resolve a URL-shaped client_id by fetching the document it names"
        checked={value.enabled}
        onChange={(enabled) => patch({ enabled })}
        description={
          <>
            Off by default, and with it off a URL-shaped <code>client_id</code>{" "}
            is exactly today&rsquo;s unknown client: nothing is fetched and
            nothing is materialised. {orderingNote}
          </>
        }
      >
        <Refusals field="enabled" violations={violations} />
      </CimdSwitch>

      <CimdSwitch
        id={`${idPrefix}-cimd-allow-http`}
        label="Allow http:// client_id URLs and plaintext fetches"
        checked={value.allow_http}
        onChange={(allow_http) => patch({ allow_http })}
        description={
          <>
            <strong>Development only, and it does more than its name says.</strong>{" "}
            The shared SSRF guard couples the scheme rule to the address rule, so
            a tenant that allows <code>http</code> also allows the first hop to
            resolve to a private address. A public deployment that sets this has
            removed the control that makes <code>169.254.169.254</code>{" "}
            unreachable. Redirect hops stay strictly validated whatever this
            says.
          </>
        }
      />

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-cimd-publishers`}>
          Trusted publisher domains
        </Label>
        <Textarea
          id={`${idPrefix}-cimd-publishers`}
          value={value.trusted_client_id_domains.join("\n")}
          onChange={(e) =>
            patch({ trusted_client_id_domains: parseLines(e.target.value) })
          }
          placeholder={"mcp.example.com\n*.example.com"}
          rows={3}
          className="font-mono"
          aria-label="Trusted publisher domains (one per line)"
        />
        <p className="text-xs text-muted-foreground">
          The hosts whose documents this tenant will fetch at all, one per line.
          The fetch is triggered by an unauthenticated request naming the URL, so
          an unrestricted list is a request-forgery primitive offered to
          strangers — which is why an empty list, <code>*</code> and a wildcard
          over a whole top-level domain (<code>*.com</code>) are all{" "}
          <strong>refused</strong> while this is on. A floor, not a
          public-suffix check: <code>*.github.io</code> passes, and trusting
          shared hosting stays your decision.
        </p>
        <Refusals field="trusted_client_id_domains" violations={violations} />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-cimd-redirects`}>
          Trusted redirect domains
        </Label>
        <Textarea
          id={`${idPrefix}-cimd-redirects`}
          value={value.trusted_redirect_domains.join("\n")}
          onChange={(e) =>
            patch({ trusted_redirect_domains: parseLines(e.target.value) })
          }
          placeholder={"app.example.com\n*.example.com\n*"}
          rows={2}
          className="font-mono"
          aria-label="Trusted redirect domains (one per line)"
        />
        <p className="text-xs text-muted-foreground">
          Where a document may point a browser. <code>*</code> is valid here,
          because these entries are not fetch targets. Empty is a working
          posture rather than a refusal of everything:{" "}
          <code>127.0.0.1</code>, <code>localhost</code> and <code>[::1]</code>{" "}
          are always allowed, so an empty list means &ldquo;loopback
          only&rdquo; — which is exactly the desktop MCP profile.
        </p>
        <Refusals field="trusted_redirect_domains" violations={violations} />
      </div>

      <CimdSwitch
        id={`${idPrefix}-cimd-same-domain`}
        label="Require a document's redirect hosts to match the client_id's host"
        checked={value.restrict_same_domain}
        onChange={(restrict_same_domain) => patch({ restrict_same_domain })}
        description={
          <>
            On by default: the document says who the client is, and a redirect to
            somewhere else is the one thing a stolen or mirrored document would
            want to change. <strong>Turn it off for desktop MCP clients</strong>{" "}
            (Claude Code, VS Code, MCP Inspector) — their callbacks arrive on{" "}
            <code>http://127.0.0.1:&lt;random port&gt;/…</code> (RFC 8252 §7.3),
            which can never share a host with an <code>https</code>{" "}
            <code>client_id</code>, so leaving it on refuses every one of them
            every time. What stands in its place is that the code is delivered
            to the loopback interface of the machine the person is sitting at.
          </>
        }
      />

      <CimdSwitch
        id={`${idPrefix}-cimd-confidential-only`}
        label="Refuse a document whose token_endpoint_auth_method is none"
        checked={value.confidential_only}
        onChange={(confidential_only) => patch({ confidential_only })}
        description={
          <>
            Off by default, because <code>none</code> is what every desktop MCP
            client is. Turn it on for a deployment whose CIMD clients are servers
            rather than desktops: only <code>private_key_jwt</code> documents are
            then accepted.
          </>
        }
      />

      <div className="grid gap-4 sm:grid-cols-3">
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-cimd-min-cache`}>
            Cache floor (seconds)
          </Label>
          <Input
            id={`${idPrefix}-cimd-min-cache`}
            type="number"
            min={CIMD_MIN_CACHE_FLOOR_SECS}
            max={CIMD_MAX_CACHE_CEILING_SECS}
            value={value.min_cache_secs}
            onChange={(e) => patch({ min_cache_secs: Number(e.target.value) })}
          />
          <p className="text-xs text-muted-foreground">
            What stands between one authorization request and one outbound
            fetch. Never below {CIMD_MIN_CACHE_FLOOR_SECS}.
          </p>
          <Refusals field="min_cache_secs" violations={violations} />
        </div>
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-cimd-max-cache`}>
            Cache ceiling (seconds)
          </Label>
          <Input
            id={`${idPrefix}-cimd-max-cache`}
            type="number"
            min={CIMD_MIN_CACHE_FLOOR_SECS}
            max={CIMD_MAX_CACHE_CEILING_SECS}
            value={value.max_cache_secs}
            onChange={(e) => patch({ max_cache_secs: Number(e.target.value) })}
          />
          <p className="text-xs text-muted-foreground">
            How long a stranger&rsquo;s registration stays live. Never above{" "}
            {CIMD_MAX_CACHE_CEILING_SECS}.
          </p>
          <Refusals field="max_cache_secs" violations={violations} />
        </div>
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-cimd-max-bytes`}>
            Document read cap (bytes)
          </Label>
          <Input
            id={`${idPrefix}-cimd-max-bytes`}
            type="number"
            min={1}
            max={CIMD_MAX_METADATA_BYTES_CEILING}
            value={value.max_metadata_bytes}
            onChange={(e) =>
              patch({ max_metadata_bytes: Number(e.target.value) })
            }
          />
          <p className="text-xs text-muted-foreground">
            The ceiling on a read from an attacker-chosen URL. Between 1 and{" "}
            {CIMD_MAX_METADATA_BYTES_CEILING}.
          </p>
          <Refusals field="max_metadata_bytes" violations={violations} />
        </div>
      </div>
    </div>
  );
}

/**
 * Read-mode summary. **I1**, the rule `DcrPolicySummary` follows: while
 * `enabled` is false — the default, and what every deployment that has not
 * decided otherwise is on — nothing beyond that fact is shown. An empty
 * publisher list and the default bounds would still be true, but rendering them
 * invites an operator to read significance into a policy that does nothing.
 */
export function CimdPolicySummary({ value }: { value: CimdPolicy }) {
  if (!value.enabled) {
    return (
      <div className="flex items-center gap-2">
        <p className="text-xs text-muted-foreground uppercase tracking-wide">
          Client ID metadata documents
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
          Client ID metadata documents
        </p>
        <Badge>Enabled</Badge>
      </div>
      <div className="grid gap-4 sm:grid-cols-3">
        <NumberDisplay
          label="Cache floor"
          value={value.min_cache_secs}
          unit="seconds"
        />
        <NumberDisplay
          label="Cache ceiling"
          value={value.max_cache_secs}
          unit="seconds"
        />
        <NumberDisplay
          label="Document read cap"
          value={value.max_metadata_bytes}
          unit="bytes"
        />
      </div>
      <div className="grid gap-4 sm:grid-cols-3">
        <BooleanDisplay label="Plaintext fetches" enabled={value.allow_http} />
        <BooleanDisplay
          label="Same-domain redirects"
          enabled={value.restrict_same_domain}
        />
        <BooleanDisplay
          label="Confidential only"
          enabled={value.confidential_only}
        />
      </div>
      <div className="space-y-2 text-sm">
        <p>
          <span className="text-muted-foreground">
            Trusted publisher domains:{" "}
          </span>
          {listOrNone(value.trusted_client_id_domains)}
        </p>
        <p>
          <span className="text-muted-foreground">
            Trusted redirect domains:{" "}
          </span>
          <span>{listOrNone(value.trusted_redirect_domains)}</span>
          <span className="text-muted-foreground">
            {" "}
            (loopback always allowed)
          </span>
        </p>
      </div>
    </div>
  );
}

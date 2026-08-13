import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { ToggleField } from "@/components/shared";
import {
  DEFAULT_TOKEN_EXCHANGE_TRUST,
  MAX_TOKEN_AGE_CEILING_SECS,
  type SubjectMapping,
  type TokenExchangeTrust,
} from "@/services/federation";

/**
 * X4 — editor for a federation provider's external token-exchange trust.
 *
 * Operator guide: `docs/api/federated-token-exchange.md`. This form configures
 * a **trust boundary**: switching it on means AXIAM will accept tokens minted
 * by someone else's identity provider as proof that a user authenticated. The
 * copy below is deliberately explicit about that, because the two fields that
 * decide the blast radius (`accepted_audiences` and `scope_map`) both look like
 * ordinary optional settings and are neither.
 *
 * OIDC only — the server refuses an enabled block on a SAML provider, which has
 * no issuer to match and no JWKS to verify against.
 */

/** Parse the audience textarea: one per line, blanks dropped. */
export function parseAudiences(raw: string): string[] {
  return raw
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s !== "");
}

export function stringifyAudiences(audiences: string[]): string {
  return audiences.join("\n");
}

/**
 * Parse the scope map from `partner.value = axiam:scope another:scope` lines.
 *
 * A line-oriented format rather than raw JSON: this is a mapping an operator
 * reads and edits far more often than they write, and `{"a": ["b"]}` obscures
 * the one thing they are checking — which partner claim buys which scope.
 *
 * Returns the parsed map, or an error naming the offending line. Never returns
 * a partial map: a half-parsed trust configuration submitted by accident is
 * exactly the failure this whole form is careful about.
 */
export function parseScopeMap(
  raw: string,
): { value: Record<string, string[]> } | { error: string } {
  const map: Record<string, string[]> = {};
  const lines = raw.split("\n");
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line === "" || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) {
      return {
        error: `Line ${i + 1}: expected "partner.value = axiam:scope [more:scopes]".`,
      };
    }
    const key = line.slice(0, eq).trim();
    const scopes = line
      .slice(eq + 1)
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter((s) => s !== "");
    if (key === "") {
      return { error: `Line ${i + 1}: the partner value is blank.` };
    }
    if (scopes.length === 0) {
      return {
        error: `Line ${i + 1}: "${key}" maps to no AXIAM scopes. Remove the line instead — an empty mapping grants nothing and reads as if it grants something.`,
      };
    }
    map[key] = scopes;
  }
  return { value: map };
}

export function stringifyScopeMap(map: Record<string, string[]>): string {
  return Object.entries(map)
    .map(([key, scopes]) => `${key} = ${scopes.join(" ")}`)
    .join("\n");
}

export interface TokenExchangeTrustEditorProps {
  /** The live trust block. */
  value: TokenExchangeTrust;
  onChange: (next: TokenExchangeTrust) => void;
  /** Raw textarea state, kept outside `value` so a half-typed map survives. */
  audiencesText: string;
  onAudiencesTextChange: (raw: string) => void;
  scopeMapText: string;
  onScopeMapTextChange: (raw: string) => void;
  /** Disabled with an explanation on non-OIDC providers. */
  isOidc: boolean;
  idPrefix: string;
}

export function TokenExchangeTrustEditor({
  value,
  onChange,
  audiencesText,
  onAudiencesTextChange,
  scopeMapText,
  onScopeMapTextChange,
  isOidc,
  idPrefix,
}: TokenExchangeTrustEditorProps) {
  if (!isOidc) {
    return (
      <div className="border-t border-border pt-4 mt-4">
        <h3 className="text-sm font-semibold mb-1">External Token Exchange</h3>
        <p className="text-xs text-muted-foreground">
          Available for OIDC providers only. A SAML provider has no issuer to
          match and no JWKS to verify tokens against, so there is nothing an
          exchange could check.
        </p>
      </div>
    );
  }

  const set = (patch: Partial<TokenExchangeTrust>) =>
    onChange({ ...value, ...patch });

  return (
    <div className="border-t border-border pt-4 mt-4 space-y-4">
      <div>
        <h3 className="text-sm font-semibold">External Token Exchange (X4)</h3>
        <p className="text-xs text-muted-foreground mt-1">
          Accept access tokens issued by <em>this</em> provider as proof that a
          user authenticated, and exchange them for AXIAM tokens. Configuring a
          provider for login does not enable this — it is a separate trust
          decision.
        </p>
      </div>

      <ToggleField
        id={`${idPrefix}-tx-enabled`}
        label="Accept this provider's tokens for exchange"
        checked={value.enabled}
        onChange={(enabled) => set({ enabled })}
      />

      <div className="space-y-1.5">
        <Label htmlFor={`${idPrefix}-tx-audiences`}>
          Accepted audiences (one per line)
        </Label>
        <Textarea
          id={`${idPrefix}-tx-audiences`}
          rows={3}
          value={audiencesText}
          onChange={(e) => {
            onAudiencesTextChange(e.target.value);
            set({ accepted_audiences: parseAudiences(e.target.value) });
          }}
          placeholder={"https://api.example.com"}
        />
        <p className="text-xs text-muted-foreground">
          Required when enabled, and matched exactly — a trailing slash is a
          different audience. There is deliberately no accept-all value: a token
          that was not addressed to you is one you captured, not one you were
          given.
        </p>
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={`${idPrefix}-tx-scope-map`}>Scope map</Label>
        <Textarea
          id={`${idPrefix}-tx-scope-map`}
          rows={4}
          className="font-mono text-xs"
          value={scopeMapText}
          onChange={(e) => {
            onScopeMapTextChange(e.target.value);
            const parsed = parseScopeMap(e.target.value);
            if ("value" in parsed) set({ scope_map: parsed.value });
          }}
          placeholder={"partner.orders.read = read:orders\nOrders.ReadWrite.All = read:orders write:orders"}
        />
        <p className="text-xs text-muted-foreground">
          One mapping per line. Deny-by-default: a partner assertion with no
          entry grants nothing, and there is no passthrough mode. AXIAM reads the
          partner's <code>scope</code>, <code>scp</code>, <code>roles</code> and{" "}
          <code>groups</code> claims. A mapped scope is still only issued if the
          resolved user actually holds it in AXIAM's RBAC.
        </p>
      </div>

      <div className="space-y-1.5">
        <Label htmlFor={`${idPrefix}-tx-subject-mapping`}>
          Unknown subjects
        </Label>
        <select
          id={`${idPrefix}-tx-subject-mapping`}
          className="w-full h-9 rounded-md border border-input bg-background px-3 text-sm"
          value={value.subject_mapping}
          onChange={(e) =>
            set({ subject_mapping: e.target.value as SubjectMapping })
          }
        >
          <option value="linked_only">
            Refuse — the user must already be linked
          </option>
          <option value="jit_provision">
            Provision an AXIAM user on first sight
          </option>
        </select>
        <p className="text-xs text-muted-foreground">
          A just-provisioned user holds no roles, so their first exchange still
          yields nothing. Provisioning an identity is not granting it anything.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="space-y-1.5">
          <Label htmlFor={`${idPrefix}-tx-max-age`}>
            Max token age (seconds)
          </Label>
          <Input
            id={`${idPrefix}-tx-max-age`}
            type="number"
            min={1}
            max={MAX_TOKEN_AGE_CEILING_SECS}
            value={value.max_token_age_secs}
            onChange={(e) =>
              set({
                max_token_age_secs:
                  Number(e.target.value) ||
                  DEFAULT_TOKEN_EXCHANGE_TRUST.max_token_age_secs,
              })
            }
          />
          <p className="text-xs text-muted-foreground">
            Bounds how old a presented token may be, independently of its own
            expiry. A partner issuing 24-hour tokens should not thereby hand out
            a 24-hour replay window.
          </p>
        </div>
        <div className="space-y-1.5">
          <Label htmlFor={`${idPrefix}-tx-max-lifetime`}>
            Max issued lifetime (seconds, optional)
          </Label>
          <Input
            id={`${idPrefix}-tx-max-lifetime`}
            type="number"
            min={1}
            value={value.max_lifetime_secs ?? ""}
            onChange={(e) =>
              set({
                max_lifetime_secs:
                  e.target.value === "" ? null : Number(e.target.value),
              })
            }
          />
          <p className="text-xs text-muted-foreground">
            Applied on top of &ldquo;never outlives the partner&apos;s
            token&rdquo;. Leave blank for no extra ceiling.
          </p>
        </div>
      </div>
    </div>
  );
}

import { useMemo, useState } from "react";
import { AlertCircle, Plus, Trash2 } from "lucide-react";
import {
  ATTRIBUTE_NAME_FORMATS,
  ATTRIBUTE_NAME_FORMAT_LABELS,
  ATTRIBUTE_SOURCES,
  ATTRIBUTE_SOURCE_LABELS,
  NAME_ID_FORMATS,
  NAME_ID_FORMAT_LABELS,
  SAML_BINDINGS,
  SAML_BINDING_LABELS,
  type SamlServiceProvider,
} from "@/services/saml";
import type { Group } from "@/services/users";
import { ToggleField } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import {
  ACS_MAX,
  ATTRIBUTE_MAPPINGS_MAX,
  newAcsRow,
  newMappingRow,
  type SamlForm,
} from "./samlForm";

const SELECT_CLASS =
  "flex h-9 w-full rounded-md border border-input bg-background/50 px-3 py-1 text-sm";

function Field({
  id,
  label,
  hint,
  children,
}: {
  id: string;
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <Label htmlFor={id}>{label}</Label>
      {children}
      {hint && <p className="text-xs text-muted-foreground">{hint}</p>}
    </div>
  );
}

/**
 * A select over a value set the server treats as **open**: a value this console
 * does not know is shown as it is (never dropped), and refused on save by
 * `validateForm`, because §29.2 says an SDK must not send one it does not know.
 */
function OpenSelect({
  value,
  known,
  labels,
  blank,
  ...rest
}: {
  value: string;
  known: readonly string[];
  labels: Record<string, string>;
  /** The label of the empty choice, or `undefined` for no empty choice. */
  blank?: string;
} & Omit<React.SelectHTMLAttributes<HTMLSelectElement>, "value" | "className">) {
  return (
    <select value={value} className={SELECT_CLASS} {...rest}>
      {blank !== undefined && <option value="">{blank}</option>}
      {value !== "" && !known.includes(value) && (
        <option value={value}>Unknown ({value})</option>
      )}
      {known.map((v) => (
        <option key={v} value={v}>
          {labels[v] ?? v}
        </option>
      ))}
    </select>
  );
}

interface EditorProps {
  /** The registration being edited, or `null` when creating one. */
  stored: SamlServiceProvider | null;
  form: SamlForm;
  groups: Group[];
  groupsLoading: boolean;
  onChange: <K extends keyof SamlForm>(key: K, value: SamlForm[K]) => void;
  error: string | null;
}

/**
 * The service-provider form: **manual entry** of every member of
 * `SamlServiceProviderInput` (contract §29.2). The same form takes an imported
 * draft, which is why nothing here knows where its values came from.
 */
export function ServiceProviderEditor({
  stored,
  form,
  groups,
  groupsLoading,
  onChange,
  error,
}: EditorProps) {
  const editing = stored !== null;
  const [groupFilter, setGroupFilter] = useState("");

  const visibleGroups = useMemo(() => {
    const needle = groupFilter.trim().toLowerCase();
    return needle ? groups.filter((g) => g.name.toLowerCase().includes(needle)) : groups;
  }, [groups, groupFilter]);
  const unknownGroupIds = form.allowedGroups.filter((id) => !groups.some((g) => g.id === id));

  function setDefault(key: string, checked: boolean) {
    onChange(
      "acs",
      form.acs.map((row) => ({ ...row, isDefault: row.key === key ? checked : false })),
    );
  }

  function toggleGroup(id: string, checked: boolean) {
    onChange(
      "allowedGroups",
      checked ? [...form.allowedGroups, id] : form.allowedGroups.filter((g) => g !== id),
    );
  }

  return (
    <div className="space-y-5">
      <ToggleField
        id="saml-enabled"
        label="Enabled"
        checked={form.enabled}
        onChange={(v) => onChange("enabled", v)}
        description="A disabled service provider stays registered and every sign-on for it is refused. Single logout still works."
      />

      <div className="grid gap-4 sm:grid-cols-2">
        <Field id="saml-display-name" label="Display name">
          <Input
            id="saml-display-name"
            value={form.displayName}
            onChange={(e) => onChange("displayName", e.target.value)}
            autoComplete="off"
          />
        </Field>
        <Field
          id="saml-entity-id"
          label="Entity ID"
          hint={
            editing
              ? "Cannot be changed. Every user's pairwise NameID is derived from it, so a new entity ID would give each user a new, unknown account at the service provider. To use another one, register a new service provider."
              : "The service provider's entityID, unique within this tenant. It cannot be changed after you save."
          }
        >
          <Input
            id="saml-entity-id"
            value={editing ? stored.entity_id : form.entityId}
            onChange={(e) => onChange("entityId", e.target.value)}
            readOnly={editing}
            aria-readonly={editing}
            autoComplete="off"
            spellCheck={false}
            className={editing ? "opacity-70" : undefined}
          />
        </Field>
      </div>

      <fieldset className="space-y-3">
        <legend className="text-sm font-medium text-foreground">Assertion consumer service (ACS) URLs</legend>
        <p className="text-xs text-muted-foreground">
          The allow-list an assertion may be posted to. A sign-on request naming a URL that is not
          listed here exactly, character for character, is refused: no wildcards, no prefixes. The
          default is used when a request names none; with no default marked, the first listed is
          used.
        </p>
        <ul className="space-y-3">
          {form.acs.map((row, i) => (
            <li key={row.key} className="space-y-2 rounded-md border border-white/10 p-3">
              <div className="grid gap-2 sm:grid-cols-[1fr_9rem_6rem]">
                <Input
                  aria-label={`ACS URL ${i + 1}`}
                  placeholder="https://sp.example.com/saml/acs"
                  value={row.url}
                  onChange={(e) =>
                    onChange(
                      "acs",
                      form.acs.map((r) => (r.key === row.key ? { ...r, url: e.target.value } : r)),
                    )
                  }
                  autoComplete="off"
                  spellCheck={false}
                  className="font-mono text-xs"
                />
                <OpenSelect
                  aria-label={`ACS binding ${i + 1}`}
                  value={row.binding}
                  known={SAML_BINDINGS}
                  labels={SAML_BINDING_LABELS}
                  onChange={(e) =>
                    onChange(
                      "acs",
                      form.acs.map((r) =>
                        r.key === row.key ? { ...r, binding: e.target.value } : r,
                      ),
                    )
                  }
                />
                <Input
                  aria-label={`ACS index ${i + 1}`}
                  inputMode="numeric"
                  value={row.index}
                  onChange={(e) =>
                    onChange(
                      "acs",
                      form.acs.map((r) =>
                        r.key === row.key ? { ...r, index: e.target.value } : r,
                      ),
                    )
                  }
                />
              </div>
              <div className="flex items-center justify-between gap-3">
                <label className="flex cursor-pointer items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={row.isDefault}
                    onChange={(e) => setDefault(row.key, e.target.checked)}
                    aria-label={`ACS ${i + 1} is the default`}
                    className="focus-ring h-4 w-4 accent-cyan-400"
                  />
                  Default endpoint
                </label>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label={`Remove ACS endpoint ${i + 1}`}
                  onClick={() => onChange("acs", form.acs.filter((r) => r.key !== row.key))}
                >
                  <Trash2 size={14} aria-hidden="true" />
                </Button>
              </div>
            </li>
          ))}
        </ul>
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onChange("acs", [...form.acs, newAcsRow(form.acs)])}
          disabled={form.acs.length >= ACS_MAX}
        >
          <Plus size={14} aria-hidden="true" />
          Add ACS endpoint
        </Button>
      </fieldset>

      <div className="grid gap-4 sm:grid-cols-2">
        <Field
          id="saml-slo-url"
          label="Single-logout URL"
          hint="Optional. Without a signing certificate below, only logout started at AXIAM can reach it; a logout request from the service provider must be signed."
        >
          <Input
            id="saml-slo-url"
            value={form.sloUrl}
            onChange={(e) => onChange("sloUrl", e.target.value)}
            autoComplete="off"
            spellCheck={false}
            placeholder="https://sp.example.com/saml/slo"
          />
        </Field>
        <Field id="saml-slo-binding" label="Single-logout binding" hint="Set together with the URL.">
          <OpenSelect
            id="saml-slo-binding"
            value={form.sloBinding}
            known={SAML_BINDINGS}
            labels={SAML_BINDING_LABELS}
            blank="None"
            onChange={(e) => onChange("sloBinding", e.target.value)}
          />
        </Field>
      </div>

      <Field
        id="saml-name-id-format"
        label="NameID format"
        hint="Persistent is a different, stable identifier for each user at each service provider; AXIAM never reveals the user id."
      >
        <OpenSelect
          id="saml-name-id-format"
          value={form.nameIdFormat}
          known={NAME_ID_FORMATS}
          labels={NAME_ID_FORMAT_LABELS}
          onChange={(e) => onChange("nameIdFormat", e.target.value)}
        />
      </Field>

      <div className="space-y-3">
        <ToggleField
          id="saml-sign-responses"
          label="Sign responses"
          checked={form.signResponses}
          onChange={(v) => onChange("signResponses", v)}
          description="Sign the response envelope as well. The assertion itself is always signed; that cannot be switched off."
        />
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <input
              type="checkbox"
              id="saml-encrypt-assertions"
              checked={false}
              disabled
              readOnly
              aria-describedby="saml-encrypt-assertions-note"
              className="h-5 w-5 rounded-sm opacity-50"
            />
            <Label htmlFor="saml-encrypt-assertions" className="py-1.5 flex-1 opacity-70">
              Encrypt assertions
            </Label>
          </div>
          <p id="saml-encrypt-assertions-note" className="pl-8 text-xs text-muted-foreground">
            Not yet supported. Assertions are signed and sent over TLS; AXIAM never sends a
            plaintext assertion to a service provider that asked for encryption, so this stays off.
          </p>
        </div>
        <ToggleField
          id="saml-want-signed"
          label="Require signed sign-on requests"
          checked={form.wantAuthnRequestsSigned}
          onChange={(v) => onChange("wantAuthnRequestsSigned", v)}
          description="Refuse an unsigned request from this service provider. Needs its signing certificate below."
        />
        <ToggleField
          id="saml-idp-initiated"
          label="Allow IdP-initiated sign-on"
          checked={form.allowIdpInitiated}
          onChange={(v) => onChange("allowIdpInitiated", v)}
          description="Lets AXIAM start a sign-on the service provider did not ask for. Such an assertion has no request to bind it to, so it is off unless you opt in."
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Field
          id="saml-sp-signing-cert"
          label="Signing certificate (PEM)"
          hint="What the service provider signs its requests with: one certificate, public material only. RSA of at least 2048 bits, or ECDSA P-256/384/521 (ECDSA verifies the HTTP-POST binding only). Never paste a key."
        >
          <Textarea
            id="saml-sp-signing-cert"
            value={form.spSigningCertPem}
            onChange={(e) => onChange("spSigningCertPem", e.target.value)}
            rows={5}
            spellCheck={false}
            className="font-mono text-xs"
          />
        </Field>
        <Field
          id="saml-sp-encryption-cert"
          label="Encryption certificate (PEM)"
          hint="Stored for when assertion encryption is implemented. It changes nothing today."
        >
          <Textarea
            id="saml-sp-encryption-cert"
            value={form.spEncryptionCertPem}
            onChange={(e) => onChange("spEncryptionCertPem", e.target.value)}
            rows={5}
            spellCheck={false}
            className="font-mono text-xs"
          />
        </Field>
      </div>

      <fieldset className="space-y-3">
        <legend className="text-sm font-medium text-foreground">Attribute mappings</legend>
        <p className="text-xs text-muted-foreground">
          Which attributes are released in the assertion, and from what. With no rows only the
          NameID is sent.
        </p>
        {form.mappings.length === 0 ? (
          <p className="text-sm text-muted-foreground">No mappings.</p>
        ) : (
          <ul className="space-y-2">
            {form.mappings.map((row, i) => (
              <li key={row.key} className="grid gap-2 sm:grid-cols-[1fr_10rem_9rem_auto]">
                <Input
                  aria-label={`Attribute name ${i + 1}`}
                  placeholder="mail"
                  value={row.samlName}
                  onChange={(e) =>
                    onChange(
                      "mappings",
                      form.mappings.map((r) =>
                        r.key === row.key ? { ...r, samlName: e.target.value } : r,
                      ),
                    )
                  }
                  autoComplete="off"
                  spellCheck={false}
                />
                <select
                  aria-label={`Attribute source ${i + 1}`}
                  value={row.source}
                  className={SELECT_CLASS}
                  onChange={(e) =>
                    onChange(
                      "mappings",
                      form.mappings.map((r) =>
                        r.key === row.key ? { ...r, source: e.target.value } : r,
                      ),
                    )
                  }
                >
                  <option value="">Choose a source…</option>
                  {row.source !== "" && !ATTRIBUTE_SOURCES.some((s) => s === row.source) && (
                    <option value={row.source}>Unknown ({row.source})</option>
                  )}
                  {ATTRIBUTE_SOURCES.map((s) => (
                    <option key={s} value={s}>
                      {ATTRIBUTE_SOURCE_LABELS[s]}
                    </option>
                  ))}
                </select>
                <OpenSelect
                  aria-label={`Attribute name format ${i + 1}`}
                  value={row.nameFormat}
                  known={ATTRIBUTE_NAME_FORMATS}
                  labels={ATTRIBUTE_NAME_FORMAT_LABELS}
                  blank="Format not set"
                  onChange={(e) =>
                    onChange(
                      "mappings",
                      form.mappings.map((r) =>
                        r.key === row.key ? { ...r, nameFormat: e.target.value } : r,
                      ),
                    )
                  }
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label={`Remove attribute mapping ${i + 1}`}
                  onClick={() =>
                    onChange("mappings", form.mappings.filter((r) => r.key !== row.key))
                  }
                >
                  <Trash2 size={14} aria-hidden="true" />
                </Button>
              </li>
            ))}
          </ul>
        )}
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onChange("mappings", [...form.mappings, newMappingRow()])}
          disabled={form.mappings.length >= ATTRIBUTE_MAPPINGS_MAX}
        >
          <Plus size={14} aria-hidden="true" />
          Add attribute mapping
        </Button>
      </fieldset>

      <fieldset className="space-y-3">
        <legend className="text-sm font-medium text-foreground">Allowed groups</legend>
        <p className="text-xs text-muted-foreground">
          Members of the groups you tick may sign in to this service provider.{" "}
          <strong>With none ticked, every active user of the tenant may.</strong>
        </p>
        {groups.length > 8 && (
          <Input
            aria-label="Filter groups"
            placeholder="Filter groups…"
            value={groupFilter}
            onChange={(e) => setGroupFilter(e.target.value)}
          />
        )}
        {groupsLoading ? (
          <p className="text-sm text-muted-foreground">Loading groups…</p>
        ) : groups.length === 0 && unknownGroupIds.length === 0 ? (
          <p className="text-sm text-muted-foreground">This tenant has no groups.</p>
        ) : (
          <ul className="max-h-48 space-y-1 overflow-y-auto rounded-md border border-white/10 p-2">
            {visibleGroups.map((group) => (
              <li key={group.id}>
                <label className="flex cursor-pointer items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={form.allowedGroups.includes(group.id)}
                    onChange={(e) => toggleGroup(group.id, e.target.checked)}
                    className="focus-ring h-4 w-4 accent-cyan-400"
                  />
                  {group.name}
                </label>
              </li>
            ))}
            {unknownGroupIds.map((id) => (
              <li key={id}>
                <label className="flex cursor-pointer items-center gap-2 text-sm text-amber-300">
                  <input
                    type="checkbox"
                    checked
                    onChange={() => toggleGroup(id, false)}
                    className="focus-ring h-4 w-4 accent-cyan-400"
                  />
                  Unknown group ({id.slice(0, 8)}…): untick to remove
                </label>
              </li>
            ))}
          </ul>
        )}
      </fieldset>

      {error && (
        <p role="alert" className="flex items-start gap-2 text-sm text-destructive">
          <AlertCircle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </p>
      )}
    </div>
  );
}

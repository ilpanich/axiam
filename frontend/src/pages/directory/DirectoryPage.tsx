import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Pencil,
  Plus,
  Repeat2,
  Trash2,
  X,
} from "lucide-react";
import {
  DIRECTORY_KINDS,
  DIRECTORY_KIND_LABELS,
  directoryService,
  movedConnectionFields,
  type DirectoryConfig,
  type DirectoryKind,
} from "@/services/directory";
import { fetchAllPages } from "@/services/_pagination";
import type { Group } from "@/services/users";
import { useAuthStore } from "@/stores/auth";
import { usePermissions } from "@/hooks/usePermissions";
import { PageHeader } from "@/components/PageHeader";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { InfoRow, SectionCard, ToggleField } from "@/components/shared";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { formatDateTime } from "@/lib/utils";
import { invalidateEntity } from "@/lib/queryInvalidation";
import {
  buildSetPayload,
  buildUpdatePayload,
  emptyForm,
  formConnection,
  formFromConfig,
  kindDefaults,
  secretRequired,
  validateForm,
  type DirectoryForm,
} from "./directoryForm";
import { directoryErrorMessage } from "./directoryErrors";
import { GroupMappingsEditor } from "./GroupMappingsEditor";
import { LinkAccountPanel } from "./LinkAccountPanel";
import { SyncStatusPanel } from "./SyncStatusPanel";

/**
 * How the form is being used. `edit` sends only what changed (`PATCH`);
 * `create` and `replace` send every member the form shows (`PUT`), so a
 * replacement resets nothing by omission.
 */
type Mode = "view" | "create" | "edit" | "replace";

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

// ─────────────────────────────────────────────────────────────────────────────
// The read-only view
// ─────────────────────────────────────────────────────────────────────────────

function ConfigSummary({ config, groups }: { config: DirectoryConfig; groups: Group[] }) {
  const groupName = (id: string) => groups.find((g) => g.id === id)?.name ?? `${id.slice(0, 8)}…`;
  return (
    <div>
      <InfoRow label="Status">
        <Badge variant={config.enabled ? "default" : "secondary"}>
          {config.enabled ? "Enabled" : "Disabled"}
        </Badge>
      </InfoRow>
      <InfoRow label="Kind">
        {DIRECTORY_KIND_LABELS[config.kind as DirectoryKind] ?? config.kind}
      </InfoRow>
      <InfoRow label="URL">
        <code className="text-xs">{config.url}</code>
        {config.start_tls && " (StartTLS)"}
      </InfoRow>
      <InfoRow label="Bind DN">
        <code className="text-xs break-all">{config.bind_dn}</code>
      </InfoRow>
      <InfoRow label="Bind secret">
        <span className="text-muted-foreground">
          Write-only — never shown. Enter it again to change it.
        </span>
      </InfoRow>
      <InfoRow label="Base DN">
        <code className="text-xs break-all">{config.base_dn}</code>
      </InfoRow>
      <InfoRow label="User filter">
        <code className="text-xs break-all">{config.user_filter}</code>
      </InfoRow>
      <InfoRow label="Attributes">
        <code className="text-xs">
          {config.user_attribute_map.username} / {config.user_attribute_map.email} /{" "}
          {config.user_attribute_map.display_name} / {config.user_attribute_map.external_id}
        </code>
      </InfoRow>
      <InfoRow label="Groups">
        {config.group_base_dn ? (
          <code className="text-xs break-all">{config.group_base_dn}</code>
        ) : (
          <span className="text-muted-foreground">No group search base</span>
        )}
        {config.group_filter && (
          <>
            {" "}
            <code className="text-xs break-all">{config.group_filter}</code>
          </>
        )}
        <span className="block text-xs text-muted-foreground">
          member attribute <code>{config.group_member_attribute}</code>, nesting depth{" "}
          {config.group_nesting_depth}
        </span>
      </InfoRow>
      <InfoRow label="Group mappings">
        {config.group_mappings.length === 0 ? (
          <span className="text-muted-foreground">None — no directory group maps to anything</span>
        ) : (
          <ul className="space-y-1">
            {config.group_mappings.map((m) => (
              <li key={`${m.directory_group_dn}|${m.group_id}`} className="text-xs">
                <code className="break-all">{m.directory_group_dn}</code> →{" "}
                <strong>{groupName(m.group_id)}</strong>
              </li>
            ))}
          </ul>
        )}
      </InfoRow>
      <InfoRow label="Sync interval">{config.sync_interval_secs} s</InfoRow>
      <InfoRow label="Provisioning">
        <Badge variant={config.jit_provisioning ? "default" : "secondary"}>
          {config.jit_provisioning ? "Just-in-time on" : "Just-in-time off"}
        </Badge>
      </InfoRow>
      <InfoRow label="Trust anchors">
        {config.trust_anchors_pem.length === 0
          ? "None — the public roots"
          : `${config.trust_anchors_pem.length} CA certificate${config.trust_anchors_pem.length === 1 ? "" : "s"}`}
      </InfoRow>
      <InfoRow label="Updated">{formatDateTime(config.updated_at)}</InfoRow>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// The editor
// ─────────────────────────────────────────────────────────────────────────────

interface EditorProps {
  stored: DirectoryConfig | null;
  mode: Exclude<Mode, "view">;
  form: DirectoryForm;
  groups: Group[];
  groupsLoading: boolean;
  onChange: <K extends keyof DirectoryForm>(key: K, value: DirectoryForm[K]) => void;
  error: string | null;
}

function DirectoryEditor({
  stored,
  mode,
  form,
  groups,
  groupsLoading,
  onChange,
  error,
}: EditorProps) {
  const needsSecret = secretRequired(stored, form);
  const moved = stored ? movedConnectionFields(stored, formConnection(form)) : [];

  function changeKind(next: DirectoryKind) {
    // Switching kind re-seeds the attributes only while they still hold the
    // previous kind's defaults, so a customised mapping is never overwritten.
    const was = kindDefaults(form.kind);
    const to = kindDefaults(next);
    onChange("kind", next);
    if (form.attrUsername === was.attributes.username) onChange("attrUsername", to.attributes.username);
    if (form.attrExternalId === was.attributes.external_id) {
      onChange("attrExternalId", to.attributes.external_id);
    }
    if (form.groupMemberAttribute === was.groupMemberAttribute) {
      onChange("groupMemberAttribute", to.groupMemberAttribute);
    }
  }

  return (
    <div className="space-y-5">
      {mode === "replace" && (
        <p className="rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
          <strong>Replace</strong> saves every member of this form as the new
          configuration. Use <em>Edit</em> to change one thing and leave the rest
          exactly as stored.
        </p>
      )}

      <ToggleField
        id="dir-enabled"
        label="Enabled"
        checked={form.enabled}
        onChange={(v) => onChange("enabled", v)}
        description="A disabled directory serves no sign-in and is not synced. Directory accounts then cannot sign in with a password at all — there is no fallback to a local hash — but sessions and passkeys they already hold keep working until they expire."
      />

      <div className="grid gap-4 sm:grid-cols-2">
        <Field id="dir-kind" label="Kind" hint="Chooses defaults only.">
          <select
            id="dir-kind"
            value={form.kind}
            onChange={(e) => changeKind(e.target.value as DirectoryKind)}
            className={SELECT_CLASS}
          >
            {DIRECTORY_KINDS.map((kind) => (
              <option key={kind} value={kind}>
                {DIRECTORY_KIND_LABELS[kind]}
              </option>
            ))}
          </select>
        </Field>
        <Field
          id="dir-url"
          label="URL"
          hint="ldaps://host[:port], or ldap://host[:port] with StartTLS. Name the host; an IPv6 literal cannot be certificate-checked."
        >
          <Input
            id="dir-url"
            value={form.url}
            onChange={(e) => onChange("url", e.target.value)}
            autoComplete="off"
            spellCheck={false}
            placeholder="ldaps://ldap.example.com"
          />
        </Field>
      </div>

      <ToggleField
        id="dir-starttls"
        label="Use StartTLS"
        checked={form.startTls}
        onChange={(v) => onChange("startTls", v)}
        description="On for ldap:// URLs, off for ldaps://. Plaintext ldap:// without StartTLS is refused."
      />

      <div className="grid gap-4 sm:grid-cols-2">
        <Field
          id="dir-bind-dn"
          label="Bind DN"
          hint="A read-only service account. AXIAM never writes to a directory."
        >
          <Input
            id="dir-bind-dn"
            value={form.bindDn}
            onChange={(e) => onChange("bindDn", e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
        <Field
          id="dir-bind-secret"
          label={needsSecret ? "Bind secret (required)" : "Bind secret"}
          hint={
            needsSecret
              ? undefined
              : "Leave empty to keep the stored secret. It is never shown, and there is no way to read it back."
          }
        >
          <Input
            id="dir-bind-secret"
            type="password"
            value={form.bindSecret}
            onChange={(e) => onChange("bindSecret", e.target.value)}
            autoComplete="new-password"
            spellCheck={false}
          />
        </Field>
      </div>

      {stored && moved.length > 0 && (
        <p
          role="alert"
          className="flex items-start gap-2 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200"
        >
          <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>
            You changed the {moved.join(", ")}. Enter the bind secret again: a stored
            secret is never sent to a connection it was not entered for, and the server
            refuses the save without it.
          </span>
        </p>
      )}

      <div className="grid gap-4 sm:grid-cols-2">
        <Field id="dir-base-dn" label="Base DN" hint="Where users are searched for.">
          <Input
            id="dir-base-dn"
            value={form.baseDn}
            onChange={(e) => onChange("baseDn", e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
        <Field
          id="dir-user-filter"
          label="User filter"
          hint="Exactly one {username}, in value position — it is escaped, never formatted in."
        >
          <Input
            id="dir-user-filter"
            value={form.userFilter}
            onChange={(e) => onChange("userFilter", e.target.value)}
            autoComplete="off"
            spellCheck={false}
            className="font-mono text-xs"
          />
        </Field>
      </div>

      <fieldset className="space-y-3">
        <legend className="text-sm font-medium text-foreground">Attribute map</legend>
        <p className="text-xs text-muted-foreground">
          An entry without a usable e-mail address cannot be provisioned: a local
          account must have one, and AXIAM does not invent a placeholder. Map the
          e-mail attribute to one every entry has.
        </p>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field id="dir-attr-username" label="Username attribute">
            <Input
              id="dir-attr-username"
              value={form.attrUsername}
              onChange={(e) => onChange("attrUsername", e.target.value)}
              autoComplete="off"
            />
          </Field>
          <Field id="dir-attr-email" label="E-mail attribute">
            <Input
              id="dir-attr-email"
              value={form.attrEmail}
              onChange={(e) => onChange("attrEmail", e.target.value)}
              autoComplete="off"
            />
          </Field>
          <Field id="dir-attr-display" label="Display-name attribute">
            <Input
              id="dir-attr-display"
              value={form.attrDisplayName}
              onChange={(e) => onChange("attrDisplayName", e.target.value)}
              autoComplete="off"
            />
          </Field>
          <Field
            id="dir-attr-external"
            label="Immutable-id attribute"
            hint="entryUUID or objectGUID: what an account is keyed on."
          >
            <Input
              id="dir-attr-external"
              value={form.attrExternalId}
              onChange={(e) => onChange("attrExternalId", e.target.value)}
              autoComplete="off"
            />
          </Field>
        </div>
      </fieldset>

      <fieldset className="space-y-3">
        <legend className="text-sm font-medium text-foreground">Groups</legend>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field
            id="dir-group-base"
            label="Group base DN"
            hint="Where groups are searched for. Required for OpenLDAP when mappings exist."
          >
            <Input
              id="dir-group-base"
              value={form.groupBaseDn}
              onChange={(e) => onChange("groupBaseDn", e.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </Field>
          <Field id="dir-group-filter" label="Group filter" hint="Optional; no placeholder.">
            <Input
              id="dir-group-filter"
              value={form.groupFilter}
              onChange={(e) => onChange("groupFilter", e.target.value)}
              autoComplete="off"
              spellCheck={false}
              className="font-mono text-xs"
            />
          </Field>
          <Field id="dir-group-member" label="Group member attribute">
            <Input
              id="dir-group-member"
              value={form.groupMemberAttribute}
              onChange={(e) => onChange("groupMemberAttribute", e.target.value)}
              autoComplete="off"
            />
          </Field>
          <Field id="dir-nesting" label="Nesting depth" hint="0 to 10.">
            <Input
              id="dir-nesting"
              inputMode="numeric"
              value={form.groupNestingDepth}
              onChange={(e) => onChange("groupNestingDepth", e.target.value)}
            />
          </Field>
        </div>
      </fieldset>

      <GroupMappingsEditor
        rows={form.mappings}
        groups={groups}
        groupsLoading={groupsLoading}
        onChange={(rows) => onChange("mappings", rows)}
      />

      <div className="grid gap-4 sm:grid-cols-2">
        <Field
          id="dir-sync-interval"
          label="Sync interval (seconds)"
          hint="300 to 86400. A full reconciliation also runs every 24 hours."
        >
          <Input
            id="dir-sync-interval"
            inputMode="numeric"
            value={form.syncIntervalSecs}
            onChange={(e) => onChange("syncIntervalSecs", e.target.value)}
          />
        </Field>
      </div>

      <ToggleField
        id="dir-jit"
        label="Provision accounts at first sign-in"
        checked={form.jitProvisioning}
        onChange={(v) => onChange("jitProvisioning", v)}
        description="Creates an account for a directory user whose name matches no local account. It never links an existing account (use “Link an account”), and an entry with no usable e-mail address cannot be provisioned."
      />

      <Field
        id="dir-anchors"
        label="Trust anchors (PEM)"
        hint="The CA certificates the directory's server certificate must chain to, at most 16. Empty means the public roots; the two are never combined and verification cannot be switched off."
      >
        <Textarea
          id="dir-anchors"
          value={form.anchorsText}
          onChange={(e) => onChange("anchorsText", e.target.value)}
          rows={5}
          spellCheck={false}
          className="font-mono text-xs"
          placeholder="-----BEGIN CERTIFICATE-----"
        />
      </Field>

      {error && (
        <p role="alert" className="flex items-start gap-2 text-sm text-destructive">
          <AlertCircle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>{error}</span>
        </p>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// The page
// ─────────────────────────────────────────────────────────────────────────────

export function DirectoryPage() {
  const tenantId = useAuthStore((s) => s.user?.tenant_id);
  const { can } = usePermissions();
  const queryClient = useQueryClient();

  const [mode, setMode] = useState<Mode>("view");
  const [form, setForm] = useState<DirectoryForm>(() => emptyForm());
  const [formError, setFormError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  const canWrite = can("directory:write");
  const canLink = can("directory:link");

  const {
    data: config,
    isLoading,
    error: loadError,
  } = useQuery({
    queryKey: ["directory-config", tenantId],
    queryFn: () => directoryService.get(tenantId!),
    enabled: !!tenantId,
  });

  const { data: groupList, isLoading: groupsLoading } = useQuery({
    queryKey: ["groups", "all-pages"],
    queryFn: () => fetchAllPages<Group>("/api/v1/groups"),
    // Only the editor and the summary's names need them.
    enabled: !!tenantId && (mode !== "view" || (config?.group_mappings.length ?? 0) > 0),
  });
  const groups = useMemo(() => groupList ?? [], [groupList]);

  function done(message: string) {
    invalidateEntity(queryClient, "directory-config");
    // The typed secret is gone from state the moment the request has been sent.
    setForm((f) => ({ ...f, bindSecret: "" }));
    setMode("view");
    setFormError(null);
    setFeedback(message);
  }

  const save = useMutation({
    mutationFn: (args: { mode: Mode; stored: DirectoryConfig | null; form: DirectoryForm }) =>
      args.mode === "edit" && args.stored
        ? directoryService.update(tenantId!, buildUpdatePayload(args.stored, args.form))
        : directoryService.set(tenantId!, buildSetPayload(args.form)),
    onSuccess: (_saved, args) => {
      done(args.mode === "create" ? "Directory configuration created." : "Directory configuration saved.");
    },
    onError: (err: unknown, args) => {
      setFormError(directoryErrorMessage(err, args.form.bindSecret));
      // Not kept in state longer than it has to be.
      setForm((f) => ({ ...f, bindSecret: "" }));
    },
  });

  const remove = useMutation({
    mutationFn: () => directoryService.remove(tenantId!),
    onSuccess: () => {
      invalidateEntity(queryClient, "directory-config");
      setConfirmDelete(false);
      setDeleteError(null);
      setMode("view");
      setFeedback("Directory configuration deleted.");
    },
    onError: (err: unknown) => setDeleteError(directoryErrorMessage(err, "", "Delete failed.")),
  });

  function setField<K extends keyof DirectoryForm>(key: K, value: DirectoryForm[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function open(next: Exclude<Mode, "view">) {
    setFeedback(null);
    setFormError(null);
    setForm(next === "create" || !config ? emptyForm() : formFromConfig(config));
    setMode(next);
  }

  function handleSave() {
    if (mode === "view") return;
    setFormError(null);
    const problem = validateForm(config ?? null, form);
    if (problem) {
      setFormError(problem);
      return;
    }
    setFeedback(null);
    save.mutate({ mode, stored: config ?? null, form });
  }

  function handleCancel() {
    setForm(emptyForm());
    setFormError(null);
    setMode("view");
  }

  return (
    <div className="max-w-3xl space-y-6">
      <PageHeader
        title="Directory"
        description="Sign this tenant's people in through its own LDAP or Active Directory server. The directory checks the password; AXIAM never stores it. Read-only against the directory."
      />

      {feedback && (
        <div
          role="status"
          className="flex items-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 p-3 text-sm text-emerald-400"
        >
          <CheckCircle2 size={16} />
          <span>{feedback}</span>
        </div>
      )}

      {isLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="animate-spin text-primary" size={24} />
        </div>
      ) : loadError ? (
        <p role="alert" className="text-sm text-destructive">
          Failed to load the directory configuration. Please refresh the page.
        </p>
      ) : mode !== "view" ? (
        <SectionCard
          title={
            mode === "create"
              ? "Configure a directory"
              : mode === "replace"
                ? "Replace the directory configuration"
                : "Edit the directory configuration"
          }
        >
          <DirectoryEditor
            stored={config ?? null}
            mode={mode}
            form={form}
            groups={groups}
            groupsLoading={groupsLoading}
            onChange={setField}
            error={formError}
          />
          <div className="mt-2 flex gap-3 border-t border-primary/10 pt-4">
            <Button size="sm" onClick={handleSave} disabled={save.isPending}>
              {save.isPending && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
              {mode === "create" ? "Create" : mode === "replace" ? "Replace" : "Save changes"}
            </Button>
            <Button variant="outline" size="sm" onClick={handleCancel} disabled={save.isPending}>
              <X size={14} aria-hidden="true" />
              Cancel
            </Button>
          </div>
        </SectionCard>
      ) : config ? (
        <SectionCard
          title="Configuration"
          action={
            canWrite ? (
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => open("edit")}>
                  <Pencil size={14} aria-hidden="true" />
                  Edit
                </Button>
                <Button variant="outline" size="sm" onClick={() => open("replace")}>
                  <Repeat2 size={14} aria-hidden="true" />
                  Replace
                </Button>
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={() => {
                    setDeleteError(null);
                    setConfirmDelete(true);
                  }}
                >
                  <Trash2 size={14} aria-hidden="true" />
                  Delete
                </Button>
              </div>
            ) : undefined
          }
        >
          <ConfigSummary config={config} groups={groups} />
        </SectionCard>
      ) : (
        <SectionCard
          title="No directory configured"
          action={
            canWrite ? (
              <Button size="sm" onClick={() => open("create")}>
                <Plus size={14} aria-hidden="true" />
                Configure a directory
              </Button>
            ) : undefined
          }
        >
          <p className="text-sm text-muted-foreground">
            Before you start: the deployment needs a directory encryption key to store the
            bind secret, and a directory on a private network needs the operator to list
            that network. The connection must use TLS, and the directory&rsquo;s certificate
            must chain to the trust anchors you give (or a public root).
          </p>
        </SectionCard>
      )}

      {tenantId && config && mode === "view" && (
        <>
          <SyncStatusPanel tenantId={tenantId} />
          {canLink && <LinkAccountPanel tenantId={tenantId} directoryEnabled={config.enabled} />}
        </>
      )}

      <ConfirmDialog
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={() => remove.mutate()}
        title="Delete the directory configuration?"
        description="This removes the configuration and its sync state. Directory accounts can no longer sign in with a password, and the sync job stops for this tenant. Sessions, refresh tokens and passkeys they already hold keep working until they expire or you deactivate the accounts; there is no unlink."
        confirmLabel="Delete directory"
        isLoading={remove.isPending}
        error={deleteError}
      />
    </div>
  );
}

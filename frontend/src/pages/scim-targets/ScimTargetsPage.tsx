import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  scimTargetService,
  credentialRequiredFor,
  validateScimTargetInput,
  AUTH_KINDS,
  AUTH_KIND_LABELS,
  DEPROVISION_LABELS,
  DEPROVISION_POLICIES,
  SCIM_TARGETS_URL,
  SCIM_TARGET_BOUNDS,
  USER_NAME_SOURCES,
  USER_NAME_SOURCE_LABELS,
  type AuthKind,
  type DeprovisionPolicy,
  type ScimTarget,
  type ScimTargetInput,
  type UserNameSource,
} from "@/services/scimTargets";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { PaginationControls, SearchBox } from "@/components/ListToolbar";
import { usePaginatedList } from "@/hooks/usePaginatedList";
import { usePermissions } from "@/hooks/usePermissions";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Pencil, Plus, RefreshCw, Trash2 } from "lucide-react";

import { formatDateTime } from "@/lib/utils";
import { getApiErrorMessage } from "@/lib/apiError";
import { ToggleField } from "@/components/shared";

const SELECT_CLASS =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40 disabled:opacity-50";

// ─── Form state ───────────────────────────────────────────────────────────────

interface FormState {
  name: string;
  baseUrl: string;
  enabled: boolean;
  authKind: AuthKind;
  tokenUrl: string;
  clientId: string;
  oauthScope: string;
  /** Write-only. Blank on edit; sent only when typed. */
  credential: string;
  scopeKind: "all_users" | "groups";
  groupIds: string[];
  pushGroups: boolean;
  userNameFrom: UserNameSource;
  deprovision: DeprovisionPolicy;
}

const EMPTY_FORM: FormState = {
  name: "",
  baseUrl: "",
  enabled: true,
  authKind: "bearer",
  tokenUrl: "",
  clientId: "",
  oauthScope: "",
  credential: "",
  scopeKind: "all_users",
  groupIds: [],
  pushGroups: false,
  userNameFrom: "username",
  deprovision: "deactivate",
};

function isKnown<T extends string>(all: readonly T[], value: string): value is T {
  return (all as readonly string[]).includes(value);
}

/** A stored target as form state — the credential is never part of it. */
function formFrom(target: ScimTarget): FormState {
  return {
    name: target.name,
    baseUrl: target.base_url,
    enabled: target.enabled,
    authKind: target.auth.type,
    tokenUrl:
      target.auth.type === "oauth2_client_credentials" ? target.auth.token_url : "",
    clientId:
      target.auth.type === "oauth2_client_credentials" ? target.auth.client_id : "",
    oauthScope:
      target.auth.type === "oauth2_client_credentials"
        ? (target.auth.scope ?? "")
        : "",
    credential: "",
    scopeKind: target.scope.type,
    groupIds: target.scope.type === "groups" ? target.scope.group_ids : [],
    pushGroups: target.push_groups,
    userNameFrom: isKnown(USER_NAME_SOURCES, target.user_name_from)
      ? target.user_name_from
      : "username",
    deprovision: isKnown(DEPROVISION_POLICIES, target.deprovision)
      ? target.deprovision
      : "deactivate",
  };
}

/** The replacement body for a form; the credential only when one was typed. */
function inputFrom(form: FormState): ScimTargetInput {
  return {
    name: form.name.trim(),
    base_url: form.baseUrl.trim(),
    enabled: form.enabled,
    auth:
      form.authKind === "bearer"
        ? { type: "bearer" }
        : {
            type: "oauth2_client_credentials",
            token_url: form.tokenUrl.trim(),
            client_id: form.clientId.trim(),
            scope: form.oauthScope.trim() || null,
          },
    ...(form.credential ? { credential: form.credential } : {}),
    scope:
      form.scopeKind === "all_users"
        ? { type: "all_users" }
        : { type: "groups", group_ids: form.groupIds },
    push_groups: form.pushGroups,
    user_name_from: form.userNameFrom,
    deprovision: form.deprovision,
  };
}

// ─── Form fields ──────────────────────────────────────────────────────────────

interface TargetFieldsProps {
  idPrefix: string;
  form: FormState;
  onChange: (next: FormState) => void;
  /** The stored target when editing: the credential field is then optional. */
  stored: ScimTarget | null;
}

function TargetFields({ idPrefix, form, onChange, stored }: TargetFieldsProps) {
  const set = (patch: Partial<FormState>) => onChange({ ...form, ...patch });

  const groups = useQuery({
    queryKey: ["scim-target-groups"],
    queryFn: scimTargetService.listGroups,
    enabled: form.scopeKind === "groups",
  });

  // D-57: a stored credential does not follow its URL or its kind. The form
  // asks for it, with the reason, as soon as the edit makes it necessary.
  const reason = stored
    ? credentialRequiredFor(stored, inputFrom(form))
    : null;
  const credentialRequired = stored === null || reason !== null;
  const credentialLabel =
    form.authKind === "bearer" ? "Bearer token" : "Client secret";

  function toggleGroup(id: string) {
    set({
      groupIds: form.groupIds.includes(id)
        ? form.groupIds.filter((g) => g !== id)
        : [...form.groupIds, id],
    });
  }

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-name`}>Name *</Label>
        <Input
          id={`${idPrefix}-name`}
          value={form.name}
          onChange={(e) => set({ name: e.target.value })}
          placeholder="HR system"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-base-url`}>Base URL *</Label>
        <Input
          id={`${idPrefix}-base-url`}
          type="url"
          value={form.baseUrl}
          onChange={(e) => set({ baseUrl: e.target.value })}
          placeholder="https://scim.example.com/scim/v2"
          required
          autoComplete="off"
        />
        <p className="text-xs text-muted-foreground">
          The SCIM service root of the downstream. Must be https and a public
          address.
        </p>
      </div>

      <ToggleField
        id={`${idPrefix}-enabled`}
        label="Enabled"
        checked={form.enabled}
        onChange={(v) => set({ enabled: v })}
        description="A disabled target receives nothing. Enabling one starts a reconciliation that sends everything in scope."
      />

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-auth-kind`}>Authentication</Label>
        <select
          id={`${idPrefix}-auth-kind`}
          value={form.authKind}
          onChange={(e) => set({ authKind: e.target.value as AuthKind })}
          className={SELECT_CLASS}
        >
          {AUTH_KINDS.map((kind) => (
            <option key={kind} value={kind}>
              {AUTH_KIND_LABELS[kind]}
            </option>
          ))}
        </select>
      </div>

      {form.authKind === "oauth2_client_credentials" && (
        <>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-token-url`}>Token URL *</Label>
            <Input
              id={`${idPrefix}-token-url`}
              type="url"
              value={form.tokenUrl}
              onChange={(e) => set({ tokenUrl: e.target.value })}
              placeholder="https://idp.example.com/oauth/token"
              autoComplete="off"
            />
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor={`${idPrefix}-client-id`}>Client ID *</Label>
              <Input
                id={`${idPrefix}-client-id`}
                value={form.clientId}
                onChange={(e) => set({ clientId: e.target.value })}
                autoComplete="off"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor={`${idPrefix}-oauth-scope`}>Scope</Label>
              <Input
                id={`${idPrefix}-oauth-scope`}
                value={form.oauthScope}
                onChange={(e) => set({ oauthScope: e.target.value })}
                placeholder="optional"
                autoComplete="off"
              />
            </div>
          </div>
        </>
      )}

      {/* Write-only. Never pre-filled, never shown, never returned by the API. */}
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-credential`}>
          {credentialLabel}
          {credentialRequired ? " *" : ""}
        </Label>
        <Input
          id={`${idPrefix}-credential`}
          type="password"
          value={form.credential}
          onChange={(e) => set({ credential: e.target.value })}
          placeholder={
            credentialRequired ? "" : "Leave blank to keep the stored credential"
          }
          autoComplete="new-password"
        />
        <p className="text-xs text-muted-foreground">
          {reason
            ? `${reason} sends the credential somewhere new, so it must be entered again.`
            : stored
              ? "Write-only: AXIAM never shows the stored credential."
              : "Write-only: stored encrypted and never shown again."}
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-scope-kind`}>Users to provision</Label>
        <select
          id={`${idPrefix}-scope-kind`}
          value={form.scopeKind}
          onChange={(e) =>
            set({ scopeKind: e.target.value as FormState["scopeKind"] })
          }
          className={SELECT_CLASS}
        >
          <option value="all_users">Every user of the tenant</option>
          <option value="groups">Members of selected groups</option>
        </select>
      </div>

      {form.scopeKind === "groups" && (
        <div className="space-y-2">
          <Label>Groups * (direct members are provisioned)</Label>
          <div
            className="rounded-md border border-input bg-background/50 p-3 max-h-40 overflow-y-auto space-y-1"
            role="group"
            aria-label="Groups in scope"
          >
            {groups.isLoading && (
              <p className="text-xs text-muted-foreground">Loading groups…</p>
            )}
            {groups.isError && (
              <p className="text-xs text-destructive">
                Groups could not be loaded.
              </p>
            )}
            {groups.data?.length === 0 && (
              <p className="text-xs text-muted-foreground">
                This tenant has no groups yet.
              </p>
            )}
            {groups.data?.map((group) => (
              <label
                key={group.id}
                className="flex items-center gap-2.5 cursor-pointer text-sm text-foreground/80"
              >
                <input
                  type="checkbox"
                  checked={form.groupIds.includes(group.id)}
                  onChange={() => toggleGroup(group.id)}
                  className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
                  aria-label={group.name}
                />
                {group.name}
              </label>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            {form.groupIds.length === 0
              ? "Select at least one group."
              : `${form.groupIds.length} of at most ${SCIM_TARGET_BOUNDS.scopeGroups} selected.`}
          </p>
        </div>
      )}

      <ToggleField
        id={`${idPrefix}-push-groups`}
        label="Push groups"
        checked={form.pushGroups}
        onChange={(v) => set({ pushGroups: v })}
        description="Also create the groups in scope downstream, with their members."
      />

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-user-name`}>Downstream userName</Label>
          <select
            id={`${idPrefix}-user-name`}
            value={form.userNameFrom}
            onChange={(e) =>
              set({ userNameFrom: e.target.value as UserNameSource })
            }
            className={SELECT_CLASS}
          >
            {USER_NAME_SOURCES.map((source) => (
              <option key={source} value={source}>
                {USER_NAME_SOURCE_LABELS[source]}
              </option>
            ))}
          </select>
        </div>
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-deprovision`}>
            When a user leaves scope
          </Label>
          <select
            id={`${idPrefix}-deprovision`}
            value={form.deprovision}
            onChange={(e) =>
              set({ deprovision: e.target.value as DeprovisionPolicy })
            }
            className={SELECT_CLASS}
          >
            {DEPROVISION_POLICIES.map((policy) => (
              <option key={policy} value={policy}>
                {DEPROVISION_LABELS[policy]}
              </option>
            ))}
          </select>
        </div>
      </div>
      <p className="text-xs text-muted-foreground">
        A GDPR erasure always deletes the downstream account, whatever this
        says.
      </p>
    </>
  );
}

// ─── Status cell ──────────────────────────────────────────────────────────────

function DeliveryStatus({ target }: { target: ScimTarget }) {
  const state = target.state;
  const failing = state !== null && state.consecutive_failures > 0;
  return (
    <div className="space-y-1">
      <StatusBadge status={target.enabled ? "active" : "inactive"} />
      {failing && (
        <p className="text-xs text-amber-400">
          Failing ({state.consecutive_failures} in a row
          {state.last_failure_reason ? `: ${state.last_failure_reason}` : ""})
        </p>
      )}
      {state !== null && state.dead_lettered_total > 0 && (
        <p className="text-xs text-destructive">
          {state.dead_lettered_total} dead-lettered
        </p>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

export function ScimTargetsPage() {
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can("scim_targets:write");

  const {
    items: targets,
    isLoading,
    search,
    setSearch,
    page,
    totalPages,
    total,
    setPage,
    isFiltered,
  } = usePaginatedList<ScimTarget>(["scim-targets"], SCIM_TARGETS_URL);

  const refresh = () =>
    void queryClient.invalidateQueries({ queryKey: ["scim-targets"] });

  // ─── Create ────────────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState<FormState>(EMPTY_FORM);
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: ScimTargetInput) => scimTargetService.create(payload),
    onSuccess: () => {
      refresh();
      setCreateOpen(false);
      setCreateForm(EMPTY_FORM);
    },
    onError: (err: unknown) =>
      setCreateError(
        getApiErrorMessage(
          err,
          err instanceof Error ? err.message : "Failed to create the target.",
        ),
      ),
  });

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    if (!createForm.credential) {
      setCreateError(
        `${createForm.authKind === "bearer" ? "Bearer token" : "Client secret"} is required.`,
      );
      return;
    }
    const payload = inputFrom(createForm);
    const problem = validateScimTargetInput(payload);
    if (problem) {
      setCreateError(problem);
      return;
    }
    createMutation.mutate(payload);
  }

  // ─── Edit ──────────────────────────────────────────────────────────────────
  const [editTarget, setEditTarget] = useState<ScimTarget | null>(null);
  const [editForm, setEditForm] = useState<FormState>(EMPTY_FORM);
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: ScimTargetInput }) =>
      scimTargetService.update(id, payload),
    onSuccess: () => {
      refresh();
      setEditTarget(null);
    },
    onError: (err: unknown) =>
      setEditError(
        getApiErrorMessage(
          err,
          err instanceof Error ? err.message : "Failed to update the target.",
        ),
      ),
  });

  function openEdit(target: ScimTarget) {
    setEditTarget(target);
    setEditForm(formFrom(target));
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editTarget) return;
    // The version the form was opened from, so an edit overtaken by another
    // administrator is a 409 and not a silent overwrite (T-416).
    const payload: ScimTargetInput = {
      ...inputFrom(editForm),
      expected_updated_at: editTarget.updated_at,
    };
    const reason = credentialRequiredFor(editTarget, payload);
    if (reason && !payload.credential) {
      setEditError(
        `${reason} requires the ${editForm.authKind === "bearer" ? "bearer token" : "client secret"} to be entered again.`,
      );
      return;
    }
    const problem = validateScimTargetInput(payload);
    if (problem) {
      setEditError(problem);
      return;
    }
    editMutation.mutate({ id: editTarget.id, payload });
  }

  // ─── Delete ────────────────────────────────────────────────────────────────
  const [deleteTarget, setDeleteTarget] = useState<ScimTarget | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => scimTargetService.remove(id),
    onSuccess: () => {
      refresh();
      setDeleteTarget(null);
    },
  });

  // ─── Reconcile now ─────────────────────────────────────────────────────────
  const [notice, setNotice] = useState<{ kind: "ok" | "error"; text: string } | null>(
    null,
  );

  const reconcileMutation = useMutation({
    mutationFn: (target: ScimTarget) => scimTargetService.reconcile(target.id),
    onSuccess: (_data, target) => {
      setNotice({ kind: "ok", text: `Reconciliation of "${target.name}" started.` });
      refresh();
    },
    onError: (err: unknown) =>
      setNotice({
        kind: "error",
        text: getApiErrorMessage(
          err,
          err instanceof Error ? err.message : "Could not start the reconciliation.",
        ),
      }),
  });

  // ─── Columns ───────────────────────────────────────────────────────────────
  const columns: Column<ScimTarget>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <div className="max-w-[280px]">
          <span className="font-medium text-foreground/90 text-sm block truncate">
            {row.name}
          </span>
          <span
            className="text-xs text-muted-foreground block truncate"
            title={row.base_url}
          >
            {row.base_url}
          </span>
        </div>
      ),
    },
    {
      key: "auth",
      header: "Authentication",
      render: (row) => (
        <span className="text-sm text-foreground/80">
          {isKnown(AUTH_KINDS, row.auth.type)
            ? AUTH_KIND_LABELS[row.auth.type]
            : row.auth.type}
        </span>
      ),
    },
    {
      key: "scope",
      header: "Scope",
      render: (row) => (
        <span className="text-sm text-foreground/80">
          {row.scope.type === "groups"
            ? `${row.scope.group_ids.length} ${row.scope.group_ids.length === 1 ? "group" : "groups"}`
            : "All users"}
        </span>
      ),
    },
    {
      key: "enabled",
      header: "Status",
      render: (row) => <DeliveryStatus target={row} />,
    },
    {
      key: "last_success",
      header: "Last delivery",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {row.state?.last_success_at
            ? formatDateTime(row.state.last_success_at)
            : "Never"}
        </span>
      ),
    },
    {
      key: "last_reconciled",
      header: "Reconciled",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {row.state?.last_reconciled_at
            ? formatDateTime(row.state.last_reconciled_at)
            : "Never"}
        </span>
      ),
    },
    ...(canWrite
      ? [
          {
            key: "actions",
            header: "Actions",
            width: "w-32",
            render: (row: ScimTarget) => (
              <div className="flex items-center gap-1">
                <button
                  aria-label={`Reconcile now ${row.name}`}
                  title="Reconcile now"
                  onClick={() => reconcileMutation.mutate(row)}
                  disabled={reconcileMutation.isPending}
                  className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors disabled:opacity-50"
                >
                  <RefreshCw size={14} />
                </button>
                <button
                  aria-label={`Edit SCIM target ${row.name}`}
                  onClick={() => openEdit(row)}
                  className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
                >
                  <Pencil size={14} />
                </button>
                <button
                  aria-label={`Delete SCIM target ${row.name}`}
                  onClick={() => setDeleteTarget(row)}
                  className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ),
          } satisfies Column<ScimTarget>,
        ]
      : []),
  ];

  return (
    <div>
      <PageHeader
        title="SCIM targets"
        description="Push this tenant's users and groups to downstream SCIM 2.0 service providers."
        action={
          canWrite ? (
            <Button
              onClick={() => {
                setCreateForm(EMPTY_FORM);
                setCreateError("");
                setCreateOpen(true);
              }}
            >
              <Plus size={16} />
              New SCIM target
            </Button>
          ) : undefined
        }
      />

      {notice && (
        <div
          role={notice.kind === "error" ? "alert" : "status"}
          className={
            notice.kind === "error"
              ? "mb-4 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
              : "mb-4 rounded-md border border-cyan-500/30 bg-cyan-500/10 p-3 text-sm text-cyan-400"
          }
        >
          {notice.text}
        </div>
      )}

      <SearchBox
        value={search}
        onChange={setSearch}
        noun="SCIM targets"
        className="mb-4 max-w-sm"
      />

      <DataTable
        columns={columns}
        data={targets}
        isLoading={isLoading}
        emptyMessage={
          isFiltered
            ? "No SCIM targets match your search."
            : "No SCIM targets configured."
        }
      />

      <PaginationControls
        page={page}
        totalPages={totalPages}
        total={total}
        onPageChange={setPage}
      />

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          setCreateForm(EMPTY_FORM);
          setCreateError("");
        }}
        title="New SCIM target"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
        error={createError}
        errorId="scim-target-create-error"
      >
        <TargetFields
          idPrefix="st"
          form={createForm}
          onChange={setCreateForm}
          stored={null}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        title="Edit SCIM target"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
        error={editError}
        errorId="scim-target-edit-error"
      >
        <TargetFields
          idPrefix="edit-st"
          form={editForm}
          onChange={setEditForm}
          stored={editTarget}
        />
      </FormDialog>

      {/* Delete confirm — says what deleting does not do. */}
      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && deleteMutation.mutate(deleteTarget.id)}
        title="Delete SCIM target"
        description={`Delete "${deleteTarget?.name}"? Its link records and delivery state are removed. This does not deprovision anything downstream: the users and groups AXIAM created in the service provider stay there, and AXIAM will no longer know them.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}

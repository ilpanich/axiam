import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { CheckCircle2, FileUp, Loader2, Pencil, Plus, Trash2, X } from "lucide-react";
import {
  samlService,
  serviceProvidersPath,
  type SamlServiceProvider,
  type SamlSpMetadataDraft,
} from "@/services/saml";
import { fetchAllPages } from "@/services/_pagination";
import type { Group } from "@/services/users";
import { usePermissions } from "@/hooks/usePermissions";
import { usePaginatedList } from "@/hooks/usePaginatedList";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DataTable, type Column } from "@/components/DataTable";
import { PaginationControls, SearchBox } from "@/components/ListToolbar";
import { SectionCard } from "@/components/shared";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { formatDateTime } from "@/lib/utils";
import { invalidateEntity } from "@/lib/queryInvalidation";
import { DraftReview, MetadataImportPanel } from "./MetadataImport";
import { ServiceProviderEditor } from "./ServiceProviderEditor";
import { samlErrorMessage } from "./samlErrors";
import {
  buildServiceProviderInput,
  emptyForm,
  formFromServiceProvider,
  validateForm,
  type SamlForm,
} from "./samlForm";

/**
 * What the section is showing. `create` carries the draft it was seeded from,
 * if any, so the review stays on screen beside the form until it is saved or
 * abandoned.
 */
type Mode =
  | { kind: "list" }
  | { kind: "import" }
  | { kind: "create"; draft: SamlSpMetadataDraft | null }
  | { kind: "edit"; stored: SamlServiceProvider };

/**
 * The tenant's service-provider registry (contract §29): a searchable,
 * paginated list, manual entry, import from metadata as a draft, edit and
 * delete. Reads need `saml_sp:read`; every write here needs `saml_sp:write`.
 */
export function ServiceProvidersSection({ tenantId }: { tenantId: string }) {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const canWrite = can("saml_sp:write");

  const [mode, setMode] = useState<Mode>({ kind: "list" });
  const [form, setForm] = useState<SamlForm>(() => emptyForm());
  const [formError, setFormError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{ ok: boolean; text: string } | null>(null);
  const [opening, setOpening] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<SamlServiceProvider | null>(null);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const { items, total, page, totalPages, isLoading, search, setSearch, setPage, isFiltered } =
    usePaginatedList<SamlServiceProvider>(
      ["saml-service-providers", tenantId],
      serviceProvidersPath(tenantId),
    );

  const editing = mode.kind === "create" || mode.kind === "edit";
  const { data: groupList, isLoading: groupsLoading } = useQuery({
    queryKey: ["groups", "all-pages"],
    queryFn: () => fetchAllPages<Group>("/api/v1/groups"),
    enabled: editing,
  });
  const groups = useMemo(() => groupList ?? [], [groupList]);

  function setField<K extends keyof SamlForm>(key: K, value: SamlForm[K]) {
    setForm((prev) => ({ ...prev, [key]: value }));
  }

  function backToList() {
    setMode({ kind: "list" });
    setForm(emptyForm());
    setFormError(null);
  }

  function openCreate() {
    setFeedback(null);
    setFormError(null);
    setForm(emptyForm());
    setMode({ kind: "create", draft: null });
  }

  /** Re-read the registration first: an update is a replacement, and a listed row may be stale. */
  async function openEdit(row: SamlServiceProvider) {
    setFeedback(null);
    setOpening(row.id);
    try {
      const stored = await samlService.getServiceProvider(tenantId, row.id);
      setForm(formFromServiceProvider(stored));
      setFormError(null);
      setMode({ kind: "edit", stored });
    } catch (err) {
      setFeedback({ ok: false, text: samlErrorMessage(err, "The service provider could not be loaded.") });
    } finally {
      setOpening(null);
    }
  }

  /** The draft opens the ordinary form, seeded; nothing is saved until Save is pressed there. */
  function openDraft(draft: SamlSpMetadataDraft) {
    setFeedback(null);
    setFormError(null);
    setForm(formFromServiceProvider(draft.service_provider));
    setMode({ kind: "create", draft });
  }

  const save = useMutation({
    mutationFn: (args: { stored: SamlServiceProvider | null; form: SamlForm }) => {
      const input = buildServiceProviderInput(args.form, args.stored);
      return args.stored
        ? samlService.updateServiceProvider(tenantId, args.stored.id, input)
        : samlService.createServiceProvider(tenantId, input);
    },
    onSuccess: (saved, args) => {
      invalidateEntity(queryClient, "saml-service-providers");
      backToList();
      setFeedback({
        ok: true,
        text: args.stored
          ? `Service provider “${saved.display_name}” saved.`
          : `Service provider “${saved.display_name}” registered.`,
      });
    },
    onError: (err: unknown) => setFormError(samlErrorMessage(err, "The service provider could not be saved.")),
  });

  const remove = useMutation({
    mutationFn: (sp: SamlServiceProvider) => samlService.deleteServiceProvider(tenantId, sp.id),
    onSuccess: (_void, sp) => {
      invalidateEntity(queryClient, "saml-service-providers");
      setDeleteTarget(null);
      setDeleteError(null);
      setFeedback({ ok: true, text: `Service provider “${sp.display_name}” deleted.` });
    },
    onError: (err: unknown) => setDeleteError(samlErrorMessage(err, "Delete failed.")),
  });

  function handleSave() {
    if (mode.kind !== "create" && mode.kind !== "edit") return;
    setFormError(null);
    const stored = mode.kind === "edit" ? mode.stored : null;
    const problem = validateForm(form, stored);
    if (problem) {
      setFormError(problem);
      return;
    }
    setFeedback(null);
    save.mutate({ stored, form });
  }

  const columns: Column<SamlServiceProvider>[] = [
    {
      key: "display_name",
      header: "Service provider",
      render: (row) => (
        <div>
          <span className="font-medium text-foreground/90">{row.display_name}</span>
          <span
            className="block max-w-[320px] truncate font-mono text-xs text-foreground/60"
            title={row.entity_id}
          >
            {row.entity_id}
          </span>
        </div>
      ),
    },
    {
      key: "enabled",
      header: "Status",
      render: (row) => (
        <Badge variant={row.enabled ? "default" : "secondary"}>
          {row.enabled ? "Enabled" : "Disabled"}
        </Badge>
      ),
    },
    {
      key: "acs",
      header: "ACS",
      render: (row) => (
        <span className="text-xs text-foreground/70">
          {row.acs_urls.length} endpoint{row.acs_urls.length === 1 ? "" : "s"}
        </span>
      ),
    },
    {
      key: "name_id_format",
      header: "NameID",
      render: (row) => (
        <span className="text-xs text-foreground/70">
          {row.name_id_format === "persistent"
            ? "Persistent"
            : row.name_id_format === "email_address"
              ? "E-mail address"
              : row.name_id_format}
        </span>
      ),
    },
    {
      key: "groups",
      header: "Who may sign in",
      render: (row) => (
        <span className="text-xs text-foreground/70">
          {row.allowed_groups.length === 0
            ? "Every active user"
            : `${row.allowed_groups.length} group${row.allowed_groups.length === 1 ? "" : "s"}`}
        </span>
      ),
    },
    {
      key: "updated_at",
      header: "Updated",
      render: (row) => (
        <span className="text-xs text-foreground/70">{formatDateTime(row.updated_at)}</span>
      ),
    },
    ...(canWrite
      ? [
          {
            key: "actions",
            header: "Actions",
            render: (row: SamlServiceProvider) => (
              <div className="flex gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={`Edit ${row.display_name}`}
                  disabled={opening === row.id}
                  onClick={() => void openEdit(row)}
                >
                  {opening === row.id ? (
                    <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                  ) : (
                    <Pencil size={14} aria-hidden="true" />
                  )}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  aria-label={`Delete ${row.display_name}`}
                  onClick={() => {
                    setDeleteError(null);
                    setDeleteTarget(row);
                  }}
                >
                  <Trash2 size={14} aria-hidden="true" />
                </Button>
              </div>
            ),
          } satisfies Column<SamlServiceProvider>,
        ]
      : []),
  ];

  return (
    <>
      {feedback && (
        <div
          role={feedback.ok ? "status" : "alert"}
          className={
            feedback.ok
              ? "mb-6 flex items-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 p-3 text-sm text-emerald-400"
              : "mb-6 flex items-center gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
          }
        >
          {feedback.ok && <CheckCircle2 size={16} aria-hidden="true" />}
          <span>{feedback.text}</span>
        </div>
      )}

      {mode.kind === "import" ? (
        <MetadataImportPanel
          tenantId={tenantId}
          onDraft={openDraft}
          onCancel={backToList}
        />
      ) : editing ? (
        <SectionCard
          title={
            mode.kind === "edit"
              ? `Edit ${mode.stored.display_name}`
              : mode.draft
                ? "Review the imported service provider"
                : "Register a service provider"
          }
        >
          {mode.kind === "edit" && (
            <p className="mb-4 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-200">
              Saving <strong>replaces</strong> the whole registration with this form. Nothing is
              kept from the stored one except the entity ID.
            </p>
          )}
          {mode.kind === "create" && mode.draft && <DraftReview draft={mode.draft} />}
          <ServiceProviderEditor
            stored={mode.kind === "edit" ? mode.stored : null}
            form={form}
            groups={groups}
            groupsLoading={groupsLoading}
            onChange={setField}
            error={formError}
          />
          <div className="mt-2 flex gap-3 border-t border-primary/10 pt-4">
            <Button size="sm" onClick={handleSave} disabled={save.isPending}>
              {save.isPending && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
              {mode.kind === "edit" ? "Save changes" : mode.draft ? "Save as a service provider" : "Register"}
            </Button>
            <Button variant="outline" size="sm" onClick={backToList} disabled={save.isPending}>
              <X size={14} aria-hidden="true" />
              Cancel
            </Button>
          </div>
        </SectionCard>
      ) : (
        <SectionCard
          title="Service providers"
          action={
            canWrite ? (
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setMode({ kind: "import" })}>
                  <FileUp size={14} aria-hidden="true" />
                  Import from metadata
                </Button>
                <Button size="sm" onClick={openCreate}>
                  <Plus size={14} aria-hidden="true" />
                  Register a service provider
                </Button>
              </div>
            ) : undefined
          }
        >
          <p className="mb-4 text-sm text-muted-foreground">
            The applications this tenant signs people in to over SAML. A service provider that is
            not registered here is refused, whatever it asks for.
          </p>
          <SearchBox
            value={search}
            onChange={setSearch}
            noun="service providers"
            className="mb-4 max-w-sm"
          />
          <DataTable
            columns={columns}
            data={items}
            isLoading={isLoading}
            getRowKey={(row) => row.id}
            emptyMessage={
              isFiltered
                ? "No service providers match that search."
                : "No service providers are registered yet."
            }
          />
          <PaginationControls
            page={page}
            totalPages={totalPages}
            total={total}
            onPageChange={setPage}
          />
        </SectionCard>
      )}

      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && remove.mutate(deleteTarget)}
        title={deleteTarget ? `Delete ${deleteTarget.display_name}?` : "Delete service provider?"}
        description="This removes the registration and the record of which sessions signed in to it, so sign-on and logout for it stop. It ends no session: people already signed in at the service provider stay signed in there until that session ends. Registering the same entity ID again gives its users their identifiers back."
        confirmLabel="Delete service provider"
        isLoading={remove.isPending}
        error={deleteError}
      />
    </>
  );
}

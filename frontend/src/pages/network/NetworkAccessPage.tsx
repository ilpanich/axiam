import { useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileSliders, Pencil, Plus, Trash2 } from "lucide-react";
import {
  networkService,
  NETWORK_HINTS,
  SEGMENT_KINDS,
  SEGMENT_KIND_BRANCH,
  SEGMENT_KIND_LABELS,
  type NetworkSegment,
  type ReplaceNetworkSegmentRequest,
  type SegmentKind,
} from "@/services/network";
import { getApiErrorStatus } from "@/lib/apiError";
import { invalidateEntity } from "@/lib/queryInvalidation";
import { usePermissions } from "@/hooks/usePermissions";
import { useDebounced } from "@/hooks/usePaginatedList";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { SearchBox } from "@/components/ListToolbar";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { ToggleField } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  EMPTY_SEGMENT_FORM,
  createSegmentBody,
  replaceSegmentBody,
  segmentFormFrom,
  segmentKindOf,
  type SegmentFormState,
} from "./networkForm";
import { networkErrorMessage } from "./networkErrors";
import { PolicyPanel } from "./PolicyPanel";
import { ReplyProfileDialog } from "./ReplyProfileDialog";

const SELECT_CLASS =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40 disabled:opacity-50";

// ─── Segment form fields ──────────────────────────────────────────────────────

interface SegmentFieldsProps {
  idPrefix: string;
  form: SegmentFormState;
  onChange: (next: SegmentFormState) => void;
  /** Editing: kind, site and name are fixed for the segment's life (§36.3 rule 4). */
  fixedPlace: boolean;
}

function SegmentFields({ idPrefix, form, onChange, fixedPlace }: SegmentFieldsProps) {
  const set = (patch: Partial<SegmentFormState>) => onChange({ ...form, ...patch });
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-kind`}>Kind *</Label>
        <select
          id={`${idPrefix}-kind`}
          value={form.kind}
          onChange={(e) => set({ kind: e.target.value as SegmentKind })}
          disabled={fixedPlace}
          className={SELECT_CLASS}
        >
          {SEGMENT_KINDS.map((kind) => (
            <option key={kind} value={kind}>
              {SEGMENT_KIND_LABELS[kind]}
            </option>
          ))}
        </select>
        <p className="text-xs text-muted-foreground">
          {fixedPlace
            ? "Kind, site and name do not change; to move a segment, create the new one and delete this one."
            : `An access segment lives under ${SEGMENT_KIND_BRANCH.access}, a quarantine segment under ${SEGMENT_KIND_BRANCH.quarantine}: a sibling branch, so that a deny on the zones quarantines a device without also denying its quarantine segment.`}
        </p>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-site`}>Site *</Label>
          <Input
            id={`${idPrefix}-site`}
            value={form.siteKey}
            onChange={(e) => set({ siteKey: e.target.value })}
            disabled={fixedPlace}
            autoComplete="off"
          />
        </div>
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-name`}>Name *</Label>
          <Input
            id={`${idPrefix}-name`}
            value={form.name}
            onChange={(e) => set({ name: e.target.value })}
            disabled={fixedPlace}
            placeholder="corp"
            autoComplete="off"
          />
        </div>
      </div>
      {!fixedPlace && (
        <p className="text-xs text-muted-foreground">
          Site and name: letters, digits, dot, underscore and hyphen, starting with
          a letter or digit. A single-site tenant uses <code>default</code>.
        </p>
      )}

      <div className="grid gap-3 sm:grid-cols-2">
        <div className="space-y-2">
          <Label htmlFor={`${idPrefix}-vlan`}>VLAN *</Label>
          <Input
            id={`${idPrefix}-vlan`}
            inputMode="numeric"
            value={form.vlanId}
            onChange={(e) => set({ vlanId: e.target.value })}
            placeholder="10"
            autoComplete="off"
          />
          <p className="text-xs text-muted-foreground">
            {NETWORK_HINTS.vlanMin} to {NETWORK_HINTS.vlanMax}, unique within the site.
          </p>
        </div>
        {form.kind === "access" && (
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-rank`}>Rank *</Label>
            <Input
              id={`${idPrefix}-rank`}
              inputMode="numeric"
              value={form.rank}
              onChange={(e) => set({ rank: e.target.value })}
              placeholder="10"
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              Lowest wins among the site&apos;s access segments; unique within the site.
            </p>
          </div>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-filters`}>Filter-Id names</Label>
        <Input
          id={`${idPrefix}-filters`}
          value={form.filterIds}
          onChange={(e) => set({ filterIds: e.target.value })}
          placeholder="corp-in, corp-out"
          autoComplete="off"
        />
        <p className="text-xs text-muted-foreground">
          The segment&apos;s envelope: the names its reply profile may choose from,
          at most {NETWORK_HINTS.filterIdsMax}, separated by commas or spaces. Removing
          the one the profile uses is refused.
        </p>
      </div>

      <ToggleField
        id={`${idPrefix}-enabled`}
        label="Enabled"
        checked={form.enabled}
        onChange={(v) => set({ enabled: v })}
        description="A disabled segment is not a placement candidate."
      />
    </>
  );
}

// ─── The list, grouped ────────────────────────────────────────────────────────

interface SiteGroup {
  site: string;
  segments: NetworkSegment[];
}

/** Kind, then site, then rank (access) or name: the order a decision reads them. */
function groupSegments(segments: NetworkSegment[]) {
  return SEGMENT_KINDS.map((kind) => {
    const ofKind = segments.filter((s) => segmentKindOf(s) === kind);
    const sites = [...new Set(ofKind.map((s) => s.site_key))].sort();
    const groups: SiteGroup[] = sites.map((site) => ({
      site,
      segments: ofKind
        .filter((s) => s.site_key === site)
        .sort(
          (a, b) =>
            (a.rank ?? Number.MAX_SAFE_INTEGER) - (b.rank ?? Number.MAX_SAFE_INTEGER) ||
            a.name.localeCompare(b.name),
        ),
    }));
    return { kind, groups };
  });
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export function NetworkAccessPage() {
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWriteSegments = can("network:segments_write");

  const [search, setSearch] = useState("");
  const debouncedSearch = useDebounced(search);

  const segmentsQuery = useQuery({
    queryKey: ["network-segments", debouncedSearch.trim()],
    queryFn: () =>
      networkService.listSegments(
        debouncedSearch.trim() ? { search: debouncedSearch.trim() } : undefined,
      ),
    // Every write names the version read here: never serve it from a cache.
    staleTime: 0,
  });
  const segments = useMemo(() => segmentsQuery.data ?? [], [segmentsQuery.data]);
  const grouped = useMemo(() => groupSegments(segments), [segments]);

  // The cap, for the profile editor's hint. The policy panel reads the same key.
  const policy = useQuery({
    queryKey: ["network-policy"],
    queryFn: networkService.getPolicy,
    staleTime: 0,
  });
  const cap = policy.data?.session_timeout_max_secs ?? NETWORK_HINTS.capDefaultSecs;

  const nodeName = (resourceId: string) => segments.find((s) => s.id === resourceId)?.path;
  const errorText = (err: unknown, fallback: string) =>
    networkErrorMessage(err, { fallback, nodeName });

  const refresh = () => invalidateEntity(queryClient, "network-segments");
  // A 409 is a write that no longer fits what the page shows (§36.4): read the
  // list again, whatever its reason_code.
  const reloadOnConflict = (err: unknown) => {
    if (getApiErrorStatus(err) === 409) refresh();
  };

  // ─── Create ────────────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState<SegmentFormState>(EMPTY_SEGMENT_FORM);
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: networkService.createSegment,
    onSuccess: () => {
      refresh();
      setCreateOpen(false);
      setCreateForm(EMPTY_SEGMENT_FORM);
    },
    onError: (err: unknown) => {
      setCreateError(errorText(err, "Failed to create the segment."));
      reloadOnConflict(err);
    },
  });

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    const built = createSegmentBody(createForm);
    if (!built.ok) {
      setCreateError(built.error);
      return;
    }
    createMutation.mutate(built.body);
  }

  // ─── Edit (a replacement, conditional on the version read) ─────────────────
  const [editTarget, setEditTarget] = useState<NetworkSegment | null>(null);
  const [editForm, setEditForm] = useState<SegmentFormState>(EMPTY_SEGMENT_FORM);
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, body }: { id: string; body: ReplaceNetworkSegmentRequest }) =>
      networkService.replaceSegment(id, body),
    onSuccess: () => {
      refresh();
      setEditTarget(null);
    },
    onError: (err: unknown) => {
      setEditError(errorText(err, "Failed to update the segment."));
      reloadOnConflict(err);
    },
  });

  function openEdit(segment: NetworkSegment) {
    setEditTarget(segment);
    setEditForm(segmentFormFrom(segment));
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editTarget) return;
    // The version the form was opened from, so an edit overtaken by another
    // administrator is a 409 and not a silent overwrite (§36.3 rule 2).
    const built = replaceSegmentBody(editForm, editTarget.version);
    if (!built.ok) {
      setEditError(built.error);
      return;
    }
    editMutation.mutate({ id: editTarget.id, body: built.body });
  }

  // ─── Delete (`?version=`) ──────────────────────────────────────────────────
  const [deleteTarget, setDeleteTarget] = useState<NetworkSegment | null>(null);
  const [deleteError, setDeleteError] = useState("");

  const deleteMutation = useMutation({
    mutationFn: (segment: NetworkSegment) =>
      networkService.deleteSegment(segment.id, segment.version),
    onSuccess: () => {
      refresh();
      setDeleteTarget(null);
    },
    onError: (err: unknown) => {
      setDeleteError(errorText(err, "Failed to delete the segment."));
      reloadOnConflict(err);
    },
  });

  // ─── Reply profile ─────────────────────────────────────────────────────────
  const [profileTarget, setProfileTarget] = useState<NetworkSegment | null>(null);

  // ─── Columns ───────────────────────────────────────────────────────────────
  const columns: Column<NetworkSegment>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <div className="max-w-[260px]">
          <span className="font-medium text-foreground/90 text-sm block truncate">
            {row.name}
          </span>
          <span className="text-xs text-muted-foreground block truncate" title={row.path}>
            {row.path}
          </span>
        </div>
      ),
    },
    {
      key: "vlan",
      header: "VLAN",
      render: (row) => <span className="text-sm text-foreground/80">{row.vlan_id}</span>,
    },
    {
      key: "rank",
      header: "Rank",
      render: (row) => (
        <span className="text-sm text-foreground/80">{row.rank ?? "—"}</span>
      ),
    },
    {
      key: "filters",
      header: "Filter-Id names",
      render: (row) => (
        <span className="text-sm text-foreground/80 break-words">
          {row.filter_ids.length > 0 ? row.filter_ids.join(", ") : "—"}
        </span>
      ),
    },
    {
      key: "enabled",
      header: "Status",
      render: (row) => <StatusBadge status={row.enabled ? "active" : "inactive"} />,
    },
    {
      key: "version",
      header: "Version",
      render: (row) => <span className="text-sm text-muted-foreground">{row.version}</span>,
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-32",
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`Reply profile of ${row.name}`}
            title="Reply profile"
            onClick={() => setProfileTarget(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <FileSliders size={14} />
          </button>
          {canWriteSegments && (
            <>
              <button
                aria-label={`Edit segment ${row.name}`}
                onClick={() => openEdit(row)}
                className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
              >
                <Pencil size={14} />
              </button>
              <button
                aria-label={`Delete segment ${row.name}`}
                onClick={() => {
                  setDeleteError("");
                  setDeleteTarget(row);
                }}
                className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
              >
                <Trash2 size={14} />
              </button>
            </>
          )}
        </div>
      ),
    },
  ];

  const nothing = !segmentsQuery.isLoading && segments.length === 0;

  return (
    <div>
      <PageHeader
        title="Network access"
        description="Which network segment a device is placed on after EAP-TLS, and what the Access-Accept gives it. Who may be placed where is ordinary RBAC: a device's service account holds network:join on a segment, and quarantine is a deny of it."
        action={
          canWriteSegments ? (
            <Button
              onClick={() => {
                setCreateForm(EMPTY_SEGMENT_FORM);
                setCreateError("");
                setCreateOpen(true);
              }}
            >
              <Plus size={16} />
              New segment
            </Button>
          ) : undefined
        }
      />

      <PolicyPanel />

      <h2 className="text-base font-semibold text-foreground mb-3">Segments</h2>

      <SearchBox
        value={search}
        onChange={setSearch}
        noun="segments"
        className="mb-4 max-w-sm"
      />

      {segmentsQuery.isError && (
        <p role="alert" className="mb-4 text-sm text-destructive">
          {errorText(segmentsQuery.error, "The segments could not be loaded.")}
        </p>
      )}

      {segmentsQuery.isLoading && <DataTable columns={columns} data={[]} isLoading />}

      {nothing && !segmentsQuery.isError && (
        <DataTable
          columns={columns}
          data={[]}
          emptyMessage={
            debouncedSearch.trim()
              ? "No segments match your search."
              : "No network segments configured."
          }
        />
      )}

      {grouped.map(({ kind, groups }) =>
        groups.length === 0 ? null : (
          <section key={kind} aria-label={SEGMENT_KIND_LABELS[kind]} className="mb-8">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-primary/80 mb-1">
              {SEGMENT_KIND_LABELS[kind]}
            </h3>
            <p className="text-xs text-muted-foreground mb-3">
              {SEGMENT_KIND_BRANCH[kind]}
              {kind === "quarantine"
                ? " — used only when no access segment remains for the device, which a deny on the zones brings about."
                : " — the lowest rank among the segments a device may join wins."}
            </p>
            {groups.map((group) => (
              <div key={group.site} className="mb-4">
                <h4
                  className="text-sm font-medium text-foreground/90 mb-2"
                  data-testid={`site-${kind}-${group.site}`}
                >
                  Site {group.site}{" "}
                  <span className="text-xs text-muted-foreground">
                    {SEGMENT_KIND_BRANCH[kind]}/{group.site}
                  </span>
                </h4>
                <DataTable columns={columns} data={group.segments} />
              </div>
            ))}
          </section>
        ),
      )}

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          setCreateError("");
        }}
        title="New network segment"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
        error={createError}
        errorId="network-segment-create-error"
      >
        <SegmentFields
          idPrefix="ns"
          form={createForm}
          onChange={setCreateForm}
          fixedPlace={false}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editTarget !== null}
        onClose={() => setEditTarget(null)}
        title="Edit network segment"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
        error={editError}
        errorId="network-segment-edit-error"
      >
        <SegmentFields
          idPrefix="edit-ns"
          form={editForm}
          onChange={setEditForm}
          fixedPlace
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={() => deleteTarget && deleteMutation.mutate(deleteTarget)}
        title="Delete network segment"
        description={`Delete "${deleteTarget?.name}"? Its reply profile is deleted with it. Role assignments and grants that name the segment are not touched; the segment is simply gone.`}
        isLoading={deleteMutation.isPending}
        error={deleteError}
      />

      {profileTarget && (
        <ReplyProfileDialog
          segment={profileTarget}
          cap={cap}
          nodeName={nodeName}
          onClose={() => setProfileTarget(null)}
        />
      )}
    </div>
  );
}

import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Pencil, Plus, Trash2 } from "lucide-react";

import {
  DELIVERY_METHODS,
  DELIVERY_METHOD_LABELS,
  SSF_EVENT_TYPES,
  STREAM_STATUSES,
  STREAM_STATUS_HELP,
  SUBJECT_FORMATS,
  SUBJECT_FORMAT_LABELS,
  endpointMoveNeedsHeader,
  eventLabel,
  ssfStreamService,
  ssfStreamsPath,
  validateSsfStreamInput,
  type SsfDeliveryMethod,
  type SsfStream,
  type SsfStreamInput,
  type SsfStreamStatus,
  type SsfSubjectFormat,
} from "@/services/ssf";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { PaginationControls, SearchBox } from "@/components/ListToolbar";
import { usePaginatedList } from "@/hooks/usePaginatedList";
import { usePermissions } from "@/hooks/usePermissions";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { ToggleField } from "@/components/shared";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { formatDateTime } from "@/lib/utils";
import { getApiErrorMessage, getApiErrorStatus } from "@/lib/apiError";
import { useAuthStore } from "@/stores/auth";

const SELECT_CLASS =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40 disabled:opacity-50";

// ─── Form state ───────────────────────────────────────────────────────────────

interface FormState {
  receiverClientId: string;
  audience: string;
  description: string;
  deliveryMethod: SsfDeliveryMethod;
  endpointUrl: string;
  /** Write-only. Blank on edit; sent only when typed. */
  authorizationHeader: string;
  clearHeader: boolean;
  eventsAllowed: string[];
  subjectFormat: SsfSubjectFormat;
  status: SsfStreamStatus;
  statusReason: string;
}

const EMPTY_FORM: FormState = {
  receiverClientId: "",
  audience: "",
  description: "",
  deliveryMethod: "push",
  endpointUrl: "",
  authorizationHeader: "",
  clearHeader: false,
  eventsAllowed: SSF_EVENT_TYPES.map((e) => e.uri),
  subjectFormat: "iss_sub",
  status: "enabled",
  statusReason: "",
};

function isKnown<T extends string>(all: readonly T[], value: string): value is T {
  return (all as readonly string[]).includes(value);
}

/** A stored stream as form state — the header is never part of it. */
function formFrom(stream: SsfStream): FormState {
  return {
    receiverClientId: stream.receiver_client_id,
    audience: stream.audience,
    description: stream.description ?? "",
    deliveryMethod: isKnown(DELIVERY_METHODS, stream.delivery_method)
      ? stream.delivery_method
      : "push",
    endpointUrl: stream.endpoint_url ?? "",
    authorizationHeader: "",
    clearHeader: false,
    eventsAllowed: stream.events_allowed,
    subjectFormat: isKnown(SUBJECT_FORMATS, stream.subject_format)
      ? stream.subject_format
      : "iss_sub",
    status: isKnown(STREAM_STATUSES, stream.status) ? stream.status : "enabled",
    statusReason: stream.status_reason ?? "",
  };
}

/**
 * The replacement body for a form.
 *
 * `events_requested` is what the *receiver* narrowed to, and a replacement that
 * omitted it would put it back to "everything allowed", so an edit sends the
 * stored value cut to the new ceiling. A create omits it.
 */
function inputFrom(form: FormState, stored: SsfStream | null): SsfStreamInput {
  const push = form.deliveryMethod === "push";
  const requested = stored?.events_requested.filter((e) =>
    form.eventsAllowed.includes(e),
  );
  return {
    receiver_client_id: form.receiverClientId.trim(),
    audience: form.audience.trim(),
    description: form.description.trim() || null,
    delivery_method: form.deliveryMethod,
    ...(push ? { endpoint_url: form.endpointUrl.trim() } : {}),
    ...(push && form.authorizationHeader
      ? { authorization_header: form.authorizationHeader }
      : {}),
    ...(stored && push && form.clearHeader
      ? { clear_authorization_header: true }
      : {}),
    events_allowed: form.eventsAllowed,
    ...(requested && requested.length > 0 ? { events_requested: requested } : {}),
    subject_format: form.subjectFormat,
    status: form.status,
    status_reason: form.statusReason.trim() || null,
  };
}

// ─── Form fields ──────────────────────────────────────────────────────────────

interface StreamFieldsProps {
  idPrefix: string;
  form: FormState;
  onChange: (next: FormState) => void;
  /** The stored stream when editing. */
  stored: SsfStream | null;
}

function StreamFields({ idPrefix, form, onChange, stored }: StreamFieldsProps) {
  const set = (patch: Partial<FormState>) => onChange({ ...form, ...patch });
  const push = form.deliveryMethod === "push";
  const movesOrigin =
    stored !== null &&
    endpointMoveNeedsHeader(stored, {
      delivery_method: form.deliveryMethod,
      endpoint_url: form.endpointUrl.trim(),
      authorization_header: form.authorizationHeader,
      clear_authorization_header: form.clearHeader,
    });

  function toggleEvent(uri: string) {
    set({
      eventsAllowed: form.eventsAllowed.includes(uri)
        ? form.eventsAllowed.filter((e) => e !== uri)
        : [...form.eventsAllowed, uri],
    });
  }

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-receiver`}>Receiver client id *</Label>
        <Input
          id={`${idPrefix}-receiver`}
          value={form.receiverClientId}
          onChange={(e) => set({ receiverClientId: e.target.value })}
          autoComplete="off"
          required
        />
        <p className="text-xs text-muted-foreground">
          An OAuth2 client of this tenant with the client-credentials grant and
          the <code>ssf.manage</code> scope. It is the receiver&rsquo;s identity
          on the stream management API.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-audience`}>Audience *</Label>
        <Input
          id={`${idPrefix}-audience`}
          value={form.audience}
          onChange={(e) => set({ audience: e.target.value })}
          autoComplete="off"
          required
        />
        <p className="text-xs text-muted-foreground">
          The <code>aud</code> of every event sent. Unique across the whole
          deployment, not only this tenant.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-description`}>Description</Label>
        <Input
          id={`${idPrefix}-description`}
          value={form.description}
          onChange={(e) => set({ description: e.target.value })}
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-method`}>Delivery method</Label>
        <select
          id={`${idPrefix}-method`}
          value={form.deliveryMethod}
          onChange={(e) =>
            set({ deliveryMethod: e.target.value as SsfDeliveryMethod })
          }
          className={SELECT_CLASS}
        >
          {DELIVERY_METHODS.map((m) => (
            <option key={m} value={m}>
              {DELIVERY_METHOD_LABELS[m]}
            </option>
          ))}
        </select>
      </div>

      {push && (
        <>
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-endpoint`}>Push endpoint URL *</Label>
            <Input
              id={`${idPrefix}-endpoint`}
              type="url"
              value={form.endpointUrl}
              onChange={(e) => set({ endpointUrl: e.target.value })}
              placeholder="https://receiver.example.com/events"
              autoComplete="off"
            />
            <p className="text-xs text-muted-foreground">
              Must be https and a public address.
            </p>
          </div>

          {/* Write-only. Never pre-filled, never shown, never returned. */}
          <div className="space-y-2">
            <Label htmlFor={`${idPrefix}-header`}>
              Authorization header{movesOrigin ? " *" : ""}
            </Label>
            <Input
              id={`${idPrefix}-header`}
              type="password"
              value={form.authorizationHeader}
              onChange={(e) =>
                set({ authorizationHeader: e.target.value, clearHeader: false })
              }
              placeholder={
                stored?.authorization_header_set
                  ? "Leave blank to keep the stored header"
                  : ""
              }
              autoComplete="new-password"
            />
            <p className="text-xs text-muted-foreground">
              {stored?.authorization_header_set
                ? "Write-only: AXIAM never shows the stored header. "
                : "Write-only: stored encrypted and never shown again. "}
              Moving the push endpoint to another origin requires the header to
              be entered again (or cleared), so a credential never follows an
              endpoint somewhere it was not given for.
            </p>
            {movesOrigin && (
              <p role="alert" className="text-xs text-amber-400">
                This moves the endpoint to another origin: enter the
                authorization header again, or clear the stored one.
              </p>
            )}
            {stored?.authorization_header_set && (
              <ToggleField
                id={`${idPrefix}-clear-header`}
                label="Remove the stored authorization header"
                checked={form.clearHeader}
                onChange={(v) =>
                  set({
                    clearHeader: v,
                    authorizationHeader: v ? "" : form.authorizationHeader,
                  })
                }
              />
            )}
          </div>
        </>
      )}

      <div className="space-y-2">
        <Label>Events allowed *</Label>
        <div
          className="rounded-md border border-input bg-background/50 p-3 space-y-1"
          role="group"
          aria-label="Events allowed"
        >
          {SSF_EVENT_TYPES.map((event) => (
            <label
              key={event.uri}
              className="flex items-center gap-2.5 cursor-pointer text-sm text-foreground/80"
            >
              <input
                type="checkbox"
                checked={form.eventsAllowed.includes(event.uri)}
                onChange={() => toggleEvent(event.uri)}
                className="w-3.5 h-3.5 accent-cyan-400 cursor-pointer"
              />
              {event.label}
            </label>
          ))}
        </div>
        <p className="text-xs text-muted-foreground">
          The ceiling. The receiver may narrow what it asks for, never widen it.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-subject`}>Subject format</Label>
        <select
          id={`${idPrefix}-subject`}
          value={form.subjectFormat}
          onChange={(e) =>
            set({ subjectFormat: e.target.value as SsfSubjectFormat })
          }
          className={SELECT_CLASS}
        >
          {SUBJECT_FORMATS.map((f) => (
            <option key={f} value={f}>
              {SUBJECT_FORMAT_LABELS[f]}
            </option>
          ))}
        </select>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-status`}>Status</Label>
        <select
          id={`${idPrefix}-status`}
          value={form.status}
          onChange={(e) => set({ status: e.target.value as SsfStreamStatus })}
          className={SELECT_CLASS}
        >
          {STREAM_STATUSES.map((s) => (
            <option key={s} value={s}>
              {s.charAt(0).toUpperCase() + s.slice(1)}
            </option>
          ))}
        </select>
        <p className="text-xs text-muted-foreground">
          {STREAM_STATUS_HELP[form.status]} A status you set to anything but
          enabled cannot be changed by the receiver.
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor={`${idPrefix}-reason`}>Status reason</Label>
        <Input
          id={`${idPrefix}-reason`}
          value={form.statusReason}
          onChange={(e) => set({ statusReason: e.target.value })}
          autoComplete="off"
        />
      </div>
    </>
  );
}

// ─── Cells ────────────────────────────────────────────────────────────────────

function EventNames({ label, events }: { label: string; events: string[] }) {
  return (
    <p className="text-xs text-muted-foreground">
      <span className="font-medium text-foreground/80">{label}:</span>{" "}
      {events.length > 0 ? events.map(eventLabel).join(", ") : "none"}
    </p>
  );
}

function StatusCell({ stream }: { stream: SsfStream }) {
  const live = stream.status === "enabled" && stream.transmitter_active;
  return (
    <div className="space-y-1">
      <Badge variant={live ? "default" : "secondary"}>{stream.status}</Badge>
      <p className="text-xs text-muted-foreground">
        Set by {stream.status_actor}
        {stream.status_reason ? `: ${stream.status_reason}` : ""}
      </p>
      {stream.status === "enabled" && !stream.transmitter_active && (
        <p className="text-xs text-amber-400">Carries nothing: transmitter off</p>
      )}
    </div>
  );
}

// ─── Main page ────────────────────────────────────────────────────────────────

type Notice = { kind: "ok" | "error"; text: string };

export function SsfStreamsPage() {
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can("ssf_streams:write");
  const tenantId = useAuthStore((s) => s.user?.tenant_id);

  const {
    items: streams,
    isLoading,
    search,
    setSearch,
    page,
    totalPages,
    total,
    setPage,
    isFiltered,
  } = usePaginatedList<SsfStream>(
    ["ssf-streams", tenantId],
    ssfStreamsPath(tenantId ?? ""),
    { enabled: !!tenantId },
  );

  const refresh = () =>
    void queryClient.invalidateQueries({ queryKey: ["ssf-streams"] });

  const [notice, setNotice] = useState<Notice | null>(null);

  // The transmitter's state is the tenant's, so any row says it.
  const inactive = streams.find((s) => !s.transmitter_active);

  // ─── Create ────────────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createForm, setCreateForm] = useState<FormState>(EMPTY_FORM);
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: SsfStreamInput) =>
      ssfStreamService.create(tenantId ?? "", payload),
    onSuccess: () => {
      refresh();
      setCreateOpen(false);
      setCreateForm(EMPTY_FORM);
    },
    onError: (err: unknown) =>
      setCreateError(
        getApiErrorMessage(err, "Failed to register the stream."),
      ),
  });

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    const payload = inputFrom(createForm, null);
    const problem = validateSsfStreamInput(payload);
    if (problem) {
      setCreateError(problem);
      return;
    }
    createMutation.mutate(payload);
  }

  // ─── Edit ──────────────────────────────────────────────────────────────────
  const [editStream, setEditStream] = useState<SsfStream | null>(null);
  const [editForm, setEditForm] = useState<FormState>(EMPTY_FORM);
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: SsfStreamInput }) =>
      ssfStreamService.update(tenantId ?? "", id, payload),
    onSuccess: () => {
      refresh();
      setEditStream(null);
    },
    onError: (err: unknown) => {
      const message = getApiErrorMessage(err, "Failed to update the stream.");
      // T-406: the write is conditional on the version the server read, so a
      // `409` that is not about the audience means the stream changed under
      // the form (its receiver, or another administrator). The form's values
      // are stale: reload the list and say so, rather than offer a retry that
      // would be judged against a stream the administrator has not seen.
      if (getApiErrorStatus(err) === 409 && !/audience/i.test(message)) {
        refresh();
        setEditStream(null);
        setNotice({
          kind: "error",
          text: "This stream changed since you opened it (its receiver or another administrator wrote it). The list has been reloaded; check the current values and make your change again.",
        });
        return;
      }
      setEditError(message);
    },
  });

  function openEdit(stream: SsfStream) {
    setNotice(null);
    setEditStream(stream);
    setEditForm(formFrom(stream));
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editStream) return;
    const payload = inputFrom(editForm, editStream);
    if (endpointMoveNeedsHeader(editStream, payload)) {
      setEditError(
        "Moving the push endpoint to another origin requires the authorization header to be entered again (or cleared).",
      );
      return;
    }
    const problem = validateSsfStreamInput(payload);
    if (problem) {
      setEditError(problem);
      return;
    }
    editMutation.mutate({ id: editStream.id, payload });
  }

  // ─── Delete ────────────────────────────────────────────────────────────────
  const [deleteStream, setDeleteStream] = useState<SsfStream | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => ssfStreamService.remove(tenantId ?? "", id),
    onSuccess: () => {
      refresh();
      setDeleteStream(null);
    },
    onError: (err: unknown) => {
      setDeleteStream(null);
      setNotice({
        kind: "error",
        text: getApiErrorMessage(err, "Failed to delete the stream."),
      });
    },
  });

  // ─── Columns ───────────────────────────────────────────────────────────────
  const columns: Column<SsfStream>[] = [
    {
      key: "receiver",
      header: "Receiver",
      render: (row) => (
        <div className="max-w-[240px]">
          <span className="font-medium text-foreground/90 text-sm block truncate">
            {row.receiver_client_id}
          </span>
          {row.description && (
            <span className="text-xs text-muted-foreground block truncate">
              {row.description}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "audience",
      header: "Audience",
      render: (row) => (
        <span
          className="text-sm text-foreground/80 block max-w-[220px] truncate"
          title={row.audience}
        >
          {row.audience}
        </span>
      ),
    },
    {
      key: "delivery",
      header: "Delivery",
      render: (row) => (
        <div className="max-w-[260px]">
          <span className="text-sm text-foreground/80 block">
            {isKnown(DELIVERY_METHODS, row.delivery_method)
              ? DELIVERY_METHOD_LABELS[row.delivery_method]
              : row.delivery_method}
          </span>
          {row.endpoint_url && (
            <span
              className="text-xs text-muted-foreground block truncate"
              title={row.endpoint_url}
            >
              {row.endpoint_url}
            </span>
          )}
          {row.delivery_method === "push" && (
            <span className="text-xs text-muted-foreground block">
              {row.authorization_header_set
                ? "Authorization header stored"
                : "No authorization header"}
            </span>
          )}
        </div>
      ),
    },
    {
      key: "events",
      header: "Events",
      render: (row) => (
        <div className="max-w-[320px] space-y-0.5">
          <EventNames label="Delivered" events={row.events_delivered} />
          <EventNames label="Allowed" events={row.events_allowed} />
        </div>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusCell stream={row} />,
    },
    {
      key: "updated",
      header: "Updated",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {formatDateTime(row.updated_at)}
        </span>
      ),
    },
    ...(canWrite
      ? [
          {
            key: "actions",
            header: "Actions",
            width: "w-24",
            render: (row: SsfStream) => (
              <div className="flex items-center gap-1">
                <button
                  aria-label={`Edit SSF stream ${row.receiver_client_id}`}
                  onClick={() => openEdit(row)}
                  className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
                >
                  <Pencil size={14} />
                </button>
                <button
                  aria-label={`Delete SSF stream ${row.receiver_client_id}`}
                  onClick={() => setDeleteStream(row)}
                  className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
                >
                  <Trash2 size={14} />
                </button>
              </div>
            ),
          } satisfies Column<SsfStream>,
        ]
      : []),
  ];

  return (
    <div>
      <PageHeader
        title="SSF streams"
        description="The third parties that receive security events about this tenant's users: session revocations, credential changes and account state, sent as Shared Signals Framework events."
        action={
          canWrite ? (
            <Button
              onClick={() => {
                setNotice(null);
                setCreateForm(EMPTY_FORM);
                setCreateError("");
                setCreateOpen(true);
              }}
            >
              <Plus size={16} />
              New stream
            </Button>
          ) : undefined
        }
      />

      {inactive && (
        <div
          role="status"
          className="mb-4 rounded-md border border-amber-500/30 bg-amber-500/10 p-3 text-sm text-amber-400"
        >
          The SSF transmitter is not active for this tenant, so no stream below
          carries anything.{" "}
          {inactive.transmitter_inactive_reason ??
            "Turn on ssf_enabled in the organization and tenant settings."}{" "}
          <Link to="/settings" className="underline">
            Open settings
          </Link>
        </div>
      )}

      {notice && (
        <div
          role={notice.kind === "error" ? "alert" : "status"}
          className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
        >
          {notice.text}
        </div>
      )}

      <SearchBox
        value={search}
        onChange={setSearch}
        noun="SSF streams"
        className="mb-4 max-w-sm"
      />

      <DataTable
        columns={columns}
        data={streams}
        isLoading={isLoading}
        emptyMessage={
          isFiltered
            ? "No SSF streams match your search."
            : "No SSF streams registered."
        }
      />

      <PaginationControls
        page={page}
        totalPages={totalPages}
        total={total}
        onPageChange={setPage}
      />

      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          setCreateForm(EMPTY_FORM);
          setCreateError("");
        }}
        title="New SSF stream"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Register"
        error={createError}
        errorId="ssf-stream-create-error"
      >
        <StreamFields
          idPrefix="ssf"
          form={createForm}
          onChange={setCreateForm}
          stored={null}
        />
      </FormDialog>

      <FormDialog
        open={editStream !== null}
        onClose={() => setEditStream(null)}
        title="Edit SSF stream"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
        error={editError}
        errorId="ssf-stream-edit-error"
      >
        <StreamFields
          idPrefix="edit-ssf"
          form={editForm}
          onChange={setEditForm}
          stored={editStream}
        />
      </FormDialog>

      <ConfirmDialog
        open={deleteStream !== null}
        onClose={() => setDeleteStream(null)}
        onConfirm={() =>
          deleteStream && deleteMutation.mutate(deleteStream.id)
        }
        title="Delete SSF stream"
        description={`Delete the stream for "${deleteStream?.receiver_client_id}"? It stops receiving events at once and its buffered events are discarded. To stop events without losing the registration, set the status to disabled instead.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  networkService,
  NETWORK_HINTS,
  REPLY_DICTIONARY,
  SERVICE_TYPES,
  SERVICE_TYPE_LABELS,
  TERMINATION_ACTIONS,
  TERMINATION_ACTION_LABELS,
  type NetworkReplyProfile,
  type NetworkReplyProfileInput,
  type NetworkSegment,
  type TerminationAction,
  type ServiceType,
} from "@/services/network";
import { getApiErrorStatus } from "@/lib/apiError";
import { invalidateEntity } from "@/lib/queryInvalidation";
import { usePermissions } from "@/hooks/usePermissions";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { InfoRow } from "@/components/shared";
import {
  describeSeconds,
  emptyProfileForm,
  profileFormFrom,
  profileInputFrom,
  type ProfileFormState,
} from "./networkForm";
import { networkErrorMessage } from "./networkErrors";

const SELECT_CLASS =
  "w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40 disabled:opacity-50";

interface ReplyProfileDialogProps {
  /** The segment whose profile this is; `null` closes the dialog. */
  segment: NetworkSegment | null;
  /** The tenant's current cap, for the hint and the new-profile default. */
  cap: number;
  /** Turns a node id a `403` names into a path, when the page knows it. */
  nodeName: (resourceId: string) => string | undefined;
  onClose: () => void;
}

/** What the stored and the effective `Session-Timeout` are, said plainly. */
function EffectiveValues({ profile, cap }: { profile: NetworkReplyProfile; cap: number }) {
  return (
    <div className="rounded-md border border-white/10 bg-white/5 px-3 py-1">
      <InfoRow label="Dictionary">{profile.dictionary}</InfoRow>
      <InfoRow label="Session-Timeout (effective)">
        <span data-testid="profile-effective-timeout">
          {profile.session_timeout_secs} s
        </span>{" "}
        <span className="text-muted-foreground">
          ({describeSeconds(profile.session_timeout_secs)})
        </span>
      </InfoRow>
      <InfoRow label="Session-Timeout (stored)">
        {profile.session_timeout_clamped ? (
          <span data-testid="profile-stored-timeout">
            above the cap of {cap} s — the API returns the effective value only
          </span>
        ) : (
          <span data-testid="profile-stored-timeout">
            {profile.session_timeout_secs} s (the same: not clamped)
          </span>
        )}
      </InfoRow>
      <InfoRow label="Clamped">
        <span data-testid="profile-clamped">
          {profile.session_timeout_clamped ? "Yes" : "No"}
        </span>
      </InfoRow>
      <InfoRow label="Version">{profile.version}</InfoRow>
    </div>
  );
}

/**
 * A segment's reply profile: view, create, replace, delete.
 *
 * The editor offers only the closed dictionary's typed fields
 * (`axiam-radius-reply/1`): there is no way to name an attribute, a vendor
 * attribute or a VLAN here, because the profile record has no such member. The
 * server checks every value against the segment's envelope and the tenant cap
 * and its `400` / `403` is printed as it comes.
 */
export function ReplyProfileDialog({ segment, cap, nodeName, onClose }: ReplyProfileDialogProps) {
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can("network:profiles_write");
  const segmentId = segment?.id;

  const profile = useQuery({
    queryKey: ["network-profile", segmentId],
    queryFn: () => networkService.getProfile(segmentId as string),
    enabled: segmentId !== undefined,
    // The version a write names is read here: never serve it from a cache.
    staleTime: 0,
  });

  // A segment without a profile answers 404, which is an empty state, not a fault.
  const missing = profile.isError && getApiErrorStatus(profile.error) === 404;
  const stored = profile.data;

  const [form, setForm] = useState<ProfileFormState>(() => emptyProfileForm(cap));
  const [error, setError] = useState("");
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  // Fill the form from what was read, once per read. Derived during render
  // rather than in an effect: the form is state seeded from a fetched value, and
  // an effect would paint one frame of the previous values first. A refetch that
  // returns the same record keeps its identity (structural sharing), so typing is
  // never overwritten by a background refresh.
  const seedKey: NetworkReplyProfile | string | null =
    stored ?? (missing ? `no-profile:${cap}` : null);
  const [seededFrom, setSeededFrom] = useState<NetworkReplyProfile | string | null>(null);
  if (seedKey !== null && seedKey !== seededFrom) {
    setSeededFrom(seedKey);
    setForm(stored ? profileFormFrom(stored) : emptyProfileForm(cap));
    setError("");
  }

  const refresh = () => {
    invalidateEntity(queryClient, "network-profile");
  };

  const errorText = (err: unknown, fallback: string) =>
    networkErrorMessage(err, { fallback, nodeName });

  const save = useMutation({
    mutationFn: (input: NetworkReplyProfileInput) => {
      if (!segment) throw new Error("No segment.");
      return stored
        ? networkService.replaceProfile(segment.id, {
            version: stored.version,
            segment_version: segment.version,
            profile: input,
          })
        : networkService.createProfile({
            segment_id: segment.id,
            segment_version: segment.version,
            profile: input,
          });
    },
    onSuccess: () => {
      refresh();
      onClose();
    },
    onError: (err: unknown) => {
      setError(errorText(err, "Failed to save the reply profile."));
      // A 409 means someone wrote first; read again so a reopen starts fresh.
      if (getApiErrorStatus(err) === 409) refresh();
    },
  });

  const remove = useMutation({
    mutationFn: (version: number) => networkService.deleteProfile(segmentId as string, version),
    onSuccess: () => {
      refresh();
      setConfirmDelete(false);
      onClose();
    },
    onError: (err: unknown) => {
      setDeleteError(errorText(err, "Failed to delete the reply profile."));
      if (getApiErrorStatus(err) === 409) refresh();
    },
  });

  if (!segment) return null;

  const filterOptions = segment.filter_ids;
  // A filter the profile uses must stay selectable even if the segment no
  // longer lists it, so the form shows the truth and the server refuses.
  const filterChoices =
    form.filterId && !filterOptions.includes(form.filterId)
      ? [...filterOptions, form.filterId]
      : filterOptions;

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    const input = profileInputFrom(form);
    if (!input.ok) {
      setError(input.error);
      return;
    }
    save.mutate(input.body);
  }

  const set = (patch: Partial<ProfileFormState>) => setForm({ ...form, ...patch });
  const loading = profile.isLoading;
  const failed = profile.isError && !missing;

  return (
    <>
      <FormDialog
        open={!confirmDelete}
        onClose={onClose}
        title={`Reply profile: ${segment.name}`}
        onSubmit={handleSubmit}
        isLoading={save.isPending}
        submitLabel={stored ? "Save profile" : "Create profile"}
        error={error}
        errorId="network-profile-error"
        readOnly={!canWrite || loading || failed}
      >
        <p className="text-xs text-muted-foreground" data-testid="profile-segment-path">
          {segment.path} — VLAN {segment.vlan_id}. The VLAN is the segment&apos;s;
          a profile cannot name one.
        </p>

        {loading && <p className="text-sm text-muted-foreground">Loading the profile…</p>}
        {failed && (
          <p role="alert" className="text-sm text-destructive">
            {errorText(profile.error, "The reply profile could not be loaded.")}
          </p>
        )}
        {missing && (
          <p className="text-sm text-muted-foreground">
            This segment has no reply profile, so it is no placement candidate.
            {canWrite ? " Create one below." : ""}
          </p>
        )}

        {stored && <EffectiveValues profile={stored} cap={cap} />}

        {stored?.session_timeout_clamped && (
          <p role="status" className="text-xs text-amber-400">
            The stored Session-Timeout is above the tenant cap of {cap} s, so every
            read — and every decision — uses the cap. Saving this form stores the
            effective value shown in the field below; raising the cap instead
            restores the stored one.
          </p>
        )}

        {(stored || missing) && canWrite && (
          <>
            <div className="space-y-2">
              <Label htmlFor="np-session-timeout">Session-Timeout (seconds) *</Label>
              <Input
                id="np-session-timeout"
                inputMode="numeric"
                value={form.sessionTimeout}
                onChange={(e) => set({ sessionTimeout: e.target.value })}
                autoComplete="off"
              />
              <p className="text-xs text-muted-foreground">
                From {NETWORK_HINTS.sessionTimeoutFloorSecs} up to the tenant cap
                ({cap} s). Never 0.
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="np-idle-timeout">Idle-Timeout (seconds)</Label>
              <Input
                id="np-idle-timeout"
                inputMode="numeric"
                value={form.idleTimeout}
                onChange={(e) => set({ idleTimeout: e.target.value })}
                placeholder="optional"
                autoComplete="off"
              />
              <p className="text-xs text-muted-foreground">
                From {NETWORK_HINTS.idleTimeoutFloorSecs} up to the Session-Timeout.
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="np-termination">Termination-Action</Label>
              <select
                id="np-termination"
                value={form.terminationAction}
                onChange={(e) =>
                  set({ terminationAction: e.target.value as TerminationAction })
                }
                className={SELECT_CLASS}
              >
                {TERMINATION_ACTIONS.map((action) => (
                  <option key={action} value={action}>
                    {TERMINATION_ACTION_LABELS[action]}
                  </option>
                ))}
              </select>
            </div>

            <div className="space-y-2">
              <Label htmlFor="np-filter-id">Filter-Id</Label>
              <select
                id="np-filter-id"
                value={form.filterId}
                onChange={(e) => set({ filterId: e.target.value })}
                className={SELECT_CLASS}
              >
                <option value="">None</option>
                {filterChoices.map((name) => (
                  <option key={name} value={name}>
                    {name}
                  </option>
                ))}
              </select>
              <p className="text-xs text-muted-foreground">
                One of the segment&apos;s declared Filter-Id names
                {filterOptions.length === 0
                  ? " — this segment declares none; add some by editing the segment."
                  : "."}
              </p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="np-service-type">Service-Type</Label>
              <select
                id="np-service-type"
                value={form.serviceType}
                onChange={(e) => set({ serviceType: e.target.value as ServiceType | "" })}
                className={SELECT_CLASS}
              >
                <option value="">Not set</option>
                {SERVICE_TYPES.map((type) => (
                  <option key={type} value={type}>
                    {SERVICE_TYPE_LABELS[type]}
                  </option>
                ))}
              </select>
              <p className="text-xs text-muted-foreground">
                Only Framed-User is accepted: the administrative values would grant
                login to the access device and are refused.
              </p>
            </div>

            <p className="text-xs text-muted-foreground">
              Dictionary {REPLY_DICTIONARY}: these five attributes are the whole
              record. Writing it needs <code>network:profiles_write</code> and{" "}
              <code>network:grant</code> on the segment.
            </p>

            {stored && (
              <Button
                type="button"
                variant="destructive"
                size="sm"
                onClick={() => {
                  setDeleteError("");
                  setConfirmDelete(true);
                }}
              >
                Delete profile
              </Button>
            )}
          </>
        )}

        {stored && !canWrite && (
          <dl className="text-sm space-y-1">
            <div className="flex gap-2">
              <dt className="text-muted-foreground">Termination-Action:</dt>
              <dd>{stored.termination_action}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-muted-foreground">Idle-Timeout:</dt>
              <dd>{stored.idle_timeout_secs ?? "not set"}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-muted-foreground">Filter-Id:</dt>
              <dd>{stored.filter_id ?? "none"}</dd>
            </div>
            <div className="flex gap-2">
              <dt className="text-muted-foreground">Service-Type:</dt>
              <dd>{stored.service_type ?? "not set"}</dd>
            </div>
          </dl>
        )}
      </FormDialog>

      <ConfirmDialog
        open={confirmDelete}
        onClose={() => setConfirmDelete(false)}
        onConfirm={() => stored && remove.mutate(stored.version)}
        title="Delete reply profile"
        description={`Delete the reply profile of "${segment.name}"? The segment stays, but with no profile it is no placement candidate: devices that would land on it are rejected.`}
        isLoading={remove.isPending}
        error={deleteError}
      />
    </>
  );
}

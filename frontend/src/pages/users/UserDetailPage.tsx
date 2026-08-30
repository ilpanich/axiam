import { useState } from "react";
import { useParams } from "react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  userService,
  type MfaMethod,
  type UpdateUserPayload,
} from "@/services/users";
import { roleService } from "@/services/roles";
import {
  federationService,
  federationLinkService,
  type FederationLink,
} from "@/services/federation";
import { usePermissions } from "@/hooks/usePermissions";
import { FormDialog } from "@/components/FormDialog";
import { AssignRoleDialog } from "@/components/AssignRoleDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DataTable, type Column } from "@/components/DataTable";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, Trash2, ShieldX, Unlink } from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import { SectionCard, ToggleField } from "@/components/shared";
import { invalidateEntity } from "@/lib/queryInvalidation";

// ─── Info row ─────────────────────────────────────────────────────────────────
// NOTE: kept as a local copy — this InfoRow differs from components/shared.tsx's
// InfoRow (sm:items-center vs sm:items-start, sm:w-40 vs sm:w-36, no pt-0.5 on the
// label). Migrating would visibly change label alignment/width on this page, which
// violates this plan's behavior-preservation constraint (D-03). Left as a
// documented deviation for a future plan to reconcile intentionally.

function InfoRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-4 py-2 border-b border-white/5 last:border-0">
      <span className="text-xs font-medium uppercase tracking-wider text-muted-foreground sm:w-40 shrink-0">
        {label}
      </span>
      <span className="text-sm text-foreground/90">{children}</span>
    </div>
  );
}

// ─── Edit user form ───────────────────────────────────────────────────────────

interface EditFormProps {
  email: string;
  displayName: string;
  isActive: boolean;
  onEmailChange: (v: string) => void;
  onDisplayNameChange: (v: string) => void;
  onIsActiveChange: (v: boolean) => void;
}

function EditUserForm({
  email,
  displayName,
  isActive,
  onEmailChange,
  onDisplayNameChange,
  onIsActiveChange,
}: EditFormProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="detail-edit-email">Email *</Label>
        <Input
          id="detail-edit-email"
          type="email"
          value={email}
          onChange={(e) => onEmailChange(e.target.value)}
          required
        />
      </div>
      <div className="space-y-2">
        <Label htmlFor="detail-edit-display-name">Display Name</Label>
        <Input
          id="detail-edit-display-name"
          value={displayName}
          onChange={(e) => onDisplayNameChange(e.target.value)}
          placeholder="Alice Smith"
        />
      </div>
      <ToggleField
        id="detail-edit-is-active"
        label="Active"
        checked={isActive}
        onChange={onIsActiveChange}
      />
    </>
  );
}

// ─── MFA method type badge ────────────────────────────────────────────────────

function MethodTypeBadge({ type }: { type: "totp" | "webauthn" }) {
  const styles =
    type === "totp"
      ? "bg-cyan-500/15 text-cyan-400 border-cyan-500/30"
      : "bg-purple-500/15 text-purple-400 border-purple-500/30";
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border uppercase",
        styles
      )}
    >
      {type === "totp" ? "TOTP" : "WebAuthn"}
    </span>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function UserDetailPage() {
  const { userId } = useParams<{ userId: string }>();
  const queryClient = useQueryClient();
  const { can } = usePermissions();

  // ─── User query ───────────────────────────────────────────────────────────────
  const {
    data: user,
    isLoading: userLoading,
    error: userError,
  } = useQuery({
    queryKey: ["user", userId],
    queryFn: () => userService.get(userId!),
    enabled: !!userId,
  });

  // ─── MFA methods query ────────────────────────────────────────────────────────
  const { data: mfaMethods = [], isLoading: mfaLoading } = useQuery({
    queryKey: ["user-mfa", userId],
    queryFn: () => userService.listMfaMethods(userId!),
    enabled: !!userId,
  });

  // ─── Federation links ─────────────────────────────────────────────────────────
  const canListFederation = can("federation:list");
  const canUnlinkFederation = can("federation:delete");

  const { data: federationLinks = [], isLoading: federationLinksLoading } =
    useQuery({
      queryKey: ["user-federation-links", userId],
      queryFn: () => federationLinkService.listForUser(userId!),
      enabled: !!userId && canListFederation,
    });

  // Resolve `federation_config_id` to the provider's name. The link endpoint
  // returns the id only, and a bare UUID tells an operator nothing about which
  // IdP is on the other end.
  const { data: federationConfigs = [] } = useQuery({
    queryKey: ["federation-configs"],
    queryFn: federationService.getAll,
    enabled: canListFederation,
  });

  const [unlinkTarget, setUnlinkTarget] = useState<FederationLink | null>(null);

  const unlinkMutation = useMutation({
    mutationFn: (id: string) => federationLinkService.unlink(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({
        queryKey: ["user-federation-links", userId],
      });
      setUnlinkTarget(null);
    },
  });

  // ─── Edit state ───────────────────────────────────────────────────────────────
  const [editOpen, setEditOpen] = useState(false);
  const [editEmail, setEditEmail] = useState("");
  const [editDisplayName, setEditDisplayName] = useState("");
  const [editIsActive, setEditIsActive] = useState(true);
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: UpdateUserPayload }) =>
      userService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["user", userId] });
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setEditOpen(false);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update user."
      );
    },
  });

  function openEdit() {
    if (!user) return;
    setEditEmail(user.email);
    setEditDisplayName(user.display_name ?? "");
    setEditIsActive(user.status === "Active");
    setEditError("");
    setEditOpen(true);
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editEmail.trim()) {
      setEditError("Email is required.");
      return;
    }
    editMutation.mutate({
      id: userId!,
      payload: {
        email: editEmail.trim(),
        display_name: editDisplayName.trim() || undefined,
        status: editIsActive ? "Active" : "Inactive",
      },
    });
  }

  // ─── Delete MFA method state ──────────────────────────────────────────────────
  const [deleteMethod, setDeleteMethod] = useState<MfaMethod | null>(null);

  const deleteMethodMutation = useMutation({
    mutationFn: (methodId: string) =>
      userService.deleteMfaMethod(userId!, methodId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["user-mfa", userId] });
      void queryClient.invalidateQueries({ queryKey: ["user", userId] });
      setDeleteMethod(null);
    },
  });

  // ─── Reset MFA state ──────────────────────────────────────────────────────────
  const [resetMfaOpen, setResetMfaOpen] = useState(false);

  const resetMfaMutation = useMutation({
    mutationFn: () => userService.resetMfa(userId!),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["user-mfa", userId] });
      void queryClient.invalidateQueries({ queryKey: ["user", userId] });
      setResetMfaOpen(false);
    },
  });

  // ─── Role assignment state ────────────────────────────────────────────────────
  //
  // The dialog owns the role list, both scope pickers and the error; this page
  // only says who is being granted the role and what to refresh afterwards.
  const [assignRoleOpen, setAssignRoleOpen] = useState(false);

  // ─── MFA table columns ────────────────────────────────────────────────────────
  const mfaColumns: Column<MfaMethod>[] = [
    {
      key: "method_type",
      header: "Type",
      render: (row) => <MethodTypeBadge type={row.method_type} />,
    },
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="text-sm text-foreground/90">{row.name}</span>
      ),
    },
    {
      key: "created_at",
      header: "Registered",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {formatDate(row.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-20",
      render: (row) => (
        <button
          aria-label={`Remove ${row.name}`}
          onClick={() => setDeleteMethod(row)}
          className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
        >
          <Trash2 size={14} />
        </button>
      ),
    },
  ];

  const federationLinkColumns: Column<FederationLink>[] = [
    {
      key: "provider",
      header: "Provider",
      render: (row) => {
        const config = federationConfigs.find(
          (c) => c.id === row.federation_config_id
        );
        return (
          <span className="text-sm text-foreground/90">
            {/* The config may have been deleted out from under the link, so
                fall back to the raw id rather than rendering an empty cell. */}
            {config?.provider ?? row.federation_config_id}
          </span>
        );
      },
    },
    {
      key: "external_subject",
      header: "External Subject",
      render: (row) => (
        <span
          className="font-mono text-xs text-foreground/70 max-w-[220px] truncate block"
          title={row.external_subject}
        >
          {row.external_subject}
        </span>
      ),
    },
    {
      key: "external_email",
      header: "External Email",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.external_email ?? "—"}
        </span>
      ),
    },
    {
      key: "created_at",
      header: "Linked",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {formatDate(row.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-20",
      render: (row) =>
        canUnlinkFederation ? (
          <button
            aria-label={`Unlink federated identity ${row.external_subject}`}
            onClick={() => setUnlinkTarget(row)}
            className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
          >
            <Unlink size={14} />
          </button>
        ) : null,
    },
  ];

  // ─── Loading / error states ───────────────────────────────────────────────────
  if (userLoading) {
    return (
      <div className="flex items-center justify-center py-20">
        <Loader2 size={28} className="animate-spin text-primary/60" />
      </div>
    );
  }

  if (userError || !user) {
    return (
      <div className="glass-card text-center py-12 text-muted-foreground">
        User not found or failed to load.
      </div>
    );
  }

  return (
    <div className="max-w-4xl">
      {/* ── Section 1: User Info ── */}
      <SectionCard
        title="User Info"
        action={
          <Button size="sm" variant="ghost" onClick={openEdit}>
            Edit
          </Button>
        }
      >
        <InfoRow label="Username">{user.username}</InfoRow>
        <InfoRow label="Email">{user.email}</InfoRow>
        <InfoRow label="Display Name">
          {user.display_name ?? <span className="opacity-40">—</span>}
        </InfoRow>
        <InfoRow label="Status">
          <StatusBadge status={user.status === "Active" ? "active" : "inactive"} />
        </InfoRow>
        <InfoRow label="Email Verified">
          {user.email_verified ? (
            <span className="text-cyan-400">Verified</span>
          ) : (
            <span className="text-muted-foreground">Not verified</span>
          )}
        </InfoRow>
        <InfoRow label="MFA">
          {user.mfa_enabled ? (
            <span className="text-purple-400">Enabled</span>
          ) : (
            <span className="text-muted-foreground">Disabled</span>
          )}
        </InfoRow>
        <InfoRow label="Created">{formatDate(user.created_at)}</InfoRow>
        <InfoRow label="Updated">{formatDate(user.updated_at)}</InfoRow>
      </SectionCard>

      {/* ── Section 2: MFA Methods ── */}
      <SectionCard
        title="MFA Methods"
        action={
          <Button
            size="sm"
            variant="ghost"
            className="text-destructive hover:text-destructive"
            onClick={() => setResetMfaOpen(true)}
            disabled={mfaMethods.length === 0}
          >
            <ShieldX size={14} className="mr-1" />
            Reset MFA
          </Button>
        }
      >
        <DataTable
          columns={mfaColumns}
          data={mfaMethods}
          isLoading={mfaLoading}
          emptyMessage="No MFA methods registered."
        />
      </SectionCard>

      {/* ── Section 3: Federated Identities ──
          Which external IdP accounts can sign in as this user. Gated on
          federation:list, the same permission the endpoint enforces, so an
          operator without it sees no perpetually-failing panel. */}
      {canListFederation && (
        <SectionCard title="Federated Identities">
          <DataTable
            columns={federationLinkColumns}
            data={federationLinks}
            isLoading={federationLinksLoading}
            emptyMessage="No external identity provider is linked to this user."
          />
        </SectionCard>
      )}

      {/* ── Section 4: Role Assignments ── */}
      <SectionCard
        title="Role Assignments"
        action={
          <Button size="sm" onClick={() => setAssignRoleOpen(true)}>
            Assign Role
          </Button>
        }
      >
        <p className="text-sm text-muted-foreground">
          Use "Assign Role" above to grant this user a role, optionally confined
          to one resource or to particular tenants. The assignments a role
          already carries are listed on the{" "}
          <span className="text-primary">Roles</span> page.
        </p>
      </SectionCard>

      {/* Edit dialog */}
      <FormDialog
        open={editOpen}
        onClose={() => setEditOpen(false)}
        title="Edit User"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
        error={editError}
        errorId="user-detail-edit-error"
      >
        <EditUserForm
          email={editEmail}
          displayName={editDisplayName}
          isActive={editIsActive}
          onEmailChange={setEditEmail}
          onDisplayNameChange={setEditDisplayName}
          onIsActiveChange={setEditIsActive}
        />
      </FormDialog>

      {/* Delete MFA method confirm */}
      <ConfirmDialog
        open={deleteMethod !== null}
        onClose={() => setDeleteMethod(null)}
        onConfirm={() =>
          deleteMethod && deleteMethodMutation.mutate(deleteMethod.id)
        }
        title="Remove MFA Method"
        description={`Are you sure you want to remove "${deleteMethod?.name}"?`}
        isLoading={deleteMethodMutation.isPending}
      />

      {/* Unlink federated identity confirm */}
      <ConfirmDialog
        open={unlinkTarget !== null}
        onClose={() => setUnlinkTarget(null)}
        onConfirm={() =>
          unlinkTarget && unlinkMutation.mutate(unlinkTarget.id)
        }
        title="Unlink Federated Identity"
        description={`"${unlinkTarget?.external_subject}" will no longer be able to sign in as this user through that identity provider. A later federated login with the same subject will establish a fresh link.`}
        confirmLabel="Unlink"
        isLoading={unlinkMutation.isPending}
      />

      {/* Reset MFA confirm */}
      <ConfirmDialog
        open={resetMfaOpen}
        onClose={() => setResetMfaOpen(false)}
        onConfirm={() => resetMfaMutation.mutate()}
        title="Reset MFA"
        description="This will remove ALL MFA methods and reset the MFA state for this user. They will need to re-enroll. Are you sure?"
        isLoading={resetMfaMutation.isPending}
      />

      {/* Assign role dialog */}
      <AssignRoleDialog
        open={assignRoleOpen}
        onClose={() => setAssignRoleOpen(false)}
        subject="user"
        errorId="user-assign-role-error"
        onAssign={(roleId, resourceId, tenantScope) =>
          roleService.assignToUser(roleId, userId!, resourceId, tenantScope)
        }
        onAssigned={() => invalidateEntity(queryClient, "role-users")}
      />
    </div>
  );
}

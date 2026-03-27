import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  userService,
  type MfaMethod,
  type UpdateUserPayload,
} from "@/services/users";
import { roleService, type Role } from "@/services/roles";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DataTable, type Column } from "@/components/DataTable";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Loader2, Trash2, ShieldX } from "lucide-react";
import { cn } from "@/lib/utils";

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(iso));

// ─── Section card wrapper ─────────────────────────────────────────────────────

function SectionCard({
  title,
  action,
  children,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="glass-card mb-6">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-base font-semibold text-foreground">{title}</h2>
        {action}
      </div>
      {children}
    </div>
  );
}

// ─── Info row ─────────────────────────────────────────────────────────────────

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

// ─── Toggle field ─────────────────────────────────────────────────────────────

function ToggleField({
  id,
  label,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center gap-3">
      <input
        type="checkbox"
        id={id}
        checked={checked}
        onChange={(e) => onChange(e.target.checked)}
        className="w-4 h-4 accent-cyan-400 cursor-pointer"
      />
      <Label htmlFor={id} className="cursor-pointer">
        {label}
      </Label>
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
  error?: string;
}

function EditUserForm({
  email,
  displayName,
  isActive,
  onEmailChange,
  onDisplayNameChange,
  onIsActiveChange,
  error,
}: EditFormProps) {
  return (
    <>
      <div className="space-y-1.5">
        <Label htmlFor="detail-edit-email">Email *</Label>
        <Input
          id="detail-edit-email"
          type="email"
          value={email}
          onChange={(e) => onEmailChange(e.target.value)}
          required
        />
      </div>
      <div className="space-y-1.5">
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
      {error && <p className="text-sm text-destructive">{error}</p>}
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

  // ─── Roles query ──────────────────────────────────────────────────────────────
  const { data: allRoles = [] } = useQuery({
    queryKey: ["roles"],
    queryFn: roleService.list,
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
    setEditIsActive(user.is_active);
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
        is_active: editIsActive,
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
  const [assignRoleOpen, setAssignRoleOpen] = useState(false);
  const [selectedRoleId, setSelectedRoleId] = useState("");
  const [assignError, setAssignError] = useState("");

  const assignRoleMutation = useMutation({
    mutationFn: (roleId: string) => roleService.assignToUser(roleId, userId!),
    onSuccess: () => {
      setAssignRoleOpen(false);
      setSelectedRoleId("");
      setAssignError("");
    },
    onError: (err: unknown) => {
      setAssignError(
        err instanceof Error ? err.message : "Failed to assign role."
      );
    },
  });

  function handleAssignRoleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setAssignError("");
    if (!selectedRoleId) {
      setAssignError("Please select a role.");
      return;
    }
    assignRoleMutation.mutate(selectedRoleId);
  }

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
          <StatusBadge status={user.is_active ? "active" : "inactive"} />
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

      {/* ── Section 3: Role Assignments ── */}
      <SectionCard
        title="Role Assignments"
        action={
          <Button size="sm" onClick={() => setAssignRoleOpen(true)}>
            Assign Role
          </Button>
        }
      >
        <p className="text-sm text-muted-foreground">
          Role assignments are managed via the{" "}
          <span className="text-primary">Roles</span> page. Use "Assign Role"
          above to link a role to this user.
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
      >
        <EditUserForm
          email={editEmail}
          displayName={editDisplayName}
          isActive={editIsActive}
          onEmailChange={setEditEmail}
          onDisplayNameChange={setEditDisplayName}
          onIsActiveChange={setEditIsActive}
          error={editError}
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
      <FormDialog
        open={assignRoleOpen}
        onClose={() => {
          setAssignRoleOpen(false);
          setSelectedRoleId("");
          setAssignError("");
        }}
        title="Assign Role"
        onSubmit={handleAssignRoleSubmit}
        isLoading={assignRoleMutation.isPending}
        submitLabel="Assign"
      >
        <div className="space-y-1.5">
          <Label htmlFor="assign-role-select">Role</Label>
          {allRoles.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No roles available. Create roles in the Roles page first.
            </p>
          ) : (
            <select
              id="assign-role-select"
              value={selectedRoleId}
              onChange={(e) => setSelectedRoleId(e.target.value)}
              className={cn(
                "flex h-9 w-full rounded-md px-3 py-1 text-sm",
                "bg-white/5 border border-primary/20 text-foreground",
                "focus:outline-none focus:ring-2 focus:ring-primary/40 focus:border-primary",
                "transition-colors duration-200"
              )}
            >
              <option value="" disabled>
                Select a role…
              </option>
              {allRoles.map((role: Role) => (
                <option key={role.id} value={role.id}>
                  {role.name}
                </option>
              ))}
            </select>
          )}
        </div>
        {assignError && (
          <p className="text-sm text-destructive">{assignError}</p>
        )}
      </FormDialog>
    </div>
  );
}

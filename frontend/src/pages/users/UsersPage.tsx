import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  userService,
  type User,
  type CreateUserPayload,
  type UpdateUserPayload,
} from "@/services/users";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SearchInput } from "@/components/SearchInput";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Eye, Pencil, Plus, Trash2 } from "lucide-react";
import { cn } from "@/lib/utils";

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );

// ─── MFA Badge ────────────────────────────────────────────────────────────────

function MfaBadge({ enabled }: { enabled: boolean }) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border",
        enabled
          ? "bg-purple-500/15 text-purple-400 border-purple-500/30"
          : "bg-muted/40 text-muted-foreground border-border"
      )}
    >
      {enabled ? "Enabled" : "Disabled"}
    </span>
  );
}

// ─── Toggle field ─────────────────────────────────────────────────────────────

interface ToggleFieldProps {
  id: string;
  label: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}

function ToggleField({ id, label, checked, onChange }: ToggleFieldProps) {
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

// ─── Create form fields ───────────────────────────────────────────────────────

interface CreateUserFieldsProps {
  username: string;
  email: string;
  password: string;
  displayName: string;
  isActive: boolean;
  onUsernameChange: (v: string) => void;
  onEmailChange: (v: string) => void;
  onPasswordChange: (v: string) => void;
  onDisplayNameChange: (v: string) => void;
  onIsActiveChange: (v: boolean) => void;
  error?: string;
}

function CreateUserFields({
  username,
  email,
  password,
  displayName,
  isActive,
  onUsernameChange,
  onEmailChange,
  onPasswordChange,
  onDisplayNameChange,
  onIsActiveChange,
  error,
}: CreateUserFieldsProps) {
  return (
    <>
      <div className="space-y-1.5">
        <Label htmlFor="user-username">Username *</Label>
        <Input
          id="user-username"
          value={username}
          onChange={(e) => onUsernameChange(e.target.value)}
          placeholder="alice"
          required
          autoComplete="off"
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="user-email">Email *</Label>
        <Input
          id="user-email"
          type="email"
          value={email}
          onChange={(e) => onEmailChange(e.target.value)}
          placeholder="alice@example.com"
          required
          autoComplete="off"
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="user-password">Password *</Label>
        <Input
          id="user-password"
          type="password"
          value={password}
          onChange={(e) => onPasswordChange(e.target.value)}
          placeholder="••••••••"
          required
          autoComplete="new-password"
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="user-display-name">Display Name</Label>
        <Input
          id="user-display-name"
          value={displayName}
          onChange={(e) => onDisplayNameChange(e.target.value)}
          placeholder="Alice Smith"
          autoComplete="off"
        />
      </div>
      <ToggleField
        id="user-is-active"
        label="Active"
        checked={isActive}
        onChange={onIsActiveChange}
      />
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Edit form fields ─────────────────────────────────────────────────────────

interface EditUserFieldsProps {
  email: string;
  displayName: string;
  isActive: boolean;
  onEmailChange: (v: string) => void;
  onDisplayNameChange: (v: string) => void;
  onIsActiveChange: (v: boolean) => void;
  error?: string;
}

function EditUserFields({
  email,
  displayName,
  isActive,
  onEmailChange,
  onDisplayNameChange,
  onIsActiveChange,
  error,
}: EditUserFieldsProps) {
  return (
    <>
      <div className="space-y-1.5">
        <Label htmlFor="edit-user-email">Email *</Label>
        <Input
          id="edit-user-email"
          type="email"
          value={email}
          onChange={(e) => onEmailChange(e.target.value)}
          placeholder="alice@example.com"
          required
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="edit-user-display-name">Display Name</Label>
        <Input
          id="edit-user-display-name"
          value={displayName}
          onChange={(e) => onDisplayNameChange(e.target.value)}
          placeholder="Alice Smith"
        />
      </div>
      <ToggleField
        id="edit-user-is-active"
        label="Active"
        checked={isActive}
        onChange={onIsActiveChange}
      />
      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function UsersPage() {
  const navigate = useNavigate();
  const queryClient = useQueryClient();

  // ─── Pagination + search state ───────────────────────────────────────────────
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");

  const { data, isLoading } = useQuery({
    queryKey: ["users", page, search],
    queryFn: () => userService.list(page, 20, search),
  });

  const users = data?.data ?? [];
  const total = data?.total ?? 0;
  const perPage = data?.per_page ?? 20;
  const totalPages = Math.max(1, Math.ceil(total / perPage));

  function handleSearchChange(value: string) {
    setSearch(value);
    setPage(1);
  }

  // ─── Create state ─────────────────────────────────────────────────────────────
  const [createOpen, setCreateOpen] = useState(false);
  const [createUsername, setCreateUsername] = useState("");
  const [createEmail, setCreateEmail] = useState("");
  const [createPassword, setCreatePassword] = useState("");
  const [createDisplayName, setCreateDisplayName] = useState("");
  const [createIsActive, setCreateIsActive] = useState(true);
  const [createError, setCreateError] = useState("");

  const createMutation = useMutation({
    mutationFn: (payload: CreateUserPayload) => userService.create(payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setCreateOpen(false);
      resetCreateForm();
    },
    onError: (err: unknown) => {
      setCreateError(
        err instanceof Error ? err.message : "Failed to create user."
      );
    },
  });

  function resetCreateForm() {
    setCreateUsername("");
    setCreateEmail("");
    setCreatePassword("");
    setCreateDisplayName("");
    setCreateIsActive(true);
    setCreateError("");
  }

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    if (!createUsername.trim() || !createEmail.trim() || !createPassword) {
      setCreateError("Username, email, and password are required.");
      return;
    }
    createMutation.mutate({
      username: createUsername.trim(),
      email: createEmail.trim(),
      password: createPassword,
      display_name: createDisplayName.trim() || undefined,
      is_active: createIsActive,
    });
  }

  // ─── Edit state ───────────────────────────────────────────────────────────────
  const [editUser, setEditUser] = useState<User | null>(null);
  const [editEmail, setEditEmail] = useState("");
  const [editDisplayName, setEditDisplayName] = useState("");
  const [editIsActive, setEditIsActive] = useState(true);
  const [editError, setEditError] = useState("");

  const editMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: UpdateUserPayload }) =>
      userService.update(id, payload),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setEditUser(null);
    },
    onError: (err: unknown) => {
      setEditError(
        err instanceof Error ? err.message : "Failed to update user."
      );
    },
  });

  function openEdit(user: User) {
    setEditUser(user);
    setEditEmail(user.email);
    setEditDisplayName(user.display_name ?? "");
    setEditIsActive(user.is_active);
    setEditError("");
  }

  function handleEditSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setEditError("");
    if (!editUser || !editEmail.trim()) {
      setEditError("Email is required.");
      return;
    }
    editMutation.mutate({
      id: editUser.id,
      payload: {
        email: editEmail.trim(),
        display_name: editDisplayName.trim() || undefined,
        is_active: editIsActive,
      },
    });
  }

  // ─── Delete state ─────────────────────────────────────────────────────────────
  const [deleteUser, setDeleteUser] = useState<User | null>(null);

  const deleteMutation = useMutation({
    mutationFn: (id: string) => userService.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["users"] });
      setDeleteUser(null);
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────────
  const columns: Column<User>[] = [
    {
      key: "display_name",
      header: "Display Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">
          {row.display_name ?? row.username}
        </span>
      ),
    },
    {
      key: "username",
      header: "Username",
      render: (row) => (
        <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-muted-foreground">
          {row.username}
        </code>
      ),
    },
    {
      key: "email",
      header: "Email",
      render: (row) => (
        <span className="text-muted-foreground text-sm">{row.email}</span>
      ),
    },
    {
      key: "is_active",
      header: "Status",
      render: (row) => (
        <StatusBadge status={row.is_active ? "active" : "inactive"} />
      ),
    },
    {
      key: "mfa_enabled",
      header: "MFA",
      render: (row) => <MfaBadge enabled={row.mfa_enabled} />,
    },
    {
      key: "email_verified",
      header: "Verified",
      render: (row) =>
        row.email_verified ? (
          <span className="text-cyan-400 text-sm" aria-label="Email verified">
            ✓
          </span>
        ) : (
          <span
            className="text-muted-foreground text-sm"
            aria-label="Email not verified"
          >
            —
          </span>
        ),
    },
    {
      key: "created_at",
      header: "Created",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {formatDate(row.created_at)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-28",
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`Edit ${row.username}`}
            onClick={() => openEdit(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Pencil size={14} />
          </button>
          <button
            aria-label={`View ${row.username}`}
            onClick={() => navigate(`/users/${row.id}`)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
          >
            <Eye size={14} />
          </button>
          <button
            aria-label={`Delete ${row.username}`}
            onClick={() => setDeleteUser(row)}
            className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
          >
            <Trash2 size={14} />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Users"
        description="Manage user accounts, credentials, and MFA settings."
        action={
          <Button
            onClick={() => {
              resetCreateForm();
              setCreateOpen(true);
            }}
          >
            <Plus size={16} />
            New User
          </Button>
        }
      />

      {/* Search */}
      <div className="mb-4">
        <SearchInput
          value={search}
          onChange={handleSearchChange}
          placeholder="Search users…"
          className="max-w-sm"
        />
      </div>

      <DataTable
        columns={columns}
        data={users}
        isLoading={isLoading}
        emptyMessage="No users found."
      />

      {/* Pagination */}
      <div className="flex items-center justify-between mt-4 text-sm text-muted-foreground">
        <span>
          Page {page} of {totalPages}
        </span>
        <div className="flex gap-2">
          <Button
            variant="ghost"
            size="sm"
            disabled={page <= 1}
            onClick={() => setPage((p) => Math.max(1, p - 1))}
          >
            Previous
          </Button>
          <Button
            variant="ghost"
            size="sm"
            disabled={page >= totalPages}
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
          >
            Next
          </Button>
        </div>
      </div>

      {/* Create dialog */}
      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreateForm();
        }}
        title="New User"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
      >
        <CreateUserFields
          username={createUsername}
          email={createEmail}
          password={createPassword}
          displayName={createDisplayName}
          isActive={createIsActive}
          onUsernameChange={setCreateUsername}
          onEmailChange={setCreateEmail}
          onPasswordChange={setCreatePassword}
          onDisplayNameChange={setCreateDisplayName}
          onIsActiveChange={setCreateIsActive}
          error={createError}
        />
      </FormDialog>

      {/* Edit dialog */}
      <FormDialog
        open={editUser !== null}
        onClose={() => setEditUser(null)}
        title="Edit User"
        onSubmit={handleEditSubmit}
        isLoading={editMutation.isPending}
        submitLabel="Save Changes"
      >
        <EditUserFields
          email={editEmail}
          displayName={editDisplayName}
          isActive={editIsActive}
          onEmailChange={setEditEmail}
          onDisplayNameChange={setEditDisplayName}
          onIsActiveChange={setEditIsActive}
          error={editError}
        />
      </FormDialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={deleteUser !== null}
        onClose={() => setDeleteUser(null)}
        onConfirm={() => deleteUser && deleteMutation.mutate(deleteUser.id)}
        title="Delete User"
        description={`Are you sure you want to delete "${deleteUser?.username}"? This action cannot be undone.`}
        isLoading={deleteMutation.isPending}
      />
    </div>
  );
}

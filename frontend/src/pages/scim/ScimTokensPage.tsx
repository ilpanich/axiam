import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import {
  scimTokenService,
  DEFAULT_MAX_LIFETIME_DAYS,
  type ScimToken,
  type ScimTokenStatus,
  type CreateScimTokenPayload,
} from "@/services/scimTokens";
import { userService, type User } from "@/services/users";
import { usePermissions } from "@/hooks/usePermissions";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { SecretRevealModal } from "@/components/SecretRevealModal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { getApiErrorMessage, redactSecrets } from "@/lib/apiError";
import { cn, formatDate, formatDateTime } from "@/lib/utils";

// ─── Status badge ─────────────────────────────────────────────────────────────

const STATUS_STYLES: Record<ScimTokenStatus, string> = {
  active: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  expired: "bg-amber-500/15 text-amber-400 border-amber-500/30",
  revoked: "bg-red-500/15 text-red-400 border-red-500/30",
};

function StatusPill({ status }: { status: ScimTokenStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium border capitalize",
        STATUS_STYLES[status] ?? STATUS_STYLES.expired
      )}
    >
      {status}
    </span>
  );
}

/**
 * Prefer the backend's `message` over its `error` field.
 *
 * AXIAM's `ErrorBody` carries a machine code in `error` ("validation_error")
 * and the human sentence in `message`, but the shared `getApiErrorMessage`
 * reads `error` first — so on this page it would show "validation_error" in
 * place of the one refusal that actually tells an operator what to do ("the
 * named user does not hold scim:provision… Grant the permission first").
 *
 * Localized rather than fixed in the shared helper because that helper backs
 * 38 other call sites and changing which field wins is a UX change across all
 * of them, not a SCIM concern. Worth doing separately.
 */
function createErrorMessage(err: unknown): string {
  const message = (
    err as { response?: { data?: { message?: unknown } } }
  )?.response?.data?.message;
  // redactSecrets, not the raw value: reading `data.message` directly is what
  // bypasses `getApiErrorMessage`, and with it the redaction — on the one page
  // whose whole subject is a live credential. The preference for `message`
  // over `error` is the only thing this helper is allowed to change.
  return typeof message === "string" && message.length > 0
    ? redactSecrets(message)
    : getApiErrorMessage(err);
}

// ─── Page ─────────────────────────────────────────────────────────────────────

/**
 * Manages the long-lived credential an IdP pastes into its SCIM connector.
 *
 * See `claude_dev/scim-provisioning-token-design.md`. The property that shapes
 * this page: a token carries no permissions of its own — it authenticates as a
 * tenant user, and that user's `scim:provision` grant is what it can do. So
 * the list shows which user each token speaks for, and revoking a role is as
 * effective as revoking a token.
 */
export function ScimTokensPage() {
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canCreate = can("scim_tokens:create");
  const canRevoke = can("scim_tokens:revoke");

  const { data: tokens = [], isLoading } = useQuery({
    queryKey: ["scim-tokens"],
    queryFn: () => scimTokenService.list(),
  });

  // Only fetched when the create dialog opens — an operator who never mints a
  // token should not pay for a user list.
  const [createOpen, setCreateOpen] = useState(false);
  // A generous page: the provisioner is one specific non-interactive account,
  // and paginating a picker the operator uses once per IdP would cost more
  // than it saves. The server caps `limit` at 200 regardless.
  const { data: userPage } = useQuery({
    queryKey: ["users", "scim-token-picker"],
    queryFn: () => userService.list(1, 200),
    enabled: createOpen,
  });
  const users: User[] = userPage?.items ?? [];

  const [name, setName] = useState("");
  const [userId, setUserId] = useState("");
  const [expiresInDays, setExpiresInDays] = useState(
    String(DEFAULT_MAX_LIFETIME_DAYS)
  );
  const [createError, setCreateError] = useState("");

  const [revealOpen, setRevealOpen] = useState(false);
  const [revealed, setRevealed] = useState("");

  function resetCreate() {
    setName("");
    setUserId("");
    setExpiresInDays(String(DEFAULT_MAX_LIFETIME_DAYS));
    setCreateError("");
  }

  const createMutation = useMutation({
    mutationFn: (payload: CreateScimTokenPayload) =>
      scimTokenService.create(payload),
    onSuccess: (resp) => {
      void queryClient.invalidateQueries({ queryKey: ["scim-tokens"] });
      setCreateOpen(false);
      resetCreate();
      setRevealed(resp.provisioning_token);
      setRevealOpen(true);
    },
    // The server's refusal for a user without scim:provision names the missing
    // permission and what to do about it, so it is surfaced verbatim rather
    // than replaced with a generic failure message.
    onError: (err: unknown) => setCreateError(createErrorMessage(err)),
  });

  function handleCreateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCreateError("");
    if (!name.trim()) {
      setCreateError("Name is required.");
      return;
    }
    if (!userId) {
      setCreateError("Select the user this token will authenticate as.");
      return;
    }
    const days = Number.parseInt(expiresInDays, 10);
    if (!(days > 0)) {
      setCreateError("Expiry must be a positive number of days.");
      return;
    }
    createMutation.mutate({
      name: name.trim(),
      user_id: userId,
      expires_in_days: days,
    });
  }

  const [revokeTarget, setRevokeTarget] = useState<ScimToken | null>(null);

  const revokeMutation = useMutation({
    mutationFn: (id: string) => scimTokenService.revoke(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["scim-tokens"] });
      setRevokeTarget(null);
    },
  });

  function userLabel(id: string): string {
    const u = users.find((x: User) => x.id === id);
    return u?.username ?? id;
  }

  const columns: Column<ScimToken>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.name}</span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusPill status={row.status} />,
    },
    {
      key: "user_id",
      header: "Authenticates As",
      render: (row) => (
        <span
          className="font-mono text-xs text-foreground/70 max-w-[200px] truncate block"
          title={row.user_id}
        >
          {userLabel(row.user_id)}
        </span>
      ),
    },
    {
      key: "expires_at",
      header: "Expires",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {formatDate(row.expires_at)}
        </span>
      ),
    },
    {
      key: "last_used_at",
      header: "Last Used",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {row.last_used_at ? formatDateTime(row.last_used_at) : "Never"}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-20",
      render: (row) =>
        // A revoked token has nothing left to revoke; an expired one is
        // already inert. Offering the action anyway would be a button whose
        // only outcome is a no-op.
        canRevoke && row.status === "active" ? (
          <button
            aria-label={`Revoke ${row.name}`}
            onClick={() => setRevokeTarget(row)}
            className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors"
          >
            <Trash2 size={14} />
          </button>
        ) : null,
    },
  ];

  return (
    <div>
      <PageHeader
        title="SCIM Provisioning"
        description="Long-lived tokens for an external identity provider's SCIM connector. Each one authenticates as a tenant user and inherits that user's permissions."
        action={
          canCreate ? (
            <Button
              onClick={() => {
                resetCreate();
                setCreateOpen(true);
              }}
            >
              <Plus size={16} />
              New Token
            </Button>
          ) : undefined
        }
      />

      <div
        role="note"
        className="mb-4 rounded-md border border-primary/20 bg-primary/5 px-3 py-2.5 text-xs text-muted-foreground"
      >
        Point your IdP's SCIM connector at{" "}
        <code className="text-foreground/80">
          {window.location.origin}/scim/v2
        </code>{" "}
        and paste the token into its bearer-token field (Okta: "HTTP Header"
        auth mode; Entra: "Secret Token"). A token stops working the moment its
        bound user is deactivated or loses <code>scim:provision</code> — you do
        not have to revoke it separately.
      </div>

      <DataTable
        columns={columns}
        data={tokens}
        isLoading={isLoading}
        emptyMessage="No provisioning tokens yet."
      />

      <FormDialog
        open={createOpen}
        onClose={() => {
          setCreateOpen(false);
          resetCreate();
        }}
        title="New Provisioning Token"
        onSubmit={handleCreateSubmit}
        isLoading={createMutation.isPending}
        submitLabel="Create"
        error={createError}
        errorId="scim-token-create-error"
      >
        <div className="space-y-2">
          <Label htmlFor="scim-token-name">Name *</Label>
          <Input
            id="scim-token-name"
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="okta-production"
            autoComplete="off"
          />
          <p className="text-xs text-muted-foreground">
            A label so you can revoke the right one later.
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="scim-token-user">Authenticates As *</Label>
          <select
            id="scim-token-user"
            value={userId}
            onChange={(e) => setUserId(e.target.value)}
            className="w-full rounded-md border border-input bg-background/50 px-3 py-2 text-sm"
          >
            <option value="">Select a user…</option>
            {users.map((u: User) => (
              <option key={u.id} value={u.id}>
                {u.username}
              </option>
            ))}
          </select>
          <p className="text-xs text-muted-foreground">
            Must already hold <code>scim:provision</code>. The usual setup is a
            dedicated non-interactive user (e.g. <code>scim-provisioner</code>)
            holding a role with only that permission.
          </p>
        </div>

        <div className="space-y-2">
          <Label htmlFor="scim-token-expiry">Expires In (days) *</Label>
          <Input
            id="scim-token-expiry"
            type="number"
            min={1}
            max={DEFAULT_MAX_LIFETIME_DAYS}
            value={expiresInDays}
            onChange={(e) => setExpiresInDays(e.target.value)}
          />
          <p className="text-xs text-muted-foreground">
            There is no never-expires option — a credential nobody revisits is
            one nobody notices the loss of.
          </p>
        </div>
      </FormDialog>

      <SecretRevealModal
        open={revealOpen}
        onClose={() => {
          setRevealOpen(false);
          setRevealed("");
        }}
        title="Provisioning Token Created"
        description="Paste this into your IdP's SCIM connector now — it is stored hashed and cannot be shown again."
        secrets={[{ label: "Provisioning Token", value: revealed }]}
      />

      <ConfirmDialog
        open={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={() => revokeTarget && revokeMutation.mutate(revokeTarget.id)}
        title="Revoke Provisioning Token"
        description={`"${revokeTarget?.name}" will stop working immediately and your IdP's SCIM sync will fail until it is given a new token.`}
        confirmLabel="Revoke"
        isLoading={revokeMutation.isPending}
      />
    </div>
  );
}

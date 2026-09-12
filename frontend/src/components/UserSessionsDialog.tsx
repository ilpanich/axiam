import { useCallback, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Clock, Loader2, X } from "lucide-react";
import {
  userService,
  type RefreshReplayVerdict,
  type UserSession,
} from "@/services/users";
import { useModalA11y } from "@/hooks/useModalA11y";
import { formatDate } from "@/lib/utils";
import { getApiErrorMessage } from "@/lib/apiError";

interface UserSessionsDialogProps {
  open: boolean;
  onClose: () => void;
  userId: string | null;
  username: string;
}

/**
 * T-254 — the refresh-replay badge.
 *
 * The whole point of the marker is that an operator can tell the two apart at
 * a glance, so they are given different words, different colours and different
 * icons rather than one badge with a number in it:
 *
 * - **FAPI grace retry** (amber, clock) — a `fapi2` client re-presented a
 *   rotated refresh token inside the sixty-second window FAPI 2.0 §5.3.2.1-9
 *   requires, and was served. That is the window working: it is the only
 *   recovery a client has from a rotation response lost in transit.
 * - **Replay refused** (red, warning) — a rotated refresh token was presented
 *   with no window to accept it in. Nothing a conformant client does.
 *
 * A session that has seen neither gets no badge at all. An empty column is the
 * normal state and should look like one.
 */
export function RefreshReplayBadge({
  verdict,
  graceAccepted,
  refused,
}: {
  verdict: RefreshReplayVerdict;
  graceAccepted: number;
  refused: number;
}) {
  if (verdict === "none") {
    return (
      <span className="text-muted-foreground text-sm" aria-label="No refresh replay">
        —
      </span>
    );
  }
  if (verdict === "fapi_grace_retry") {
    return (
      <span
        className="inline-flex items-center gap-1 rounded border border-amber-500/30 bg-amber-500/15 px-2 py-0.5 text-xs font-medium text-amber-400"
        title="A fapi2 client re-presented a rotated refresh token inside the FAPI 2.0 §5.3.2.1-9 grace window and was served. This is the retry the window exists for."
      >
        <Clock size={12} />
        FAPI grace retry
        {graceAccepted > 1 ? ` ×${graceAccepted}` : ""}
      </span>
    );
  }
  return (
    <span
      className="inline-flex items-center gap-1 rounded border border-destructive/40 bg-destructive/15 px-2 py-0.5 text-xs font-medium text-destructive"
      title="A refresh token was presented after it had already been rotated, with no grace window to accept it in. Nothing a conformant client does."
    >
      <AlertTriangle size={12} />
      Replay refused
      {refused > 1 ? ` ×${refused}` : ""}
    </span>
  );
}

function SessionRow({ session }: { session: UserSession }) {
  return (
    <div className="rounded-md border border-white/10 bg-white/[0.04] p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <code className="text-xs text-muted-foreground">{session.id}</code>
        <RefreshReplayBadge
          verdict={session.refresh_replay_verdict}
          graceAccepted={session.refresh_replay_grace_accepted}
          refused={session.refresh_replay_refused}
        />
      </div>
      <dl className="mt-2 grid gap-x-4 gap-y-2 sm:grid-cols-2">
        <div>
          <dt className="text-xs font-semibold uppercase tracking-wider text-primary/70">
            Authenticated
          </dt>
          <dd className="mt-0.5 text-sm text-foreground/90">
            {formatDate(session.authenticated_at)}
            {session.amr.length > 0 && (
              <span className="ml-1.5 text-xs text-muted-foreground">
                ({session.amr.join(", ")})
              </span>
            )}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-semibold uppercase tracking-wider text-primary/70">
            Expires
          </dt>
          <dd className="mt-0.5 text-sm text-foreground/90">
            {formatDate(session.expires_at)}
          </dd>
        </div>
        <div>
          <dt className="text-xs font-semibold uppercase tracking-wider text-primary/70">
            Origin
          </dt>
          <dd className="mt-0.5 break-all text-sm text-foreground/90">
            {session.ip_address ?? "—"}
          </dd>
        </div>
        {session.refresh_replay_at && (
          <div>
            <dt className="text-xs font-semibold uppercase tracking-wider text-primary/70">
              Last replay
            </dt>
            <dd className="mt-0.5 text-sm text-foreground/90">
              {formatDate(session.refresh_replay_at)}
            </dd>
          </div>
        )}
      </dl>
    </div>
  );
}

/**
 * The sessions a user currently holds, and what each of them has seen.
 *
 * Read-only. Ending a session is the account-lifecycle surface (a password
 * change, a reset, a delete), not a button here — this dialog exists so an
 * operator who has been alerted to an `oauth2.refresh_token_replayed` audit row
 * can see which session it landed on and what else that session did.
 */
export function UserSessionsDialog({
  open,
  onClose,
  userId,
  username,
}: UserSessionsDialogProps) {
  const dialogRef = useRef<HTMLDivElement>(null);
  const closeRef = useRef<HTMLButtonElement>(null);

  useModalA11y(open);

  const { data, isLoading, error } = useQuery({
    queryKey: ["users", userId, "sessions"],
    queryFn: () => userService.listSessions(userId as string),
    enabled: open && !!userId,
  });

  const handleKeyDown = useCallback(
    (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    },
    [onClose]
  );

  useEffect(() => {
    if (!open) return;
    closeRef.current?.focus();
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [open, handleKeyDown]);

  if (!open) return null;

  const sessions = data ?? [];
  const flagged = sessions.filter(
    (s) => s.refresh_replay_verdict === "refused"
  ).length;

  return (
    <div
      ref={dialogRef}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="user-sessions-title"
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-xs"
        onClick={onClose}
        aria-hidden="true"
      />

      <div className="relative z-10 glass-card flex max-h-[90dvh] w-full max-w-2xl flex-col p-6">
        <div className="flex items-start justify-between gap-4 border-b border-primary/10 pb-4">
          <div className="min-w-0">
            <h2
              id="user-sessions-title"
              className="text-lg font-semibold text-foreground"
            >
              Sessions
            </h2>
            <p className="mt-0.5 truncate text-sm text-muted-foreground">
              {username}
            </p>
          </div>
          <button
            ref={closeRef}
            onClick={onClose}
            className="focus-ring rounded p-1 text-muted-foreground transition-colors hover:text-foreground"
            aria-label="Close dialog"
          >
            <X size={18} />
          </button>
        </div>

        <div className="min-h-0 flex-1 space-y-3 overflow-y-auto py-4">
          {isLoading && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Loading sessions…
            </div>
          )}
          {error && (
            <p role="alert" className="text-sm text-destructive">
              {getApiErrorMessage(error)}
            </p>
          )}
          {!isLoading && !error && sessions.length === 0 && (
            <p className="text-sm text-muted-foreground">
              This user holds no sessions.
            </p>
          )}
          {flagged > 0 && (
            <p
              role="alert"
              className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-sm text-destructive"
            >
              {flagged === 1 ? "One session has" : `${flagged} sessions have`} a
              refused refresh-token replay. A rotated refresh token was
              presented again with no grace window to accept it in — search the
              audit log for <code>oauth2.refresh_token_replayed</code>.
            </p>
          )}
          {sessions.map((s) => (
            <SessionRow key={s.id} session={s} />
          ))}
        </div>
      </div>
    </div>
  );
}

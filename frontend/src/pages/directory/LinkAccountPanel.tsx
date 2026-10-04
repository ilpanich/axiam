import { useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { AlertCircle, CheckCircle2, Link2 } from "lucide-react";
import { directoryService, type DirectoryLinkResult } from "@/services/directory";
import type { User } from "@/services/users";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { UserSearchDialog } from "@/components/UserSearchDialog";
import { SectionCard } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { directoryErrorMessage } from "./directoryErrors";

function describe(result: DirectoryLinkResult, username: string): string {
  const retried = result.was_already_linked
    ? " It was already linked to that entry, so only the revocations ran again."
    : "";
  return (
    `${username} is linked to directory entry ${result.directory_external_id}.${retried} ` +
    `${result.webauthn_credentials_deleted} passkey(s) deleted, ` +
    `${result.certificates_revoked} certificate(s) revoked, every session and refresh token revoked.`
  );
}

/**
 * The administrator's act of linking an existing local account to its directory
 * entry (D-28). It lives here rather than on the user page because it needs
 * the directory and answers with the directory's own refusals (no enabled
 * directory, no single entry, an entry linked elsewhere).
 */
export function LinkAccountPanel({
  tenantId,
  directoryEnabled,
}: {
  tenantId: string;
  directoryEnabled: boolean;
}) {
  const [searching, setSearching] = useState(false);
  const [pending, setPending] = useState<User | null>(null);
  const [outcome, setOutcome] = useState<{ ok: boolean; text: string } | null>(null);

  const link = useMutation({
    mutationFn: (user: User) => directoryService.linkAccount(tenantId, user.id),
    onSuccess: (result, user) => {
      setPending(null);
      setOutcome({ ok: true, text: describe(result, user.username) });
    },
    onError: (err: unknown) => {
      setOutcome({ ok: false, text: directoryErrorMessage(err, "", "Linking failed.") });
      setPending(null);
    },
  });

  return (
    <SectionCard
      title="Link an existing account"
      action={
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            setOutcome(null);
            setSearching(true);
          }}
          disabled={!directoryEnabled}
        >
          <Link2 size={14} aria-hidden="true" />
          Link an account…
        </Button>
      }
    >
      <p className="text-sm text-muted-foreground">
        Directory sign-in only ever <em>creates</em> accounts, for names that match no
        local account, so a directory administrator cannot take over a local account by
        creating a matching entry. Linking is the explicit act that turns an existing
        account into a directory account: the directory finds the entry from the
        account&rsquo;s own username, and from then on only the directory decides its
        password.
      </p>
      <p className="mt-2 text-sm text-amber-300">
        <strong>The owner is signed out everywhere.</strong> Their passkeys and security
        keys are deleted, so are any social or upstream-IdP identities linked to the
        account, their user certificates are revoked, and every session and refresh token
        revoked. Their authenticator-app (TOTP) enrolment is kept. There is no
        unlink.
      </p>
      {!directoryEnabled && (
        <p className="mt-2 text-xs text-muted-foreground">
          Enable the directory to link accounts.
        </p>
      )}
      {outcome && (
        <div
          role="alert"
          className={
            outcome.ok
              ? "mt-4 flex items-start gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 p-3 text-sm text-emerald-400"
              : "mt-4 flex items-start gap-2 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
          }
        >
          {outcome.ok ? <CheckCircle2 size={16} /> : <AlertCircle size={16} />}
          <span>{outcome.text}</span>
        </div>
      )}

      <UserSearchDialog
        open={searching}
        onClose={() => setSearching(false)}
        title="Link an account to its directory entry"
        actionLabel="Link"
        tenantId={tenantId}
        onAction={async (user) => {
          setSearching(false);
          setPending(user);
        }}
      />
      <ConfirmDialog
        open={pending !== null}
        onClose={() => setPending(null)}
        onConfirm={() => pending && link.mutate(pending)}
        title="Link this account?"
        description={
          pending
            ? `${pending.username} will be signed out everywhere, lose their passkeys and linked social or upstream-IdP identities, and have their user certificates revoked, and from now on can sign in only with their directory password. This cannot be undone from here.`
            : ""
        }
        confirmLabel="Link account"
        isLoading={link.isPending}
      />
    </SectionCard>
  );
}

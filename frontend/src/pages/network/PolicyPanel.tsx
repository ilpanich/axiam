import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Loader2 } from "lucide-react";
import {
  networkService,
  NETWORK_HINTS,
  type NetworkPolicy,
} from "@/services/network";
import { invalidateEntity } from "@/lib/queryInvalidation";
import { usePermissions } from "@/hooks/usePermissions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { InfoRow, SectionCard } from "@/components/shared";
import { formatDateTime } from "@/lib/utils";
import { describeSeconds, parseWholeNumber } from "./networkForm";
import { networkErrorMessage } from "./networkErrors";

/**
 * The tenant's `Session-Timeout` cap (`network.session_timeout_max_secs`).
 *
 * Shown to everyone who can read the network section; the editor is offered to
 * a holder of `network:segments_write`, and the server decides whether that
 * grant is the one that counts — it must sit **at the `/network` root**, so a
 * site-level administrator sees the editor and is refused with the node named
 * (§36.3 rule 1).
 */
export function PolicyPanel() {
  const queryClient = useQueryClient();
  const { can } = usePermissions();
  const canWrite = can("network:segments_write");

  const policy = useQuery({
    queryKey: ["network-policy"],
    queryFn: networkService.getPolicy,
    // The version the next write names is read here: never serve it from a cache.
    staleTime: 0,
  });

  const [draft, setDraft] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState<NetworkPolicy | null>(null);

  const save = useMutation({
    mutationFn: (body: { session_timeout_max_secs: number; version: number }) =>
      networkService.replacePolicy(body),
    onSuccess: (written) => {
      // The cap clamps every profile at read, so the profile views are stale too.
      invalidateEntity(queryClient, "network-policy");
      setDraft(null);
      setError("");
      setSaved(written);
    },
    onError: (err: unknown) =>
      setError(
        networkErrorMessage(err, {
          fallback: "Failed to save the Session-Timeout cap.",
          staleOnly: true,
        }),
      ),
  });

  const current = policy.data;

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    setSaved(null);
    if (!current || draft === null) return;
    const cap = parseWholeNumber(draft);
    if (cap === null) {
      setError("The cap must be a whole number of seconds.");
      return;
    }
    save.mutate({ session_timeout_max_secs: cap, version: current.version });
  }

  return (
    <SectionCard title="Session-Timeout cap">
      <p className="text-sm text-muted-foreground mb-4">
        The longest <code>Session-Timeout</code> any reply profile of this tenant
        may carry, from {NETWORK_HINTS.capMinSecs} to {NETWORK_HINTS.capMaxSecs}{" "}
        seconds (default {NETWORK_HINTS.capDefaultSecs}). It bounds how long a
        quarantine or a revocation waits for a device to re-authenticate.{" "}
        <strong>Lowering it</strong> never rewrites a profile: every read clamps
        the stored value to the cap and says so, and raising the cap again
        restores it. <strong>Raising it</strong> is allowed and is audited as a
        raise.
      </p>

      {policy.isLoading && (
        <p className="text-sm text-muted-foreground">Loading the cap…</p>
      )}
      {policy.isError && (
        <p role="alert" className="text-sm text-destructive">
          {networkErrorMessage(policy.error, {
            fallback: "The Session-Timeout cap could not be loaded.",
          })}
        </p>
      )}

      {current && (
        <>
          <div className="mb-4">
            <InfoRow label="Cap">
              <span data-testid="network-cap-value">
                {current.session_timeout_max_secs} s
              </span>{" "}
              <span className="text-muted-foreground">
                ({describeSeconds(current.session_timeout_max_secs)})
              </span>
            </InfoRow>
            <InfoRow label="Version">
              {current.version === 0
                ? "0 (the default; this tenant has not written one)"
                : current.version}
            </InfoRow>
            {current.updated_at && (
              <InfoRow label="Last changed">{formatDateTime(current.updated_at)}</InfoRow>
            )}
          </div>

          {saved && (
            <p role="status" className="mb-3 text-sm text-cyan-400">
              Saved: the cap is now {saved.session_timeout_max_secs} s.
            </p>
          )}

          {canWrite &&
            (draft === null ? (
              <Button
                type="button"
                variant="outline"
                onClick={() => {
                  setSaved(null);
                  setError("");
                  setDraft(String(current.session_timeout_max_secs));
                }}
              >
                Change the cap
              </Button>
            ) : (
              <form onSubmit={handleSubmit} className="space-y-3 max-w-sm">
                <div className="space-y-2">
                  <Label htmlFor="network-cap-input">Cap in seconds</Label>
                  <Input
                    id="network-cap-input"
                    inputMode="numeric"
                    value={draft}
                    onChange={(e) => setDraft(e.target.value)}
                    autoComplete="off"
                  />
                  <p className="text-xs text-muted-foreground">
                    Writing it needs <code>network:segments_write</code> at the{" "}
                    <code>/network</code> root; a grant on a site below does not
                    count.
                  </p>
                </div>
                <div className="flex gap-2">
                  <Button type="submit" disabled={save.isPending}>
                    {save.isPending ? (
                      <Loader2 size={14} className="animate-spin" />
                    ) : (
                      "Save the cap"
                    )}
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    disabled={save.isPending}
                    onClick={() => {
                      setDraft(null);
                      setError("");
                    }}
                  >
                    Cancel
                  </Button>
                </div>
              </form>
            ))}
        </>
      )}

      {error && (
        <p role="alert" id="network-policy-error" className="mt-3 text-sm text-destructive">
          {error}
        </p>
      )}
    </SectionCard>
  );
}

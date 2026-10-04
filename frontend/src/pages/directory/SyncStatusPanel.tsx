import { useQuery } from "@tanstack/react-query";
import { Badge } from "@/components/ui/badge";
import { SectionCard } from "@/components/shared";
import { directoryService, type DirectorySyncStatus } from "@/services/directory";
import { formatDateTime } from "@/lib/utils";

/** What a result means to an operator, in the words of D-31. */
function resultText(result: string | null): { label: string; detail: string; variant: "default" | "secondary" | "destructive" } {
  switch (result) {
    case null:
      return {
        label: "Not run yet",
        detail: "The job runs on the server's cleanup schedule, and only while the directory is enabled.",
        variant: "secondary",
      };
    case "ok":
      return { label: "OK", detail: "Every account was handled.", variant: "default" };
    case "partial":
      return {
        label: "Partial",
        detail:
          "The run completed but skipped at least one account (for example a changed username or e-mail that would collide with another account). The next run is a full one.",
        variant: "secondary",
      };
    case "failed":
      return {
        label: "Failed",
        detail:
          "The directory could not be asked, or the configuration is unusable. The run changed nothing and is retried at the next interval.",
        variant: "destructive",
      };
    case "safety_valve":
      return {
        label: "Safety valve",
        detail:
          "A full run would have deactivated more than 10% of this tenant's directory accounts (and at least 5), so it applied nothing. Check base DN and the filters, or deactivate the accounts that really left by hand; the run stays blocked until the numbers are back under the limit.",
        variant: "destructive",
      };
    default:
      return { label: result, detail: "A result this console does not describe.", variant: "secondary" };
  }
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">{label}</p>
      <div className="text-sm text-foreground font-medium">{children}</div>
    </div>
  );
}

function StatusBody({ status }: { status: DirectorySyncStatus }) {
  const result = resultText(status.last_result);
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2">
        <Field label="Last result">
          <Badge variant={result.variant}>{result.label}</Badge>
        </Field>
        <Field label="Last attempt">
          {status.last_attempt_at ? formatDateTime(status.last_attempt_at) : "—"}
        </Field>
        <Field label="Last full run">
          {status.last_full_run_at ? formatDateTime(status.last_full_run_at) : "—"}
        </Field>
        <Field label="Next run">
          {status.full_required || !status.has_watermark ? "Full reconciliation" : "Incremental"}
        </Field>
        <Field label="Incremental watermark">{status.has_watermark ? "Present" : "None"}</Field>
      </div>
      <p className="text-xs text-muted-foreground">{result.detail}</p>
      <p className="text-xs text-muted-foreground">
        What a run did — accounts deactivated, attributes refreshed, memberships
        changed — is in the audit log (<code>directory.sync_run</code>,{" "}
        <code>directory.sync_safety_valve</code>), not here.
      </p>
    </div>
  );
}

export function SyncStatusPanel({ tenantId }: { tenantId: string }) {
  const { data, isLoading, error } = useQuery({
    queryKey: ["directory-sync-status", tenantId],
    queryFn: () => directoryService.getSyncStatus(tenantId),
  });

  return (
    <SectionCard title="Sync status">
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading&hellip;</p>
      ) : error ? (
        <p role="alert" className="text-sm text-destructive">
          Failed to load the sync status.
        </p>
      ) : data ? (
        <StatusBody status={data} />
      ) : (
        <p className="text-sm text-muted-foreground">No directory is configured.</p>
      )}
    </SectionCard>
  );
}

import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Download, KeyRound, Loader2, ShieldAlert, Undo2 } from "lucide-react";
import { gdprService, saveExportBlob } from "@/services/gdpr";
import { settingsService } from "@/services/settings";
import { DEFAULT_DELETION_GRACE_PERIOD_DAYS } from "@/services/organizations";
import { usePermissions } from "@/hooks/usePermissions";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";
import { PageHeader } from "@/components/PageHeader";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { SectionCard } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// ─── GDPR export/erasure console (Art. 15 / Art. 17) ──────────────────────────
//
// Self-service by default: every authenticated user can export or erase their
// OWN data with no special permission. An admin acting on behalf of another
// account additionally needs `gdpr:export` (export) or `users:erase`
// (erasure) — enforced server-side by `is_own_resource` OR the permission
// check in gdpr.rs; the optional "act on behalf of" fields here are shown
// only when the caller holds the matching permission, so the UI doesn't
// dangle a control that will just 403.
//
// Deadlines: export is a 24h single-use download link; erasure has a
// cancellable grace window (D-07/D-08/D-09) — both are why the coverage
// matrix calls this the highest-value existing gap. That window is the
// tenant's effective `privacy.deletion_grace_period_days`, which is read here
// rather than written as "30 days" in prose: it used to be hard-coded on both
// sides, so this page promised a duration nothing could change and an operator
// had no way to find out what it actually was.

export function PrivacyPage() {
  const { can } = usePermissions();

  // `/api/v1/settings` is the caller's own effective settings and needs no
  // special permission beyond `settings:get`. A failed read falls back to the
  // server's own default rather than blanking the sentence — the number is
  // context for a decision, not the thing being decided.
  const { data: settings } = useQuery({
    queryKey: ["settings"],
    queryFn: () => settingsService.getSettings(),
  });
  const graceDays =
    settings?.privacy?.deletion_grace_period_days ??
    DEFAULT_DELETION_GRACE_PERIOD_DAYS;
  const { toast } = useToast();
  const canActForOthers = can("gdpr:export");
  const canEraseForOthers = can("users:erase");

  // ─── Export ────────────────────────────────────────────────────────────────
  const [exportTargetId, setExportTargetId] = useState("");
  const exportMutation = useMutation({
    mutationFn: () => gdprService.requestExport(exportTargetId.trim() || undefined),
    onSuccess: () => {
      toast({
        description:
          "Export requested. A single-use download link will arrive by email within a few minutes.",
      });
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  // ─── Redeem download token ─────────────────────────────────────────────────
  const [downloadToken, setDownloadToken] = useState("");
  const [downloadError, setDownloadError] = useState("");
  const downloadMutation = useMutation({
    mutationFn: () => gdprService.downloadExport(downloadToken.trim()),
    onSuccess: (data) => {
      setDownloadError("");
      saveExportBlob(data);
      setDownloadToken("");
      toast({ description: "Export downloaded." });
    },
    onError: (err: unknown) => {
      setDownloadError(getApiErrorMessage(err));
    },
  });

  // ─── Erasure ───────────────────────────────────────────────────────────────
  const [eraseTargetId, setEraseTargetId] = useState("");
  const [confirmEraseOpen, setConfirmEraseOpen] = useState(false);
  const eraseMutation = useMutation({
    mutationFn: () => gdprService.requestErasure(eraseTargetId.trim() || undefined),
    onSuccess: () => {
      setConfirmEraseOpen(false);
      toast({
        description:
          "Erasure scheduled for 30 days from now. A cancellation link has been emailed — the account is disabled immediately.",
      });
    },
    onError: (err: unknown) => {
      setConfirmEraseOpen(false);
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  // ─── Cancel pending erasure ────────────────────────────────────────────────
  const [cancelToken, setCancelToken] = useState("");
  const [cancelError, setCancelError] = useState("");
  const cancelMutation = useMutation({
    mutationFn: () => gdprService.cancelErasure(cancelToken.trim()),
    onSuccess: () => {
      setCancelError("");
      setCancelToken("");
      toast({ description: "Pending deletion cancelled. The account is re-enabled." });
    },
    onError: (err: unknown) => {
      setCancelError(getApiErrorMessage(err));
    },
  });

  return (
    <div>
      <PageHeader
        title="Privacy & Data"
        description="Export your account data (GDPR Art. 15) or request account erasure (Art. 17)."
      />

      <SectionCard title="Export your data">
        <p className="text-sm text-muted-foreground mb-4">
          Request a full export of your account data. You'll receive a
          single-use download link by email, valid for 24 hours.
        </p>
        {canActForOthers && (
          <div className="space-y-2 mb-4">
            <Label htmlFor="export-target-id">
              Act on behalf of (user ID, optional)
            </Label>
            <Input
              id="export-target-id"
              value={exportTargetId}
              onChange={(e) => setExportTargetId(e.target.value)}
              placeholder="Leave blank to export your own data"
              autoComplete="off"
            />
          </div>
        )}
        <Button
          onClick={() => exportMutation.mutate()}
          disabled={exportMutation.isPending}
        >
          {exportMutation.isPending ? (
            <Loader2 size={16} className="animate-spin" />
          ) : (
            <Download size={16} />
          )}
          Request Export
        </Button>
      </SectionCard>

      <SectionCard title="Redeem a download link">
        <p className="text-sm text-muted-foreground mb-4">
          Paste the token from your export-ready email to download the data.
        </p>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 space-y-2">
            <Label htmlFor="download-token">Download token</Label>
            <Input
              id="download-token"
              value={downloadToken}
              onChange={(e) => setDownloadToken(e.target.value)}
              placeholder="Token from the export email"
              autoComplete="off"
              error={downloadError || undefined}
            />
          </div>
          <Button
            className="sm:self-end"
            disabled={downloadMutation.isPending || !downloadToken.trim()}
            onClick={() => downloadMutation.mutate()}
          >
            {downloadMutation.isPending ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <KeyRound size={16} />
            )}
            Download
          </Button>
        </div>
      </SectionCard>

      <SectionCard title="Delete your account">
        <p className="text-sm text-muted-foreground mb-4">
          Requests immediate account disablement, revokes all sessions, and
          schedules permanent erasure in {graceDays}{" "}
          {graceDays === 1 ? "day" : "days"}. You can cancel within that window
          using the link emailed to you.
        </p>
        {canEraseForOthers && (
          <div className="space-y-2 mb-4">
            <Label htmlFor="erase-target-id">
              Act on behalf of (user ID, optional)
            </Label>
            <Input
              id="erase-target-id"
              value={eraseTargetId}
              onChange={(e) => setEraseTargetId(e.target.value)}
              placeholder="Leave blank to erase your own account"
              autoComplete="off"
            />
          </div>
        )}
        <Button
          variant="destructive"
          onClick={() => setConfirmEraseOpen(true)}
          disabled={eraseMutation.isPending}
        >
          <ShieldAlert size={16} />
          Request Erasure
        </Button>
      </SectionCard>

      <SectionCard title="Cancel a pending deletion">
        <p className="text-sm text-muted-foreground mb-4">
          Paste the cancellation token from the erasure confirmation email to
          abort the scheduled deletion and re-enable the account. This works for{" "}
          {graceDays} {graceDays === 1 ? "day" : "days"} after the request;
          after that the purge has run and there is nothing left to restore.
          Administrators set the window on the organization, and a tenant may
          shorten it.
        </p>
        <div className="flex flex-col sm:flex-row gap-3">
          <div className="flex-1 space-y-2">
            <Label htmlFor="cancel-token">Cancellation token</Label>
            <Input
              id="cancel-token"
              value={cancelToken}
              onChange={(e) => setCancelToken(e.target.value)}
              placeholder="Token from the deletion email"
              autoComplete="off"
              error={cancelError || undefined}
            />
          </div>
          <Button
            variant="outline"
            className="sm:self-end"
            disabled={cancelMutation.isPending || !cancelToken.trim()}
            onClick={() => cancelMutation.mutate()}
          >
            {cancelMutation.isPending ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              <Undo2 size={16} />
            )}
            Cancel Deletion
          </Button>
        </div>
      </SectionCard>

      <ConfirmDialog
        open={confirmEraseOpen}
        onClose={() => setConfirmEraseOpen(false)}
        onConfirm={() => eraseMutation.mutate()}
        title="Request account erasure"
        description={
          eraseTargetId.trim()
            ? `This will disable the account ${eraseTargetId.trim()} immediately and schedule permanent erasure in 30 days. This can be cancelled via the emailed link.`
            : "This will disable your account immediately and schedule permanent erasure in 30 days. This can be cancelled via the emailed link."
        }
        confirmLabel="Request Erasure"
        isLoading={eraseMutation.isPending}
      />
    </div>
  );
}

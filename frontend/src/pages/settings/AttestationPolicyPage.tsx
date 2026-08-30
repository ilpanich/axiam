import { useMemo, useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  AlertCircle,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Pencil,
  RefreshCw,
  X,
} from "lucide-react";
import {
  webauthnPolicyService,
  effectiveUnknownAaguid,
  validateAttestationPolicy,
  isValidAaguid,
  parseAaguidList,
  isUnknownCredential,
  complianceReasonLabel,
  CERTIFICATION_LEVELS,
  CERTIFICATION_LEVEL_LABEL,
  DEFAULT_ATTESTATION_POLICY,
  type WebauthnAttestationPolicy,
  type AttestationMode,
  type CertificationLevel,
  type UnknownAaguidAction,
  type ComplianceReportEntry,
} from "@/services/webauthnPolicy";
import { mdsService, type MdsRefreshOutcome } from "@/services/mds";
import { useAuthStore } from "@/stores/auth";
import { usePermissions } from "@/hooks/usePermissions";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { SectionCard, ToggleField } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { formatDateTime } from "@/lib/utils";
import { getApiErrorMessage } from "@/lib/apiError";
import { invalidateEntity } from "@/lib/queryInvalidation";

// ─────────────────────────────────────────────────────────────────────────────
// The passkey caveat (docs/admin/authenticator-policies.md, "The passkey
// caveat — read this before enabling anything"). Copied verbatim in
// substance: turning attestation on AT ALL — indirect just as much as
// direct_required — excludes iCloud Keychain, Google Password Manager, and
// hybrid ("use your phone") sign-in, because the attested ceremony always
// requests direct conveyance and always rejects synced authenticators,
// regardless of mode. This is not a per-mode trade; it is a property of
// requesting attestation at all.
// ─────────────────────────────────────────────────────────────────────────────

const PASSKEY_CAVEAT_TEXT =
  "Turning attestation on at all excludes an entire class of authenticator " +
  "your users may already have: iCloud Keychain, Google Password Manager, " +
  "any other synced passkey provider, and hybrid (\"use your phone\") " +
  "sign-in. This is true for Indirect mode exactly as much as Direct " +
  "required — it is a property of requesting attestation at all, not a " +
  "dial you can split the difference on. Only new registrations are " +
  "affected; passkeys already registered keep working.";

// ─────────────────────────────────────────────────────────────────────────────
// Form <-> wire conversion
// ─────────────────────────────────────────────────────────────────────────────

type AllowedAaguidsMode = "all" | "explicit";

interface PolicyForm {
  mode: AttestationMode;
  require_fido_certified: boolean;
  min_certification: CertificationLevel | "";
  allowedMode: AllowedAaguidsMode;
  allowedAaguidsText: string;
  blockedAaguidsText: string;
  block_revoked_status: boolean;
  unknownAaguid: "default" | UnknownAaguidAction;
  /** UI-only: has the admin acknowledged the passkey caveat for the
   * mode currently selected in this editing session? Seeded `true` when the
   * loaded policy is already non-`none` (that decision was already made,
   * possibly in a previous session) and reset to `false` whenever the mode
   * is changed away from `none` during this session, so switching INTO a
   * stricter posture always requires a fresh, explicit acknowledgement. */
  passkeyCaveatAcknowledged: boolean;
}

function policyToForm(policy: WebauthnAttestationPolicy): PolicyForm {
  return {
    mode: policy.mode,
    require_fido_certified: policy.require_fido_certified,
    min_certification: policy.min_certification ?? "",
    allowedMode: policy.allowed_aaguids === null ? "all" : "explicit",
    allowedAaguidsText: (policy.allowed_aaguids ?? []).join("\n"),
    blockedAaguidsText: policy.blocked_aaguids.join("\n"),
    block_revoked_status: policy.block_revoked_status,
    unknownAaguid: policy.unknown_aaguid ?? "default",
    passkeyCaveatAcknowledged: policy.mode !== "none",
  };
}

/** Returns the wire payload, or a validation error string. Parsing AAGUID
 * lists happens here rather than on every keystroke, so a stray blank line
 * while typing never flashes an error. */
function formToPolicy(
  form: PolicyForm,
): { policy: WebauthnAttestationPolicy } | { error: string } {
  const allowedList =
    form.allowedMode === "all" ? null : parseAaguidList(form.allowedAaguidsText);
  const blockedList = parseAaguidList(form.blockedAaguidsText);

  const badAllowed = (allowedList ?? []).filter((v) => !isValidAaguid(v));
  const badBlocked = blockedList.filter((v) => !isValidAaguid(v));
  if (badAllowed.length > 0 || badBlocked.length > 0) {
    const bad = [...badAllowed, ...badBlocked];
    return {
      error: `Not a valid AAGUID (expected a UUID): ${bad.join(", ")}`,
    };
  }

  if (form.mode !== "none" && !form.passkeyCaveatAcknowledged) {
    return {
      error:
        "Acknowledge the passkey caveat above before saving a non-none mode.",
    };
  }

  const policy: WebauthnAttestationPolicy = {
    mode: form.mode,
    require_fido_certified: form.mode === "none" ? false : form.require_fido_certified,
    min_certification:
      form.mode === "none" || form.min_certification === ""
        ? null
        : form.min_certification,
    allowed_aaguids: allowedList,
    blocked_aaguids: blockedList,
    block_revoked_status: form.block_revoked_status,
    unknown_aaguid: form.unknownAaguid === "default" ? null : form.unknownAaguid,
  };

  const serverSideError = validateAttestationPolicy(policy);
  if (serverSideError) return { error: serverSideError };

  return { policy };
}

// ─────────────────────────────────────────────────────────────────────────────
// Policy editor
// ─────────────────────────────────────────────────────────────────────────────

function ModeDescription({ mode }: { mode: AttestationMode }) {
  switch (mode) {
    case "none":
      return (
        <p className="text-xs text-muted-foreground">
          No attestation requested, no MDS lookup, every authenticator
          accepted — today&rsquo;s behavior, unchanged.
        </p>
      );
    case "indirect":
      return (
        <p className="text-xs text-muted-foreground">
          Requests attestation (the library has no separate &quot;indirect&quot;
          wire conveyance — this uses the same ceremony as Direct required)
          but is lenient by default on unrecognized authenticators.
        </p>
      );
    case "direct_required":
      return (
        <p className="text-xs text-muted-foreground">
          Requires real attestation. A missing or &quot;none&quot;-format
          attestation is rejected outright, before any other check runs.
        </p>
      );
  }
}

interface PolicyEditorProps {
  form: PolicyForm;
  onChange: <K extends keyof PolicyForm>(key: K, value: PolicyForm[K]) => void;
  error: string | null;
}

function PolicyEditor({ form, onChange, error }: PolicyEditorProps) {
  const resolvedUnknownDefault = effectiveUnknownAaguid({
    mode: form.mode,
    unknown_aaguid: null,
  });

  function handleModeChange(next: AttestationMode) {
    if (next === "none") {
      onChange("mode", next);
      // Nothing is enforceable under mode: none — mirror the server's
      // validation rule client-side rather than let a stale value linger
      // invisibly until the next save attempt trips it.
      onChange("require_fido_certified", false);
      onChange("min_certification", "");
      return;
    }
    // Switching INTO a non-none mode from none is exactly the moment the
    // admin needs to see and accept the passkey caveat again, even if they
    // acknowledged it in a previous editing session.
    if (form.mode === "none") {
      onChange("passkeyCaveatAcknowledged", false);
    }
    onChange("mode", next);
  }

  return (
    <div className="space-y-5">
      <div className="space-y-2">
        <Label htmlFor="policy-mode">Mode</Label>
        <select
          id="policy-mode"
          value={form.mode}
          onChange={(e) => handleModeChange(e.target.value as AttestationMode)}
          className="flex h-9 w-full rounded-md border border-input bg-background/50 px-3 py-1 text-sm"
        >
          <option value="none">None — accept every authenticator (default)</option>
          <option value="indirect">Indirect — lenient unknown handling</option>
          <option value="direct_required">
            Direct required — strict, rejects missing attestation
          </option>
        </select>
        <ModeDescription mode={form.mode} />
      </div>

      {form.mode !== "none" && (
        <div
          role="alert"
          className="space-y-3 p-4 rounded-md bg-amber-500/10 border border-amber-500/30"
        >
          <div className="flex items-start gap-2">
            <AlertTriangle
              size={16}
              className="text-amber-400 shrink-0 mt-0.5"
              aria-hidden="true"
            />
            <p className="text-sm text-amber-200">{PASSKEY_CAVEAT_TEXT}</p>
          </div>
          <label
            htmlFor="policy-caveat-ack"
            className="flex items-start gap-2.5 cursor-pointer select-none pl-6"
          >
            <input
              id="policy-caveat-ack"
              type="checkbox"
              checked={form.passkeyCaveatAcknowledged}
              onChange={(e) =>
                onChange("passkeyCaveatAcknowledged", e.target.checked)
              }
              className="mt-0.5 w-4 h-4 accent-amber-400 cursor-pointer"
            />
            <span className="text-sm text-amber-100">
              I understand this excludes iCloud Keychain, Google Password
              Manager, and hybrid sign-in for new registrations, and want to
              proceed anyway.
            </span>
          </label>
        </div>
      )}

      <ToggleField
        id="policy-require-fido-certified"
        label="Require FIDO certification (any level)"
        checked={form.require_fido_certified}
        onChange={(v) => onChange("require_fido_certified", v)}
      />
      {form.mode === "none" && (
        <p className="text-xs text-muted-foreground -mt-3 pl-8">
          Disabled — cannot be enforced when mode is None.
        </p>
      )}

      <div className="space-y-2">
        <Label htmlFor="policy-min-cert">Minimum certification level</Label>
        <select
          id="policy-min-cert"
          value={form.min_certification}
          disabled={form.mode === "none"}
          onChange={(e) =>
            onChange(
              "min_certification",
              e.target.value as CertificationLevel | "",
            )
          }
          className="flex h-9 w-full rounded-md border border-input bg-background/50 px-3 py-1 text-sm disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <option value="">No minimum</option>
          {CERTIFICATION_LEVELS.map((level) => (
            <option key={level} value={level}>
              {CERTIFICATION_LEVEL_LABEL[level]}
            </option>
          ))}
        </select>
        <p className="text-xs text-muted-foreground">
          The authenticator&rsquo;s highest-ever certified level must meet
          this bar. {form.mode === "none" && "Disabled — cannot be enforced when mode is None."}
        </p>
      </div>

      <ToggleField
        id="policy-block-revoked"
        label="Block revoked / compromised authenticators"
        checked={form.block_revoked_status}
        onChange={(v) => onChange("block_revoked_status", v)}
      />
      <p className="text-xs text-muted-foreground -mt-3 pl-8">
        Denies REVOKED and any *_COMPROMISE status found anywhere in the
        authenticator&rsquo;s MDS history — sticky, even if a later report was
        benign. Does not cover USER_VERIFICATION_BYPASS; use the block list
        below for that.
      </p>

      <div className="space-y-2">
        <Label htmlFor="policy-unknown-aaguid">
          Unknown AAGUID (no FIDO metadata)
        </Label>
        <select
          id="policy-unknown-aaguid"
          value={form.unknownAaguid}
          onChange={(e) =>
            onChange(
              "unknownAaguid",
              e.target.value as "default" | UnknownAaguidAction,
            )
          }
          className="flex h-9 w-full rounded-md border border-input bg-background/50 px-3 py-1 text-sm"
        >
          <option value="default">
            Use mode default — currently resolves to{" "}
            {resolvedUnknownDefault === "allow" ? "Allow" : "Deny"}
          </option>
          <option value="allow">Always allow</option>
          <option value="deny">Always deny</option>
        </select>
        <p className="text-xs text-muted-foreground">
          MDS coverage is incomplete for some legitimate authenticators —
          &quot;unknown&quot; is not itself evidence of anything malicious.
          The stored default is always Allow unless set explicitly here, even
          under Direct required.
        </p>
      </div>

      <div className="space-y-2">
        <Label>Allow list</Label>
        <div className="flex flex-col gap-2 text-sm">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="allowed-mode"
              checked={form.allowedMode === "all"}
              onChange={() => onChange("allowedMode", "all")}
              className="accent-cyan-400"
            />
            Allow every authenticator except the block list below
          </label>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="radio"
              name="allowed-mode"
              checked={form.allowedMode === "explicit"}
              onChange={() => onChange("allowedMode", "explicit")}
              className="accent-cyan-400"
            />
            Restrict registration to an explicit allow list
          </label>
        </div>
        {form.allowedMode === "explicit" && (
          <>
            <Textarea
              id="policy-allowed-aaguids"
              value={form.allowedAaguidsText}
              onChange={(e) => onChange("allowedAaguidsText", e.target.value)}
              placeholder={"one AAGUID per line, e.g.\nee882879-721c-4913-9775-3dfcce97072a"}
              rows={3}
              className="font-mono text-xs"
            />
            {parseAaguidList(form.allowedAaguidsText).length === 0 && (
              <p className="text-xs text-amber-400">
                Empty list — this is a deliberate lockout. Nothing may
                register until an AAGUID is added.
              </p>
            )}
          </>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="policy-blocked-aaguids">
          Block list (always denied, beats the allow list)
        </Label>
        <Textarea
          id="policy-blocked-aaguids"
          value={form.blockedAaguidsText}
          onChange={(e) => onChange("blockedAaguidsText", e.target.value)}
          placeholder="one AAGUID per line"
          rows={2}
          className="font-mono text-xs"
        />
      </div>

      {error && (
        <p role="alert" className="text-sm text-destructive">
          {error}
        </p>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Read-only view of the effective policy
// ─────────────────────────────────────────────────────────────────────────────

function PolicySummary({ policy }: { policy: WebauthnAttestationPolicy }) {
  const modeLabel: Record<AttestationMode, string> = {
    none: "None (default) — every authenticator accepted",
    indirect: "Indirect",
    direct_required: "Direct required",
  };
  const unknownLabel =
    policy.unknown_aaguid === null
      ? `Use mode default (currently: ${
          effectiveUnknownAaguid(policy) === "allow" ? "Allow" : "Deny"
        })`
      : policy.unknown_aaguid === "allow"
        ? "Always allow"
        : "Always deny";

  return (
    <div className="grid gap-4 sm:grid-cols-2">
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
          Mode
        </p>
        <p className="text-sm text-foreground font-medium">
          {modeLabel[policy.mode]}
        </p>
      </div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
          Require FIDO certified
        </p>
        <Badge variant={policy.require_fido_certified ? "default" : "secondary"}>
          {policy.require_fido_certified ? "Yes" : "No"}
        </Badge>
      </div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
          Minimum certification
        </p>
        <p className="text-sm text-foreground font-medium">
          {policy.min_certification
            ? CERTIFICATION_LEVEL_LABEL[policy.min_certification]
            : "No minimum"}
        </p>
      </div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
          Block revoked / compromised
        </p>
        <Badge variant={policy.block_revoked_status ? "default" : "secondary"}>
          {policy.block_revoked_status ? "Yes" : "No"}
        </Badge>
      </div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
          Unknown AAGUID
        </p>
        <p className="text-sm text-foreground font-medium">{unknownLabel}</p>
      </div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
          Allow list
        </p>
        <p className="text-sm text-foreground font-medium">
          {policy.allowed_aaguids === null
            ? "All except blocked"
            : policy.allowed_aaguids.length === 0
              ? "Empty — deliberate lockout"
              : `${policy.allowed_aaguids.length} explicit AAGUID${policy.allowed_aaguids.length === 1 ? "" : "s"}`}
        </p>
      </div>
      <div>
        <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
          Block list
        </p>
        <p className="text-sm text-foreground font-medium">
          {policy.blocked_aaguids.length === 0
            ? "Empty"
            : `${policy.blocked_aaguids.length} AAGUID${policy.blocked_aaguids.length === 1 ? "" : "s"}`}
        </p>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Compliance report
// ─────────────────────────────────────────────────────────────────────────────

type ComplianceStatus = "compliant" | "unknown" | "violation";

function complianceStatusOf(entry: ComplianceReportEntry): ComplianceStatus {
  if (isUnknownCredential(entry)) return "unknown";
  return entry.compliant ? "compliant" : "violation";
}

function ComplianceStatusBadge({ status }: { status: ComplianceStatus }) {
  const styles: Record<ComplianceStatus, string> = {
    compliant: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    // Deliberately NOT amber/red: an unknown-AAGUID credential is never a
    // violation (D9), and a warning color would visually contradict that —
    // the docs are explicit that this bucket must read as distinct from,
    // not milder than, a real violation.
    unknown: "bg-muted/40 text-muted-foreground border-border",
    violation: "bg-rose-500/15 text-rose-400 border-rose-500/30",
  };
  const label: Record<ComplianceStatus, string> = {
    compliant: "Compliant",
    unknown: "Unknown",
    violation: "Violation",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${styles[status]}`}
    >
      {label[status]}
    </span>
  );
}

function ComplianceReportPanel({ tenantId }: { tenantId: string }) {
  const {
    data: report = [],
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ["webauthn-compliance-report", tenantId],
    queryFn: () => webauthnPolicyService.complianceReport(tenantId),
  });

  const columns: Column<ComplianceReportEntry>[] = [
    {
      key: "name",
      header: "Credential",
      render: (row) => (
        <div className="min-w-0">
          <span className="block text-sm text-foreground/90 truncate">
            {row.name}
          </span>
          <span className="block text-xs text-muted-foreground truncate">
            {row.authenticator_name ?? "Unrecognized authenticator model"}
          </span>
        </div>
      ),
    },
    {
      key: "aaguid",
      header: "AAGUID",
      render: (row) => (
        <span className="font-mono text-xs text-muted-foreground">
          {row.aaguid ?? "—"}
        </span>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <ComplianceStatusBadge status={complianceStatusOf(row)} />,
    },
    {
      key: "reason",
      header: "Reason",
      render: (row) => (
        <span className="text-xs text-muted-foreground">
          {complianceReasonLabel(row.reason) ?? "—"}
        </span>
      ),
    },
    {
      key: "actions",
      header: "",
      render: (row) => (
        <Link
          to={`/users/${row.user_id}`}
          className="text-xs text-primary hover:underline"
        >
          View user
        </Link>
      ),
      width: "w-24",
    },
  ];

  const violationCount = report.filter((r) => complianceStatusOf(r) === "violation").length;

  return (
    <SectionCard title="Compliance report">
      <p className="text-xs text-muted-foreground mb-3">
        Every registered credential re-evaluated against the{" "}
        <strong>current</strong> policy. Nothing here is ever auto-revoked —
        to remove a credential, use the delete action on the user&rsquo;s MFA
        methods page.{" "}
        {violationCount > 0 && (
          <span className="text-rose-400">
            {violationCount} credential{violationCount === 1 ? "" : "s"} would
            be denied if registered today.
          </span>
        )}
      </p>
      <DataTable
        columns={columns}
        data={report}
        isLoading={isLoading}
        getRowKey={(row) => row.credential_id}
        emptyMessage="No WebAuthn credentials registered in this tenant."
        error={error ? "Failed to load the compliance report." : null}
        onRetry={() => void refetch()}
      />
    </SectionCard>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// MDS status panel
// ─────────────────────────────────────────────────────────────────────────────

function mdsRefreshOutcomeMessage(outcome: MdsRefreshOutcome): string {
  switch (outcome.outcome) {
    case "initial":
      return `First ingestion complete — serial ${outcome.no}, ${outcome.entry_count} entries.`;
    case "replaced":
      return `Ingested a newer BLOB — serial ${outcome.no}, ${outcome.entry_count} entries.`;
    case "no_op_refresh":
      return `Already current at serial ${outcome.no} — no changes.`;
    case "rollback_rejected":
      return `Rejected: fetched serial ${outcome.attempted_no} is older than the stored serial ${outcome.stored_no}. Nothing was written.`;
  }
}

function MdsStatusPanel({ canRefresh }: { canRefresh: boolean }) {
  const queryClient = useQueryClient();
  const [refreshMessage, setRefreshMessage] = useState<{
    type: "success" | "error";
    text: string;
  } | null>(null);

  const {
    data: status,
    isLoading,
    error,
  } = useQuery({
    queryKey: ["mds-status"],
    queryFn: mdsService.getStatus,
  });

  const refreshMutation = useMutation({
    mutationFn: mdsService.refresh,
    onSuccess: (outcome) => {
      setRefreshMessage({ type: "success", text: mdsRefreshOutcomeMessage(outcome) });
      void queryClient.invalidateQueries({ queryKey: ["mds-status"] });
    },
    onError: (err: unknown) => {
      setRefreshMessage({ type: "error", text: getApiErrorMessage(err) });
    },
  });

  return (
    <SectionCard
      title="FIDO MDS3 status"
      action={
        canRefresh ? (
          <Button
            size="sm"
            variant="outline"
            onClick={() => {
              setRefreshMessage(null);
              refreshMutation.mutate();
            }}
            disabled={refreshMutation.isPending}
          >
            {refreshMutation.isPending ? (
              <Loader2 size={14} className="animate-spin" aria-hidden="true" />
            ) : (
              <RefreshCw size={14} aria-hidden="true" />
            )}
            Refresh now
          </Button>
        ) : undefined
      }
    >
      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading&hellip;</p>
      ) : error ? (
        <p role="alert" className="text-sm text-destructive">
          Failed to load MDS status.
        </p>
      ) : !status || status.no === null ? (
        <p className="text-sm text-muted-foreground">
          MDS has never been ingested on this deployment. Attestation policies
          that need MDS metadata (certification level, revocation status)
          will treat every AAGUID as unknown until a refresh succeeds.
        </p>
      ) : (
        <div className="grid gap-4 sm:grid-cols-2">
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
              Serial (no.)
            </p>
            <p className="text-sm text-foreground font-medium">{status.no}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
              Entries
            </p>
            <p className="text-sm text-foreground font-medium">
              {status.entry_count.toLocaleString()}
            </p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
              Next update
            </p>
            <p className="text-sm text-foreground font-medium">
              {status.next_update ?? "—"}
            </p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
              Last refreshed
            </p>
            <p className="text-sm text-foreground font-medium">
              {status.last_refreshed_at
                ? formatDateTime(status.last_refreshed_at)
                : "—"}
            </p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wide mb-0.5">
              Staleness
            </p>
            <span
              className={
                status.stale
                  ? "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-amber-500/15 text-amber-400 border border-amber-500/30"
                  : "inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-emerald-500/15 text-emerald-400 border border-emerald-500/30"
              }
            >
              {status.stale ? "Stale — past next_update" : "Fresh"}
            </span>
          </div>
        </div>
      )}

      {refreshMessage && (
        <div
          role="alert"
          className={
            refreshMessage.type === "success"
              ? "flex items-center gap-2 mt-4 p-3 rounded-md bg-emerald-400/10 border border-emerald-400/30 text-emerald-400 text-sm"
              : "flex items-center gap-2 mt-4 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
          }
        >
          {refreshMessage.type === "success" ? (
            <CheckCircle2 size={16} />
          ) : (
            <AlertCircle size={16} />
          )}
          <span>{refreshMessage.text}</span>
        </div>
      )}
    </SectionCard>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Main page
// ─────────────────────────────────────────────────────────────────────────────

export function AttestationPolicyPage() {
  const tenantId = useAuthStore((s) => s.user?.tenant_id);
  const { can } = usePermissions();
  const queryClient = useQueryClient();

  const [editing, setEditing] = useState(false);
  const [formOverrides, setFormOverrides] = useState<Partial<PolicyForm>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<{
    type: "success" | "error";
    message: string;
  } | null>(null);

  const {
    data: policy,
    isLoading,
    error: loadError,
  } = useQuery({
    queryKey: ["webauthn-attestation-policy", tenantId],
    queryFn: () => webauthnPolicyService.getPolicy(tenantId!),
    enabled: !!tenantId,
  });

  const form = useMemo<PolicyForm | null>(() => {
    if (!policy) return null;
    return { ...policyToForm(policy), ...formOverrides };
  }, [policy, formOverrides]);

  const saveMutation = useMutation({
    mutationFn: (next: WebauthnAttestationPolicy) =>
      webauthnPolicyService.setPolicy(tenantId!, next),
    onSuccess: () => {
      // Also refreshes the compliance report beside the form, which is the
      // server's verdict on this very policy — see `INVALIDATION_GRAPH`.
      invalidateEntity(queryClient, "webauthn-attestation-policy");
      setFormOverrides({});
      setEditing(false);
      setFormError(null);
      setFeedback({ type: "success", message: "Attestation policy saved." });
      setTimeout(() => setFeedback(null), 4000);
    },
    onError: (err: unknown) => {
      setFormError(getApiErrorMessage(err));
    },
  });

  function setField<K extends keyof PolicyForm>(key: K, value: PolicyForm[K]) {
    setFormOverrides((prev) => ({ ...prev, [key]: value }));
  }

  function handleSave() {
    if (!form) return;
    setFormError(null);
    const result = formToPolicy(form);
    if ("error" in result) {
      setFormError(result.error);
      return;
    }
    setFeedback(null);
    saveMutation.mutate(result.policy);
  }

  function handleCancel() {
    setFormOverrides({});
    setFormError(null);
    setEditing(false);
  }

  const canWrite = can("webauthn_policy:write");
  const canViewMds = can("ca_certificates:list");
  const canRefreshMds = can("ca_certificates:generate");

  return (
    <div className="space-y-6 max-w-3xl">
      <PageHeader
        title="WebAuthn Attestation Policy"
        description={
          'Restrict which security key or passkey models may register. ' +
          'The default (mode: none) is unchanged from today’s behavior — ' +
          'every authenticator accepted, no MDS lookups.'
        }
      />

      {feedback && (
        <div
          role="alert"
          className={
            feedback.type === "success"
              ? "flex items-center gap-2 p-3 rounded-md bg-emerald-400/10 border border-emerald-400/30 text-emerald-400 text-sm"
              : "flex items-center gap-2 p-3 rounded-md bg-destructive/10 border border-destructive/30 text-destructive text-sm"
          }
        >
          {feedback.type === "success" ? (
            <CheckCircle2 size={16} />
          ) : (
            <AlertCircle size={16} />
          )}
          <span>{feedback.message}</span>
        </div>
      )}

      <SectionCard
        title="Policy"
        action={
          !editing && canWrite ? (
            <Button variant="outline" size="sm" onClick={() => setEditing(true)}>
              <Pencil size={14} aria-hidden="true" />
              Edit Policy
            </Button>
          ) : undefined
        }
      >
        {isLoading || !form ? (
          loadError ? (
            <p role="alert" className="text-sm text-destructive">
              Failed to load the attestation policy. Please refresh the page.
            </p>
          ) : (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="animate-spin text-primary" size={24} />
            </div>
          )
        ) : editing ? (
          <>
            <PolicyEditor
              form={form}
              onChange={setField}
              error={formError}
            />
            <div className="flex gap-3 pt-4 mt-2 border-t border-primary/10">
              <Button
                size="sm"
                onClick={handleSave}
                disabled={saveMutation.isPending}
              >
                {saveMutation.isPending ? (
                  <Loader2 size={14} className="animate-spin" aria-hidden="true" />
                ) : null}
                Save Policy
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleCancel}
                disabled={saveMutation.isPending}
              >
                <X size={14} aria-hidden="true" />
                Cancel
              </Button>
            </div>
          </>
        ) : (
          <PolicySummary policy={policy ?? DEFAULT_ATTESTATION_POLICY} />
        )}
      </SectionCard>

      {tenantId && <ComplianceReportPanel tenantId={tenantId} />}

      {canViewMds ? (
        <MdsStatusPanel canRefresh={canRefreshMds} />
      ) : (
        <SectionCard title="FIDO MDS3 status">
          <p className="text-sm text-muted-foreground">
            You don&rsquo;t have permission to view MDS ingestion status.
          </p>
        </SectionCard>
      )}
    </div>
  );
}

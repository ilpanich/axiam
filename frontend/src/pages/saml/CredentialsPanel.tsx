import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowUpCircle, CheckCircle2, Loader2, Plus, ShieldOff } from "lucide-react";
import {
  SAML_IDP_SLOTS,
  VALIDITY_DAYS_DEFAULT,
  VALIDITY_DAYS_MAX,
  VALIDITY_DAYS_MIN,
  samlService,
  type SamlIdpCredential,
  type SamlIdpSlot,
} from "@/services/saml";
import { certificateService } from "@/services/certificates";
import { useAuthStore } from "@/stores/auth";
import { usePermissions } from "@/hooks/usePermissions";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { SectionCard } from "@/components/shared";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { formatDate } from "@/lib/utils";
import { invalidateEntity } from "@/lib/queryInvalidation";
import { CopyValue } from "./CopyValue";
import { samlErrorMessage } from "./samlErrors";
import { parseValidityDays } from "./samlForm";

const SELECT_CLASS =
  "flex h-9 w-full rounded-md border border-input bg-background/50 px-3 py-1 text-sm";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function StatusBadge({ status }: { status: string }) {
  const variant =
    status === "active" ? "default" : status === "next" ? "accent" : "outline";
  return <Badge variant={variant}>{status}</Badge>;
}

/**
 * What retiring `credential` does, said before the confirmation asks. Retiring
 * the **active** credential with no successor stops SAML sign-on for the whole
 * tenant at once (contract §29.3 rule 7): it is the incident response to a
 * leaked key, and also a way to take every service provider down by accident.
 */
function retireWarning(credential: SamlIdpCredential, credentials: SamlIdpCredential[]): string {
  if (credential.status === "active") {
    const hasNext = credentials.some((c) => c.status === "next");
    return (
      "Retiring the active credential stops SAML sign-on for the whole tenant at once, for every " +
      "service provider, until a new active credential exists. Its key is destroyed and it " +
      "disappears from the metadata, so it cannot be undone. Do this when the key may have " +
      "leaked." +
      (hasNext
        ? " A next credential exists but is not signing yet, and retiring does not promote it: to rotate without a gap, use Promote instead."
        : " There is no next credential to take over.")
    );
  }
  return (
    "Retiring the next credential removes it from the metadata and destroys its key. " +
    "Sign-on is not affected: the active credential keeps signing."
  );
}

/**
 * The tenant's IdP signing credential (contract §29): what is issued, and the
 * three moves that change what signs assertions. All three need
 * `saml_idp:credential`, which is kept apart from `saml_sp:write` because one
 * call can change or stop sign-on at every service provider of the tenant.
 */
export function CredentialsPanel({ tenantId }: { tenantId: string }) {
  const { can } = usePermissions();
  const queryClient = useQueryClient();
  const canManage = can("saml_idp:credential");

  const [issuing, setIssuing] = useState(false);
  const [promoting, setPromoting] = useState<SamlIdpCredential | null>(null);
  const [retiring, setRetiring] = useState<SamlIdpCredential | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [feedback, setFeedback] = useState<string | null>(null);

  const {
    data: credentials,
    isLoading,
    error: loadError,
  } = useQuery({
    queryKey: ["saml-idp-credentials", tenantId],
    queryFn: () => samlService.listIdpCredentials(tenantId),
  });
  const list = credentials ?? [];

  function changed(message: string) {
    invalidateEntity(queryClient, "saml-idp-credentials");
    setActionError(null);
    setFeedback(message);
  }

  const promote = useMutation({
    mutationFn: (c: SamlIdpCredential) => samlService.promoteIdpCredential(tenantId, c.id),
    onSuccess: (result) => {
      setPromoting(null);
      changed(
        result.retired
          ? "The next credential is now active and the previous one is retired."
          : "The next credential is now active.",
      );
    },
    onError: (err: unknown) => setActionError(samlErrorMessage(err, "Promote failed.")),
  });

  const retire = useMutation({
    mutationFn: (c: SamlIdpCredential) => samlService.retireIdpCredential(tenantId, c.id),
    onSuccess: (_c, retired) => {
      setRetiring(null);
      changed(
        retired.status === "active"
          ? "The active credential is retired. SAML sign-on is stopped until a new active credential exists."
          : "The credential is retired.",
      );
    },
    onError: (err: unknown) => setActionError(samlErrorMessage(err, "Retire failed.")),
  });

  const columns: Column<SamlIdpCredential>[] = [
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      key: "fingerprint",
      header: "SHA-256 fingerprint",
      render: (row) => <CopyValue label="fingerprint" value={row.fingerprint} />,
    },
    {
      key: "validity",
      header: "Valid",
      render: (row) => (
        <span className="text-xs text-foreground/70">
          {formatDate(row.not_before)} to {formatDate(row.not_after)}
        </span>
      ),
    },
    {
      key: "serial",
      header: "Serial",
      render: (row) => (
        <span className="block max-w-[160px] truncate font-mono text-xs text-foreground/70" title={row.serial}>
          {row.serial}
        </span>
      ),
    },
    ...(canManage
      ? [
          {
            key: "actions",
            header: "Actions",
            render: (row: SamlIdpCredential) => (
              <div className="flex gap-1">
                {row.status === "next" && (
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label={`Promote credential ${row.fingerprint.slice(0, 12)}`}
                    onClick={() => {
                      setActionError(null);
                      setPromoting(row);
                    }}
                  >
                    <ArrowUpCircle size={14} aria-hidden="true" />
                    Promote
                  </Button>
                )}
                {(row.status === "next" || row.status === "active") && (
                  <Button
                    variant="ghost"
                    size="sm"
                    aria-label={`Retire credential ${row.fingerprint.slice(0, 12)}`}
                    onClick={() => {
                      setActionError(null);
                      setRetiring(row);
                    }}
                  >
                    <ShieldOff size={14} aria-hidden="true" />
                    Retire
                  </Button>
                )}
              </div>
            ),
          } satisfies Column<SamlIdpCredential>,
        ]
      : []),
  ];

  return (
    <SectionCard
      title="Signing credentials"
      action={
        canManage ? (
          <Button
            size="sm"
            onClick={() => {
              setFeedback(null);
              setIssuing(true);
            }}
          >
            <Plus size={14} aria-hidden="true" />
            Issue a credential
          </Button>
        ) : undefined
      }
    >
      <p className="mb-4 text-sm text-muted-foreground">
        The certificate AXIAM signs assertions with, issued from one of your organization&rsquo;s
        CAs. The private key is generated on the server and never leaves it. To rotate without an
        outage: issue into <strong>next</strong>, wait until every service provider has refreshed
        the metadata (which publishes both), then promote it.
      </p>

      {feedback && (
        <p
          role="status"
          className="mb-4 flex items-center gap-2 rounded-md border border-emerald-400/30 bg-emerald-400/10 p-3 text-sm text-emerald-400"
        >
          <CheckCircle2 size={16} aria-hidden="true" />
          <span>{feedback}</span>
        </p>
      )}

      {loadError ? (
        <p role="alert" className="text-sm text-destructive">
          {samlErrorMessage(loadError, "Failed to load the signing credentials.")}
        </p>
      ) : (
        <DataTable
          columns={columns}
          data={list}
          isLoading={isLoading}
          getRowKey={(row) => row.id}
          emptyMessage="No signing credential has been issued yet. Without one the metadata is not served and no sign-on can succeed."
        />
      )}

      {issuing && (
        <IssueDialog
          tenantId={tenantId}
          credentials={list}
          onClose={() => setIssuing(false)}
          onIssued={(slot) => {
            setIssuing(false);
            changed(`A credential was issued into the ${slot} slot.`);
          }}
        />
      )}

      <ConfirmDialog
        open={promoting !== null}
        onClose={() => setPromoting(null)}
        onConfirm={() => promoting && promote.mutate(promoting)}
        title="Promote the next credential?"
        description="The next credential becomes the one that signs, and the current active credential is retired and its key destroyed, in one step. Every service provider must already have fetched the metadata that published the next credential, or it will reject assertions signed with it. Wait at least the metadata cache time (one hour) and the service providers' own refresh interval after issuing it."
        confirmLabel="Promote"
        isLoading={promote.isPending}
        error={actionError}
      />

      <ConfirmDialog
        open={retiring !== null}
        onClose={() => setRetiring(null)}
        onConfirm={() => retiring && retire.mutate(retiring)}
        title={
          retiring?.status === "active"
            ? "Retire the active credential?"
            : "Retire the next credential?"
        }
        description={retiring ? retireWarning(retiring, list) : ""}
        confirmLabel="Retire"
        isLoading={retire.isPending}
        error={actionError}
      />
    </SectionCard>
  );
}

function IssueDialog({
  tenantId,
  credentials,
  onClose,
  onIssued,
}: {
  tenantId: string;
  credentials: SamlIdpCredential[];
  onClose: () => void;
  onIssued: (slot: SamlIdpSlot) => void;
}) {
  const queryClient = useQueryClient();
  const orgId = useAuthStore((s) => s.user?.org_id);

  const occupied = (slot: SamlIdpSlot) => credentials.some((c) => c.status === slot);
  const [slot, setSlot] = useState<SamlIdpSlot>(occupied("active") ? "next" : "active");
  const [caId, setCaId] = useState("");
  const [days, setDays] = useState(String(VALIDITY_DAYS_DEFAULT));
  const [problem, setProblem] = useState<string | null>(null);

  const cas = useQuery({
    queryKey: ["ca-certificates", orgId, "signing"],
    queryFn: () => certificateService.listSigningCas(orgId),
    enabled: !!orgId,
  });
  // Without the right to list CAs the picker cannot be filled; the id can still be typed.
  const manualCa = !orgId || cas.isError;

  const issue = useMutation({
    mutationFn: (body: { issuer_ca_id: string; slot: SamlIdpSlot; validity_days: number }) =>
      samlService.issueIdpCredential(tenantId, body),
    onSuccess: (_c, body) => {
      invalidateEntity(queryClient, "saml-idp-credentials");
      onIssued(body.slot);
    },
    onError: (err: unknown) => setProblem(samlErrorMessage(err, "The credential could not be issued.")),
  });

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setProblem(null);
    const issuer = caId.trim();
    if (!issuer) {
      setProblem(manualCa ? "Enter the id of the issuing CA." : "Choose the issuing CA.");
      return;
    }
    if (manualCa && !UUID.test(issuer)) {
      setProblem("The issuing CA id must be a UUID.");
      return;
    }
    const validity = parseValidityDays(days);
    if (!validity.ok) {
      setProblem(validity.reason);
      return;
    }
    issue.mutate({ issuer_ca_id: issuer, slot, validity_days: validity.days });
  }

  const noCas = !manualCa && !cas.isLoading && (cas.data?.length ?? 0) === 0;

  return (
    <FormDialog
      open
      onClose={onClose}
      title="Issue a signing credential"
      onSubmit={handleSubmit}
      isLoading={issue.isPending}
      submitLabel="Issue"
      error={problem ?? undefined}
    >
      <div className="space-y-1.5">
        <Label htmlFor="saml-issue-ca">Issuing CA</Label>
        {manualCa ? (
          <>
            <Input
              id="saml-issue-ca"
              value={caId}
              onChange={(e) => setCaId(e.target.value)}
              autoComplete="off"
              spellCheck={false}
              placeholder="CA id (UUID)"
            />
            <p className="text-xs text-muted-foreground">
              {orgId
                ? "The CA list could not be loaded with your permissions; enter the id of an active signing CA of your organization."
                : "Enter the id of an active signing CA of your organization."}
            </p>
          </>
        ) : (
          <>
            <select
              id="saml-issue-ca"
              value={caId}
              onChange={(e) => setCaId(e.target.value)}
              className={SELECT_CLASS}
            >
              <option value="">{cas.isLoading ? "Loading CAs…" : "Choose a CA…"}</option>
              {(cas.data ?? []).map((ca) => (
                <option key={ca.id} value={ca.id}>
                  {ca.subject}
                </option>
              ))}
            </select>
            {noCas && (
              <p className="text-xs text-amber-300">
                Your organization has no active CA. An organization administrator must create one first.
              </p>
            )}
          </>
        )}
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="saml-issue-slot">Slot</Label>
        <select
          id="saml-issue-slot"
          value={slot}
          onChange={(e) => setSlot(e.target.value as SamlIdpSlot)}
          className={SELECT_CLASS}
        >
          {SAML_IDP_SLOTS.map((s) => (
            <option key={s} value={s}>
              {s}
              {occupied(s) ? " (occupied)" : ""}
            </option>
          ))}
        </select>
        <p className="text-xs text-muted-foreground">
          <strong>active</strong> signs from now on. <strong>next</strong> is published in the
          metadata but does not sign until you promote it. A slot that is already filled is refused.
        </p>
      </div>

      <div className="space-y-1.5">
        <Label htmlFor="saml-issue-days">Validity (days)</Label>
        <Input
          id="saml-issue-days"
          inputMode="numeric"
          value={days}
          onChange={(e) => setDays(e.target.value)}
        />
        <p className="text-xs text-muted-foreground">
          {VALIDITY_DAYS_MIN} to {VALIDITY_DAYS_MAX}, and never beyond the CA&rsquo;s own expiry.
        </p>
      </div>

      {issue.isPending && (
        <p role="status" className="flex items-center gap-2 text-sm text-muted-foreground">
          <Loader2 size={14} className="animate-spin" aria-hidden="true" />
          Generating a 4096-bit key. This can take several seconds; do not submit again.
        </p>
      )}
    </FormDialog>
  );
}

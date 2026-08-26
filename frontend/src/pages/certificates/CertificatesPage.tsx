import { useState } from "react";
import { Link } from "react-router";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  certificateService,
  type Certificate,
  type CertificateStatus,
  type CertificateType,
  type KeyAlgorithm,
  type GenerateCertificatePayload,
} from "@/services/certificates";
import { useAuthStore } from "@/stores/auth";
import { orgService } from "@/services/organizations";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SecretRevealModal } from "@/components/SecretRevealModal";
import { CertificateViewDialog } from "@/components/CertificateViewDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ShieldPlus } from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";
import { invalidateEntity } from "@/lib/queryInvalidation";

/**
 * The CA/Browser Forum leaf maximum, mirroring `MAX_LEAF_CERT_VALIDITY_DAYS` in
 * `axiam-pki`.
 *
 * Duplicated here rather than fetched: it is a Baseline Requirements constant,
 * not deployment configuration, and the server enforces it regardless. The
 * value's only job on this side is to stop the form offering a number that will
 * be refused.
 */
const MAX_LEAF_VALIDITY_DAYS = 825;

/**
 * Map the backend's PascalCase `CertificateStatus` onto the lowercase
 * variants accepted by the shared `StatusBadge`. `Expired` has no badge
 * variant of its own, so it renders with the neutral `inactive` style.
 */
function badgeStatus(status: CertificateStatus): "active" | "revoked" | "inactive" {
  switch (status) {
    case "Active":
      return "active";
    case "Revoked":
      return "revoked";
    case "Expired":
      return "inactive";
  }
}

function isExpiringSoon(notAfter: string): boolean {
  const diff = new Date(notAfter).getTime() - Date.now();
  return diff > 0 && diff < 30 * 24 * 60 * 60 * 1000;
}

// ─── Generate form fields ─────────────────────────────────────────────────────

interface CaOption {
  id: string;
  subject: string;
}

interface GenerateFieldsProps {
  subject: string;
  certType: CertificateType;
  keyAlgorithm: KeyAlgorithm;
  validityDays: number;
  issuerCaId: string;
  caOptions: CaOption[];
  caLoading: boolean;
  onSubjectChange: (v: string) => void;
  onCertTypeChange: (v: CertificateType) => void;
  onKeyAlgorithmChange: (v: KeyAlgorithm) => void;
  onValidityDaysChange: (v: number) => void;
  onIssuerCaIdChange: (v: string) => void;
  /** Where to send an operator who has no CA yet; `null` while the org is unknown. */
  caSetupHref: string | null;
}

function GenerateFields({
  subject,
  certType,
  keyAlgorithm,
  validityDays,
  issuerCaId,
  caOptions,
  caLoading,
  onSubjectChange,
  onCertTypeChange,
  onKeyAlgorithmChange,
  onValidityDaysChange,
  onIssuerCaIdChange,
  caSetupHref,
}: GenerateFieldsProps) {
  const noCas = !caLoading && caOptions.length === 0;

  // The issuing CA's remaining life, floored at one day and capped by the
  // CA/Browser Forum leaf maximum the server enforces (825 days). Rounded down
  // to whole days for the same reason the server rounds down: a CA with 36
  // hours left can grant one day, not two.
  // `now` is captured once, in a lazy initialiser, rather than read on every
  // render: reading the clock during render is impure and makes the cap drift
  // between renders for no benefit — the number is in whole days and the form
  // is open for seconds.
  const [now] = useState(() => Date.now());
  const selectedCa = caOptions.find((ca) => ca.id === issuerCaId);
  // `NaN` when the CA carries no parseable expiry. Every real response does,
  // but a form that throws `RangeError: Invalid time value` and blanks the page
  // is a worse answer to a malformed field than falling back to the standards
  // cap, so both the number below and the hint are guarded on it.
  const caExpiresAt = selectedCa ? new Date(selectedCa.not_after).getTime() : NaN;
  const caExpiryKnown = Number.isFinite(caExpiresAt);
  const maxValidityDays = caExpiryKnown
    ? Math.max(
        1,
        Math.min(
          MAX_LEAF_VALIDITY_DAYS,
          Math.floor((caExpiresAt - now) / 86_400_000)
        )
      )
    : MAX_LEAF_VALIDITY_DAYS;

  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="cert-issuer-ca">Issuing CA *</Label>
        <select
          id="cert-issuer-ca"
          value={issuerCaId}
          onChange={(e) => onIssuerCaIdChange(e.target.value)}
          disabled={caLoading || noCas}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40 disabled:opacity-50"
        >
          {caLoading && <option value="">Loading CAs…</option>}
          {noCas && <option value="">No active CA available</option>}
          {!caLoading &&
            caOptions.map((ca) => (
              <option key={ca.id} value={ca.id}>
                {ca.subject}
              </option>
            ))}
        </select>
        {noCas && (
          // A bare "create a CA first" left an operator on a dead end: nothing
          // on this page says where CAs live, and the section that issues them
          // is two levels down under a different top-level nav item.
          <div
            role="note"
            className="space-y-1.5 rounded-md border border-amber-500/30 bg-amber-500/8 p-3 text-sm text-amber-300"
          >
            <p>
              <strong>This organization has no active CA.</strong> Every
              certificate AXIAM issues is signed by one, so there is nothing to
              issue against yet.
            </p>
            <p className="text-xs">
              Create one under{" "}
              {caSetupHref ? (
                <Link
                  to={caSetupHref}
                  className="underline hover:text-amber-200"
                >
                  Organizations → your organization → CA Certificates
                </Link>
              ) : (
                <span className="font-medium">
                  Organizations → your organization → CA Certificates
                </span>
              )}
              . Generating a CA needs <code>ca_certificates:generate</code>; the
              private key is generated server-side, encrypted at rest and never
              returned. A revoked or expired CA does not count — this list only
              offers CAs whose status is Active.
            </p>
          </div>
        )}
      </div>

      <div className="space-y-2">
        <Label htmlFor="cert-subject">Subject *</Label>
        <Input
          id="cert-subject"
          value={subject}
          onChange={(e) => onSubjectChange(e.target.value)}
          placeholder="CN=device-001"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="cert-type">Certificate Type</Label>
        <select
          id="cert-type"
          value={certType}
          onChange={(e) => onCertTypeChange(e.target.value as CertificateType)}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40"
        >
          <option value="User">User</option>
          <option value="Service">Service</option>
          <option value="Device">IoT Device</option>
        </select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="cert-key-algorithm">Key Algorithm</Label>
        <select
          id="cert-key-algorithm"
          value={keyAlgorithm}
          onChange={(e) =>
            onKeyAlgorithmChange(e.target.value as KeyAlgorithm)
          }
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40"
        >
          <option value="Rsa4096">RSA-4096</option>
          <option value="Ed25519">Ed25519</option>
        </select>
      </div>

      <div className="space-y-2">
        <Label htmlFor="cert-validity-days">Validity Days</Label>
        <Input
          id="cert-validity-days"
          type="number"
          min={1}
          max={maxValidityDays}
          value={validityDays}
          onChange={(e) => onValidityDaysChange(Number(e.target.value))}
          aria-describedby="cert-validity-help"
        />
        {/* A certificate cannot outlive the CA that signed it — past the
            issuer's notAfter the chain stops validating, so the extra days are
            time the holder believes they have and does not. The server refuses
            such a request outright (it used to truncate silently); saying the
            limit here means an operator picks a real number instead of
            discovering it on submit. */}
        <p id="cert-validity-help" className="text-xs text-muted-foreground">
          {selectedCa && caExpiryKnown ? (
            <>
              Up to <strong>{maxValidityDays}</strong> day
              {maxValidityDays === 1 ? "" : "s"} — this CA expires on{" "}
              {formatDate(selectedCa.not_after)}, and a certificate cannot
              outlive its issuer.
            </>
          ) : (
            <>Capped by the CA/Browser Forum limit and by the issuing CA's own expiry.</>
          )}
        </p>
      </div>
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function CertificatesPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  const orgSlug = useAuthStore((s) => s.orgSlug);

  const { data: certificates = [], isLoading } = useQuery({
    queryKey: ["certificates"],
    queryFn: () => certificateService.list(),
  });

  // Active CA certificates available to sign new certs (hard prerequisite).
  const { data: caCertificates = [], isLoading: caLoading } = useQuery({
    queryKey: ["ca-certificates", orgSlug],
    queryFn: () => certificateService.listSigningCas(orgSlug ?? undefined),
  });
  const caOptions: CaOption[] = caCertificates.map((ca) => ({
    id: ca.id,
    subject: ca.subject,
  }));

  // Where CAs are issued. The org detail page's CA section is the only place
  // in the UI that generates one, and nothing on this page pointed at it. The
  // org id is resolved the same way `listSigningCas` resolves it — from the
  // caller's own organization, the only one that endpoint returns.
  const { data: caSetupHref = null } = useQuery({
    queryKey: ["ca-setup-href", orgSlug],
    queryFn: async () => {
      const orgs = await orgService.list();
      const org = orgSlug ? orgs.find((o) => o.slug === orgSlug) : orgs[0];
      return org ? `/organizations/${org.id}` : null;
    },
  });

  // ─── Generate state ────────────────────────────────────────────────────────
  const [generateOpen, setGenerateOpen] = useState(false);
  const [subject, setSubject] = useState("");
  const [certType, setCertType] = useState<CertificateType>("User");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("Rsa4096");
  const [validityDays, setValidityDays] = useState(365);
  const [issuerCaId, setIssuerCaId] = useState("");
  const [generateError, setGenerateError] = useState("");

  // ─── Secret reveal state ───────────────────────────────────────────────────
  const [secretOpen, setSecretOpen] = useState(false);
  const [privateKeyPem, setPrivateKeyPem] = useState("");

  // ─── View state ────────────────────────────────────────────────────────────
  // The public certificate, which is not a secret and is the thing that has to
  // be distributed. The list endpoint already returns `public_cert_pem` for
  // every row, so this needs no extra request.
  const [viewCert, setViewCert] = useState<Certificate | null>(null);
  /** Shown as soon as the private-key reveal is acknowledged. */
  const [pendingView, setPendingView] = useState<Certificate | null>(null);

  const generateMutation = useMutation({
    mutationFn: (payload: GenerateCertificatePayload) =>
      certificateService.generate(payload),
    onSuccess: (resp) => {
      invalidateEntity(queryClient, "certificates");
      setGenerateOpen(false);
      resetGenerateForm();
      setPrivateKeyPem(resp.private_key_pem);
      setSecretOpen(true);
      // Queued behind the one-time key reveal: once the operator acknowledges
      // that, they land on the certificate itself with a download button —
      // which is what they came here to obtain and what the key is useless
      // without.
      setPendingView(resp);
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      setGenerateError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function resetGenerateForm() {
    setSubject("");
    setCertType("User");
    setKeyAlgorithm("Rsa4096");
    setValidityDays(365);
    setIssuerCaId("");
    setGenerateError("");
  }

  function openGenerate() {
    resetGenerateForm();
    // Default to the first active CA, if any.
    setIssuerCaId(caOptions[0]?.id ?? "");
    setGenerateOpen(true);
  }

  function handleGenerateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setGenerateError("");
    if (!issuerCaId) {
      setGenerateError("An active CA certificate is required.");
      return;
    }
    if (!subject.trim()) {
      setGenerateError("Subject is required.");
      return;
    }
    const payload: GenerateCertificatePayload = {
      issuer_ca_id: issuerCaId,
      subject: subject.trim(),
      cert_type: certType,
      key_algorithm: keyAlgorithm,
      validity_days: validityDays,
    };
    generateMutation.mutate(payload);
  }

  // ─── Revoke state ──────────────────────────────────────────────────────────
  const [revokeTarget, setRevokeTarget] = useState<Certificate | null>(null);

  const revokeMutation = useMutation({
    mutationFn: (id: string) => certificateService.revoke(id),
    onSuccess: () => {
      invalidateEntity(queryClient, "certificates");
      setRevokeTarget(null);
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<Certificate>[] = [
    {
      key: "subject",
      header: "Subject",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.subject}</span>
      ),
    },
    {
      key: "cert_type",
      header: "Type",
      render: (row) => (
        <span className="text-muted-foreground text-sm">{row.cert_type}</span>
      ),
    },
    {
      key: "key_algorithm",
      header: "Key Algorithm",
      render: (row) => (
        <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-muted-foreground">
          {row.key_algorithm}
        </code>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusBadge status={badgeStatus(row.status)} />,
    },
    {
      key: "not_after",
      header: "Expires At",
      render: (row) => (
        <span
          className={cn(
            "text-sm",
            row.status === "Active" && isExpiringSoon(row.not_after)
              ? "text-amber-400 font-medium"
              : "text-muted-foreground"
          )}
        >
          {formatDate(row.not_after)}
        </span>
      ),
    },
    {
      key: "fingerprint",
      header: "Fingerprint",
      render: (row) => (
        <code className="text-xs text-muted-foreground" title={row.fingerprint}>
          {row.fingerprint.length > 17
            ? `${row.fingerprint.slice(0, 17)}…`
            : row.fingerprint}
        </code>
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
      width: "w-40",
      render: (row) => (
        <div className="flex items-center gap-2">
          {/* Available whatever the status: a revoked or expired certificate is
              still the one a relying party is asking about, and refusing to
              show it is what sends an operator to the database. */}
          <button
            aria-label={`View certificate for ${row.subject}`}
            onClick={() => setViewCert(row)}
            className="px-2.5 py-1 rounded text-xs font-medium border border-white/10 text-muted-foreground transition-colors hover:text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40"
          >
            View
          </button>
          <button
            aria-label={`Revoke certificate for ${row.subject}`}
            disabled={row.status !== "Active"}
            onClick={() => setRevokeTarget(row)}
            className={cn(
              "px-2.5 py-1 rounded text-xs font-medium border transition-colors focus:outline-hidden focus:ring-2 focus:ring-primary/40",
              row.status !== "Active"
                ? "border-white/5 text-muted-foreground/40 cursor-not-allowed"
                : "border-red-500/30 text-red-400 hover:bg-red-500/10 hover:border-red-500/50"
            )}
          >
            Revoke
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="Certificates"
        description="Manage X.509 certificates for users, services, and IoT devices."
        action={
          <Button onClick={openGenerate}>
            <ShieldPlus size={16} />
            Generate Certificate
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={certificates}
        isLoading={isLoading}
        emptyMessage="No certificates found."
      />

      {/* Generate dialog */}
      <FormDialog
        open={generateOpen}
        onClose={() => {
          setGenerateOpen(false);
          resetGenerateForm();
        }}
        title="Generate Certificate"
        onSubmit={handleGenerateSubmit}
        isLoading={generateMutation.isPending}
        submitLabel="Generate"
        error={generateError}
        errorId="certificate-generate-error"
      >
        <GenerateFields
          subject={subject}
          certType={certType}
          keyAlgorithm={keyAlgorithm}
          validityDays={validityDays}
          issuerCaId={issuerCaId}
          caOptions={caOptions}
          caLoading={caLoading}
          onSubjectChange={setSubject}
          onCertTypeChange={setCertType}
          onKeyAlgorithmChange={setKeyAlgorithm}
          onValidityDaysChange={setValidityDays}
          onIssuerCaIdChange={setIssuerCaId}
          caSetupHref={caSetupHref}
        />
      </FormDialog>

      {/* Private key reveal — shown once after generation */}
      <SecretRevealModal
        open={secretOpen}
        onClose={() => {
          setSecretOpen(false);
          setPrivateKeyPem("");
          if (pendingView) {
            setViewCert(pendingView);
            setPendingView(null);
          }
        }}
        title="Certificate Generated"
        description="Your certificate has been generated. Save the private key now — it will not be shown again. The certificate itself stays available from the list."
        secrets={[{ label: "Private Key (PEM)", value: privateKeyPem, mono: true }]}
      />

      {/* The public certificate — readable and downloadable at any time */}
      <CertificateViewDialog
        open={viewCert !== null}
        onClose={() => setViewCert(null)}
        subject={viewCert?.subject ?? ""}
        publicCertPem={viewCert?.public_cert_pem ?? ""}
        details={
          viewCert
            ? [
                { label: "Subject", value: viewCert.subject },
                { label: "Type", value: viewCert.cert_type },
                {
                  label: "Key algorithm",
                  value: (
                    <code className="text-xs">{viewCert.key_algorithm}</code>
                  ),
                },
                {
                  label: "Status",
                  value: <StatusBadge status={badgeStatus(viewCert.status)} />,
                },
                { label: "Valid from", value: formatDate(viewCert.not_before) },
                { label: "Expires", value: formatDate(viewCert.not_after) },
                {
                  label: "Fingerprint",
                  value: (
                    <code className="text-xs">{viewCert.fingerprint}</code>
                  ),
                },
                {
                  label: "Issuing CA",
                  value: (
                    <code className="text-xs">{viewCert.issuer_ca_id}</code>
                  ),
                },
              ]
            : []
        }
      />

      {/* Revoke confirm */}
      <ConfirmDialog
        open={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={() => revokeTarget && revokeMutation.mutate(revokeTarget.id)}
        title="Revoke Certificate"
        description={`Are you sure you want to revoke the certificate for "${revokeTarget?.subject}"? This action cannot be undone.`}
        isLoading={revokeMutation.isPending}
        confirmLabel="Revoke"
      />
    </div>
  );
}

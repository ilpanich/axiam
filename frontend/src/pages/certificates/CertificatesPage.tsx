import { useState } from "react";
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
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SecretRevealModal } from "@/components/SecretRevealModal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ShieldPlus } from "lucide-react";
import { cn, formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";

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
  error?: string;
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
  error,
}: GenerateFieldsProps) {
  const noCas = !caLoading && caOptions.length === 0;

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
          <p className="text-sm text-amber-400">
            Create an organization CA certificate first — certificates must be
            signed by an active CA.
          </p>
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
          max={3650}
          value={validityDays}
          onChange={(e) => onValidityDaysChange(Number(e.target.value))}
        />
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
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

  const generateMutation = useMutation({
    mutationFn: (payload: GenerateCertificatePayload) =>
      certificateService.generate(payload),
    onSuccess: (resp) => {
      void queryClient.invalidateQueries({ queryKey: ["certificates"] });
      setGenerateOpen(false);
      resetGenerateForm();
      setPrivateKeyPem(resp.private_key_pem);
      setSecretOpen(true);
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
      void queryClient.invalidateQueries({ queryKey: ["certificates"] });
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
      width: "w-24",
      render: (row) => (
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
          error={generateError}
        />
      </FormDialog>

      {/* Private key reveal — shown once after generation */}
      <SecretRevealModal
        open={secretOpen}
        onClose={() => {
          setSecretOpen(false);
          setPrivateKeyPem("");
        }}
        title="Certificate Generated"
        description="Your certificate has been generated. Save the private key now — it will not be shown again."
        secrets={[{ label: "Private Key (PEM)", value: privateKeyPem, mono: true }]}
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

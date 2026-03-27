import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  certificateService,
  type Certificate,
  type GenerateCertificatePayload,
} from "@/services/certificates";
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
import { cn } from "@/lib/utils";
import { Textarea } from "@/components/ui/textarea";

// ─── Helpers ──────────────────────────────────────────────────────────────────

const formatDate = (iso: string) =>
  new Intl.DateTimeFormat("en-US", { dateStyle: "medium" }).format(
    new Date(iso)
  );

function isExpiringSoon(expiresAt: string): boolean {
  const diff = new Date(expiresAt).getTime() - Date.now();
  return diff > 0 && diff < 30 * 24 * 60 * 60 * 1000;
}

// ─── Generate form fields ─────────────────────────────────────────────────────

interface GenerateFieldsProps {
  commonName: string;
  keyType: "RSA4096" | "Ed25519";
  validityDays: number;
  sanDns: string;
  sanIp: string;
  onCommonNameChange: (v: string) => void;
  onKeyTypeChange: (v: "RSA4096" | "Ed25519") => void;
  onValidityDaysChange: (v: number) => void;
  onSanDnsChange: (v: string) => void;
  onSanIpChange: (v: string) => void;
  error?: string;
}

function GenerateFields({
  commonName,
  keyType,
  validityDays,
  sanDns,
  sanIp,
  onCommonNameChange,
  onKeyTypeChange,
  onValidityDaysChange,
  onSanDnsChange,
  onSanIpChange,
  error,
}: GenerateFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="cert-common-name">Common Name *</Label>
        <Input
          id="cert-common-name"
          value={commonName}
          onChange={(e) => onCommonNameChange(e.target.value)}
          placeholder="api.example.com"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="cert-key-type">Key Type</Label>
        <select
          id="cert-key-type"
          value={keyType}
          onChange={(e) => onKeyTypeChange(e.target.value as "RSA4096" | "Ed25519")}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/40"
        >
          <option value="RSA4096">RSA-4096</option>
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

      <div className="space-y-2">
        <Label htmlFor="cert-san-dns">SAN DNS Names (one per line)</Label>
        <Textarea
          id="cert-san-dns"
          value={sanDns}
          onChange={(e) => onSanDnsChange(e.target.value)}
          placeholder={"api.example.com\nwww.example.com"}
          rows={3}
          className="resize-y"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="cert-san-ip">SAN IP Addresses (one per line)</Label>
        <Textarea
          id="cert-san-ip"
          value={sanIp}
          onChange={(e) => onSanIpChange(e.target.value)}
          placeholder={"192.168.1.1\n10.0.0.1"}
          rows={2}
          className="resize-y"
        />
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function CertificatesPage() {
  const queryClient = useQueryClient();

  const { data: certificates = [], isLoading } = useQuery({
    queryKey: ["certificates"],
    queryFn: () => certificateService.list(),
  });

  // ─── Generate state ────────────────────────────────────────────────────────
  const [generateOpen, setGenerateOpen] = useState(false);
  const [commonName, setCommonName] = useState("");
  const [keyType, setKeyType] = useState<"RSA4096" | "Ed25519">("RSA4096");
  const [validityDays, setValidityDays] = useState(365);
  const [sanDns, setSanDns] = useState("");
  const [sanIp, setSanIp] = useState("");
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
      setGenerateError(
        err instanceof Error ? err.message : "Failed to generate certificate."
      );
    },
  });

  function resetGenerateForm() {
    setCommonName("");
    setKeyType("RSA4096");
    setValidityDays(365);
    setSanDns("");
    setSanIp("");
    setGenerateError("");
  }

  function handleGenerateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setGenerateError("");
    if (!commonName.trim()) {
      setGenerateError("Common name is required.");
      return;
    }
    const payload: GenerateCertificatePayload = {
      common_name: commonName.trim(),
      key_type: keyType,
      validity_days: validityDays,
    };
    const dnsLines = sanDns
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    const ipLines = sanIp
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    if (dnsLines.length > 0) payload.san_dns = dnsLines;
    if (ipLines.length > 0) payload.san_ip = ipLines;
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
  });

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<Certificate>[] = [
    {
      key: "common_name",
      header: "Common Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.common_name}</span>
      ),
    },
    {
      key: "key_type",
      header: "Key Type",
      render: (row) => (
        <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-muted-foreground">
          {row.key_type}
        </code>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusBadge status={row.status} />,
    },
    {
      key: "expires_at",
      header: "Expires At",
      render: (row) => (
        <span
          className={cn(
            "text-sm",
            row.status === "active" && isExpiringSoon(row.expires_at)
              ? "text-amber-400 font-medium"
              : "text-muted-foreground"
          )}
        >
          {formatDate(row.expires_at)}
        </span>
      ),
    },
    {
      key: "serial_number",
      header: "Serial Number",
      render: (row) => (
        <code
          className="text-xs text-muted-foreground"
          title={row.serial_number}
        >
          {row.serial_number.length > 17
            ? `${row.serial_number.slice(0, 17)}…`
            : row.serial_number}
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
          aria-label={`Revoke certificate for ${row.common_name}`}
          disabled={row.status === "revoked"}
          onClick={() => setRevokeTarget(row)}
          className={cn(
            "px-2.5 py-1 rounded text-xs font-medium border transition-colors focus:outline-none focus:ring-2 focus:ring-primary/40",
            row.status === "revoked"
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
          <Button
            onClick={() => {
              resetGenerateForm();
              setGenerateOpen(true);
            }}
          >
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
          commonName={commonName}
          keyType={keyType}
          validityDays={validityDays}
          sanDns={sanDns}
          sanIp={sanIp}
          onCommonNameChange={setCommonName}
          onKeyTypeChange={setKeyType}
          onValidityDaysChange={setValidityDays}
          onSanDnsChange={setSanDns}
          onSanIpChange={setSanIp}
          error={generateError}
        />
      </FormDialog>

      {/* Private key reveal — shown once after generation */}
      <SecretRevealModal
        open={secretOpen}
        onClose={() => setSecretOpen(false)}
        title="Certificate Generated"
        description="Your certificate has been generated. Save the private key now — it will not be shown again."
        secrets={[{ label: "Private Key (PEM)", value: privateKeyPem, mono: true }]}
      />

      {/* Revoke confirm */}
      <ConfirmDialog
        open={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={() =>
          revokeTarget && revokeMutation.mutate(revokeTarget.id)
        }
        title="Revoke Certificate"
        description={`Are you sure you want to revoke the certificate for "${revokeTarget?.common_name}"? This action cannot be undone.`}
        isLoading={revokeMutation.isPending}
      />
    </div>
  );
}

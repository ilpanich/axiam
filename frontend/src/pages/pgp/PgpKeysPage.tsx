import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  pgpService,
  type PgpKey,
  type PgpKeyAlgorithm,
  type PgpKeyPurpose,
  type PgpKeyStatus,
  type GeneratePgpKeyPayload,
} from "@/services/pgp";
import { PageHeader } from "@/components/PageHeader";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { StatusBadge } from "@/components/StatusBadge";
import { SecretRevealModal } from "@/components/SecretRevealModal";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Eye, KeyRound, Lock } from "lucide-react";

import { formatDate } from "@/lib/utils";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function truncateFingerprint(fp: string): string {
  return fp.length > 24 ? `${fp.slice(0, 24)}…` : fp;
}

/**
 * Map the backend's PascalCase `PgpKeyStatus` onto the lowercase variants
 * accepted by the shared `StatusBadge`.
 */
function badgeStatus(status: PgpKeyStatus): "active" | "revoked" {
  return status === "Active" ? "active" : "revoked";
}

/** UTF-8 safe base64 encoding for the encrypt request body. */
function toBase64(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

// ─── View Public Key modal ────────────────────────────────────────────────────

interface ViewPublicKeyModalProps {
  open: boolean;
  onClose: () => void;
  pgpKey: PgpKey | null;
}

function ViewPublicKeyModal({ open, onClose, pgpKey }: ViewPublicKeyModalProps) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    if (!pgpKey) return;
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(pgpKey.public_key_armored);
      } else {
        const el = document.createElement("textarea");
        el.value = pgpKey.public_key_armored;
        el.style.position = "fixed";
        el.style.top = "-9999px";
        document.body.appendChild(el);
        el.select();
        document.execCommand("copy");
        document.body.removeChild(el);
      }
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Silently fail
    }
  }

  if (!open || !pgpKey) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      aria-modal="true"
      role="dialog"
      aria-labelledby="pubkey-modal-title"
    >
      <div
        className="absolute inset-0 bg-black/60 backdrop-blur-xs"
        onClick={onClose}
        aria-hidden="true"
      />
      <div className="relative z-10 glass-card w-full max-w-lg flex flex-col max-h-[90vh]">
        <div className="flex items-center justify-between pb-4 border-b border-primary/10">
          <h2
            id="pubkey-modal-title"
            className="text-lg font-semibold text-foreground"
          >
            Public Key
          </h2>
          <button
            onClick={onClose}
            className="text-muted-foreground hover:text-foreground transition-colors rounded p-1 focus:outline-hidden focus:ring-2 focus:ring-primary/40"
            aria-label="Close"
          >
            ✕
          </button>
        </div>
        <div className="py-4 space-y-3 overflow-y-auto flex-1">
          <div className="flex items-center justify-between gap-3">
            <div className="space-y-0.5">
              <p className="text-xs font-semibold uppercase tracking-wider text-primary/70">
                Fingerprint
              </p>
              <code className="text-sm text-muted-foreground font-mono">
                {pgpKey.fingerprint}
              </code>
            </div>
            <button
              type="button"
              onClick={() => void handleCopy()}
              className="shrink-0 inline-flex items-center gap-1.5 px-3 py-1.5 rounded text-xs font-medium border border-white/12 text-white/55 hover:border-primary/40 hover:text-primary transition-all focus:outline-hidden focus:ring-2 focus:ring-primary/40"
            >
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <div className="rounded-md border border-white/10 bg-white/[0.04] p-3 overflow-x-auto">
            <pre className="text-xs text-foreground/80 whitespace-pre-wrap break-all font-mono leading-relaxed">
              {pgpKey.public_key_armored}
            </pre>
          </div>
        </div>
        <div className="flex justify-end pt-4 border-t border-primary/10">
          <Button type="button" variant="ghost" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
}

// ─── Encrypt Data modal ────────────────────────────────────────────────────────

interface EncryptDataModalProps {
  open: boolean;
  onClose: () => void;
  pgpKeyId: string | null;
}

function EncryptDataModal({ open, onClose, pgpKeyId }: EncryptDataModalProps) {
  const [data, setData] = useState("");
  const [error, setError] = useState("");
  const [encryptedResult, setEncryptedResult] = useState("");
  const [revealOpen, setRevealOpen] = useState(false);

  const encryptMutation = useMutation({
    mutationFn: ({ id, plaintext }: { id: string; plaintext: string }) =>
      pgpService.encrypt(id, { data_base64: toBase64(plaintext) }),
    onSuccess: (resp) => {
      setEncryptedResult(resp.ciphertext_armored);
      setRevealOpen(true);
    },
    onError: (err: unknown) => {
      setError(getApiErrorMessage(err));
    },
  });

  function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError("");
    if (!pgpKeyId || !data.trim()) {
      setError("Data is required.");
      return;
    }
    encryptMutation.mutate({ id: pgpKeyId, plaintext: data });
  }

  function handleClose() {
    setData("");
    setError("");
    setEncryptedResult("");
    onClose();
  }

  return (
    <>
      <FormDialog
        open={open && !revealOpen}
        onClose={handleClose}
        title="Encrypt Data"
        onSubmit={handleSubmit}
        isLoading={encryptMutation.isPending}
        submitLabel="Encrypt"
      >
        <div className="space-y-2">
          <Label htmlFor="encrypt-data">Data to Encrypt *</Label>
          <Textarea
            id="encrypt-data"
            value={data}
            onChange={(e) => setData(e.target.value)}
            placeholder="Enter data to encrypt…"
            rows={5}
            required
            className="resize-y font-mono"
          />
        </div>
        {error && <p className="text-sm text-destructive">{error}</p>}
      </FormDialog>

      <SecretRevealModal
        open={revealOpen}
        onClose={() => {
          setRevealOpen(false);
          handleClose();
        }}
        title="Data Encrypted"
        description="The encrypted payload is shown below. Copy it now."
        secrets={[{ label: "Encrypted Data", value: encryptedResult, mono: true }]}
      />
    </>
  );
}

// ─── Generate form fields ─────────────────────────────────────────────────────

interface GenerateFieldsProps {
  name: string;
  email: string;
  purpose: PgpKeyPurpose;
  algorithm: PgpKeyAlgorithm;
  onNameChange: (v: string) => void;
  onEmailChange: (v: string) => void;
  onPurposeChange: (v: PgpKeyPurpose) => void;
  onAlgorithmChange: (v: PgpKeyAlgorithm) => void;
  error?: string;
}

function GenerateFields({
  name,
  email,
  purpose,
  algorithm,
  onNameChange,
  onEmailChange,
  onPurposeChange,
  onAlgorithmChange,
  error,
}: GenerateFieldsProps) {
  return (
    <>
      <div className="space-y-2">
        <Label htmlFor="pgp-name">Name *</Label>
        <Input
          id="pgp-name"
          value={name}
          onChange={(e) => onNameChange(e.target.value)}
          placeholder="e.g. Audit signing key"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="pgp-email">Email *</Label>
        <Input
          id="pgp-email"
          type="email"
          value={email}
          onChange={(e) => onEmailChange(e.target.value)}
          placeholder="audit@example.com"
          required
          autoComplete="off"
        />
      </div>

      <div className="space-y-2">
        <Label htmlFor="pgp-purpose">Purpose</Label>
        <select
          id="pgp-purpose"
          value={purpose}
          onChange={(e) => onPurposeChange(e.target.value as PgpKeyPurpose)}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40"
        >
          <option value="AuditSigning">Audit Signing</option>
          <option value="Export">Export (encryption)</option>
        </select>
        <p className="text-xs text-muted-foreground">
          {purpose === "AuditSigning"
            ? "Server-side signing key for audit log batches. The private key is stored encrypted and never returned."
            : "Zero-knowledge export key. The private key is returned once on generation and never stored."}
        </p>
      </div>

      <div className="space-y-2">
        <Label htmlFor="pgp-algorithm">Algorithm</Label>
        <select
          id="pgp-algorithm"
          value={algorithm}
          onChange={(e) =>
            onAlgorithmChange(e.target.value as PgpKeyAlgorithm)
          }
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40"
        >
          <option value="Rsa4096">RSA-4096 (signing + encryption)</option>
          <option value="Ed25519">Ed25519 (signing only)</option>
        </select>
        <p className="text-xs text-muted-foreground">
          {algorithm === "Rsa4096"
            ? "RSA-4096 supports both signing/verification and asymmetric encryption."
            : "Ed25519 supports signing and signature verification only."}
        </p>
      </div>

      {error && <p className="text-sm text-destructive">{error}</p>}
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function PgpKeysPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const { data: pgpKeys = [], isLoading } = useQuery({
    queryKey: ["pgp-keys"],
    queryFn: () => pgpService.list(),
  });

  // ─── Generate state ────────────────────────────────────────────────────────
  const [generateOpen, setGenerateOpen] = useState(false);
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [purpose, setPurpose] = useState<PgpKeyPurpose>("AuditSigning");
  const [algorithm, setAlgorithm] = useState<PgpKeyAlgorithm>("Rsa4096");
  const [generateError, setGenerateError] = useState("");

  // ─── Secret reveal state ───────────────────────────────────────────────────
  const [secretOpen, setSecretOpen] = useState(false);
  const [privateKeyArmored, setPrivateKeyArmored] = useState("");

  const generateMutation = useMutation({
    mutationFn: (payload: GeneratePgpKeyPayload) => pgpService.generate(payload),
    onSuccess: (resp) => {
      void queryClient.invalidateQueries({ queryKey: ["pgp-keys"] });
      setGenerateOpen(false);
      resetGenerateForm();
      // Private key is only returned for Export-purpose keys; for
      // AuditSigning keys it is omitted, so skip the reveal modal entirely.
      if (resp.private_key_armored) {
        setPrivateKeyArmored(resp.private_key_armored);
        setSecretOpen(true);
      } else {
        toast({ description: "PGP key generated." });
      }
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      setGenerateError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function resetGenerateForm() {
    setName("");
    setEmail("");
    setPurpose("AuditSigning");
    setAlgorithm("Rsa4096");
    setGenerateError("");
  }

  function handleGenerateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setGenerateError("");
    if (!name.trim()) {
      setGenerateError("Name is required.");
      return;
    }
    if (!email.trim()) {
      setGenerateError("Email is required.");
      return;
    }
    generateMutation.mutate({
      name: name.trim(),
      email: email.trim(),
      purpose,
      algorithm,
    });
  }

  // ─── Revoke state ──────────────────────────────────────────────────────────
  const [revokeTarget, setRevokeTarget] = useState<PgpKey | null>(null);

  const revokeMutation = useMutation({
    mutationFn: (id: string) => pgpService.revoke(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["pgp-keys"] });
      setRevokeTarget(null);
    },
    onError: (err: unknown) => {
      toast({ description: getApiErrorMessage(err), variant: "destructive" });
    },
  });

  // ─── View public key state ─────────────────────────────────────────────────
  const [viewKey, setViewKey] = useState<PgpKey | null>(null);

  // ─── Encrypt state ─────────────────────────────────────────────────────────
  const [encryptKeyId, setEncryptKeyId] = useState<string | null>(null);

  // ─── Table columns ─────────────────────────────────────────────────────────
  const columns: Column<PgpKey>[] = [
    {
      key: "name",
      header: "Name",
      render: (row) => (
        <span className="font-medium text-foreground/90">{row.name}</span>
      ),
    },
    {
      key: "fingerprint",
      header: "Fingerprint",
      render: (row) => (
        <code
          className="text-xs text-muted-foreground font-mono"
          title={row.fingerprint}
        >
          {truncateFingerprint(row.fingerprint)}
        </code>
      ),
    },
    {
      key: "purpose",
      header: "Purpose",
      render: (row) => (
        <span className="text-muted-foreground text-sm">
          {row.purpose === "AuditSigning" ? "Audit Signing" : "Export"}
        </span>
      ),
    },
    {
      key: "algorithm",
      header: "Algorithm",
      render: (row) => (
        <code className="text-xs bg-white/5 px-1.5 py-0.5 rounded text-muted-foreground">
          {row.algorithm}
        </code>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row) => <StatusBadge status={badgeStatus(row.status)} />,
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
      width: "w-44",
      render: (row) => (
        <div className="flex items-center gap-1">
          <button
            aria-label={`View public key for ${row.name}`}
            onClick={() => setViewKey(row)}
            className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors"
            title="View Public Key"
          >
            <Eye size={14} />
          </button>
          {row.algorithm === "Rsa4096" && (
            <button
              aria-label={`Encrypt data with ${row.name}`}
              onClick={() => setEncryptKeyId(row.id)}
              disabled={row.status === "Revoked"}
              className="p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-purple-400 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
              title="Encrypt Data"
            >
              <Lock size={14} />
            </button>
          )}
          <button
            aria-label={`Revoke key ${row.name}`}
            disabled={row.status === "Revoked"}
            onClick={() => setRevokeTarget(row)}
            className="p-1.5 rounded hover:bg-destructive/20 text-muted-foreground hover:text-destructive transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            title="Revoke"
          >
            <KeyRound size={14} />
          </button>
        </div>
      ),
    },
  ];

  return (
    <div>
      <PageHeader
        title="PGP Keys"
        description="Manage OpenPGP keys for audit signing and encrypted data exports."
        action={
          <Button
            onClick={() => {
              resetGenerateForm();
              setGenerateOpen(true);
            }}
          >
            <KeyRound size={16} />
            Generate PGP Key
          </Button>
        }
      />

      <DataTable
        columns={columns}
        data={pgpKeys}
        isLoading={isLoading}
        emptyMessage="No PGP keys found."
      />

      {/* Generate dialog */}
      <FormDialog
        open={generateOpen}
        onClose={() => {
          setGenerateOpen(false);
          resetGenerateForm();
        }}
        title="Generate PGP Key"
        onSubmit={handleGenerateSubmit}
        isLoading={generateMutation.isPending}
        submitLabel="Generate"
      >
        <GenerateFields
          name={name}
          email={email}
          purpose={purpose}
          algorithm={algorithm}
          onNameChange={setName}
          onEmailChange={setEmail}
          onPurposeChange={setPurpose}
          onAlgorithmChange={setAlgorithm}
          error={generateError}
        />
      </FormDialog>

      {/* Private key reveal — shown once after generating an Export key */}
      <SecretRevealModal
        open={secretOpen}
        onClose={() => {
          setSecretOpen(false);
          setPrivateKeyArmored("");
        }}
        title="PGP Key Generated"
        description="Your PGP key pair has been generated. Save the private key now — it will not be shown again."
        secrets={[
          {
            label: "Private Key (ASCII Armor)",
            value: privateKeyArmored,
            mono: true,
          },
        ]}
      />

      {/* View Public Key modal */}
      <ViewPublicKeyModal
        open={viewKey !== null}
        onClose={() => setViewKey(null)}
        pgpKey={viewKey}
      />

      {/* Encrypt Data modal */}
      <EncryptDataModal
        open={encryptKeyId !== null}
        onClose={() => setEncryptKeyId(null)}
        pgpKeyId={encryptKeyId}
      />

      {/* Revoke confirm */}
      <ConfirmDialog
        open={revokeTarget !== null}
        onClose={() => setRevokeTarget(null)}
        onConfirm={() => revokeTarget && revokeMutation.mutate(revokeTarget.id)}
        title="Revoke PGP Key"
        description={`Are you sure you want to revoke the key "${revokeTarget?.name}"? This action cannot be undone.`}
        isLoading={revokeMutation.isPending}
        confirmLabel="Revoke"
      />
    </div>
  );
}

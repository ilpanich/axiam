import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileSignature, Plus, Upload } from "lucide-react";
import {
  caCertService,
  signingCaService,
  type CaCertificate,
  type GenerateSigningCaPayload,
  type SignSigningCaCsrPayload,
} from "@/services/organizations";
import { DataTable, type Column } from "@/components/DataTable";
import { FormDialog } from "@/components/FormDialog";
import { ConfirmDialog } from "@/components/ConfirmDialog";
import { CertificateViewDialog } from "@/components/CertificateViewDialog";
import { SecretRevealModal } from "@/components/SecretRevealModal";
import { StatusBadge } from "@/components/StatusBadge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { cn, formatDate } from "@/lib/utils";
import { getApiErrorMessage } from "@/lib/apiError";

type KeyAlgorithm = "Rsa4096" | "Ed25519";

function badgeStatus(
  status: CaCertificate["status"]
): "active" | "revoked" | "inactive" {
  switch (status) {
    case "Active":
      return "active";
    case "Revoked":
      return "revoked";
    case "Expired":
      return "inactive";
  }
}

/**
 * The tenant's signing CAs — the intermediates its certificates are issued from.
 *
 * Both ways of getting one are here because they answer different situations,
 * not because one is a fallback for the other:
 *
 * * **Generate** when AXIAM (or the Vault behind it) should hold the key. The
 *   private key is returned once, and under Vault's PKI engine not at all,
 *   because it was created inside Vault and no API exports it.
 * * **Sign a CSR** when the tenant's key is made somewhere AXIAM will never
 *   see — an offline ceremony, an HSM, a separate operator's tooling. Only the
 *   request crosses the wire, and the certificate that comes back is signed by
 *   the organization CA all the same.
 */
export function SigningCaPanel({
  orgId,
  tenantId,
  tenantName,
}: {
  orgId: string;
  tenantId: string;
  tenantName?: string;
}) {
  const queryClient = useQueryClient();
  const listKey = ["signing-cas", orgId, tenantId];

  const { data: signingCas = [], isLoading } = useQuery({
    queryKey: listKey,
    queryFn: () => signingCaService.list(orgId, tenantId),
  });

  // Only organization CAs can be a parent, and only Active ones with a key.
  // A tenant signing CA is constrained to a path length of zero and cannot
  // parent another; the server refuses it, and offering it here would be an
  // invitation to a 400.
  const { data: orgCas = [], isLoading: parentsLoading } = useQuery({
    queryKey: ["ca-certificates", orgId],
    queryFn: () => caCertService.list(orgId),
  });
  const parentOptions = orgCas.filter(
    (ca) =>
      !ca.tenant_id && ca.status === "Active" && ca.key_custody !== "external"
  );
  const noParents = !parentsLoading && parentOptions.length === 0;

  // ─── Generate ──────────────────────────────────────────────────────────────
  const [generateOpen, setGenerateOpen] = useState(false);
  const [parentCaId, setParentCaId] = useState("");
  const [subject, setSubject] = useState("");
  const [keyAlgorithm, setKeyAlgorithm] = useState<KeyAlgorithm>("Ed25519");
  const [validityDays, setValidityDays] = useState(1825);
  const [generateError, setGenerateError] = useState("");
  const [revealedSecrets, setRevealedSecrets] = useState<
    { label: string; value: string }[] | null
  >(null);

  const generateMutation = useMutation({
    mutationFn: (payload: GenerateSigningCaPayload) =>
      signingCaService.generate(orgId, tenantId, payload),
    onSuccess: (result) => {
      void queryClient.invalidateQueries({ queryKey: listKey });
      setGenerateOpen(false);
      resetGenerate();
      // Only what no endpoint returns again. Under Vault's PKI engine there is
      // no private key at all, and showing a redaction marker for one would say
      // a key was withheld when none exists.
      if (result.private_key_pem) {
        setRevealedSecrets([
          { label: "Private Key (PEM)", value: result.private_key_pem },
        ]);
      }
    },
    onError: (err: unknown) =>
      setGenerateError(
        getApiErrorMessage(err, "Failed to create the signing CA.")
      ),
  });

  function resetGenerate() {
    setSubject("");
    setKeyAlgorithm("Ed25519");
    setValidityDays(1825);
    setGenerateError("");
  }

  function openGenerate() {
    resetGenerate();
    setParentCaId(parentOptions[0]?.id ?? "");
    setGenerateOpen(true);
  }

  function handleGenerateSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setGenerateError("");
    if (!parentCaId) {
      setGenerateError("An active organization CA is required to sign it.");
      return;
    }
    if (!subject.trim()) {
      setGenerateError("Subject is required.");
      return;
    }
    generateMutation.mutate({
      parent_ca_id: parentCaId,
      subject: subject.trim(),
      key_algorithm: keyAlgorithm,
      validity_days: validityDays,
    });
  }

  // ─── Sign a CSR ────────────────────────────────────────────────────────────
  const [csrOpen, setCsrOpen] = useState(false);
  const [csrPem, setCsrPem] = useState("");
  const [csrError, setCsrError] = useState("");
  const [signedCert, setSignedCert] = useState<CaCertificate | null>(null);

  const csrMutation = useMutation({
    mutationFn: (payload: SignSigningCaCsrPayload) =>
      signingCaService.signCsr(orgId, tenantId, payload),
    onSuccess: (cert) => {
      void queryClient.invalidateQueries({ queryKey: listKey });
      setCsrOpen(false);
      resetCsr();
      // The certificate is the entire product of this call — whoever sent the
      // CSR needs it back, and has no key reveal to prompt them for it.
      setSignedCert(cert);
    },
    onError: (err: unknown) =>
      setCsrError(getApiErrorMessage(err, "Failed to sign the request.")),
  });

  function resetCsr() {
    setCsrPem("");
    setCsrError("");
  }

  function openCsr() {
    resetCsr();
    setParentCaId(parentOptions[0]?.id ?? "");
    setValidityDays(1825);
    setCsrOpen(true);
  }

  function handleCsrSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCsrError("");
    if (!parentCaId) {
      setCsrError("An active organization CA is required to sign it.");
      return;
    }
    const pem = csrPem.trim();
    if (!pem.includes("BEGIN CERTIFICATE REQUEST")) {
      setCsrError(
        "Paste the PEM-encoded certificate signing request, including its BEGIN and END lines."
      );
      return;
    }
    // Everything else — that it parses, that its signature verifies against the
    // key it carries, that it names a subject — is checked server-side.
    // Duplicating those rules here would give an operator two opinions that can
    // disagree.
    csrMutation.mutate({
      parent_ca_id: parentCaId,
      csr_pem: pem,
      validity_days: validityDays,
    });
  }

  // ─── View / revoke ─────────────────────────────────────────────────────────
  const [viewCert, setViewCert] = useState<CaCertificate | null>(null);
  const [revokeCert, setRevokeCert] = useState<CaCertificate | null>(null);

  const revokeMutation = useMutation({
    mutationFn: (id: string) => signingCaService.revoke(orgId, id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: listKey });
      setRevokeCert(null);
    },
  });

  const columns: Column<CaCertificate>[] = [
    {
      key: "subject",
      header: "Subject",
      render: (row) => (
        <span className="font-medium text-foreground">{row.subject}</span>
      ),
    },
    {
      key: "key_algorithm",
      header: "Key Algorithm",
      render: (row) => (
        <code className="rounded bg-white/5 px-1.5 py-0.5 text-xs text-muted-foreground">
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
      key: "key_custody",
      header: "Key",
      render: (row) => (
        <span
          className="text-xs text-muted-foreground"
          title={
            row.key_custody === "external"
              ? "AXIAM signed this CA from a request and holds no key for it. Whoever made the request issues against it."
              : "AXIAM can issue against this CA — its key is with the server's configured custodian."
          }
        >
          {row.key_custody === "external" ? "Held by tenant" : "Held by AXIAM"}
        </span>
      ),
    },
    {
      key: "not_after",
      header: "Expires",
      render: (row) => (
        <span className="text-sm text-muted-foreground">
          {formatDate(row.not_after)}
        </span>
      ),
    },
    {
      key: "actions",
      header: "Actions",
      width: "w-40",
      render: (row) => (
        <div className="flex items-center gap-2">
          <button
            aria-label={`View ${row.subject}`}
            onClick={() => setViewCert(row)}
            className="rounded border border-white/10 px-2.5 py-1 text-xs font-medium text-muted-foreground transition-colors hover:text-foreground"
          >
            View
          </button>
          <button
            aria-label={`Revoke ${row.subject}`}
            onClick={() => setRevokeCert(row)}
            disabled={row.status === "Revoked"}
            className={cn(
              "rounded px-2.5 py-1 text-xs font-medium transition-colors",
              row.status === "Revoked"
                ? "cursor-not-allowed text-muted-foreground opacity-40"
                : "text-red-400 hover:bg-red-500/20 hover:text-red-300"
            )}
          >
            Revoke
          </button>
        </div>
      ),
    },
  ];

  /** The parent picker, shared by both dialogs. */
  const parentField = (idPrefix: string) => (
    <div className="space-y-2">
      <Label htmlFor={`${idPrefix}-parent-ca`}>Signed by *</Label>
      <select
        id={`${idPrefix}-parent-ca`}
        value={parentCaId}
        onChange={(e) => setParentCaId(e.target.value)}
        disabled={parentsLoading || noParents}
        className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40 disabled:opacity-50"
      >
        {parentsLoading && <option value="">Loading CAs…</option>}
        {noParents && <option value="">No organization CA available</option>}
        {!parentsLoading &&
          parentOptions.map((ca) => (
            <option key={ca.id} value={ca.id}>
              {ca.subject}
            </option>
          ))}
      </select>
      {noParents && (
        <div
          role="note"
          className="space-y-1.5 rounded-md border border-amber-500/30 bg-amber-500/8 p-3 text-xs text-amber-300"
        >
          <p>
            <strong>This organization has no CA that can sign.</strong> A signing
            CA is created beneath one, so there is nothing to create it under.
          </p>
          <p>
            Generate or import one under the organization&rsquo;s{" "}
            <strong>CA Certificates</strong> tab. A CA imported as a trust anchor
            only — without its private key — cannot sign and is not offered here.
          </p>
        </div>
      )}
    </div>
  );

  const validityField = (idPrefix: string) => (
    <div className="space-y-2">
      <Label htmlFor={`${idPrefix}-validity`}>Validity (days)</Label>
      <Input
        id={`${idPrefix}-validity`}
        type="number"
        min={1}
        max={7300}
        value={validityDays}
        onChange={(e) => setValidityDays(Number(e.target.value))}
      />
      <p className="text-xs text-muted-foreground">
        Capped to the signing CA&rsquo;s own expiry. An intermediate that
        outlives its issuer is rejected by every validator for the whole of its
        extra life.
      </p>
    </div>
  );

  return (
    <div className="glass-card space-y-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h2 className="flex items-center gap-2 text-base font-semibold text-foreground">
            <FileSignature size={16} className="text-primary" />
            Signing CAs
          </h2>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            The intermediate CAs that sign{" "}
            {tenantName ? <strong>{tenantName}</strong> : "this tenant"}
            &rsquo;s user, service and device certificates. Each is created
            beneath an organization CA and constrained to signing leaves, so
            revoking one revokes exactly this tenant&rsquo;s issuance and leaves
            the organization&rsquo;s trust anchor alone.
          </p>
        </div>
        <div className="flex shrink-0 gap-2">
          <Button variant="outline" size="sm" onClick={openCsr}>
            <Upload size={14} />
            Sign a CSR
          </Button>
          <Button size="sm" onClick={openGenerate}>
            <Plus size={14} />
            Create Signing CA
          </Button>
        </div>
      </div>

      <DataTable
        columns={columns}
        data={signingCas}
        isLoading={isLoading}
        emptyMessage="No signing CAs yet. This tenant's certificates are issued straight from an organization CA."
      />

      {/* Generate */}
      <FormDialog
        open={generateOpen}
        onClose={() => {
          setGenerateOpen(false);
          resetGenerate();
        }}
        title="Create Signing CA"
        onSubmit={handleGenerateSubmit}
        isLoading={generateMutation.isPending}
        submitLabel="Create"
        error={generateError}
        errorId="signing-ca-generate-error"
      >
        <p className="text-sm text-muted-foreground">
          The key is generated by the server and handed to whichever custodian it
          is configured for — HashiCorp Vault&rsquo;s PKI engine, Vault&rsquo;s
          KV engine, or encrypted into the CA record. It is returned here once,
          and not at all when Vault generated it, because no API exports a key
          born inside Vault.
        </p>

        {parentField("signing-ca")}

        <div className="space-y-2">
          <Label htmlFor="signing-ca-subject">Subject *</Label>
          <Input
            id="signing-ca-subject"
            value={subject}
            onChange={(e) => setSubject(e.target.value)}
            placeholder="CN=Acme R&D Signing CA"
            required
            autoComplete="off"
          />
        </div>

        <div className="space-y-2">
          <Label htmlFor="signing-ca-key-algorithm">Key Algorithm</Label>
          <select
            id="signing-ca-key-algorithm"
            value={keyAlgorithm}
            onChange={(e) => setKeyAlgorithm(e.target.value as KeyAlgorithm)}
            className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40"
          >
            <option value="Ed25519">Ed25519</option>
            <option value="Rsa4096">RSA-4096</option>
          </select>
          <p className="text-xs text-muted-foreground">
            RSA needs a server configured with Vault&rsquo;s PKI engine — the
            in-process generator cannot produce RSA keys.
          </p>
        </div>

        {validityField("signing-ca")}
      </FormDialog>

      {/* Sign a CSR */}
      <FormDialog
        open={csrOpen}
        onClose={() => {
          setCsrOpen(false);
          resetCsr();
        }}
        title="Sign a Certificate Signing Request"
        onSubmit={handleCsrSubmit}
        isLoading={csrMutation.isPending}
        submitLabel="Sign"
        error={csrError}
        errorId="signing-ca-csr-error"
      >
        <p className="text-sm text-muted-foreground">
          For a signing CA whose private key is generated where AXIAM will never
          see it. Only the request crosses the wire; the certificate that comes
          back is signed by the organization CA, and AXIAM stores no key for it.
          Issuing against it happens wherever that key lives.
        </p>

        {parentField("csr")}

        <div className="space-y-2">
          <Label htmlFor="csr-pem">Certificate signing request (PEM) *</Label>
          <Textarea
            id="csr-pem"
            value={csrPem}
            onChange={(e) => setCsrPem(e.target.value)}
            rows={8}
            spellCheck={false}
            placeholder={
              "-----BEGIN CERTIFICATE REQUEST-----\n…\n-----END CERTIFICATE REQUEST-----"
            }
            className="font-mono text-xs"
          />
          <p className="text-xs text-muted-foreground">
            The subject is taken from the request. Its requested extensions are
            not: AXIAM decides that this is a CA and constrains it to a path
            length of zero, so it signs leaves and cannot mint a further tier.
          </p>
        </div>

        {validityField("csr")}
      </FormDialog>

      {/* One-time private key, when the server produced one */}
      <SecretRevealModal
        open={revealedSecrets !== null}
        onClose={() => setRevealedSecrets(null)}
        title="Signing CA Created"
        description="Save this now — it is never shown again and cannot be recovered. The certificate itself stays available from this list."
        secrets={revealedSecrets ?? []}
      />

      {/* The certificate — for viewing, and for handing to whoever needs it */}
      <CertificateViewDialog
        open={viewCert !== null || signedCert !== null}
        onClose={() => {
          setViewCert(null);
          setSignedCert(null);
        }}
        title="Signing CA Certificate"
        subject={(viewCert ?? signedCert)?.subject ?? ""}
        publicCertPem={(viewCert ?? signedCert)?.public_cert_pem ?? ""}
        chainPem={(viewCert ?? signedCert)?.chain_pem}
        details={
          (viewCert ?? signedCert)
            ? [
                { label: "Subject", value: (viewCert ?? signedCert)!.subject },
                {
                  label: "Key algorithm",
                  value: (
                    <code className="text-xs">
                      {(viewCert ?? signedCert)!.key_algorithm}
                    </code>
                  ),
                },
                {
                  label: "Status",
                  value: (
                    <StatusBadge
                      status={badgeStatus((viewCert ?? signedCert)!.status)}
                    />
                  ),
                },
                {
                  label: "Private key",
                  value:
                    (viewCert ?? signedCert)!.key_custody === "external"
                      ? "Held by the tenant"
                      : "Held by AXIAM's custodian",
                },
                {
                  label: "Valid from",
                  value: formatDate((viewCert ?? signedCert)!.not_before),
                },
                {
                  label: "Expires",
                  value: formatDate((viewCert ?? signedCert)!.not_after),
                },
                {
                  label: "Fingerprint",
                  value: (
                    <code className="text-xs">
                      {(viewCert ?? signedCert)!.fingerprint}
                    </code>
                  ),
                },
              ]
            : []
        }
      />

      <ConfirmDialog
        open={revokeCert !== null}
        onClose={() => setRevokeCert(null)}
        onConfirm={() => revokeCert && revokeMutation.mutate(revokeCert.id)}
        title="Revoke Signing CA"
        description={`Revoke "${revokeCert?.subject}"? Every certificate it signed stops being trusted, and this cannot be undone.`}
        isLoading={revokeMutation.isPending}
        confirmLabel="Revoke"
      />
    </div>
  );
}

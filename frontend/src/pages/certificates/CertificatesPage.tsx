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
  type SignCsrPayload,
} from "@/services/certificates";
import { useAuthStore } from "@/stores/auth";
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
import { Textarea } from "@/components/ui/textarea";
import { ShieldPlus, Upload } from "lucide-react";
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
  /**
   * When the CA itself expires.
   *
   * Carried into the form because a leaf cannot outlive its issuer — past this
   * date the chain stops validating — so it is what caps the Validity Days
   * input. The server refuses a longer request outright (it used to truncate
   * silently), and a form that could not see this date could only discover the
   * limit on submit.
   */
  not_after: string;
}

/**
 * The issuing CA's remaining life, floored at one day and capped by the
 * CA/Browser Forum leaf maximum the server enforces (825 days). Rounded down
 * to whole days for the same reason the server rounds down: a CA with 36
 * hours left can grant one day, not two.
 *
 * Shared by the Generate and Sign-a-CSR dialogs — both mint a leaf under the
 * same CA list and are bound by the same issuer expiry, so the arithmetic
 * belongs in one place rather than two copies that could drift.
 * `now` is captured once per dialog instance, in a lazy initialiser, rather
 * than read on every render: reading the clock during render is impure and
 * makes the cap drift between renders for no benefit — the number is in whole
 * days and the form is open for seconds.
 */
function useIssuerValidityCap(caOptions: CaOption[], issuerCaId: string) {
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
  return { selectedCa, caExpiryKnown, maxValidityDays };
}

interface IssuingCaSelectProps {
  /** Distinguishes this select's DOM id from the other dialog's. */
  idPrefix: string;
  issuerCaId: string;
  caOptions: CaOption[];
  caLoading: boolean;
  onIssuerCaIdChange: (v: string) => void;
  /** Where to send an operator who has no CA yet; `null` while the org is unknown. */
  caSetupHref: string | null;
}

/**
 * The issuing-CA picker and its "this org has no CA" escape hatch. Shared by
 * Generate and Sign-a-CSR: both mint a certificate under exactly the same set
 * of Active organization CAs and hit the same dead end when there is none.
 */
function IssuingCaSelect({
  idPrefix,
  issuerCaId,
  caOptions,
  caLoading,
  onIssuerCaIdChange,
  caSetupHref,
}: IssuingCaSelectProps) {
  const noCas = !caLoading && caOptions.length === 0;
  const id = `${idPrefix}-issuer-ca`;

  return (
    <div className="space-y-2">
      <Label htmlFor={id}>Issuing CA *</Label>
      <select
        id={id}
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
              <Link to={caSetupHref} className="underline hover:text-amber-200">
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
  );
}

interface ValidityDaysFieldProps {
  idPrefix: string;
  validityDays: number;
  onValidityDaysChange: (v: number) => void;
  selectedCa: CaOption | undefined;
  caExpiryKnown: boolean;
  maxValidityDays: number;
}

/** The Validity Days input and its issuer-expiry hint, shared for the same reason as `IssuingCaSelect`. */
function ValidityDaysField({
  idPrefix,
  validityDays,
  onValidityDaysChange,
  selectedCa,
  caExpiryKnown,
  maxValidityDays,
}: ValidityDaysFieldProps) {
  const id = `${idPrefix}-validity-days`;
  const helpId = `${idPrefix}-validity-help`;

  return (
    <div className="space-y-2">
      <Label htmlFor={id}>Validity Days</Label>
      <Input
        id={id}
        type="number"
        min={1}
        max={maxValidityDays}
        value={validityDays}
        onChange={(e) => onValidityDaysChange(Number(e.target.value))}
        aria-describedby={helpId}
      />
      {/* A certificate cannot outlive the CA that signed it — past the
          issuer's notAfter the chain stops validating, so the extra days are
          time the holder believes they have and does not. The server refuses
          such a request outright (it used to truncate silently); saying the
          limit here means an operator picks a real number instead of
          discovering it on submit. */}
      <p id={helpId} className="text-xs text-muted-foreground">
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
  );
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
  const { selectedCa, caExpiryKnown, maxValidityDays } = useIssuerValidityCap(
    caOptions,
    issuerCaId
  );

  return (
    <>
      <IssuingCaSelect
        idPrefix="cert"
        issuerCaId={issuerCaId}
        caOptions={caOptions}
        caLoading={caLoading}
        onIssuerCaIdChange={onIssuerCaIdChange}
        caSetupHref={caSetupHref}
      />

      <div className="space-y-2">
        <Label htmlFor="cert-subject">Subject *</Label>
        <Input
          id="cert-subject"
          value={subject}
          onChange={(e) => onSubjectChange(e.target.value)}
          placeholder="device-001"
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

      <ValidityDaysField
        idPrefix="cert"
        validityDays={validityDays}
        onValidityDaysChange={onValidityDaysChange}
        selectedCa={selectedCa}
        caExpiryKnown={caExpiryKnown}
        maxValidityDays={maxValidityDays}
      />
    </>
  );
}

// ─── Sign-a-CSR form fields ───────────────────────────────────────────────────

interface SignCsrFieldsProps {
  certType: CertificateType;
  validityDays: number;
  issuerCaId: string;
  csrPem: string;
  caOptions: CaOption[];
  caLoading: boolean;
  onCertTypeChange: (v: CertificateType) => void;
  onValidityDaysChange: (v: number) => void;
  onIssuerCaIdChange: (v: string) => void;
  onCsrPemChange: (v: string) => void;
  /** Where to send an operator who has no CA yet; `null` while the org is unknown. */
  caSetupHref: string | null;
}

/**
 * The counterpart of `GenerateFields` for a key AXIAM never sees: the same
 * issuing-CA picker, certificate type and validity cap, but no key algorithm
 * (the caller's key is whatever it is) and a CSR in place of a subject — the
 * CSR carries its own subject, and the server reads it from there rather than
 * a field that could disagree with it.
 */
function SignCsrFields({
  certType,
  validityDays,
  issuerCaId,
  csrPem,
  caOptions,
  caLoading,
  onCertTypeChange,
  onValidityDaysChange,
  onIssuerCaIdChange,
  onCsrPemChange,
  caSetupHref,
}: SignCsrFieldsProps) {
  const { selectedCa, caExpiryKnown, maxValidityDays } = useIssuerValidityCap(
    caOptions,
    issuerCaId
  );

  // Reads the chosen file and drops its text straight into the textarea, so
  // the operator sees exactly what will be submitted whichever way they got
  // it there. The input's own value is cleared afterwards so picking the same
  // file again (after editing it and re-exporting under the same name) still
  // fires a change event.
  async function handleFileChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    e.target.value = "";
    if (!file) return;
    onCsrPemChange(await file.text());
  }

  return (
    <>
      <IssuingCaSelect
        idPrefix="csr"
        issuerCaId={issuerCaId}
        caOptions={caOptions}
        caLoading={caLoading}
        onIssuerCaIdChange={onIssuerCaIdChange}
        caSetupHref={caSetupHref}
      />

      <div className="space-y-2">
        <Label htmlFor="csr-cert-type">Certificate Type</Label>
        <select
          id="csr-cert-type"
          value={certType}
          onChange={(e) => onCertTypeChange(e.target.value as CertificateType)}
          className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground focus:outline-hidden focus:ring-2 focus:ring-primary/40"
        >
          <option value="User">User</option>
          <option value="Service">Service</option>
          <option value="Device">IoT Device</option>
        </select>
      </div>

      <ValidityDaysField
        idPrefix="csr"
        validityDays={validityDays}
        onValidityDaysChange={onValidityDaysChange}
        selectedCa={selectedCa}
        caExpiryKnown={caExpiryKnown}
        maxValidityDays={maxValidityDays}
      />

      <div className="space-y-2">
        <Label htmlFor="csr-pem">Certificate signing request (PEM) *</Label>
        <Textarea
          id="csr-pem"
          value={csrPem}
          onChange={(e) => onCsrPemChange(e.target.value)}
          rows={8}
          spellCheck={false}
          placeholder={
            "-----BEGIN CERTIFICATE REQUEST-----\n…\n-----END CERTIFICATE REQUEST-----"
          }
          className="font-mono text-xs"
        />
        <input
          type="file"
          // A CSR has no fixed MIME type in the wild — most tooling emits
          // `.csr` or `.pem` with no registered type at all — so the accept
          // list leans on extensions, with the registered PKCS#10 type
          // (`application/pkcs10`) alongside for whatever does send it.
          accept=".csr,.pem,.txt,application/pkcs10"
          onChange={(e) => void handleFileChange(e)}
          aria-label="Upload certificate signing request file"
          className="block w-full text-xs text-muted-foreground file:mr-3 file:rounded-md file:border file:border-input file:bg-background file:px-3 file:py-1.5 file:text-xs file:font-medium file:text-foreground hover:file:bg-white/5"
        />
        <p className="text-xs text-muted-foreground">
          Paste the request or choose a file — either way it lands in the box
          above, so what gets submitted is exactly what is shown here. The
          legacy OpenSSL <code>BEGIN NEW CERTIFICATE REQUEST</code> header is
          not accepted (<code>rcgen</code> does not parse it). There is no key
          algorithm to choose: the key is the caller's, generated wherever the
          request was made, and AXIAM neither produces nor sees it. The
          certificate carries no <code>subjectAltName</code>,{" "}
          <code>keyUsage</code> or <code>extendedKeyUsage</code> — a request
          asking for any of those is refused rather than silently trimmed.
        </p>
      </div>
    </>
  );
}

// ─── Main page ─────────────────────────────────────────────────────────────────

export function CertificatesPage() {
  const queryClient = useQueryClient();
  const { toast } = useToast();
  // The caller's own organization, straight from `/auth/me`. Both queries below
  // used to reach it by listing every organization and matching on slug, which
  // only a `super-admin` may do — so an ordinary tenant administrator saw no CAs
  // at all and no link to where one is created.
  const orgId = useAuthStore((s) => s.user?.org_id);

  const { data: certificates = [], isLoading } = useQuery({
    queryKey: ["certificates"],
    queryFn: () => certificateService.list(),
  });

  // The organization's Active CAs — inherited by every tenant under it, and a
  // hard prerequisite for issuing anything.
  const { data: caCertificates = [], isLoading: caLoading } = useQuery({
    queryKey: ["ca-certificates", orgId],
    queryFn: () => certificateService.listSigningCas(orgId ?? undefined),
    enabled: Boolean(orgId),
  });
  const caOptions: CaOption[] = caCertificates.map((ca) => ({
    id: ca.id,
    subject: ca.subject,
    not_after: ca.not_after,
  }));

  // Where CAs are issued. The org detail page's CA section is the only place in
  // the UI that generates one, and nothing on this page pointed at it.
  const caSetupHref = orgId ? `/organizations/${orgId}` : null;

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

  // ─── Sign a CSR state ──────────────────────────────────────────────────────
  const [csrOpen, setCsrOpen] = useState(false);
  const [csrIssuerCaId, setCsrIssuerCaId] = useState("");
  const [csrCertType, setCsrCertType] = useState<CertificateType>("User");
  const [csrValidityDays, setCsrValidityDays] = useState(365);
  const [csrPem, setCsrPem] = useState("");
  const [csrError, setCsrError] = useState("");

  const signCsrMutation = useMutation({
    mutationFn: (payload: SignCsrPayload) => certificateService.signCsr(payload),
    onSuccess: (cert) => {
      invalidateEntity(queryClient, "certificates");
      setCsrOpen(false);
      resetCsrForm();
      // Straight to the view dialog, never the secret reveal: nothing was
      // generated on this path, so there is no key to acknowledge first.
      setViewCert(cert);
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      setCsrError(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  function resetCsrForm() {
    setCsrIssuerCaId("");
    setCsrCertType("User");
    setCsrValidityDays(365);
    setCsrPem("");
    setCsrError("");
  }

  function openCsr() {
    resetCsrForm();
    setCsrIssuerCaId(caOptions[0]?.id ?? "");
    setCsrOpen(true);
  }

  function handleCsrSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setCsrError("");
    if (!csrIssuerCaId) {
      setCsrError("An active CA certificate is required.");
      return;
    }
    const pem = csrPem.trim();
    if (!pem.includes("BEGIN CERTIFICATE REQUEST")) {
      setCsrError(
        "Paste the PEM-encoded certificate signing request, including its BEGIN and END lines."
      );
      return;
    }
    // Everything else — that it parses, that its signature verifies against
    // the key it carries, that the key meets AXIAM's policy, that it asks for
    // no extension AXIAM refuses, that the validity fits — is checked
    // server-side and rendered verbatim below. Duplicating those rules here
    // would give an operator two opinions that can disagree.
    signCsrMutation.mutate({
      issuer_ca_id: csrIssuerCaId,
      csr_pem: pem,
      cert_type: csrCertType,
      validity_days: csrValidityDays,
    });
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
          <div className="flex shrink-0 gap-2">
            <Button variant="outline" onClick={openCsr}>
              <Upload size={16} />
              Sign a CSR
            </Button>
            <Button onClick={openGenerate}>
              <ShieldPlus size={16} />
              Generate Certificate
            </Button>
          </div>
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

      {/* Sign a CSR — a key AXIAM never sees */}
      <FormDialog
        open={csrOpen}
        onClose={() => {
          setCsrOpen(false);
          resetCsrForm();
        }}
        title="Sign a Certificate Signing Request"
        onSubmit={handleCsrSubmit}
        isLoading={signCsrMutation.isPending}
        submitLabel="Sign"
        error={csrError}
        errorId="certificate-csr-error"
      >
        <SignCsrFields
          certType={csrCertType}
          validityDays={csrValidityDays}
          issuerCaId={csrIssuerCaId}
          csrPem={csrPem}
          caOptions={caOptions}
          caLoading={caLoading}
          onCertTypeChange={setCsrCertType}
          onValidityDaysChange={setCsrValidityDays}
          onIssuerCaIdChange={setCsrIssuerCaId}
          onCsrPemChange={setCsrPem}
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

import { useRef, useState } from "react";
import { useMutation } from "@tanstack/react-query";
import { AlertCircle, AlertTriangle, FileUp, Loader2, X } from "lucide-react";
import { samlService, type SamlSpMetadataDraft } from "@/services/saml";
import { InfoRow, SectionCard } from "@/components/shared";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { CopyValue } from "./CopyValue";
import { samlErrorMessage } from "./samlErrors";
import { importRequest, isSignatureWarning } from "./samlForm";

/** The most the server accepts of an uploaded document (§29.2). */
const METADATA_MAX_BYTES = 512 * 1024;

/**
 * Step one of an import: a metadata document, pasted, uploaded or fetched from
 * an `https` URL, handed to `parse_sp_metadata`.
 *
 * **A parse, never a write** (D-41). The response is a draft the caller reviews
 * and edits in the ordinary form; the one thing this panel stores is nothing.
 */
export function MetadataImportPanel({
  tenantId,
  onDraft,
  onCancel,
}: {
  tenantId: string;
  onDraft: (draft: SamlSpMetadataDraft) => void;
  onCancel: () => void;
}) {
  const [xml, setXml] = useState("");
  const [url, setUrl] = useState("");
  const [problem, setProblem] = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  const parse = useMutation({
    mutationFn: (body: { metadata_xml: string } | { metadata_url: string }) =>
      samlService.parseSpMetadata(tenantId, body),
    onSuccess: (draft) => {
      setProblem(null);
      onDraft(draft);
    },
    onError: (err: unknown) => setProblem(samlErrorMessage(err, "The metadata could not be parsed.")),
  });

  function handleParse() {
    setProblem(null);
    const request = importRequest(xml, url);
    if (!request.ok) {
      setProblem(request.reason);
      return;
    }
    parse.mutate(request.body);
  }

  function handleFile(file: File | undefined) {
    if (!file) return;
    if (file.size > METADATA_MAX_BYTES) {
      setProblem("That file is over 512 KiB, which is more than the server accepts.");
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      setXml(typeof reader.result === "string" ? reader.result : "");
      setUrl("");
      setProblem(null);
    };
    reader.onerror = () => setProblem("The file could not be read.");
    reader.readAsText(file);
  }

  return (
    <SectionCard title="Import from metadata">
      <div className="space-y-4">
        <p className="text-sm text-muted-foreground">
          Paste or upload the service provider&rsquo;s metadata XML, or give the https URL it is
          published at. AXIAM parses it into a <strong>draft</strong> you review and edit before
          anything is saved. The server fetches a URL itself, once, and never refreshes it later.
        </p>

        <div className="space-y-1.5">
          <Label htmlFor="saml-import-xml">Metadata XML</Label>
          <Textarea
            id="saml-import-xml"
            value={xml}
            onChange={(e) => setXml(e.target.value)}
            rows={8}
            spellCheck={false}
            className="font-mono text-xs"
            placeholder="<EntityDescriptor …>"
          />
          <div className="flex items-center gap-2">
            <input
              ref={fileRef}
              type="file"
              accept=".xml,text/xml,application/xml,application/samlmetadata+xml"
              aria-label="Upload metadata file"
              className="sr-only"
              onChange={(e) => {
                handleFile(e.target.files?.[0]);
                e.target.value = "";
              }}
            />
            <Button
              type="button"
              variant="outline"
              size="sm"
              onClick={() => fileRef.current?.click()}
            >
              <FileUp size={14} aria-hidden="true" />
              Choose a file…
            </Button>
            <span className="text-xs text-muted-foreground">At most 512 KiB.</span>
          </div>
        </div>

        <div className="space-y-1.5">
          <Label htmlFor="saml-import-url">Or metadata URL</Label>
          <Input
            id="saml-import-url"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            autoComplete="off"
            spellCheck={false}
            placeholder="https://sp.example.com/saml/metadata"
          />
          <p className="text-xs text-muted-foreground">
            https only. Addresses on a private network are refused by the server.
          </p>
        </div>

        {problem && (
          <p role="alert" className="flex items-start gap-2 text-sm text-destructive">
            <AlertCircle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
            <span>{problem}</span>
          </p>
        )}

        <div className="flex gap-3 border-t border-primary/10 pt-4">
          <Button size="sm" onClick={handleParse} disabled={parse.isPending}>
            {parse.isPending && <Loader2 size={14} className="animate-spin" aria-hidden="true" />}
            Parse metadata
          </Button>
          <Button variant="outline" size="sm" onClick={onCancel} disabled={parse.isPending}>
            <X size={14} aria-hidden="true" />
            Cancel
          </Button>
        </div>
      </div>
    </SectionCard>
  );
}

/**
 * What the parse found, with the warnings in front: shown above the form while
 * the administrator reviews a draft, so it is on screen at the moment of saving.
 *
 * Nothing in a draft is trusted because it came from a document (§29.3 rule 6).
 * The document is unsigned as far as AXIAM can tell — a signature it carries is
 * not evaluated, because there is nothing to evaluate it against — so the one
 * check that means anything is the administrator's, comparing the fingerprints
 * with the service provider's own administrator out of band.
 */
export function DraftReview({ draft }: { draft: SamlSpMetadataDraft }) {
  const signature = draft.warnings.filter(isSignatureWarning);
  const others = draft.warnings.filter((w) => !isSignatureWarning(w));
  return (
    <div className="mb-5 space-y-3" data-testid="metadata-draft">
      <div
        role="alert"
        className="rounded-md border border-amber-500/50 bg-amber-500/15 p-3 text-sm text-amber-100"
      >
        <p className="flex items-start gap-2 font-semibold">
          <AlertTriangle size={16} className="mt-0.5 shrink-0" aria-hidden="true" />
          <span>This is a draft. Nothing has been saved, and nothing in it is verified.</span>
        </p>
        <p className="mt-1">
          AXIAM cannot authenticate this document: a signature inside it is not evaluated, because
          there is nothing to evaluate it against. Treat every value below as a suggestion, and
          compare the certificate fingerprints with the service provider&rsquo;s administrator
          before you save.
        </p>
        {signature.length > 0 && (
          <ul className="mt-2 space-y-1">
            {signature.map((w) => (
              <li key={w} className="font-semibold">
                {w}
              </li>
            ))}
          </ul>
        )}
      </div>

      {others.length > 0 && (
        <div>
          <p className="text-sm font-medium text-foreground">Warnings</p>
          <ul className="mt-1 list-disc space-y-1 pl-5 text-sm text-amber-300">
            {others.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </div>
      )}

      <div>
        <InfoRow label="Signing cert SHA-256">
          {draft.signing_certificate_fingerprint ? (
            <CopyValue label="signing certificate fingerprint" value={draft.signing_certificate_fingerprint} />
          ) : (
            <span className="text-muted-foreground">No signing certificate in the document</span>
          )}
        </InfoRow>
        <InfoRow label="Encryption cert SHA-256">
          {draft.encryption_certificate_fingerprint ? (
            <CopyValue
              label="encryption certificate fingerprint"
              value={draft.encryption_certificate_fingerprint}
            />
          ) : (
            <span className="text-muted-foreground">No encryption certificate in the document</span>
          )}
        </InfoRow>
      </div>
    </div>
  );
}

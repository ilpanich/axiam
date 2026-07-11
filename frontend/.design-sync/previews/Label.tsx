import { Input, Label, Textarea } from "frontend";

// Widths use inline styles on purpose: the capture stylesheet only contains the
// utilities already used by src/, so preview-only classes like `w-80` are absent.
const field = { maxWidth: 340 };

export const LabeledField = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="lbl-org">Organization name</Label>
    <Input id="lbl-org" defaultValue="Acme Corporation" />
  </div>
);

export const RequiredField = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="lbl-role">
      Role name <span className="text-destructive">*</span>
    </Label>
    <Input id="lbl-role" placeholder="certificate-operator" />
    <p className="text-xs text-muted-foreground">Lowercase, hyphen-separated.</p>
  </div>
);

export const WithTextarea = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="lbl-desc">Role description</Label>
    <Textarea
      id="lbl-desc"
      rows={3}
      defaultValue="Grants issue and revoke on X.509 certificates within the tenant."
    />
  </div>
);

// DOM order is input-then-label so Tailwind's `peer-disabled:` sibling selector
// resolves; column-reverse restores the visual label-above-input order.
export const DisabledPeer = () => (
  <div style={{ ...field, display: "flex", flexDirection: "column-reverse", gap: 8 }}>
    <Input id="lbl-issuer" className="peer" disabled defaultValue="Acme Root CA — Ed25519" />
    <Label htmlFor="lbl-issuer">Issuing CA (locked)</Label>
  </div>
);

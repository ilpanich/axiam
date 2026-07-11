import { Label, Textarea } from "frontend";

// Widths use inline styles on purpose: the capture stylesheet only contains the
// utilities already used by src/, so preview-only classes like `w-96` are absent.
const field = { maxWidth: 400 };

export const Default = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-role">Role description</Label>
    <Textarea
      id="ta-role"
      rows={4}
      defaultValue="Grants read access to the audit log and permission to export signed OpenPGP archives for the acme-production tenant."
    />
  </div>
);

export const Placeholder = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-reason">Revocation reason</Label>
    <Textarea
      id="ta-reason"
      rows={4}
      placeholder="Explain why this X.509 certificate is being revoked (key compromise, CA compromise, superseded…)"
    />
  </div>
);

export const Monospace = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-pem">Certificate signing request (PEM)</Label>
    <Textarea
      id="ta-pem"
      rows={9}
      className="font-mono text-xs"
      defaultValue={`-----BEGIN CERTIFICATE REQUEST-----
MIIBSzCB/gIBADCBjTELMAkGA1UEBhMCSVQxDjAMBgNVBAgMBUxhemlvMQ0wCwYD
VQQHDARSb21lMRUwEwYDVQQKDAxBY21lIENvcnAxFDASBgNVBAsMC0lvVCBHYXRl
d2F5MRcwFQYDVQQDDA5nYXRld2F5LTA0LmlvdA==
-----END CERTIFICATE REQUEST-----`}
    />
  </div>
);

export const Disabled = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-locked">Tenant policy (managed by organization)</Label>
    <Textarea
      id="ta-locked"
      rows={3}
      disabled
      defaultValue="Password policy, MFA enforcement and session TTL are inherited from the Acme Corporation organization defaults."
    />
  </div>
);

export const Invalid = () => (
  <div className="space-y-2" style={field}>
    <Label htmlFor="ta-scopes">Consent scopes</Label>
    <Textarea
      id="ta-scopes"
      rows={3}
      aria-invalid
      className="border-destructive"
      defaultValue="openid profile email offline_access urn:acme:billing:*"
    />
    <p className="text-xs text-destructive">
      Wildcard scopes are not permitted for public OAuth2 clients.
    </p>
  </div>
);

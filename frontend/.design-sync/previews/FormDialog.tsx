import type { ReactNode } from "react";
import { FormDialog, Input, Label, Textarea, ToggleField } from "frontend";

/**
 * FormDialog renders `position: fixed; inset: 0` — left alone it escapes the
 * preview card and gets clipped by the sheet. A `transform` on the wrapper makes
 * it the containing block for fixed-position descendants (CSS Transforms spec),
 * so the whole dialog — backdrop, blur and all — is trapped inside the cell.
 */
function Stage({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        position: "relative",
        transform: "translateZ(0)",
        height: 480,
        width: "100%",
        overflow: "hidden",
        borderRadius: 12,
        border: "1px solid rgba(255,255,255,0.08)",
        background: "linear-gradient(135deg, #0d0d2b 0%, #1a0a3d 100%)",
      }}
    >
      {children}
    </div>
  );
}

const noop = () => {};
const submit = (e: React.FormEvent<HTMLFormElement>) => e.preventDefault();

/** Canonical: create a service account in the current tenant. */
export const CreateServiceAccount = () => (
  <Stage>
    <FormDialog
      open
      onClose={noop}
      onSubmit={submit}
      title="New service account"
      submitLabel="Create account"
    >
      <div className="space-y-2">
        <Label htmlFor="sa-name">Name</Label>
        <Input id="sa-name" defaultValue="svc-billing" />
      </div>
      <div className="space-y-2">
        <Label htmlFor="sa-desc">Description</Label>
        <Textarea
          id="sa-desc"
          rows={3}
          defaultValue="Machine-to-machine client for the invoicing pipeline."
        />
      </div>
      <ToggleField
        id="sa-mtls"
        label="Require mTLS client certificate"
        checked
        onChange={noop}
      />
    </FormDialog>
  </Stage>
);

/** A second, denser form: OAuth2 client registration. */
export const RegisterOAuthClient = () => (
  <Stage>
    <FormDialog
      open
      onClose={noop}
      onSubmit={submit}
      title="Register OAuth2 client"
      submitLabel="Register"
    >
      <div className="space-y-2">
        <Label htmlFor="oc-name">Client name</Label>
        <Input id="oc-name" defaultValue="acme-portal" />
      </div>
      <div className="space-y-2">
        <Label htmlFor="oc-redirect">Redirect URI</Label>
        <Input
          id="oc-redirect"
          defaultValue="https://portal.acme.io/oauth2/callback"
        />
      </div>
      <ToggleField
        id="oc-pkce"
        label="Enforce PKCE (Authorization Code)"
        checked
        onChange={noop}
      />
      <ToggleField
        id="oc-refresh"
        label="Issue rotating refresh tokens"
        checked={false}
        onChange={noop}
      />
    </FormDialog>
  </Stage>
);

/** Submitting state — footer button shows the spinner, fields stay readable. */
export const Submitting = () => (
  <Stage>
    <FormDialog
      open
      onClose={noop}
      onSubmit={submit}
      title="Issue X.509 certificate"
      submitLabel="Issue certificate"
      isLoading
    >
      <div className="space-y-2">
        <Label htmlFor="cert-cn">Common name</Label>
        <Input id="cert-cn" defaultValue="gateway.acme-prod" />
      </div>
      <div className="space-y-2">
        <Label htmlFor="cert-alg">Algorithm</Label>
        <Input id="cert-alg" defaultValue="Ed25519" />
      </div>
    </FormDialog>
  </Stage>
);

import type { ReactNode } from "react";
import { ConfirmDialog } from "frontend";

/**
 * ConfirmDialog renders `position: fixed; inset: 0` — left alone it escapes the
 * preview card and covers the whole sheet. A `transform` on the wrapper makes it
 * the containing block for fixed-position descendants (CSS Transforms spec), so
 * the real dialog — backdrop, blur and all — is trapped inside the cell.
 */
function Stage({ children }: { children: ReactNode }) {
  return (
    <div
      style={{
        position: "relative",
        transform: "translateZ(0)",
        height: 400,
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

export function RevokeCertificate() {
  return (
    <Stage>
      <ConfirmDialog
        open
        onClose={noop}
        onConfirm={noop}
        title="Revoke certificate 3f:a9:1c:7e:04:b2?"
        description="The X.509 device certificate for iot-gateway-04.acme-prod will be added to the CRL and stop authenticating immediately. This cannot be undone."
        confirmLabel="Revoke certificate"
      />
    </Stage>
  );
}

export function DeleteRole() {
  return (
    <Stage>
      <ConfirmDialog
        open
        onClose={noop}
        onConfirm={noop}
        title="Delete role tenant-admin?"
        description="12 users and 3 groups inherit this role. Their effective permissions are recalculated on the next token refresh."
      />
    </Stage>
  );
}

export function RotateClientSecret() {
  return (
    <Stage>
      <ConfirmDialog
        open
        onClose={noop}
        onConfirm={noop}
        title="Rotate client secret for acme-portal?"
        description="A new secret is issued once and shown only now. The current secret keeps working for a 60-second grace period."
        confirmLabel="Rotate secret"
        cancelLabel="Keep current"
      />
    </Stage>
  );
}

export function DeletingServiceAccount() {
  return (
    <Stage>
      <ConfirmDialog
        open
        isLoading
        onClose={noop}
        onConfirm={noop}
        title="Delete service account ci-deploy-bot?"
        description="Revoking this service account will break any pipeline still presenting its OAuth2 client credentials."
      />
    </Stage>
  );
}

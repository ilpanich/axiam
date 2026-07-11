import { TotpSetupPanel } from "frontend";
import { useState } from "react";

// TotpSetupPanel is fully props-driven — no fetching. The `code` value is owned
// by the caller, so each story holds it in local state.

const SETUP = {
  secret_base32: "JBSWY3DPEHPK3PXPKR2XG5DFOJZWS33O",
  totp_uri:
    "otpauth://totp/AXIAM:e.panigati@acme.example?secret=JBSWY3DPEHPK3PXPKR2XG5DFOJZWS33O&issuer=AXIAM%20acme-prod&algorithm=SHA1&digits=6&period=30",
};

export const Enrolling = () => {
  const [code, setCode] = useState("");
  return (
    <div className="glass-card p-6 max-w-sm">
      <TotpSetupPanel
        setupData={SETUP}
        code={code}
        onCodeChange={setCode}
        onConfirm={() => {}}
        error={null}
        isPending={false}
        confirmLabel="Enable MFA"
        onCancel={() => {}}
      />
    </div>
  );
};

export const CodeEntered = () => {
  const [code, setCode] = useState("482915");
  return (
    <div className="glass-card p-6 max-w-sm">
      <TotpSetupPanel
        setupData={SETUP}
        code={code}
        onCodeChange={setCode}
        onConfirm={() => {}}
        error={null}
        isPending={false}
        confirmLabel="Enable MFA"
        onCancel={() => {}}
      />
    </div>
  );
};

export const RejectedCode = () => {
  const [code, setCode] = useState("300174");
  return (
    <div className="glass-card p-6 max-w-sm">
      <TotpSetupPanel
        setupData={SETUP}
        code={code}
        onCodeChange={setCode}
        onConfirm={() => {}}
        error="Invalid MFA code — the code did not match the enrolled secret. Check your device clock and try the next code."
        isPending={false}
        confirmLabel="Enable MFA"
        onCancel={() => {}}
      />
    </div>
  );
};

export const Confirming = () => {
  const [code, setCode] = useState("729300");
  return (
    <div className="glass-card p-6 max-w-sm">
      <TotpSetupPanel
        setupData={SETUP}
        code={code}
        onCodeChange={setCode}
        onConfirm={() => {}}
        error={null}
        isPending
        confirmLabel="Enable MFA"
        confirmPendingLabel="Verifying…"
      />
    </div>
  );
};

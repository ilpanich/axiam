import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import { CheckCircle2, Loader2, ShieldQuestion, XCircle } from "lucide-react";
import {
  deviceService,
  formatUserCode,
  normalizeUserCode,
  type DeviceVerifyResponse,
} from "@/services/device";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { getApiErrorMessage } from "@/lib/apiError";

// ─── Device verification page (B2 step 3) ─────────────────────────────────────
//
// RFC 8628's second device: a human with a keyboard types the short code shown
// on the input-constrained device (a TV, a CLI, a sensor) and approves or
// refuses the grant on its behalf. See `crates/axiam-api-rest/src/handlers/
// device.rs` for the endpoint contract this page drives.
//
// No `ProtectedRoute` permission wraps this route (router.tsx): approving
// one's own device grant needs no admin permission, only an authenticated
// session — the same "requiredPermission: null" class as /profile.
// `AppLayout` still redirects to /login when unauthenticated.

type Step = "entry" | "consent" | "done";

interface DecideOutcome {
  approved: boolean;
  ok: boolean;
}

export function DevicePage() {
  const [searchParams] = useSearchParams();
  const [step, setStep] = useState<Step>("entry");
  const [rawCode, setRawCode] = useState("");
  const [verifying, setVerifying] = useState(false);
  const [deciding, setDeciding] = useState(false);
  const [error, setError] = useState("");
  const [grant, setGrant] = useState<DeviceVerifyResponse | null>(null);
  const [outcome, setOutcome] = useState<DecideOutcome | null>(null);

  async function runVerify(codeInput: string) {
    const code = normalizeUserCode(codeInput);
    if (!code) {
      setError("Enter the code shown on your device.");
      return;
    }
    setError("");
    setVerifying(true);
    try {
      const result = await deviceService.verify(code);
      setRawCode(code);
      if (result.found) {
        setGrant(result);
        setStep("consent");
      } else {
        // T-15-02 style genericity applies here too: the handler collapses
        // unknown/expired/already-decided into one `found: false`, and the
        // UI must not try to guess which — see device.rs module docs.
        setError(
          "That code wasn't found. It may have expired, already been used, or been typed incorrectly — check your device and try again.",
        );
      }
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setVerifying(false);
    }
  }

  // Support the QR-code path: a `?user_code=` query param auto-verifies so a
  // user who scans the code lands straight on the consent screen instead of
  // having to retype what a camera already read.
  const prefillCode = searchParams.get("user_code");
  useEffect(() => {
    if (prefillCode) {
      setRawCode(normalizeUserCode(prefillCode));
      void runVerify(prefillCode);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefillCode]);

  async function handleDecide(approved: boolean) {
    setError("");
    setDeciding(true);
    try {
      const result = await deviceService.decide(rawCode, approved);
      setOutcome({ approved, ok: result.ok });
      setStep("done");
    } catch (err) {
      setError(getApiErrorMessage(err));
    } finally {
      setDeciding(false);
    }
  }

  function handleEntrySubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    void runVerify(rawCode);
  }

  function startOver() {
    setStep("entry");
    setRawCode("");
    setGrant(null);
    setOutcome(null);
    setError("");
  }

  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <div className="glass-card w-full max-w-md p-8">
        <div className="flex flex-col items-center text-center gap-2 mb-6">
          <ShieldQuestion size={32} className="text-primary" aria-hidden="true" />
          <h1 className="text-xl font-bold text-foreground">Connect a device</h1>
          <p className="text-sm text-muted-foreground">
            Enter the code shown on your TV, CLI, or other device to approve
            its sign-in.
          </p>
        </div>

        {step === "entry" && (
          <form onSubmit={handleEntrySubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="device-user-code">Device code</Label>
              <Input
                id="device-user-code"
                value={rawCode}
                onChange={(e) => setRawCode(e.target.value)}
                placeholder="WXYZ-1234"
                autoComplete="off"
                autoCapitalize="characters"
                className="text-center text-lg font-mono tracking-widest"
                error={error || undefined}
              />
            </div>
            <Button type="submit" className="w-full" disabled={verifying}>
              {verifying ? <Loader2 size={16} className="animate-spin" /> : "Continue"}
            </Button>
          </form>
        )}

        {step === "consent" && grant && (
          <div className="space-y-5">
            <div className="rounded-md border border-primary/20 bg-white/5 p-4 space-y-3">
              <p className="text-xs uppercase tracking-wider text-muted-foreground">
                Code
              </p>
              <p className="text-center text-lg font-mono tracking-widest text-foreground">
                {formatUserCode(rawCode)}
              </p>
            </div>

            <div className="space-y-1">
              <p className="text-sm text-muted-foreground">
                <span className="font-medium text-foreground">
                  {grant.client_id ?? "This application"}
                </span>{" "}
                is requesting access to your account with the following
                permissions:
              </p>
              {grant.scopes && grant.scopes.length > 0 ? (
                <ul className="mt-2 space-y-1" aria-label="Requested scopes">
                  {grant.scopes.map((scope) => (
                    <li
                      key={scope}
                      className="text-sm font-mono text-foreground/80 bg-white/5 rounded px-2 py-1 border border-white/10"
                    >
                      {scope}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="text-sm text-muted-foreground italic mt-2">
                  No specific scopes requested.
                </p>
              )}
            </div>

            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}

            <div className="flex gap-3">
              <Button
                variant="ghost"
                className="flex-1"
                disabled={deciding}
                onClick={() => void handleDecide(false)}
              >
                {deciding ? <Loader2 size={16} className="animate-spin" /> : "Deny"}
              </Button>
              <Button
                className="flex-1"
                disabled={deciding}
                onClick={() => void handleDecide(true)}
              >
                {deciding ? <Loader2 size={16} className="animate-spin" /> : "Approve"}
              </Button>
            </div>
          </div>
        )}

        {step === "done" && outcome && (
          <div className="flex flex-col items-center text-center gap-3 py-4">
            {outcome.ok && outcome.approved ? (
              <>
                <CheckCircle2 size={36} className="text-primary" aria-hidden="true" />
                <p className="text-foreground font-medium">Device approved</p>
                <p className="text-sm text-muted-foreground">
                  You may now return to your device — it will finish signing in
                  automatically.
                </p>
              </>
            ) : outcome.ok && !outcome.approved ? (
              <>
                <XCircle size={36} className="text-muted-foreground" aria-hidden="true" />
                <p className="text-foreground font-medium">Access denied</p>
                <p className="text-sm text-muted-foreground">
                  The device was not granted access.
                </p>
              </>
            ) : (
              <>
                <XCircle size={36} className="text-destructive" aria-hidden="true" />
                <p className="text-foreground font-medium">Couldn't record your decision</p>
                <p className="text-sm text-muted-foreground">
                  The code may have expired or already been decided. Try again
                  from your device.
                </p>
              </>
            )}
            <Button variant="ghost" onClick={startOver} className="mt-2">
              Connect another device
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

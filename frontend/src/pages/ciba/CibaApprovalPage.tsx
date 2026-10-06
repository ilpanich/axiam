import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";
import axios from "axios";
import { CheckCircle2, Loader2, ShieldAlert, ShieldQuestion, XCircle } from "lucide-react";
import {
  cibaService,
  parseRequestId,
  stepUpLoginPath,
  type CibaApprovalRequest,
  type CibaStepUpRequired,
} from "@/services/ciba";
import { ACR_MULTI_FACTOR } from "@/lib/reauth";
import { Button } from "@/components/ui/button";
import { getApiErrorMessage } from "@/lib/apiError";

// ─── CIBA approval page (G-7, T23.7.2) ───────────────────────────────────────
//
// The user's half of an OpenID Connect CIBA request: a client (a call centre, a
// point-of-sale terminal, a back-office service) asked AXIAM to authenticate
// *this* user on another device, and the user was told by e-mail. They arrive
// from the link in that mail -- `/ciba/approve?request_id=<uuid>` -- sign in if
// they are not already, compare the binding message with what the client's own
// device shows, and approve or refuse. See `crates/axiam-api-rest/src/handlers/
// ciba_approval.rs` for the endpoint contract this page drives.
//
// What this page is careful about:
//
//  * **The binding message is text.** A client chooses it, so it is rendered as
//    a React text node and nowhere else -- never `dangerouslySetInnerHTML`, never
//    an attribute, never a link.
//  * **One answer for every reason a request cannot be decided** (unknown id,
//    another user's, expired, already decided, changed since read): the server
//    sends the same 404 for all of them (D-68) and so does this page. Trying to
//    tell them apart would turn it into an oracle for which ids exist.
//  * **Step-up** goes through the existing login hop
//    (`/login?return_to=…&reauth=1&acr=…`): the login page ends the weak session,
//    demands the factor and returns here. Nothing is consumed on the way back --
//    the page reads the request afresh and the decision is conditional on the
//    version that read returned.
//
// No `ProtectedRoute` permission wraps this route (router.tsx): deciding a
// request addressed to oneself needs no admin permission, only an authenticated
// session -- the same class as /device and /profile.

type Step = "loading" | "ready" | "done" | "gone" | "error";

/** What the user is told after deciding. */
type Outcome = "approved" | "denied" | "gone";

function formatExpiry(iso: string): string {
  const at = new Date(iso);
  if (Number.isNaN(at.getTime())) return "";
  return at.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

/** The class a `403 step_up_required` named, if that is what `err` is. */
function stepUpOf(err: unknown): string | null {
  if (!axios.isAxiosError(err) || err.response?.status !== 403) return null;
  const body = err.response.data as Partial<CibaStepUpRequired> | undefined;
  if (body?.error !== "step_up_required") return null;
  return typeof body.required_acr === "string" ? body.required_acr : ACR_MULTI_FACTOR;
}

export function CibaApprovalPage() {
  const [searchParams] = useSearchParams();
  const requestId = parseRequestId(searchParams.get("request_id"));

  const [step, setStep] = useState<Step>(requestId ? "loading" : "gone");
  const [request, setRequest] = useState<CibaApprovalRequest | null>(null);
  // The class the next sign-in has to achieve, when approving was refused for
  // want of it. Seeded from the read, overwritten by a refusal.
  const [stepUp, setStepUp] = useState<string | null>(null);
  const [deciding, setDeciding] = useState(false);
  const [error, setError] = useState("");
  const [outcome, setOutcome] = useState<Outcome | null>(null);

  useEffect(() => {
    if (!requestId) return;
    let cancelled = false;
    void (async () => {
      try {
        const read = await cibaService.get(requestId);
        if (cancelled) return;
        setRequest(read);
        setStepUp(read.step_up_required);
        setStep("ready");
      } catch (err) {
        if (cancelled) return;
        if (axios.isAxiosError(err) && err.response?.status === 404) {
          setStep("gone");
        } else {
          setError(getApiErrorMessage(err));
          setStep("error");
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [requestId]);

  async function handleDecide(approve: boolean) {
    if (!requestId || !request) return;
    setError("");
    setDeciding(true);
    try {
      if (approve) {
        await cibaService.approve(requestId, request.version);
      } else {
        await cibaService.deny(requestId, request.version);
      }
      setOutcome(approve ? "approved" : "denied");
      setStep("done");
    } catch (err) {
      const required = approve ? stepUpOf(err) : null;
      if (required) {
        // Refused for want of a stronger sign-in. Nothing was decided; offer
        // the step-up instead of an error.
        setStepUp(required);
      } else if (axios.isAxiosError(err) && err.response?.status === 404) {
        setOutcome("gone");
        setStep("done");
      } else {
        setError(getApiErrorMessage(err));
      }
    } finally {
      setDeciding(false);
    }
  }

  function startStepUp() {
    if (!requestId || !stepUp) return;
    // A full navigation: the login page is outside this view's state, and it
    // ends this session before showing its form.
    window.location.assign(stepUpLoginPath(requestId, stepUp));
  }

  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <div className="glass-card w-full max-w-md p-8">
        <div className="flex flex-col items-center text-center gap-2 mb-6">
          <ShieldQuestion size={32} className="text-primary" aria-hidden="true" />
          <h1 className="text-xl font-bold text-foreground">Approve a sign-in</h1>
          <p className="text-sm text-muted-foreground">
            An application asked to sign you in from another device.
          </p>
        </div>

        {step === "loading" && (
          <div
            className="flex justify-center py-6"
            role="status"
            aria-label="Loading the sign-in request"
          >
            <Loader2 size={24} className="animate-spin text-muted-foreground" />
          </div>
        )}

        {step === "gone" && (
          <div className="flex flex-col items-center text-center gap-3 py-4">
            <XCircle size={36} className="text-muted-foreground" aria-hidden="true" />
            <p className="text-foreground font-medium">Request not found</p>
            <p className="text-sm text-muted-foreground">
              This sign-in request was not found. It may have expired, already
              been decided, or belong to a different account. If you are
              expecting one, ask the application to send it again.
            </p>
          </div>
        )}

        {step === "error" && (
          <div className="flex flex-col items-center text-center gap-3 py-4">
            <XCircle size={36} className="text-destructive" aria-hidden="true" />
            <p className="text-foreground font-medium">Couldn't load the request</p>
            <p role="alert" className="text-sm text-muted-foreground">
              {error}
            </p>
          </div>
        )}

        {step === "ready" && request && (
          <div className="space-y-5">
            <p className="text-sm text-muted-foreground">
              <span className="font-medium text-foreground">{request.client_name}</span>{" "}
              is asking to sign you in with the following permissions:
            </p>

            {request.scopes.length > 0 && (
              <ul className="space-y-1" aria-label="Requested scopes">
                {request.scopes.map((scope) => (
                  <li
                    key={scope}
                    className="text-sm font-mono text-foreground/80 bg-white/5 rounded px-2 py-1 border border-white/10"
                  >
                    {scope}
                  </li>
                ))}
              </ul>
            )}

            {request.binding_message && (
              <div className="rounded-md border border-primary/20 bg-white/5 p-4 space-y-1">
                <p className="text-xs uppercase tracking-wider text-muted-foreground">
                  Message from the application
                </p>
                {/* Text only: the client chose this string. */}
                <p
                  data-testid="binding-message"
                  className="text-lg font-semibold text-foreground break-words"
                >
                  {request.binding_message}
                </p>
                <p className="text-xs text-muted-foreground">
                  Approve only if this matches what the application shows you.
                </p>
              </div>
            )}

            <p className="text-xs text-muted-foreground">
              Expires at {formatExpiry(request.expires_at)}.
            </p>

            {stepUp && (
              <div
                role="status"
                className="flex gap-3 rounded-md border border-amber-500/30 bg-amber-500/10 p-3"
              >
                <ShieldAlert
                  size={18}
                  className="mt-0.5 shrink-0 text-amber-500"
                  aria-hidden="true"
                />
                <p className="text-sm text-foreground">
                  This request needs a stronger sign-in than your current session
                  (a second factor). Sign in again to approve it.
                </p>
              </div>
            )}

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
                Deny
              </Button>
              {stepUp ? (
                <Button className="flex-1" disabled={deciding} onClick={startStepUp}>
                  Sign in again
                </Button>
              ) : (
                <Button
                  className="flex-1"
                  disabled={deciding}
                  onClick={() => void handleDecide(true)}
                >
                  {deciding ? <Loader2 size={16} className="animate-spin" /> : "Approve"}
                </Button>
              )}
            </div>
          </div>
        )}

        {step === "done" && outcome && (
          <div className="flex flex-col items-center text-center gap-3 py-4">
            {outcome === "approved" && (
              <>
                <CheckCircle2 size={36} className="text-primary" aria-hidden="true" />
                <p className="text-foreground font-medium">Sign-in approved</p>
                <p className="text-sm text-muted-foreground">
                  You may return to the application — it will finish signing you in.
                </p>
              </>
            )}
            {outcome === "denied" && (
              <>
                <XCircle size={36} className="text-muted-foreground" aria-hidden="true" />
                <p className="text-foreground font-medium">Sign-in refused</p>
                <p className="text-sm text-muted-foreground">
                  The application was not signed in. If you did not expect this
                  request, consider changing your password.
                </p>
              </>
            )}
            {outcome === "gone" && (
              <>
                <XCircle size={36} className="text-destructive" aria-hidden="true" />
                <p className="text-foreground font-medium">Couldn't record your decision</p>
                <p className="text-sm text-muted-foreground">
                  The request may have expired or already been decided. Ask the
                  application to send it again.
                </p>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/**
 * The OpenID Connect consent screen (W7, `claude_dev/basic-op-gap-plan.md` §4.8).
 *
 * `/oauth2/authorize` sends a **signed-in** browser here when a relying party
 * asks for `address` or `phone` and no consent record covers that client and
 * that scope set. The page asks one question, records the answer through
 * `POST /api/v1/account/consents/oidc-scopes`, and navigates back to the
 * authorization request either way.
 *
 * # Why "Not now" also navigates back
 *
 * Declining is not a dead end and it is not a separate protocol path. The
 * browser returns to the same authorization request carrying the login-hop
 * marker, and the server's return-leg rule
 * (`axiam_oauth2::sensitive::decide`) turns "asked once, still no consent"
 * into `access_denied`, redirected to the relying party's registered
 * `redirect_uri` with its `state`. So the relying party learns the outcome
 * through the protocol rather than through a page the user has to close, and
 * this component needs no knowledge of redirect URIs at all.
 *
 * It is also what bounds the chain at one hop: the server answers rather than
 * redirects a second time, exactly as it does for the W4 login hop.
 *
 * # Why there is no "remember this" checkbox
 *
 * There is nothing else it could mean. The consent record *is* the memory, it
 * is what the release gate reads on every UserInfo call, and it lasts until
 * the user withdraws it from Privacy & Data. A checkbox offering not to
 * remember would be offering a one-request release the release gate cannot
 * express.
 *
 * # Invariant 4
 *
 * No client registered before W7 can reach this page: `address` and `phone`
 * were unregistrable, so no authorization request could name them. A
 * deployment that never turns the tenant switch on never renders it.
 */

import { useEffect, useState } from "react";
import { useSearchParams } from "react-router";

import { resolveLocale, sanitizeDisplay, useMessages } from "@/i18n";
import {
  type ConsentRequest,
  parseConsentRequest,
} from "@/lib/consentRequest";
import { sanitizeReturnTo } from "@/lib/returnTo";
import { gdprService } from "@/services/gdpr";

export function ConsentPage() {
  const [searchParams] = useSearchParams();

  // Read once from the initial URL, like `LoginPage` does and for the same
  // reason: a reload mid-decision must not change the language, the layout or
  // the request being decided.
  const [locale] = useState(() => resolveLocale(searchParams.get("ui_locale")));
  const [displayMode] = useState(() =>
    sanitizeDisplay(searchParams.get("display")),
  );
  const [returnTo] = useState<string | null>(() =>
    sanitizeReturnTo(searchParams.get("return_to")),
  );
  const [request] = useState<ConsentRequest | null>(() =>
    parseConsentRequest(searchParams.get("return_to")),
  );
  const m = useMessages(locale);

  const [saving, setSaving] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    document.documentElement.lang = locale;
    return () => {
      document.documentElement.lang = "en";
    };
  }, [locale]);

  // Nothing to decide: no usable `return_to`, no client, or no sensitive scope
  // in the request. Say so rather than render a form with no subject.
  if (!returnTo || !request) {
    return (
      <main className="mx-auto max-w-md p-8" data-display={displayMode}>
        <p>{m.consentNothingToDo}</p>
      </main>
    );
  }

  // A full navigation, not a client-side route change: `return_to` names
  // `/oauth2/authorize`, which is the server's route and not the SPA's.
  const resume = () => {
    window.location.assign(returnTo);
  };

  const allow = async () => {
    setSaving(true);
    setFailed(false);
    try {
      await gdprService.grantScopeConsent(request.clientId, [...request.scopes]);
      resume();
    } catch {
      // Deliberately not resumed on failure. Returning to the authorization
      // request now would produce `access_denied` — the answer for a user who
      // declined — and this user did not decline.
      setSaving(false);
      setFailed(true);
    }
  };

  return (
    <main className="mx-auto max-w-md p-8" data-display={displayMode}>
      <h1 className="text-xl font-semibold">{m.consentHeading}</h1>

      {/*
        The client id reaches the DOM through React value binding, never
        `dangerouslySetInnerHTML` and never an attribute built by
        concatenation — the same rule `login_hint` follows on the sign-in
        page, and for the same reason: it is a registered identifier, but it
        is one an operator chose and this page does not get to assume it is
        tame.
      */}
      <p className="mt-4">
        {m.consentIntro.replace("{client}", request.clientId)}
      </p>

      <ul className="mt-4 list-disc pl-6">
        {request.scopes.map((scope) => (
          <li key={scope}>
            {scope === "phone" ? m.consentPhone : m.consentAddress}
          </li>
        ))}
      </ul>

      <p className="mt-4 text-sm text-muted-foreground">
        {m.consentWithdrawNote}
      </p>

      {failed && (
        <p className="mt-4 text-sm text-destructive" role="alert">
          {m.consentFailed}
        </p>
      )}

      <div className="mt-6 flex gap-3">
        <button type="button" onClick={allow} disabled={saving}>
          {saving ? m.consentSaving : m.consentAllowAction}
        </button>
        <button type="button" onClick={resume} disabled={saving}>
          {m.consentDenyAction}
        </button>
      </div>
    </main>
  );
}

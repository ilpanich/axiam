import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ToggleField } from "@/components/shared";
import {
  DEFAULT_NATIVE_LOGIN_TRUST,
  MAX_NATIVE_LOGIN_CLIENT_IDS,
  MAX_TOKEN_AGE_CEILING_SECS,
  validateNativeLoginClientId,
  type NativeLoginTrust,
} from "@/services/federation";

/**
 * G-A — editor for a federation provider's native sign-in trust.
 *
 * Native sign-in lets a mobile or desktop app that has already signed the user
 * in with this provider (Sign in with Google / Apple) present the provider's ID
 * token to AXIAM and receive AXIAM tokens in return, via the
 * `urn:axiam:params:oauth:grant-type:provider-id-token` grant. It is a trust
 * boundary exactly as external token exchange is, so it is its own card, off by
 * default, and enabling browser login does not turn it on.
 *
 * The one field that decides what is accepted is the client-ID list: an ID
 * token is taken only if its audience is listed. The provider's web `client_id`
 * is deliberately *not* implied — a token minted for the web client is a
 * different trust decision from one minted for an app.
 *
 * OIDC only: the server refuses an enabled block on a SAML or OAuth2 provider,
 * which has no ID token to verify.
 */

export interface NativeLoginTrustEditorProps {
  /** The live trust block. */
  value: NativeLoginTrust;
  onChange: (next: NativeLoginTrust) => void;
  /** Controls are replaced by an explanation on non-OIDC providers. */
  isOidc: boolean;
  idPrefix: string;
}

export function NativeLoginTrustEditor({
  value,
  onChange,
  isOidc,
  idPrefix,
}: NativeLoginTrustEditorProps) {
  const [draft, setDraft] = useState("");
  const [draftError, setDraftError] = useState("");

  if (!isOidc) {
    return (
      <div className="border-t border-border pt-4 mt-4">
        <h3 className="text-sm font-semibold mb-1">Native App Sign-In</h3>
        <p className="text-xs text-muted-foreground">
          Available for OpenID Connect providers only. A SAML or plain OAuth2
          provider issues no ID token, so there is nothing an app could present
          for AXIAM to verify.
        </p>
      </div>
    );
  }

  const set = (patch: Partial<NativeLoginTrust>) =>
    onChange({ ...value, ...patch });

  function addClientId() {
    // Exact entry, only trimmed at the edges of what was typed: the server
    // compares audiences byte for byte, so what is stored is what is matched.
    const candidate = draft.trim();
    const problem = validateNativeLoginClientId(candidate, value.client_ids);
    if (problem) {
      setDraftError(problem);
      return;
    }
    setDraftError("");
    setDraft("");
    set({ client_ids: [...value.client_ids, candidate] });
  }

  const ageValid =
    Number.isInteger(value.max_token_age_secs) &&
    value.max_token_age_secs >= 1 &&
    value.max_token_age_secs <= MAX_TOKEN_AGE_CEILING_SECS;

  return (
    <div
      className="border-t border-border pt-4 mt-4 space-y-4"
      data-testid="native-login-trust"
    >
      <div>
        <h3 className="text-sm font-semibold">Native App Sign-In</h3>
        <p className="text-xs text-muted-foreground mt-1">
          Accept ID tokens issued by <em>this</em> provider to your mobile or
          desktop apps as a sign-in, in exchange for AXIAM tokens. Enabling
          browser login for this provider does <strong>not</strong> imply
          accepting app tokens &mdash; this is a separate trust decision, off by
          default. The OAuth2 client that calls this must also hold the{" "}
          <code>provider-id-token</code> grant.
        </p>
      </div>

      <ToggleField
        id={`${idPrefix}-nl-enabled`}
        label="Accept this provider's ID tokens from native apps"
        checked={value.enabled}
        onChange={(enabled) => set({ enabled })}
      />

      <div className="space-y-1.5">
        <Label htmlFor={`${idPrefix}-nl-client-id`}>
          Accepted client IDs ({value.client_ids.length}/
          {MAX_NATIVE_LOGIN_CLIENT_IDS})
        </Label>
        <div className="flex gap-2">
          <Input
            id={`${idPrefix}-nl-client-id`}
            value={draft}
            onChange={(e) => {
              setDraft(e.target.value);
              if (draftError) setDraftError("");
            }}
            onKeyDown={(e) => {
              // Inside the dialog's <form>: Enter must add, not submit.
              if (e.key === "Enter") {
                e.preventDefault();
                addClientId();
              }
            }}
            placeholder="com.example.app"
            autoComplete="off"
            aria-invalid={draftError ? true : undefined}
            aria-describedby={
              draftError ? `${idPrefix}-nl-client-id-error` : undefined
            }
          />
          <Button type="button" variant="outline" onClick={addClientId}>
            Add client ID
          </Button>
        </div>
        {draftError && (
          <p
            id={`${idPrefix}-nl-client-id-error`}
            role="alert"
            className="text-xs text-destructive"
          >
            {draftError}
          </p>
        )}
        {value.client_ids.length > 0 && (
          <ul className="space-y-1" aria-label="Listed client IDs">
            {value.client_ids.map((id) => (
              <li
                key={id}
                className="flex items-center justify-between gap-2 rounded-md border border-input px-2 py-1"
              >
                <code className="text-xs break-all">{id}</code>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label={`Remove client ID ${id}`}
                  onClick={() =>
                    set({
                      client_ids: value.client_ids.filter((c) => c !== id),
                    })
                  }
                >
                  Remove
                </Button>
              </li>
            ))}
          </ul>
        )}
        <p className="text-xs text-muted-foreground">
          The audience an app&apos;s ID token must carry: the iOS bundle ID,
          Android client ID or Apple app ID the native SDK was configured with.
          Required when enabled, matched exactly, and there is no accept-all
          value. The provider&apos;s web client ID is <strong>not</strong>{" "}
          accepted unless you list it here.
        </p>
      </div>

      <div className="space-y-1.5 max-w-xs">
        <Label htmlFor={`${idPrefix}-nl-max-age`}>
          Max token age (seconds)
        </Label>
        <Input
          id={`${idPrefix}-nl-max-age`}
          type="number"
          min={1}
          max={MAX_TOKEN_AGE_CEILING_SECS}
          value={value.max_token_age_secs}
          aria-invalid={ageValid ? undefined : true}
          onChange={(e) =>
            set({
              max_token_age_secs:
                Number(e.target.value) ||
                DEFAULT_NATIVE_LOGIN_TRUST.max_token_age_secs,
            })
          }
        />
        {!ageValid && (
          <p role="alert" className="text-xs text-destructive">
            Must be a whole number between 1 and {MAX_TOKEN_AGE_CEILING_SECS}.
          </p>
        )}
        <p className="text-xs text-muted-foreground">
          Bounds how old a presented ID token may be, independently of its own
          expiry (1&ndash;{MAX_TOKEN_AGE_CEILING_SECS}, default{" "}
          {DEFAULT_NATIVE_LOGIN_TRUST.max_token_age_secs}). A short window limits
          replay of a captured token.
        </p>
      </div>
    </div>
  );
}

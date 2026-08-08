# Passkeys and security keys

A **passkey** is a sign-in credential stored on a device you already have — the
Touch ID sensor on a laptop, Face ID on a phone, Windows Hello on a PC. A
**security key** is the same idea on a removable device you plug in or tap (a
YubiKey and similar).

Both replace typing a code. Both are phishing-resistant in a way a code is not:
the credential is bound to this site's exact address, so a lookalike page
cannot use it even if you are completely fooled by it. A one-time code, by
contrast, can be typed into a fake page and forwarded to the real one within
its 30-second window.

## Adding one

**Profile → MFA methods → Passkeys & security keys.**

- **Add a passkey** — uses the authenticator built into the device you are
  on. Your browser will ask for a fingerprint, face, or device PIN.
- **Add a security key** — uses a removable key. Your browser will ask you to
  insert or tap it.

Both buttons run the same registration ceremony; they differ only in which
authenticator the browser offers you first. You can register several of each,
and they are named so you can tell them apart later — "Passkey 2" is not a
useful name, so rename it to something you will recognise when you are deciding
which one to remove.

**Register at least two**, on different devices. A passkey lives on the device
that created it; if that device is your only factor and it is lost, you are
locked out.

### If the buttons are not there

The panel explains it inline: the browser you are using does not support
passkeys. Recent versions of Chrome, Safari, Edge and Firefox all do. Your
other sign-in methods are unaffected.

## Signing in

Three ways, and you do not have to choose in advance:

1. **Autofill** — on the sign-in page, tap the username field. If you have a
   passkey saved, your browser offers it there, alongside saved passwords.
2. **"Sign in with a passkey"** — the button below the password field. You do
   not need to type a username first: the passkey itself identifies you.
3. **As a second factor** — if you sign in with a password and your account
   requires a second factor, you will be offered "Use a passkey or security
   key instead" next to the code field. The code field stays available; the
   passkey is an addition, not a replacement.

## When something goes wrong

| What you see | What it means |
|---|---|
| "The request was cancelled or timed out" | You dismissed the prompt, or it expired. Nothing is wrong; try again. The browser deliberately does not tell websites which of the two happened. |
| "This device is already registered on your account" | You are trying to add a device that is already on the list. Use a different device, or remove the existing entry first. |
| "This browser or device cannot be used for passkeys" | The browser has no WebAuthn support. Use a different browser, or another sign-in method. |

## For administrators

Passkeys are bound to a **relying party ID** — a domain — and to an
**origin**. Both are server configuration:

```bash
AXIAM__AUTH__WEBAUTHN_RP_ID=id.example.com
AXIAM__AUTH__WEBAUTHN_RP_ORIGIN=https://id.example.com
AXIAM__AUTH__WEBAUTHN_RP_NAME="Example Corp"
```

Two things follow from that binding, and both surprise people:

- **Changing `RP_ID` invalidates every registered passkey.** They are bound to
  the old domain and cannot be migrated. Treat it as a one-way decision, and
  set it to the registrable domain you intend to keep rather than to a
  subdomain you might move off.
- **The origin must match exactly**, scheme included. A passkey registered on
  `https://id.example.com` will not work on `https://www.id.example.com` or on
  `http://`.

All ceremony policy — challenge generation, `residentKey`, `userVerification`,
credential exclusion, and verification of the result — is decided and enforced
server-side. The browser client passes the server's options through unchanged.

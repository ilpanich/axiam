/**
 * The message catalogue for the authentication surface (W5,
 * `claude_dev/basic-op-gap-plan.md` §4.6).
 *
 * # Why a typed catalogue and not a library
 *
 * `ui_locales` is an *authentication-request* parameter, so the pages it can
 * reach are the sign-in page, the reauthentication and step-up prompts W3 and
 * W4 added, and their error and validation messages. That is a closed set of a
 * few dozen strings, and for a set that size a runtime i18n framework buys one
 * thing — a missing-key fallback — and charges a dependency, a provider, an
 * async bundle loader and a class of bug where the fallback quietly ships
 * English to somebody who asked for Italian.
 *
 * A hand-rolled catalogue inverts that. {@link MessageKey} is derived from the
 * English bundle, and every other bundle is declared `Record<MessageKey,
 * string>`, so a missing Italian string is a **compile error** and a stray
 * extra key is one too. There is no fallback because there is nothing to fall
 * back from. `frontend/src/i18n/messages.test.ts` asserts the same property at
 * runtime as belt-and-braces, which is worth having only because it would also
 * catch a future `as any` that switched the compile-time check off.
 *
 * If a later wave needs plurals, dates or gendered agreement, that is the
 * point at which `react-i18next` earns its keep. None of these strings need
 * any of it.
 *
 * # The admin console is out of scope, deliberately
 *
 * `ui_locales` cannot reach the console: it is a parameter on
 * `/oauth2/authorize`, and the console is behind a session the authorization
 * endpoint has already established. Translating it here would be a much larger
 * change, unreviewable in one wave, and justified by no parameter. The layer
 * is built so the console *can* adopt it later — nothing in {@link useMessages}
 * knows it is being used by a sign-in page — but this wave translates the
 * authentication surface and only that.
 *
 * # Invariant 4 lives in the English bundle
 *
 * Every English string here is the string the page rendered before W5,
 * character for character — the ellipses, the em dashes, the `...` that is
 * three periods rather than `…`. A client on the `ignore` lane is forwarded no
 * locale, renders {@link DEFAULT_LOCALE}, and must therefore produce a page
 * byte-identical to today's. Improving a piece of English copy here would be a
 * silent behaviour change for every relying party that exists, so if one of
 * these strings should read better, that is its own change with its own diff.
 */

import { DEFAULT_LOCALE, type Locale, LOCALES } from "./locales";

/**
 * The English bundle, and the definition of the key set.
 *
 * `as const` so {@link MessageKey} is the union of these names rather than
 * `string` — which is what makes every other bundle exhaustively checked.
 */
const en = {
  // ─── Notices ────────────────────────────────────────────────────────────
  bootstrapNotice: "Admin account created. Sign in to continue.",
  loopBlocked:
    "The application you are signing in to keeps asking you to " +
    "authenticate again. Something is misconfigured — please close this " +
    "page and contact the administrator of that application.",
  reauthNotice: "Please sign in again to continue.",
  reauthNoticeMfa:
    "The application you are signing in to requires multi-factor authentication. Please sign in again and complete your second factor.",

  // ─── Errors ─────────────────────────────────────────────────────────────
  authenticationError: "Authentication error. Please sign in again.",
  ssoStartFailed: "Could not start sign-in with {provider}. Please try again.",
  orgSlugRequired: "Please enter your organization slug.",
  credentialsRequired: "Please enter your username and password.",
  opaqueRequired:
    "This organization requires OPAQUE sign-in, which this browser could not complete. Please update your browser or contact your administrator.",
  securityRejected:
    "Request rejected for security reasons. Please refresh the page and try again.",
  invalidCredentials: "Invalid credentials. Please try again.",
  totpLengthRequired: "Please enter the 6-digit code from your authenticator app.",
  invalidMfaCode: "Invalid or expired MFA code.",

  // ─── WebAuthn failures ──────────────────────────────────────────────────
  //
  // The same five `WebauthnFailure` kinds `@/services/webauthn` classifies,
  // with the same English copy. The service keeps its own English-only
  // `webauthnErrorMessage` for the admin console, which this wave does not
  // translate; the sign-in page maps the classified kind to a key here.
  webauthnCancelled: "The request was cancelled or timed out. You can try again.",
  webauthnAlreadyRegistered:
    "This device is already registered on your account. Try a different device, or remove the existing one first.",
  webauthnTimeout: "The request timed out before it completed. Please try again.",
  webauthnUnsupported:
    "This browser or device cannot be used for passkeys. Try a different browser, or use another sign-in method.",
  webauthnUnknown: "Something went wrong setting up this device. Please try again.",

  // ─── Step 1: workspace ──────────────────────────────────────────────────
  workspaceLegend: "Select your workspace",
  workspaceHelp:
    "Enter your organization to continue. Add a tenant only if your account belongs to one.",
  orgSlugLabel: "Organization slug",
  orgSlugPlaceholder: "my-organization",
  tenantSlugLabel: "Tenant slug",
  optionalSuffix: "(optional)",
  tenantSlugPlaceholder: "Leave blank to sign in at organization level",
  tenantSlugHelp:
    "Organization-level accounts — including the administrator created at setup — leave this blank. Tenant accounts must name their tenant.",
  continueAction: "Continue",

  // ─── Step 2: credentials ────────────────────────────────────────────────
  signInHeading: "Sign in",
  workspaceSummaryLabel: "Workspace:",
  organizationScopeSuffix: "(organization)",
  usernameLabel: "Username or email",
  usernamePlaceholder: "username or email",
  passwordLabel: "Password",
  forgotPassword: "Forgot password?",
  backAction: "Back",
  signInAction: "Sign in",
  signingIn: "Signing in...",
  orSeparator: "or",
  passkeySignIn: "Sign in with a passkey",
  waitingForDevice: "Waiting for your device…",

  // ─── Step 3: second factor ──────────────────────────────────────────────
  mfaHeading: "Two-factor authentication",
  mfaPrompt: "Enter the 6-digit code from your authenticator app.",
  mfaCodeLabel: "Authentication code",
  mfaPasskeyAction: "Use a passkey or security key instead",
  verifyAction: "Verify",
  verifying: "Verifying...",
  // ─── Consent (W7, X7 G8) ────────────────────────────────────────────────
  consentHeading: "Share your details?",
  consentIntro:
    "{client} is asking to see some of your details. Nothing is shared unless you allow it.",
  consentPhone: "Your telephone number",
  consentAddress: "Your postal address",
  consentWithdrawNote:
    "You can withdraw this at any time from Privacy & Data, and it takes effect immediately.",
  consentAllowAction: "Allow",
  consentDenyAction: "Not now",
  consentSaving: "Saving...",
  consentFailed: "Could not record your answer. Please try again.",
  consentNothingToDo:
    "There is nothing to decide here. You can close this page.",
} as const;

/** Every message the authentication surface can render. */
export type MessageKey = keyof typeof en;

/** One complete translation. Nothing may be missing and nothing may be extra. */
export type Bundle = Record<MessageKey, string>;

/**
 * Italian. Informal register (`tu`), which is the convention for Italian
 * product UI; "tenant", "passkey", "slug", "MFA" and "OPAQUE" are kept as they
 * are, because they are the product's own vocabulary and appear in URLs and in
 * the documentation the operator reads.
 */
const it: Bundle = {
  bootstrapNotice: "Account amministratore creato. Accedi per continuare.",
  loopBlocked:
    "L'applicazione a cui stai accedendo continua a chiederti di autenticarti di nuovo. C'è un errore di configurazione: chiudi questa pagina e contatta l'amministratore di quell'applicazione.",
  reauthNotice: "Accedi di nuovo per continuare.",
  reauthNoticeMfa:
    "L'applicazione a cui stai accedendo richiede l'autenticazione a più fattori. Accedi di nuovo e completa il secondo fattore.",

  authenticationError: "Errore di autenticazione. Accedi di nuovo.",
  ssoStartFailed: "Impossibile avviare l'accesso con {provider}. Riprova.",
  orgSlugRequired: "Inserisci lo slug della tua organizzazione.",
  credentialsRequired: "Inserisci nome utente e password.",
  opaqueRequired:
    "Questa organizzazione richiede l'accesso OPAQUE, che questo browser non è riuscito a completare. Aggiorna il browser oppure contatta l'amministratore.",
  securityRejected:
    "Richiesta rifiutata per motivi di sicurezza. Ricarica la pagina e riprova.",
  invalidCredentials: "Credenziali non valide. Riprova.",
  totpLengthRequired:
    "Inserisci il codice a 6 cifre della tua app di autenticazione.",
  invalidMfaCode: "Codice MFA non valido o scaduto.",

  webauthnCancelled: "La richiesta è stata annullata o è scaduta. Puoi riprovare.",
  webauthnAlreadyRegistered:
    "Questo dispositivo è già registrato sul tuo account. Prova con un altro dispositivo oppure rimuovi prima quello esistente.",
  webauthnTimeout: "La richiesta è scaduta prima di essere completata. Riprova.",
  webauthnUnsupported:
    "Questo browser o dispositivo non può essere usato con le passkey. Prova con un altro browser oppure usa un altro metodo di accesso.",
  webauthnUnknown:
    "Si è verificato un problema durante la configurazione di questo dispositivo. Riprova.",

  workspaceLegend: "Seleziona la tua area di lavoro",
  workspaceHelp:
    "Inserisci la tua organizzazione per continuare. Aggiungi un tenant solo se il tuo account ne fa parte.",
  orgSlugLabel: "Slug dell'organizzazione",
  orgSlugPlaceholder: "la-mia-organizzazione",
  tenantSlugLabel: "Slug del tenant",
  optionalSuffix: "(facoltativo)",
  tenantSlugPlaceholder: "Lascia vuoto per accedere a livello di organizzazione",
  tenantSlugHelp:
    "Gli account a livello di organizzazione — compreso l'amministratore creato durante la configurazione iniziale — lasciano questo campo vuoto. Gli account di tenant devono indicare il proprio tenant.",
  continueAction: "Continua",

  signInHeading: "Accedi",
  workspaceSummaryLabel: "Area di lavoro:",
  organizationScopeSuffix: "(organizzazione)",
  usernameLabel: "Nome utente o email",
  usernamePlaceholder: "nome utente o email",
  passwordLabel: "Password",
  forgotPassword: "Password dimenticata?",
  backAction: "Indietro",
  signInAction: "Accedi",
  signingIn: "Accesso in corso...",
  orSeparator: "oppure",
  passkeySignIn: "Accedi con una passkey",
  waitingForDevice: "In attesa del tuo dispositivo…",

  mfaHeading: "Autenticazione a due fattori",
  mfaPrompt: "Inserisci il codice a 6 cifre della tua app di autenticazione.",
  mfaCodeLabel: "Codice di autenticazione",
  mfaPasskeyAction: "Usa invece una passkey o una chiave di sicurezza",
  verifyAction: "Verifica",
  verifying: "Verifica in corso...",
  consentHeading: "Vuoi condividere i tuoi dati?",
  consentIntro:
    "{client} chiede di vedere alcuni dei tuoi dati. Nulla viene condiviso se non lo consenti.",
  consentPhone: "Il tuo numero di telefono",
  consentAddress: "Il tuo indirizzo postale",
  consentWithdrawNote:
    "Puoi revocare il consenso in qualsiasi momento da Privacy e dati, con effetto immediato.",
  consentAllowAction: "Consenti",
  consentDenyAction: "Non ora",
  consentSaving: "Salvataggio in corso...",
  consentFailed: "Non è stato possibile registrare la tua risposta. Riprova.",
  consentNothingToDo: "Non c'è nulla da decidere qui. Puoi chiudere questa pagina.",
};

/**
 * French. Formal register (`vous`), the convention for French product UI.
 * "Passkey" is rendered *clé d'accès*, which is what Apple and Google ship in
 * French; "tenant" and "slug" are kept.
 */
const fr: Bundle = {
  bootstrapNotice: "Compte administrateur créé. Connectez-vous pour continuer.",
  loopBlocked:
    "L'application à laquelle vous vous connectez vous demande sans cesse de vous authentifier à nouveau. Quelque chose est mal configuré : veuillez fermer cette page et contacter l'administrateur de cette application.",
  reauthNotice: "Veuillez vous reconnecter pour continuer.",
  reauthNoticeMfa:
    "L'application à laquelle vous vous connectez exige une authentification multifacteur. Veuillez vous reconnecter et valider votre second facteur.",

  authenticationError: "Erreur d'authentification. Veuillez vous reconnecter.",
  ssoStartFailed:
    "Impossible de démarrer la connexion avec {provider}. Veuillez réessayer.",
  orgSlugRequired: "Veuillez saisir le slug de votre organisation.",
  credentialsRequired:
    "Veuillez saisir votre nom d'utilisateur et votre mot de passe.",
  opaqueRequired:
    "Cette organisation exige la connexion OPAQUE, que ce navigateur n'a pas pu effectuer. Veuillez mettre à jour votre navigateur ou contacter votre administrateur.",
  securityRejected:
    "Demande rejetée pour des raisons de sécurité. Veuillez actualiser la page et réessayer.",
  invalidCredentials: "Identifiants invalides. Veuillez réessayer.",
  totpLengthRequired:
    "Veuillez saisir le code à 6 chiffres de votre application d'authentification.",
  invalidMfaCode: "Code MFA invalide ou expiré.",

  webauthnCancelled:
    "La demande a été annulée ou a expiré. Vous pouvez réessayer.",
  webauthnAlreadyRegistered:
    "Cet appareil est déjà enregistré sur votre compte. Essayez un autre appareil ou supprimez d'abord l'existant.",
  webauthnTimeout:
    "La demande a expiré avant d'aboutir. Veuillez réessayer.",
  webauthnUnsupported:
    "Ce navigateur ou cet appareil ne peut pas être utilisé avec les clés d'accès. Essayez un autre navigateur ou une autre méthode de connexion.",
  webauthnUnknown:
    "Un problème est survenu lors de la configuration de cet appareil. Veuillez réessayer.",

  workspaceLegend: "Sélectionnez votre espace de travail",
  workspaceHelp:
    "Saisissez votre organisation pour continuer. N'ajoutez un tenant que si votre compte en fait partie.",
  orgSlugLabel: "Slug de l'organisation",
  orgSlugPlaceholder: "mon-organisation",
  tenantSlugLabel: "Slug du tenant",
  optionalSuffix: "(facultatif)",
  tenantSlugPlaceholder:
    "Laissez vide pour vous connecter au niveau de l'organisation",
  tenantSlugHelp:
    "Les comptes au niveau de l'organisation — y compris l'administrateur créé lors de l'installation — laissent ce champ vide. Les comptes de tenant doivent nommer leur tenant.",
  continueAction: "Continuer",

  signInHeading: "Connexion",
  workspaceSummaryLabel: "Espace de travail :",
  organizationScopeSuffix: "(organisation)",
  usernameLabel: "Nom d'utilisateur ou e-mail",
  usernamePlaceholder: "nom d'utilisateur ou e-mail",
  passwordLabel: "Mot de passe",
  forgotPassword: "Mot de passe oublié ?",
  backAction: "Retour",
  signInAction: "Se connecter",
  signingIn: "Connexion en cours...",
  orSeparator: "ou",
  passkeySignIn: "Se connecter avec une clé d'accès",
  waitingForDevice: "En attente de votre appareil…",

  mfaHeading: "Authentification à deux facteurs",
  mfaPrompt:
    "Saisissez le code à 6 chiffres de votre application d'authentification.",
  mfaCodeLabel: "Code d'authentification",
  mfaPasskeyAction: "Utiliser plutôt une clé d'accès ou une clé de sécurité",
  verifyAction: "Vérifier",
  verifying: "Vérification en cours...",
  consentHeading: "Partager vos informations ?",
  consentIntro:
    "{client} demande à consulter certaines de vos informations. Rien n'est partagé sans votre autorisation.",
  consentPhone: "Votre numéro de téléphone",
  consentAddress: "Votre adresse postale",
  consentWithdrawNote:
    "Vous pouvez retirer cette autorisation à tout moment depuis Confidentialité et données ; elle prend effet immédiatement.",
  consentAllowAction: "Autoriser",
  consentDenyAction: "Pas maintenant",
  consentSaving: "Enregistrement...",
  consentFailed: "Impossible d'enregistrer votre réponse. Veuillez réessayer.",
  consentNothingToDo: "Il n'y a rien à décider ici. Vous pouvez fermer cette page.",
};

/**
 * German. Formal register (`Sie`), the convention for German product UI.
 * "Passkey" is kept as-is, which is what Apple and Google ship in German;
 * "Tenant" and "Slug" are kept and inflected as German nouns.
 */
const de: Bundle = {
  bootstrapNotice:
    "Administratorkonto erstellt. Melden Sie sich an, um fortzufahren.",
  loopBlocked:
    "Die Anwendung, bei der Sie sich anmelden, fordert Sie immer wieder zur erneuten Authentifizierung auf. Etwas ist falsch konfiguriert – bitte schließen Sie diese Seite und wenden Sie sich an die Administration dieser Anwendung.",
  reauthNotice: "Bitte melden Sie sich erneut an, um fortzufahren.",
  reauthNoticeMfa:
    "Die Anwendung, bei der Sie sich anmelden, erfordert eine Multi-Faktor-Authentifizierung. Bitte melden Sie sich erneut an und bestätigen Sie Ihren zweiten Faktor.",

  authenticationError:
    "Authentifizierungsfehler. Bitte melden Sie sich erneut an.",
  ssoStartFailed:
    "Die Anmeldung mit {provider} konnte nicht gestartet werden. Bitte versuchen Sie es erneut.",
  orgSlugRequired: "Bitte geben Sie den Slug Ihrer Organisation ein.",
  credentialsRequired: "Bitte geben Sie Benutzernamen und Passwort ein.",
  opaqueRequired:
    "Diese Organisation erfordert die OPAQUE-Anmeldung, die dieser Browser nicht durchführen konnte. Bitte aktualisieren Sie Ihren Browser oder wenden Sie sich an Ihre Administration.",
  securityRejected:
    "Anfrage aus Sicherheitsgründen abgelehnt. Bitte laden Sie die Seite neu und versuchen Sie es erneut.",
  invalidCredentials:
    "Ungültige Anmeldedaten. Bitte versuchen Sie es erneut.",
  totpLengthRequired:
    "Bitte geben Sie den 6-stelligen Code aus Ihrer Authenticator-App ein.",
  invalidMfaCode: "MFA-Code ungültig oder abgelaufen.",

  webauthnCancelled:
    "Die Anfrage wurde abgebrochen oder ist abgelaufen. Sie können es erneut versuchen.",
  webauthnAlreadyRegistered:
    "Dieses Gerät ist bereits für Ihr Konto registriert. Versuchen Sie es mit einem anderen Gerät oder entfernen Sie zuerst das vorhandene.",
  webauthnTimeout:
    "Die Anfrage ist abgelaufen, bevor sie abgeschlossen wurde. Bitte versuchen Sie es erneut.",
  webauthnUnsupported:
    "Dieser Browser oder dieses Gerät kann nicht für Passkeys verwendet werden. Versuchen Sie einen anderen Browser oder eine andere Anmeldemethode.",
  webauthnUnknown:
    "Beim Einrichten dieses Geräts ist ein Fehler aufgetreten. Bitte versuchen Sie es erneut.",

  workspaceLegend: "Wählen Sie Ihren Arbeitsbereich",
  workspaceHelp:
    "Geben Sie Ihre Organisation ein, um fortzufahren. Fügen Sie einen Tenant nur hinzu, wenn Ihr Konto zu einem gehört.",
  orgSlugLabel: "Slug der Organisation",
  orgSlugPlaceholder: "meine-organisation",
  tenantSlugLabel: "Slug des Tenants",
  optionalSuffix: "(optional)",
  tenantSlugPlaceholder:
    "Leer lassen, um sich auf Organisationsebene anzumelden",
  tenantSlugHelp:
    "Konten auf Organisationsebene – einschließlich der bei der Einrichtung erstellten Administration – lassen dieses Feld leer. Tenant-Konten müssen ihren Tenant angeben.",
  continueAction: "Weiter",

  signInHeading: "Anmelden",
  workspaceSummaryLabel: "Arbeitsbereich:",
  organizationScopeSuffix: "(Organisation)",
  usernameLabel: "Benutzername oder E-Mail",
  usernamePlaceholder: "Benutzername oder E-Mail",
  passwordLabel: "Passwort",
  forgotPassword: "Passwort vergessen?",
  backAction: "Zurück",
  signInAction: "Anmelden",
  signingIn: "Anmeldung läuft...",
  orSeparator: "oder",
  passkeySignIn: "Mit einem Passkey anmelden",
  waitingForDevice: "Warten auf Ihr Gerät…",

  mfaHeading: "Zwei-Faktor-Authentifizierung",
  mfaPrompt:
    "Geben Sie den 6-stelligen Code aus Ihrer Authenticator-App ein.",
  mfaCodeLabel: "Authentifizierungscode",
  mfaPasskeyAction:
    "Stattdessen einen Passkey oder Sicherheitsschlüssel verwenden",
  verifyAction: "Bestätigen",
  verifying: "Wird überprüft...",
  consentHeading: "Ihre Daten freigeben?",
  consentIntro:
    "{client} möchte einige Ihrer Daten einsehen. Ohne Ihre Zustimmung wird nichts weitergegeben.",
  consentPhone: "Ihre Telefonnummer",
  consentAddress: "Ihre Postanschrift",
  consentWithdrawNote:
    "Sie können diese Zustimmung jederzeit unter Datenschutz und Daten widerrufen; sie wirkt sofort.",
  consentAllowAction: "Zulassen",
  consentDenyAction: "Jetzt nicht",
  consentSaving: "Wird gespeichert...",
  consentFailed: "Ihre Antwort konnte nicht gespeichert werden. Bitte versuchen Sie es erneut.",
  consentNothingToDo: "Hier gibt es nichts zu entscheiden. Sie können diese Seite schließen.",
};

/**
 * Spanish. Informal register (`tú`), the convention for Spanish product UI.
 * "Passkey" is rendered *clave de acceso*, which is what Apple and Google ship
 * in Spanish; "tenant" and "slug" are kept.
 */
const es: Bundle = {
  bootstrapNotice:
    "Cuenta de administrador creada. Inicia sesión para continuar.",
  loopBlocked:
    "La aplicación en la que estás iniciando sesión te pide autenticarte una y otra vez. Hay algo mal configurado: cierra esta página y ponte en contacto con el administrador de esa aplicación.",
  reauthNotice: "Vuelve a iniciar sesión para continuar.",
  reauthNoticeMfa:
    "La aplicación en la que estás iniciando sesión requiere autenticación multifactor. Vuelve a iniciar sesión y completa tu segundo factor.",

  authenticationError: "Error de autenticación. Vuelve a iniciar sesión.",
  ssoStartFailed:
    "No se pudo iniciar la sesión con {provider}. Inténtalo de nuevo.",
  orgSlugRequired: "Introduce el slug de tu organización.",
  credentialsRequired: "Introduce tu nombre de usuario y tu contraseña.",
  opaqueRequired:
    "Esta organización requiere el inicio de sesión OPAQUE, que este navegador no ha podido completar. Actualiza el navegador o ponte en contacto con tu administrador.",
  securityRejected:
    "Solicitud rechazada por motivos de seguridad. Recarga la página e inténtalo de nuevo.",
  invalidCredentials: "Credenciales no válidas. Inténtalo de nuevo.",
  totpLengthRequired:
    "Introduce el código de 6 dígitos de tu aplicación de autenticación.",
  invalidMfaCode: "Código MFA no válido o caducado.",

  webauthnCancelled:
    "La solicitud se canceló o caducó. Puedes intentarlo de nuevo.",
  webauthnAlreadyRegistered:
    "Este dispositivo ya está registrado en tu cuenta. Prueba con otro dispositivo o elimina primero el existente.",
  webauthnTimeout:
    "La solicitud caducó antes de completarse. Inténtalo de nuevo.",
  webauthnUnsupported:
    "Este navegador o dispositivo no se puede usar con claves de acceso. Prueba con otro navegador o usa otro método de inicio de sesión.",
  webauthnUnknown:
    "Se ha producido un problema al configurar este dispositivo. Inténtalo de nuevo.",

  workspaceLegend: "Selecciona tu espacio de trabajo",
  workspaceHelp:
    "Introduce tu organización para continuar. Añade un tenant solo si tu cuenta pertenece a uno.",
  orgSlugLabel: "Slug de la organización",
  orgSlugPlaceholder: "mi-organizacion",
  tenantSlugLabel: "Slug del tenant",
  optionalSuffix: "(opcional)",
  tenantSlugPlaceholder:
    "Déjalo en blanco para iniciar sesión a nivel de organización",
  tenantSlugHelp:
    "Las cuentas de nivel de organización —incluida la del administrador creado durante la instalación— dejan este campo en blanco. Las cuentas de tenant deben indicar su tenant.",
  continueAction: "Continuar",

  signInHeading: "Iniciar sesión",
  workspaceSummaryLabel: "Espacio de trabajo:",
  organizationScopeSuffix: "(organización)",
  usernameLabel: "Nombre de usuario o correo electrónico",
  usernamePlaceholder: "nombre de usuario o correo electrónico",
  passwordLabel: "Contraseña",
  forgotPassword: "¿Has olvidado tu contraseña?",
  backAction: "Atrás",
  signInAction: "Iniciar sesión",
  signingIn: "Iniciando sesión...",
  orSeparator: "o",
  passkeySignIn: "Iniciar sesión con una clave de acceso",
  waitingForDevice: "Esperando a tu dispositivo…",

  mfaHeading: "Autenticación de dos factores",
  mfaPrompt: "Introduce el código de 6 dígitos de tu aplicación de autenticación.",
  mfaCodeLabel: "Código de autenticación",
  mfaPasskeyAction: "Usa una clave de acceso o una llave de seguridad",
  verifyAction: "Verificar",
  verifying: "Verificando...",
  consentHeading: "¿Compartir tus datos?",
  consentIntro:
    "{client} solicita ver algunos de tus datos. No se comparte nada si no lo autorizas.",
  consentPhone: "Tu número de teléfono",
  consentAddress: "Tu dirección postal",
  consentWithdrawNote:
    "Puedes retirar esta autorización en cualquier momento desde Privacidad y datos, con efecto inmediato.",
  consentAllowAction: "Permitir",
  consentDenyAction: "Ahora no",
  consentSaving: "Guardando...",
  consentFailed: "No se ha podido registrar tu respuesta. Inténtalo de nuevo.",
  consentNothingToDo: "Aquí no hay nada que decidir. Puedes cerrar esta página.",
};

/**
 * Every bundle, keyed by locale.
 *
 * `Record<Locale, Bundle>` rather than a looser map: adding a sixth locale to
 * {@link LOCALES} without a bundle here does not compile, which is the half of
 * `scripts/check-locale-bundle-sync.py`'s job that TypeScript can do on its
 * own. The script covers the half it cannot — agreement with the Rust enum.
 */
export const MESSAGES: Record<Locale, Bundle> = { en, it, fr, de, es };

/**
 * Substitute `{name}` placeholders.
 *
 * The one interpolated message is {@link en.ssoStartFailed}, which names a
 * federation provider. Deliberately tiny and deliberately not a template
 * engine: it replaces named placeholders with plain strings and does no
 * escaping of its own, because the result is rendered by React as a text node
 * and React escapes it.
 *
 * A placeholder with no value is left as it is rather than replaced with
 * `undefined` — a message reading `{provider}` is a visible bug report, and
 * one reading `undefined` is a puzzle.
 */
export function format(
  template: string,
  values: Readonly<Record<string, string>>,
): string {
  return template.replace(/\{(\w+)\}/g, (whole, name: string) =>
    Object.prototype.hasOwnProperty.call(values, name) ? values[name] : whole,
  );
}

/**
 * The bundle for `locale`.
 *
 * Total by type: `locale` is a {@link Locale}, so there is always a bundle,
 * and the argument that could be `undefined` was resolved to
 * {@link DEFAULT_LOCALE} by whoever read it out of the URL.
 */
export function messagesFor(locale: Locale): Bundle {
  return MESSAGES[locale];
}

/** The locales that have a bundle. Equals {@link LOCALES}; asserted by a test. */
export const TRANSLATED_LOCALES = Object.keys(MESSAGES) as Locale[];

export { DEFAULT_LOCALE, LOCALES, type Locale };

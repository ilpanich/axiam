/**
 * OPAQUE (RFC 9807) client for the admin UI.
 *
 * This file deliberately contains **no cryptography**. Its predecessor,
 * `srp.ts`, was 361 lines of modular exponentiation, `PAD()` and SHA-256
 * transcript hashing, because SRP is arithmetic every language can express and
 * so every AXIAM client wrote its own. OPAQUE is not — it needs an oblivious
 * PRF, `hash_to_curve`, `expand_message_xmd`, an envelope construction and a
 * three-message AKE — so `sdks/CONTRACT.md` §23.1 forbids a client from
 * implementing it, and this module is a loader around the one implementation
 * the server and every SDK also use.
 *
 * # Loading
 *
 * `@axiam/opaque-wasm` is built from `crates/axiam-opaque-wasm` and resolved at
 * runtime rather than bundled, so a checkout that has not run the Rust
 * toolchain still builds and tests. When it is absent, {@link opaqueAvailable}
 * reports `false` and callers fall back to password login — the same posture
 * CONTRACT §23.1 requires of an SDK whose native library failed to load, and
 * the reason it must report rather than throw at login time.
 */

type OpaqueModule = typeof import("@axiam/opaque-wasm");

let modulePromise: Promise<OpaqueModule | null> | null = null;

/**
 * The package specifier, held in a variable so the bundler does not resolve it
 * statically.
 *
 * This is the mechanism behind the graceful degradation above: a static
 * `import("@axiam/opaque-wasm")` is a build error in a checkout where the Rust
 * artifact has not been built, which would make every developer who has not run
 * `wasm-pack` unable to build the admin UI at all. Deferring resolution to
 * runtime turns that into the `false` from {@link opaqueAvailable} that
 * CONTRACT §23.1 asks for.
 */
const WASM_PACKAGE = "@axiam/opaque-wasm";

/**
 * Load the WASM module once per page.
 *
 * Memoized on the *promise*, not the result, so two components racing to sign
 * in do not instantiate the module twice. A failure is memoized too: retrying a
 * missing artifact on every keystroke would spam the network for a file that is
 * not going to appear.
 */
async function loadModule(): Promise<OpaqueModule | null> {
  modulePromise ??= (async () => {
    try {
      const mod = (await import(/* @vite-ignore */ WASM_PACKAGE)) as OpaqueModule;
      await mod.default();
      return mod;
    } catch {
      return null;
    }
  })();
  return modulePromise;
}

/** Reset the memoized module. Test-only. */
export function __resetOpaqueModuleForTests(): void {
  modulePromise = null;
}

/**
 * Inject a module, bypassing the loader. Test-only.
 *
 * Exists because the dynamic specifier above is deliberately unresolvable at
 * build time, which also puts it out of reach of `vi.mock`.
 */
export function __setOpaqueModuleForTests(mod: unknown): void {
  modulePromise = Promise.resolve(mod as OpaqueModule);
}

/** Whether this browser can perform OPAQUE at all. */
export async function opaqueAvailable(): Promise<boolean> {
  const mod = await loadModule();
  return mod !== null && mod.opaqueAvailable();
}

/**
 * The key-stretching fields a `register/start` or `login/start` response
 * carries.
 *
 * Flat and optional, matching the wire format: the fields that do not apply to
 * the named function are **absent, not zero**. Reading an absent field as `0`
 * would stretch with the wrong cost and fail against a record that is perfectly
 * good — see CONTRACT §23.4 rule 5.
 */
export interface OpaqueKsfFields {
  ksf: string;
  memory_kib?: number;
  iterations?: number;
  parallelism?: number;
  log_n?: number;
  r?: number;
  p?: number;
}

/** Raised when the server names a KSF or suite this build cannot perform. */
export class OpaqueUnsupportedError extends Error {
  constructor(what: string) {
    super(
      `This browser cannot perform the key-stretching function this tenant requires (${what}).`
    );
    this.name = "OpaqueUnsupportedError";
  }
}

/**
 * Build the stretching function from what the **server** named.
 *
 * Never from local defaults, and never cached across exchanges: a credential
 * enrolled under one cost keeps working after a tenant raises its policy, so a
 * client that guessed would derive a different randomized password (CONTRACT
 * §23.4 rule 2).
 */
function buildKsf(
  mod: NonNullable<Awaited<ReturnType<typeof loadModule>>>,
  fields: OpaqueKsfFields
) {
  if (fields.ksf === "argon2id") {
    if (
      fields.memory_kib === undefined ||
      fields.iterations === undefined ||
      fields.parallelism === undefined
    ) {
      throw new OpaqueUnsupportedError("argon2id with missing cost parameters");
    }
    return mod.OpaqueKsf.argon2id(fields.memory_kib, fields.iterations, fields.parallelism);
  }
  if (fields.ksf === "scrypt") {
    if (fields.log_n === undefined || fields.r === undefined || fields.p === undefined) {
      throw new OpaqueUnsupportedError("scrypt with missing cost parameters");
    }
    return mod.OpaqueKsf.scrypt(fields.log_n, fields.r, fields.p);
  }
  // Refused, never substituted: substituting produces a well-formed randomized
  // password that no AXIAM server agrees with, reported to the user as a wrong
  // password (CONTRACT §23.4 rule 3).
  throw new OpaqueUnsupportedError(fields.ksf);
}

/** Raised when the WASM module could not be loaded. */
export class OpaqueUnavailableError extends Error {
  constructor() {
    super("OPAQUE is not available in this browser.");
    this.name = "OpaqueUnavailableError";
  }
}

async function requireModule() {
  const mod = await loadModule();
  if (mod === null) throw new OpaqueUnavailableError();
  return mod;
}

/** One in-flight registration. */
export interface RegistrationExchange {
  request: string;
  finish(registrationResponse: string, ksf: OpaqueKsfFields): string;
}

/** Begin an enrolment. The returned `request` goes to `register/start`. */
export async function startRegistration(password: string): Promise<RegistrationExchange> {
  const mod = await requireModule();
  const state = new mod.OpaqueRegistration(password);
  return {
    request: state.request,
    finish(registrationResponse, ksfFields) {
      const ksf = buildKsf(mod, ksfFields);
      return state.finish(password, registrationResponse, ksf).record;
    },
  };
}

/** One in-flight login. */
export interface LoginExchange {
  ke1: string;
  finish(ke2: string, ksf: OpaqueKsfFields): string;
}

/** Begin a login. The returned `ke1` goes to `login/start`. */
export async function startLogin(password: string): Promise<LoginExchange> {
  const mod = await requireModule();
  const state = new mod.OpaqueLogin(password);
  return {
    ke1: state.ke1,
    finish(ke2, ksfFields) {
      const ksf = buildKsf(mod, ksfFields);
      return state.finish(password, ke2, ksf).ke3;
    },
  };
}

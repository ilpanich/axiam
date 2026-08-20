/**
 * Ambient declaration for `@axiam/opaque-wasm`, the WebAssembly build of
 * `crates/axiam-opaque`.
 *
 * Declared here rather than depended on in `package.json` because the package
 * is an artifact of this repository's own Rust build (`wasm-pack build --target
 * web crates/axiam-opaque-wasm`) and is resolved at runtime. Typing it here
 * lets `tsc -b` and the unit tests run in a checkout where the artifact has not
 * been built — which is every checkout that has not run the Rust toolchain.
 *
 * The shape mirrors `crates/axiam-opaque-wasm/src/lib.rs` exactly. If that file
 * changes, this one must change with it; there is no generator keeping them in
 * step, which is the cost of not vendoring the artifact.
 */
declare module "@axiam/opaque-wasm" {
  /** Instantiate the module. Must be awaited before anything else. */
  export default function init(): Promise<unknown>;

  /** True when the module instantiated. See CONTRACT §23.2. */
  export function opaqueAvailable(): boolean;

  /** Key-stretching parameters, as named by the server. */
  export class OpaqueKsf {
    static argon2id(memoryKib: number, iterations: number, parallelism: number): OpaqueKsf;
    static scrypt(logN: number, r: number, p: number): OpaqueKsf;
  }

  export class OpaqueRegistrationResult {
    readonly record: string;
    readonly exportKey: string;
  }

  export class OpaqueRegistration {
    constructor(password: string);
    readonly request: string;
    /** Consumes this object. */
    finish(
      password: string,
      registrationResponse: string,
      ksf: OpaqueKsf
    ): OpaqueRegistrationResult;
  }

  export class OpaqueLoginResult {
    readonly ke3: string;
    readonly sessionKey: string;
    readonly exportKey: string;
  }

  export class OpaqueLogin {
    constructor(password: string);
    readonly ke1: string;
    /** Consumes this object. */
    finish(password: string, ke2: string, ksf: OpaqueKsf): OpaqueLoginResult;
  }
}

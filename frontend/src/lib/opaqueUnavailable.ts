/**
 * Stand-in for `@axiam/opaque-wasm` in a checkout where it has not been built.
 *
 * `vite.config.ts` aliases the package to this file when
 * `frontend/vendor/opaque-wasm/` is absent, which is every checkout that has
 * not run `just build-opaque-wasm` (or the `wasm` stage of
 * `docker/Dockerfile.frontend`, which always does). Without it the alias would
 * have nothing to resolve and the admin UI would not build at all without a
 * Rust toolchain — a floor this project deliberately does not have.
 *
 * Throwing from `default` rather than exporting a no-op is what puts the
 * failure on the path `lib/opaque.ts` already handles: it catches, memoizes
 * `null`, and {@link opaqueAvailable} reports `false`, which is the posture
 * CONTRACT §23.1 requires of a client whose OPAQUE implementation did not load.
 * A no-op `default` would instead let a half-initialized module through and
 * fail later, at the first `new OpaqueLogin(...)`, in the middle of a sign-in.
 *
 * It is deliberately NOT a re-implementation of anything. CONTRACT §23.1 allows
 * exactly one OPAQUE implementation per platform, and this file's whole purpose
 * is to be the absence of it.
 */

/** Always throws. See the module comment. */
export default async function init(): Promise<never> {
  throw new Error(
    "@axiam/opaque-wasm was not built for this bundle. Run `just build-opaque-wasm` " +
      "to enable OPAQUE sign-in locally; released images always build it."
  );
}

/** Always `false` — reached only if a caller skips {@link init}. */
export function opaqueAvailable(): boolean {
  return false;
}

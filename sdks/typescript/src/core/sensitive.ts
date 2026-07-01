// Sensitive<T> — token-redaction wrapper (CONTRACT.md §7, D-26).
//
// Redacts to '[SENSITIVE]' across all three JS stringification surfaces:
// toString(), JSON.stringify() (via toJSON), and Node's
// util.inspect/console.log (via the well-known Symbol.for('nodejs.util.inspect.custom')
// symbol). The symbol is referenced directly (not via `import { inspect } from
// 'node:util'`) so core never imports node:util and stays runtime-agnostic —
// the symbol lookup is a documented no-op in browsers, where this class is
// never constructed anyway (D-06: browser persona holds no tokens).
//
// The raw value is reachable only via `expose()`, documented @internal.

export const REDACTED = '[SENSITIVE]';

const NODE_INSPECT_CUSTOM = Symbol.for('nodejs.util.inspect.custom');

export class Sensitive<T> {
  readonly #value: T;

  constructor(value: T) {
    this.#value = value;
  }

  /** @internal package-only accessor. Never pass the return value to a log/serialize sink. */
  expose(): T {
    return this.#value;
  }

  toString(): string {
    return REDACTED;
  }

  toJSON(): string {
    return REDACTED;
  }

  [NODE_INSPECT_CUSTOM](): string {
    return REDACTED;
  }
}

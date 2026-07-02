// AxiamError taxonomy (CONTRACT.md §2, D-16).
//
// Exactly three concrete error types: AuthError, AuthzError, NetworkError,
// all extending the abstract AxiamError base. No error message or field may
// embed a raw token string (D-16). The prototype chain is fixed up manually
// in each constructor so `instanceof` works reliably across the transpiled
// CJS+ESM outputs (a well-known TS-to-ES5/ES2022-target caveat when
// extending built-ins like Error).

export abstract class AxiamError extends Error {
  protected constructor(message: string) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class AuthError extends AxiamError {
  constructor(message: string) {
    super(message);
    this.name = 'AuthError';
    Object.setPrototypeOf(this, AuthError.prototype);
  }
}

export class AuthzError extends AxiamError {
  readonly action?: string;
  readonly resourceId?: string;

  constructor(message: string, action?: string, resourceId?: string) {
    super(message);
    this.name = 'AuthzError';
    this.action = action;
    this.resourceId = resourceId;
    Object.setPrototypeOf(this, AuthzError.prototype);
  }
}

export class NetworkError extends AxiamError {
  readonly cause?: unknown;

  constructor(message: string, cause?: unknown) {
    super(message);
    this.name = 'NetworkError';
    this.cause = cause;
    Object.setPrototypeOf(this, NetworkError.prototype);
  }
}

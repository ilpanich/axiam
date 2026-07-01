// AxiamClient — the isomorphic REST + auth core (D-01/D-25).
//
// Constructor validates the required tenant (§5), builds the SharedSession
// (D-13), and installs the CSRF + reactive single-flight refresh
// interceptors (D-05/D-07). REST method implementations (login/verifyMfa/
// refresh/logout/checkAccess/can/batchCheck) are added by Task 2's
// auth.ts/authz.ts, which extend this class's prototype.

import type { AxiamClientOptions } from '../core/index.js';
import { createSession, SharedSession } from './session.js';
import { installInterceptors } from './interceptors.js';

export class AxiamClient {
  /** @internal — exposed for auth.ts/authz.ts method implementations and other transports (D-13). */
  readonly session: SharedSession;

  constructor(options: AxiamClientOptions) {
    this.session = createSession(options);
    installInterceptors(this.session.axios, this.session);
  }
}

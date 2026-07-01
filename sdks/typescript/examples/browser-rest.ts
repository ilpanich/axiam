// Browser REST example — login discriminated union + can()/batchCheck over
// REST (SC#2 browser authz path, D-18).
//
// Illustrative/compilable: constructs an isomorphic AxiamClient, narrows the
// login() result on `status` (handling both the 'mfa_required' and
// 'authenticated' branches), then demonstrates the browser authz surface
// via `can()`/`batchCheck()` (FND-04). No raw session token ever appears
// here — tokens arrive exclusively via httpOnly Set-Cookie (T-17-07).
//
// Run in a browser bundle (Vite/webpack/etc.) against a reachable AXIAM
// server; the compile check (`tsc --noEmit -p examples/tsconfig.json`) is
// the SC#4 gate here, not execution.

import { AxiamClient } from 'axiam-sdk';

const baseUrl = 'https://iam.example.com';
const tenantSlug = 'acme';

const client = new AxiamClient({ baseUrl, tenantSlug });

async function loginFlow(email: string, password: string): Promise<void> {
  const result = await client.login(email, password);

  switch (result.status) {
    case 'mfa_required': {
      // Prompt the user for their MFA code out-of-band, then complete the
      // two-phase flow with the mfaToken carried over from this branch.
      const code = await promptForMfaCode(result.availableMethods);
      const finalResult = await client.verifyMfa(result.mfaToken, code);
      if (finalResult.status === 'authenticated') {
        console.log(`Authenticated as ${finalResult.user.username}`);
      }
      break;
    }
    case 'authenticated': {
      console.log(`Authenticated as ${result.user.username} (session ${result.sessionId})`);
      break;
    }
  }
}

async function promptForMfaCode(availableMethods: string[]): Promise<string> {
  // Illustrative stand-in for a real UI prompt.
  console.log('MFA required, available methods:', availableMethods);
  return '000000';
}

async function authzDemo(): Promise<void> {
  // SC#2 browser: single access check over the FND-04 REST endpoint.
  const allowed = await client.can('read', 'doc:1');
  console.log('can read doc:1?', allowed);

  // Batch check — results preserve input order.
  const decisions = await client.batchCheck([
    { action: 'read', resourceId: 'doc:1' },
    { action: 'write', resourceId: 'doc:1' },
  ]);
  console.log('batch decisions:', decisions);
}

void loginFlow;
void authzDemo;

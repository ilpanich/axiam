// Idempotent-only retry with bounded backoff + Retry-After honoring (CF-01).
//
// Only GET (idempotent) calls retry, and only on transient NetworkError.
// State-changing calls (POST/PUT/PATCH/DELETE) pass idempotent:false and
// never auto-retry — retrying a state-changing call on ambiguous failure
// could duplicate side effects.

import { NetworkError } from '../core/index.js';

export interface RetryOptions {
  /** Only idempotent (safe-to-repeat) calls are retried. */
  idempotent: boolean;
  /** Maximum number of attempts (including the first). Defaults to 3. */
  maxAttempts?: number;
}

interface RetryAfterCarrier {
  retryAfterMs?: number;
}

function isRetryAfterCarrier(err: unknown): err is RetryAfterCarrier {
  return typeof err === 'object' && err !== null && 'retryAfterMs' in err;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Exponential backoff with jitter, bounded to a small ceiling per attempt. */
function backoffDelayMs(attempt: number): number {
  const base = Math.min(1000 * 2 ** attempt, 8000);
  const jitter = Math.random() * base * 0.2;
  return base + jitter;
}

/**
 * Runs `fn`, retrying on transient NetworkError up to `maxAttempts` (default
 * 3) when `idempotent` is true. Honors a `retryAfterMs` hint on the thrown
 * error (set by callers that observed a 429 Retry-After header) in place of
 * the computed backoff delay. Never retries non-idempotent calls or
 * non-NetworkError failures (CF-01).
 */
export async function withRetry<T>(fn: () => Promise<T>, options: RetryOptions): Promise<T> {
  const maxAttempts = options.idempotent ? (options.maxAttempts ?? 3) : 1;
  let lastError: unknown;

  for (let attempt = 0; attempt < maxAttempts; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;
      const isLastAttempt = attempt === maxAttempts - 1;
      if (!options.idempotent || !(err instanceof NetworkError) || isLastAttempt) {
        throw err;
      }
      const retryAfterMs = isRetryAfterCarrier(err) ? err.retryAfterMs : undefined;
      await sleep(retryAfterMs ?? backoffDelayMs(attempt));
    }
  }

  throw lastError;
}

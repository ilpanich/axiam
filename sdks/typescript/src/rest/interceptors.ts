// Axios interceptors: CSRF forwarding (D-05, §3) + reactive single-flight
// 401->refresh (D-07, §9). Mirrors frontend/src/lib/api.ts's proven pattern,
// generalized off the app store: this is a library, not an app — refresh
// failure clears session auth state and rejects; it never redirects
// (no window.location access anywhere in this module).

import type { AxiosError, AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import { csrfHeaderForMethod, mapHttpStatusToError, refreshOnce } from '../core/index.js';
import type { SharedSession } from './session.js';

/**
 * Endpoints that must never trigger a silent refresh, to avoid infinite
 * refresh loops (§9.3): the refresh endpoint itself, plus login/logout which
 * are not authenticated-session-continuation calls.
 */
export const SKIP_REFRESH = ['/api/v1/auth/refresh', '/api/v1/auth/login', '/api/v1/auth/logout'];

type RetryableRequestConfig = InternalAxiosRequestConfig & { _retry?: boolean };

/**
 * Request interceptor: forwards the axiam_csrf cookie as X-CSRF-Token on
 * state-changing methods (POST/PUT/PATCH/DELETE) per §3/D-05.
 *
 * Browser: reads `document.cookie` directly (guarded by `typeof document !==
 * 'undefined'`). Node: reads the session's csrfToken store, populated by the
 * Node persona's cookie-jar read (17-03) — left undefined here since no jar
 * exists in the browser-only REST core built by this plan.
 */
export function installCsrfInterceptor(axiosInstance: AxiosInstance, session: SharedSession): void {
  axiosInstance.interceptors.request.use((config: InternalAxiosRequestConfig) => {
    const method = (config.method ?? 'get').toLowerCase();
    const cookieString = typeof document !== 'undefined' ? document.cookie : '';
    const csrfToken =
      typeof document !== 'undefined' ? csrfHeaderForMethod(method, cookieString) : csrfHeaderForMethod(method, session.csrfToken ? `axiam_csrf=${session.csrfToken}` : '');

    if (csrfToken) {
      config.headers = config.headers ?? {};
      config.headers['X-CSRF-Token'] = csrfToken;
    }
    return config;
  });
}

/**
 * Response interceptor: on 401 (when authenticated, not a SKIP_REFRESH url,
 * not already retried) performs a reactive single-flight refresh and replays
 * the original request (D-07/§9). Non-2xx responses are mapped through
 * core's mapHttpStatusToError.
 */
export function installRefreshInterceptor(axiosInstance: AxiosInstance, session: SharedSession): void {
  axiosInstance.interceptors.response.use(
    (response) => response,
    async (error: AxiosError) => {
      const originalRequest = error.config as RetryableRequestConfig | undefined;

      if (!originalRequest || !error.response) {
        // No response at all (network/timeout) — surface as NetworkError below via caller mapping.
        return Promise.reject(error);
      }

      const status = error.response.status;
      const url = originalRequest.url ?? '';
      const isSkipRefresh = SKIP_REFRESH.some((skipUrl) => url.includes(skipUrl));

      if (status === 401 && !originalRequest._retry && !isSkipRefresh && session.authenticated) {
        // CQ-F32: set _retry BEFORE the refresh call so a 401 on the replayed
        // request cannot trigger a second refresh cycle.
        originalRequest._retry = true;

        try {
          await refreshOnce(async () => {
            await session.axios.post('/api/v1/auth/refresh', {});
          });
          return axiosInstance(originalRequest);
        } catch (refreshError) {
          session.authenticated = false;
          session.csrfToken = undefined;
          return Promise.reject(
            mapHttpStatusToError(401, 'session refresh failed; re-authentication required', {
              cause: refreshError,
            }),
          );
        }
      }

      if (status === 401 && isSkipRefresh) {
        return Promise.reject(mapHttpStatusToError(401, 'authentication failed'));
      }

      return Promise.reject(error);
    },
  );
}

/** Install both the CSRF and reactive single-flight refresh interceptors. */
export function installInterceptors(axiosInstance: AxiosInstance, session: SharedSession): void {
  installCsrfInterceptor(axiosInstance, session);
  installRefreshInterceptor(axiosInstance, session);
}

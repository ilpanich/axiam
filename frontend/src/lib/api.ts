import axios, {
  type AxiosInstance,
  type InternalAxiosRequestConfig,
  type AxiosResponse,
  type AxiosError,
} from "axios";
import { useAuthStore } from "@/stores/auth";
import { queryClient } from "@/lib/queryClient";

const api: AxiosInstance = axios.create({
  baseURL: "/",
  headers: {
    "Content-Type": "application/json",
  },
  withCredentials: true, // Send cookies on ALL requests
});

// Parse the axiam_csrf cookie from document.cookie string.
// Hardcoded regex avoids ReDoS (CWE-1333) from dynamic RegExp construction.
function getCookie(name: "axiam_csrf"): string | null {
  const AXIAM_CSRF_RE = /(?:^|;\s*)axiam_csrf=([^;]*)/;
  if (name !== "axiam_csrf") return null;
  const match = document.cookie.match(AXIAM_CSRF_RE);
  return match ? decodeURIComponent(match[1]) : null;
}

// State-changing HTTP methods that need CSRF token
const CSRF_METHODS = new Set(["post", "put", "patch", "delete"]);

// Request interceptor: inject X-CSRF-Token header on state-changing requests (per D-03, D-04)
api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const method = (config.method || "get").toLowerCase();
    if (CSRF_METHODS.has(method) && config.headers) {
      const csrfToken = getCookie("axiam_csrf");
      if (csrfToken) {
        config.headers["X-CSRF-Token"] = csrfToken;
      }
    }
    return config;
  },
  (error: AxiosError) => Promise.reject(error)
);

// Track if a refresh is already in progress
let isRefreshing = false;
let failedQueue: Array<{
  resolve: (value: unknown) => void;
  reject: (error: unknown) => void;
}> = [];

function processQueue(error: unknown) {
  failedQueue.forEach((prom) => {
    if (error) {
      prom.reject(error);
    } else {
      prom.resolve(undefined);
    }
  });
  failedQueue = [];
}

// Endpoints that must never trigger a silent refresh (avoids infinite loops)
const SKIP_REFRESH = [
  "/api/v1/auth/refresh",
  "/api/v1/auth/login",
  "/api/v1/auth/logout",
];

// Response interceptor: handle 401 with silent cookie-based refresh (per D-14)
api.interceptors.response.use(
  (response: AxiosResponse) => response,
  async (error: AxiosError) => {
    const originalRequest = error.config as
      | (InternalAxiosRequestConfig & { _retry?: boolean })
      | undefined;

    if (!originalRequest) {
      return Promise.reject(error);
    }

    // Skip refresh for login, logout, and the refresh endpoint itself
    const isSkipRefresh = SKIP_REFRESH.some((u) => originalRequest.url?.includes(u));
    const isAuthenticated = useAuthStore.getState().isAuthenticated;

    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !isSkipRefresh &&
      isAuthenticated
    ) {
      if (isRefreshing) {
        return new Promise((resolve, reject) => {
          failedQueue.push({ resolve, reject });
        }).then(() => api(originalRequest));
      }

      originalRequest._retry = true;
      isRefreshing = true;

      try {
        // Cookie-based refresh via the api instance so X-CSRF-Token is attached (CQ-F28)
        await api.post("/api/v1/auth/refresh", {});
        // New cookies set by server response — no store update needed
        processQueue(null);
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError);
        queryClient.clear();
        useAuthStore.getState().clearAuth();
        window.location.href = "/login";
        return Promise.reject(refreshError);
      } finally {
        isRefreshing = false;
      }
    }

    return Promise.reject(error);
  }
);

export default api;

import axios, {
  type AxiosInstance,
  type InternalAxiosRequestConfig,
  type AxiosResponse,
  type AxiosError,
} from "axios";
import { useAuthStore } from "@/stores/auth";

const api: AxiosInstance = axios.create({
  baseURL: "/",
  headers: {
    "Content-Type": "application/json",
  },
  withCredentials: true, // Send cookies on ALL requests
});

// Parse a named cookie from document.cookie string
function getCookie(name: string): string | null {
  const match = document.cookie.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
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

    // Skip refresh for auth endpoints (login, refresh itself, etc.)
    const isAuthRoute = originalRequest.url?.includes("/auth/");
    const isAuthenticated = useAuthStore.getState().isAuthenticated;

    if (
      error.response?.status === 401 &&
      !originalRequest._retry &&
      !isAuthRoute &&
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
        // Cookie-based refresh — cookies sent automatically, no token in body
        await axios.post(
          "/api/v1/auth/refresh",
          {},
          { withCredentials: true }
        );
        // New cookies set by server response — no store update needed
        processQueue(null);
        return api(originalRequest);
      } catch (refreshError) {
        processQueue(refreshError);
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

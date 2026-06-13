import type { AxiosError } from "axios";

interface ApiErrorData {
  error?: string;
  message?: string;
}

/**
 * Extract a human-readable error message from any thrown value.
 *
 * Priority order (mirrors LoginPage.tsx AxiosError unwrapping):
 *   1. response.data.error  (backend field name used in most handlers)
 *   2. response.data.message
 *   3. error.message        (plain Error or AxiosError network message)
 *   4. Generic fallback     (never returns empty)
 */
export function getApiErrorMessage(err: unknown): string {
  if (err == null) {
    return "An unexpected error occurred. Please try again.";
  }

  const axiosErr = err as AxiosError<ApiErrorData>;
  if (axiosErr.isAxiosError) {
    if (axiosErr.response?.data) {
      const data = axiosErr.response.data;
      if (typeof data.error === "string" && data.error.length > 0) {
        return data.error;
      }
      if (typeof data.message === "string" && data.message.length > 0) {
        return data.message;
      }
    }
    if (typeof axiosErr.message === "string" && axiosErr.message.length > 0) {
      return axiosErr.message;
    }
  }

  if (err instanceof Error && err.message.length > 0) {
    return err.message;
  }

  return "An unexpected error occurred. Please try again.";
}

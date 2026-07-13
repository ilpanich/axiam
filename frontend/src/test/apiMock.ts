import { vi } from "vitest";

// Shared axios-instance mock. Service modules do `import api from "@/lib/api"`
// and call api.get/post/put/delete — each returns a Promise<AxiosResponse>-ish
// object. Tests configure the resolved value per case with `.mockResolvedValue`.
export const apiMock = {
  get: vi.fn(),
  post: vi.fn(),
  put: vi.fn(),
  delete: vi.fn(),
};

/** Wrap a payload the way axios does: `{ data }`. */
export function res<T>(data: T): { data: T } {
  return { data };
}

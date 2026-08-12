import api from "@/lib/api";
import { unwrapList } from "@/services/_pagination";

// ─── Resource types ───────────────────────────────────────────────────────────

/** Selectable standard resource types (the backend stores any string). */
export const STANDARD_RESOURCE_TYPES = [
  "api",
  "service",
  "dataset",
  "endpoint",
  "iot_device",
] as const;

/** Human-readable labels for type values whose raw form reads poorly. */
export const RESOURCE_TYPE_LABELS: Record<string, string> = {
  iot_device: "IoT Device",
};

/** Display label for a resource type (falls back to the raw value). */
export function resourceTypeLabel(type: string): string {
  return RESOURCE_TYPE_LABELS[type] ?? type;
}

// ─── Domain Models ────────────────────────────────────────────────────────────

/** Free-form resource metadata. The admin UI stores `description` here. */
export interface ResourceMetadata {
  description?: string;
  [key: string]: unknown;
}

export interface Resource {
  id: string;
  name: string;
  resource_type: string;
  parent_id?: string;
  /** Backend has no `description` column — it lives under `metadata.description`. */
  metadata?: ResourceMetadata;
  /**
   * The OAuth2 `client_id` that registered this resource through the UMA
   * Protection API (X2), absent for a resource created any other way.
   *
   * Read-only: the backend accepts it on no create or update payload, so the
   * badge this drives cannot be set by editing a resource. Do not add it to
   * `CreateResourcePayload` or `UpdateResourcePayload` — a provenance marker
   * the UI can write is decoration that reads like evidence.
   */
  uma_registered_by?: string;
  created_at: string;
}

export interface CreateResourcePayload {
  name: string;
  resource_type: string;
  parent_id?: string;
  /** UI-level field; the service routes it into `metadata.description` on the wire. */
  description?: string;
}

export interface UpdateResourcePayload {
  name?: string;
  resource_type?: string;
  /**
   * `undefined` = leave parent unchanged; `null` = clear parent (make root).
   * Backend `parent_id` is `Option<Option<Uuid>>`, so JSON `null` → `Some(None)`.
   */
  parent_id?: string | null;
  description?: string;
}

/** Wire shape sent to the backend (description folded into metadata). */
interface ResourceWritePayload {
  name?: string;
  resource_type?: string;
  parent_id?: string | null;
  metadata?: ResourceMetadata;
}

// ─── Resources service ────────────────────────────────────────────────────────

/**
 * Fold the UI-level `description` into a `metadata` object for the wire.
 * Returns `undefined` when there is nothing to send (so PATCH-style updates
 * can omit the field entirely).
 */
function toWritePayload(
  payload: CreateResourcePayload | UpdateResourcePayload
): ResourceWritePayload {
  const { description, ...rest } = payload as UpdateResourcePayload;
  const wire: ResourceWritePayload = { ...rest };
  if (description !== undefined) {
    wire.metadata = { description };
  }
  return wire;
}

export const resourceService = {
  list: (): Promise<Resource[]> =>
    api
      .get<Resource[] | { items: Resource[] }>("/api/v1/resources")
      .then((r) => unwrapList(r.data)),

  get: (resourceId: string): Promise<Resource> =>
    api
      .get<Resource>(`/api/v1/resources/${resourceId}`)
      .then((r) => r.data),

  create: (payload: CreateResourcePayload): Promise<Resource> =>
    api
      .post<Resource>("/api/v1/resources", toWritePayload(payload))
      .then((r) => r.data),

  update: (
    resourceId: string,
    payload: UpdateResourcePayload
  ): Promise<Resource> =>
    api
      .put<Resource>(`/api/v1/resources/${resourceId}`, toWritePayload(payload))
      .then((r) => r.data),

  remove: (resourceId: string): Promise<void> =>
    api.delete(`/api/v1/resources/${resourceId}`).then(() => undefined),

  listChildren: (resourceId: string): Promise<Resource[]> =>
    api
      .get<Resource[] | { items: Resource[] }>(`/api/v1/resources/${resourceId}/children`)
      .then((r) => unwrapList(r.data)),
};

import api from "@/lib/api";

// ─── Domain Models ────────────────────────────────────────────────────────────

export interface Resource {
  id: string;
  name: string;
  resource_type: string;
  parent_id?: string;
  description?: string;
  created_at: string;
}

export interface CreateResourcePayload {
  name: string;
  resource_type: string;
  parent_id?: string;
  description?: string;
}

export type UpdateResourcePayload = Partial<CreateResourcePayload>;

// ─── Resources service ────────────────────────────────────────────────────────

export const resourceService = {
  list: (): Promise<Resource[]> =>
    api.get<Resource[]>("/api/v1/resources").then((r) => r.data),

  get: (resourceId: string): Promise<Resource> =>
    api
      .get<Resource>(`/api/v1/resources/${resourceId}`)
      .then((r) => r.data),

  create: (payload: CreateResourcePayload): Promise<Resource> =>
    api
      .post<Resource>("/api/v1/resources", payload)
      .then((r) => r.data),

  update: (
    resourceId: string,
    payload: UpdateResourcePayload
  ): Promise<Resource> =>
    api
      .put<Resource>(`/api/v1/resources/${resourceId}`, payload)
      .then((r) => r.data),

  remove: (resourceId: string): Promise<void> =>
    api.delete(`/api/v1/resources/${resourceId}`).then(() => undefined),

  listChildren: (resourceId: string): Promise<Resource[]> =>
    api
      .get<Resource[]>(`/api/v1/resources/${resourceId}/children`)
      .then((r) => r.data),
};

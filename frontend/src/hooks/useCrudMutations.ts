/**
 * useCrudMutations — generic create/update/delete mutation factory with
 * built-in toast error handling (CQ-F15).
 *
 * Eliminates the repeated mutation + onError + toast pattern across pages.
 */

import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useToast } from "@/hooks/useToast";
import { getApiErrorMessage } from "@/lib/apiError";

export interface UseCrudOptions<TCreate, TUpdate> {
  /** React Query cache key(s) to invalidate on success. */
  queryKey: string[];
  /** Service functions. */
  createFn?: (payload: TCreate) => Promise<unknown>;
  updateFn?: (id: string, payload: TUpdate) => Promise<unknown>;
  deleteFn?: (id: string) => Promise<unknown>;
  /** Optional callbacks. */
  onCreateSuccess?: () => void;
  onUpdateSuccess?: () => void;
  onDeleteSuccess?: () => void;
  /** Per-operation local error state setter (optional). */
  onCreateError?: (msg: string) => void;
  onUpdateError?: (msg: string) => void;
}

export function useCrudMutations<TCreate = unknown, TUpdate = unknown>({
  queryKey,
  createFn,
  updateFn,
  deleteFn,
  onCreateSuccess,
  onUpdateSuccess,
  onDeleteSuccess,
  onCreateError,
  onUpdateError,
}: UseCrudOptions<TCreate, TUpdate>) {
  const queryClient = useQueryClient();
  const { toast } = useToast();

  const createMutation = useMutation({
    mutationFn: (payload: TCreate) => {
      if (!createFn) throw new Error("createFn not provided");
      return createFn(payload);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey });
      onCreateSuccess?.();
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      onCreateError?.(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, payload }: { id: string; payload: TUpdate }) => {
      if (!updateFn) throw new Error("updateFn not provided");
      return updateFn(id, payload);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey });
      onUpdateSuccess?.();
    },
    onError: (err: unknown) => {
      const msg = getApiErrorMessage(err);
      onUpdateError?.(msg);
      toast({ description: msg, variant: "destructive" });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => {
      if (!deleteFn) throw new Error("deleteFn not provided");
      return deleteFn(id);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey });
      onDeleteSuccess?.();
    },
    onError: (err: unknown) => {
      toast({
        description: getApiErrorMessage(err),
        variant: "destructive",
      });
    },
  });

  return { createMutation, updateMutation, deleteMutation };
}

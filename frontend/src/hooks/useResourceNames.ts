import { useQuery } from "@tanstack/react-query";
import { resourceService } from "@/services/resources";

/** Resolves resource ids to names for the badge. One fetch, shared by the page. */
export function useResourceNames() {
  const { data: resources = [] } = useQuery({
    queryKey: ["resources"],
    queryFn: () => resourceService.list(),
    staleTime: 30_000,
  });
  return {
    resources,
    /**
     * A resource may be missing from the list — deleted, or not visible to this
     * admin. Fall back to the raw id rather than to "Global": claiming a scoped
     * grant applies everywhere is the one wrong answer here.
     */
    nameFor: (id: string) => resources.find((r) => r.id === id)?.name ?? id,
  };
}

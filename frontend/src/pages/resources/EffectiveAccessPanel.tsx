import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Loader2, Search, ShieldCheck, ShieldX } from "lucide-react";
import { authzCheckService, type CheckAccessResult } from "@/services/authzCheck";
import { permissionService } from "@/services/permissions";
import type { Resource } from "@/services/resources";
import type { User } from "@/services/users";
import { usePermissions } from "@/hooks/usePermissions";
import { getApiErrorMessage } from "@/lib/apiError";
import { SectionCard } from "@/components/shared";
import { UserSearchDialog } from "@/components/UserSearchDialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

// ─── Effective-access preview panel (B1) ──────────────────────────────────────
//
// Calls POST /api/v1/authz/check (and, for the inheritance preview, its
// /batch sibling) for a chosen (subject, resource, action) triple, so an
// admin can see what deny-override actually resolves to — including which
// descendant resources a deny reaches — BEFORE trying it in production.
//
// Honesty about what this previews: the engine only ever evaluates grants
// that are already SAVED. There is no "what if I added this grant" endpoint,
// so this is a preview of the tree's current effective state, not a
// simulation of an edit still sitting in a form. That is still exactly the
// tool the coverage matrix asks for -- "the net effect of a rule set is
// genuinely not obvious by inspection" applies just as much to rules an
// admin already saved five minutes ago.

function collectDescendantIds(resources: Resource[], rootId: string): string[] {
  const ids: string[] = [];
  const queue = [rootId];
  const seen = new Set<string>([rootId]);
  while (queue.length > 0) {
    const current = queue.shift()!;
    for (const r of resources) {
      if (r.parent_id === current && !seen.has(r.id)) {
        seen.add(r.id);
        ids.push(r.id);
        queue.push(r.id);
      }
    }
  }
  return ids;
}

function DecisionBadge({ result }: { result: CheckAccessResult }) {
  if (result.reason_code === "denied_by_rule") {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider bg-destructive/20 text-destructive border border-destructive/40">
        <ShieldX size={13} aria-hidden="true" />
        Deny
      </span>
    );
  }
  if (result.allowed) {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider bg-primary/20 text-primary border border-primary/40">
        <ShieldCheck size={13} aria-hidden="true" />
        Allow
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wider bg-white/10 text-muted-foreground border border-white/20">
      No grant
    </span>
  );
}

export interface EffectiveAccessPanelProps {
  resources: Resource[];
  selectedResource: Resource | undefined;
  onDenyResourceIdsChange: (ids: Set<string>) => void;
}

export function EffectiveAccessPanel({
  resources,
  selectedResource,
  onDenyResourceIdsChange,
}: EffectiveAccessPanelProps) {
  const { can } = usePermissions();
  const canCheckAs = can("authz:check_as");

  const [subjectId, setSubjectId] = useState("");
  const [subjectLabel, setSubjectLabel] = useState("");
  const [pickerOpen, setPickerOpen] = useState(false);
  const [action, setAction] = useState("read");

  // The tenant's real action vocabulary, for the Action box's suggestions.
  //
  // This list used to be four hard-coded strings — read/write/delete/admin —
  // which is a plausible vocabulary and not necessarily *this* tenant's. An
  // admin who had just created `invoices:read` saw a datalist offering `read`,
  // typed it, and got "No grant" on a rule set that was in fact correct. The
  // preview then looked broken while the only thing wrong was the question.
  //
  // Failure here is deliberately silent: the field stays free text, so a
  // permissions read the caller is not allowed to make costs suggestions, not
  // the panel.
  const { data: permissions } = useQuery({
    queryKey: ["permissions", "actions"],
    queryFn: () => permissionService.list(),
    retry: false,
  });
  const knownActions = Array.from(
    new Set((permissions ?? []).map((p) => p.action)),
  ).sort();
  const [scope, setScope] = useState("");
  const [result, setResult] = useState<CheckAccessResult | null>(null);
  const [error, setError] = useState("");
  const [inheritanceCount, setInheritanceCount] = useState<number | null>(null);

  const checkMutation = useMutation({
    mutationFn: async () => {
      if (!selectedResource) throw new Error("Select a resource first.");
      const effectiveSubject = canCheckAs && subjectId.trim() ? subjectId.trim() : undefined;
      const decision = await authzCheckService.check({
        action: action.trim(),
        resource_id: selectedResource.id,
        scope: scope || undefined,
        subject_id: effectiveSubject,
      });

      if (decision.reason_code !== "denied_by_rule") {
        onDenyResourceIdsChange(new Set());
        setInheritanceCount(null);
        return decision;
      }

      // Inheritance preview: walk every descendant of the checked resource
      // and batch-check the same (subject, action, scope) so the tree can
      // badge exactly which nodes the deny reaches — deny-override cascades
      // downward regardless of depth, so this is the only reliable way to
      // show "how far" short of reading the rule set by hand.
      const descendantIds = collectDescendantIds(resources, selectedResource.id);
      const deniedIds = new Set<string>([selectedResource.id]);
      if (descendantIds.length > 0) {
        const batch = await authzCheckService.checkBatch(
          descendantIds.map((id) => ({
            action: action.trim(),
            resource_id: id,
            scope: scope || undefined,
            subject_id: effectiveSubject,
          })),
        );
        batch.results.forEach((r, i) => {
          if (r.reason_code === "denied_by_rule") deniedIds.add(descendantIds[i]);
        });
      }
      onDenyResourceIdsChange(deniedIds);
      setInheritanceCount(deniedIds.size - 1);
      return decision;
    },
    onSuccess: (decision) => {
      setError("");
      setResult(decision);
    },
    onError: (err: unknown) => {
      setResult(null);
      setError(getApiErrorMessage(err));
    },
  });

  function handleUserPicked(user: User): Promise<void> {
    setSubjectId(user.id);
    setSubjectLabel(user.display_name ?? user.username);
    setPickerOpen(false);
    return Promise.resolve();
  }

  return (
    <SectionCard title="Effective Access Preview">
      {!selectedResource ? (
        <p className="text-sm text-muted-foreground">
          Select a resource in the tree to preview effective access for it.
        </p>
      ) : (
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Previewing access to{" "}
            <span className="font-medium text-foreground">{selectedResource.name}</span>.
            {" "}Deny-override means the net effect of saved rules is not
            always obvious from the resource tree alone — this calls the same
            engine the server uses to decide.
          </p>

          {canCheckAs ? (
            <div className="space-y-2">
              <Label htmlFor="eap-subject">Subject (defaults to you)</Label>
              <div className="flex gap-2">
                <Input
                  id="eap-subject"
                  value={subjectLabel || subjectId}
                  readOnly
                  placeholder="Yourself"
                  className="flex-1"
                />
                <Button type="button" variant="outline" onClick={() => setPickerOpen(true)}>
                  <Search size={14} />
                  Choose user
                </Button>
                {subjectId && (
                  <Button
                    type="button"
                    variant="ghost"
                    onClick={() => {
                      setSubjectId("");
                      setSubjectLabel("");
                    }}
                  >
                    Clear
                  </Button>
                )}
              </div>
            </div>
          ) : (
            <p role="note" className="text-xs text-muted-foreground">
              You can preview your own effective access. Checking another
              user's requires the <code>authz:check_as</code> permission.
            </p>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div className="space-y-2">
              <Label htmlFor="eap-action">Action</Label>
              <Input
                id="eap-action"
                list="eap-action-options"
                value={action}
                onChange={(e) => setAction(e.target.value)}
                placeholder="read"
              />
              <datalist id="eap-action-options">
                {knownActions.map((a) => (
                  <option key={a} value={a} />
                ))}
              </datalist>
              {knownActions.length > 0 && !knownActions.includes(action.trim()) && (
                <p className="text-xs text-muted-foreground">
                  No permission in this tenant has the action{" "}
                  <code>{action.trim() || "(empty)"}</code>. A check for it can
                  only come back &ldquo;No grant&rdquo;.
                </p>
              )}
            </div>
            <div className="space-y-2">
              <Label htmlFor="eap-scope">Scope (optional)</Label>
              <Input
                id="eap-scope"
                value={scope}
                onChange={(e) => setScope(e.target.value)}
                placeholder="e.g. invoices"
              />
            </div>
          </div>

          <Button
            onClick={() => checkMutation.mutate()}
            disabled={checkMutation.isPending || !action.trim()}
          >
            {checkMutation.isPending ? (
              <Loader2 size={16} className="animate-spin" />
            ) : (
              "Check access"
            )}
          </Button>

          {error && (
            <p role="alert" className="text-sm text-destructive">
              {error}
            </p>
          )}

          {result && (
            <div className="rounded-md border border-white/10 bg-white/5 p-4 space-y-2">
              <div className="flex items-center gap-3">
                <DecisionBadge result={result} />
                <span className="text-xs text-muted-foreground font-mono">
                  reason_code: {result.reason_code}
                </span>
              </div>
              {result.reason && (
                <p className="text-sm text-muted-foreground">{result.reason}</p>
              )}
              {inheritanceCount !== null && (
                <p className="text-sm text-destructive/90">
                  This deny reaches {inheritanceCount}{" "}
                  {inheritanceCount === 1 ? "descendant resource" : "descendant resources"}{" "}
                  in the tree — marked with the DENY badge above.
                </p>
              )}
            </div>
          )}
        </div>
      )}

      <UserSearchDialog
        open={pickerOpen}
        onClose={() => setPickerOpen(false)}
        title="Choose a subject"
        actionLabel="Select"
        onAction={handleUserPicked}
      />
    </SectionCard>
  );
}

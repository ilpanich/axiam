import { useCallback, useMemo, useRef, useState, type ReactNode } from "react";
import { ChevronRight, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Resource } from "@/services/resources";

// ─── Tree node type ───────────────────────────────────────────────────────────

interface TreeNode {
  resource: Resource;
  children: TreeNode[];
}

function buildTree(resources: Resource[]): TreeNode[] {
  const map = new Map<string, TreeNode>();

  // First pass: create all nodes
  for (const r of resources) {
    map.set(r.id, { resource: r, children: [] });
  }

  const roots: TreeNode[] = [];

  // Second pass: link children to parents
  for (const r of resources) {
    const node = map.get(r.id)!;
    if (r.parent_id && map.has(r.parent_id)) {
      map.get(r.parent_id)!.children.push(node);
    } else {
      roots.push(node);
    }
  }

  return roots;
}

// ─── Resource type badge ──────────────────────────────────────────────────────

function ResourceTypeBadge({ type }: { type: string }) {
  return (
    <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium uppercase tracking-wider bg-white/5 text-muted-foreground border border-white/10">
      {type}
    </span>
  );
}

// ─── Props ────────────────────────────────────────────────────────────────────

export interface ResourceTreeProps {
  resources: Resource[];
  onSelect?: (resource: Resource) => void;
  selectedId?: string;
  actions?: (resource: Resource) => ReactNode;
}

// ─── Single tree node renderer (recursive) ───────────────────────────────────

const MAX_DEPTH = 8;

interface TreeNodeRowProps {
  node: TreeNode;
  depth: number;
  onSelect?: (resource: Resource) => void;
  selectedId?: string;
  actions?: (resource: Resource) => ReactNode;
  focusedId: string | null;
  onFocus: (id: string) => void;
  visibleIds: string[];
  isFirstRoot: boolean;
  expandedIds: Set<string>;
  onToggleExpand: (id: string) => void;
}

function focusNodeById(id: string) {
  const el = document.querySelector<HTMLElement>(
    `[data-tree-node-id="${id}"]`
  );
  el?.focus();
}

function TreeNodeRow({
  node,
  depth,
  onSelect,
  selectedId,
  actions,
  focusedId,
  onFocus,
  visibleIds,
  isFirstRoot,
  expandedIds,
  onToggleExpand,
}: TreeNodeRowProps) {
  const hasChildren = node.children.length > 0;
  const expanded = expandedIds.has(node.resource.id);
  const isSelected = selectedId === node.resource.id;
  // Clamp indentation at MAX_DEPTH to avoid runaway layouts
  const indent = Math.min(depth, MAX_DEPTH) * 20;

  // Roving tabindex: only the focused node (or first root as default) is tabbable
  const isTabbable =
    focusedId === node.resource.id ||
    (focusedId === null && isFirstRoot);

  return (
    <>
      <div
        className={cn(
          "flex items-center gap-2 px-3 py-2 rounded-md group transition-colors duration-100 cursor-pointer select-none",
          isSelected
            ? "bg-cyan-500/15 text-cyan-400"
            : "hover:bg-white/[0.04] text-foreground/80"
        )}
        style={{ paddingLeft: `${12 + indent}px` }}
        data-tree-node-id={node.resource.id}
        onClick={() => {
          onFocus(node.resource.id);
          onSelect?.(node.resource);
        }}
        onFocus={() => onFocus(node.resource.id)}
        role="treeitem"
        aria-selected={isSelected}
        aria-expanded={hasChildren ? expanded : undefined}
        tabIndex={isTabbable ? 0 : -1}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === " ") {
            e.preventDefault();
            onSelect?.(node.resource);
          }
          if (e.key === "ArrowRight" && hasChildren && !expanded) {
            e.preventDefault();
            onToggleExpand(node.resource.id);
          }
          if (e.key === "ArrowLeft" && hasChildren && expanded) {
            e.preventDefault();
            onToggleExpand(node.resource.id);
          }
          if (e.key === "ArrowDown") {
            e.preventDefault();
            const idx = visibleIds.indexOf(node.resource.id);
            if (idx >= 0 && idx < visibleIds.length - 1) {
              const nextId = visibleIds[idx + 1];
              onFocus(nextId);
              focusNodeById(nextId);
            }
          }
          if (e.key === "ArrowUp") {
            e.preventDefault();
            const idx = visibleIds.indexOf(node.resource.id);
            if (idx > 0) {
              const prevId = visibleIds[idx - 1];
              onFocus(prevId);
              focusNodeById(prevId);
            }
          }
          if (e.key === "Home") {
            e.preventDefault();
            if (visibleIds.length > 0) {
              const firstId = visibleIds[0];
              onFocus(firstId);
              focusNodeById(firstId);
            }
          }
          if (e.key === "End") {
            e.preventDefault();
            if (visibleIds.length > 0) {
              const lastId = visibleIds[visibleIds.length - 1];
              onFocus(lastId);
              focusNodeById(lastId);
            }
          }
        }}
      >
        {/* Expand/collapse toggle */}
        {hasChildren ? (
          <button
            type="button"
            className="shrink-0 w-4 h-4 flex items-center justify-center text-muted-foreground hover:text-foreground transition-colors"
            onClick={(e) => {
              e.stopPropagation();
              onToggleExpand(node.resource.id);
            }}
            tabIndex={-1}
            aria-label={expanded ? "Collapse" : "Expand"}
          >
            {expanded ? (
              <ChevronDown size={14} />
            ) : (
              <ChevronRight size={14} />
            )}
          </button>
        ) : (
          <span
            className="shrink-0 w-4 h-4 flex items-center justify-center"
            aria-hidden="true"
          >
            <span className="w-1 h-1 rounded-full bg-white/20 mx-auto" />
          </span>
        )}

        {/* Resource name */}
        <span className="flex-1 text-sm font-medium truncate">
          {node.resource.name}
        </span>

        {/* Type badge */}
        <ResourceTypeBadge type={node.resource.resource_type} />

        {/* Action buttons (revealed on hover / always visible) */}
        {actions && (
          <span
            className="shrink-0 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
            onClick={(e) => e.stopPropagation()}
          >
            {actions(node.resource)}
          </span>
        )}
      </div>

      {/* Vertical connecting line + children */}
      {hasChildren && expanded && (
        <div
          className="relative"
          style={{ marginLeft: `${20 + indent}px` }}
          role="group"
        >
          {/* Subtle vertical connector line */}
          <div className="absolute left-0 top-0 bottom-0 w-px bg-white/10" />
          {node.children.map((child) => (
            <TreeNodeRow
              key={child.resource.id}
              node={child}
              depth={depth + 1}
              onSelect={onSelect}
              selectedId={selectedId}
              actions={actions}
              focusedId={focusedId}
              onFocus={onFocus}
              visibleIds={visibleIds}
              isFirstRoot={false}
              expandedIds={expandedIds}
              onToggleExpand={onToggleExpand}
            />
          ))}
        </div>
      )}
    </>
  );
}

// ─── Public component ─────────────────────────────────────────────────────────

/** Collect all node IDs that should default to expanded (all of them). */
function collectAllIds(nodes: TreeNode[]): Set<string> {
  const ids = new Set<string>();
  function walk(list: TreeNode[]) {
    for (const n of list) {
      ids.add(n.resource.id);
      walk(n.children);
    }
  }
  walk(nodes);
  return ids;
}

/** Build a flat ordered list of currently visible node IDs. */
function buildVisibleIds(
  nodes: TreeNode[],
  expandedIds: Set<string>
): string[] {
  const result: string[] = [];
  function walk(list: TreeNode[]) {
    for (const n of list) {
      result.push(n.resource.id);
      if (n.children.length > 0 && expandedIds.has(n.resource.id)) {
        walk(n.children);
      }
    }
  }
  walk(nodes);
  return result;
}

export function ResourceTree({
  resources,
  onSelect,
  selectedId,
  actions,
}: ResourceTreeProps) {
  const roots = useMemo(() => buildTree(resources), [resources]);

  // Lifted expand/collapse state: all nodes start expanded
  const [expandedIds, setExpandedIds] = useState<Set<string>>(
    () => collectAllIds(roots)
  );

  // Sync expandedIds when resources change (new nodes should default expanded)
  const prevResourcesRef = useRef(resources);
  if (prevResourcesRef.current !== resources) {
    prevResourcesRef.current = resources;
    const allIds = collectAllIds(roots);
    // Merge: keep existing collapse decisions, add any new IDs
    setExpandedIds((prev) => {
      const next = new Set(prev);
      for (const id of allIds) {
        if (!prev.has(id)) {
          next.add(id);
        }
      }
      return next;
    });
  }

  const handleToggleExpand = useCallback((id: string) => {
    setExpandedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  }, []);

  // Roving tabindex state
  const [focusedId, setFocusedId] = useState<string | null>(null);

  // Flat list of visible node IDs for arrow key navigation
  const visibleIds = useMemo(
    () => buildVisibleIds(roots, expandedIds),
    [roots, expandedIds]
  );

  if (roots.length === 0) {
    return (
      <div className="flex flex-col items-center gap-2 py-12 text-muted-foreground text-sm">
        <span className="text-4xl opacity-20">&#9632;</span>
        <span>No resources defined yet.</span>
      </div>
    );
  }

  return (
    <div role="tree" aria-label="Resource hierarchy" className="space-y-0.5">
      {roots.map((node, index) => (
        <TreeNodeRow
          key={node.resource.id}
          node={node}
          depth={0}
          onSelect={onSelect}
          selectedId={selectedId}
          actions={actions}
          focusedId={focusedId}
          onFocus={setFocusedId}
          visibleIds={visibleIds}
          isFirstRoot={index === 0}
          expandedIds={expandedIds}
          onToggleExpand={handleToggleExpand}
        />
      ))}
    </div>
  );
}

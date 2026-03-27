import { useMemo, useState, type ReactNode } from "react";
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
}

function TreeNodeRow({
  node,
  depth,
  onSelect,
  selectedId,
  actions,
}: TreeNodeRowProps) {
  const [expanded, setExpanded] = useState(true);
  const hasChildren = node.children.length > 0;
  const isSelected = selectedId === node.resource.id;
  // Clamp indentation at MAX_DEPTH to avoid runaway layouts
  const indent = Math.min(depth, MAX_DEPTH) * 20;

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
        onClick={() => onSelect?.(node.resource)}
        role="treeitem"
        aria-selected={isSelected}
        aria-expanded={hasChildren ? expanded : undefined}
      >
        {/* Expand/collapse toggle */}
        <span
          className="shrink-0 w-4 h-4 flex items-center justify-center text-muted-foreground"
          onClick={(e) => {
            e.stopPropagation();
            if (hasChildren) setExpanded((v) => !v);
          }}
          aria-hidden="true"
        >
          {hasChildren ? (
            expanded ? (
              <ChevronDown size={14} />
            ) : (
              <ChevronRight size={14} />
            )
          ) : (
            // Leaf spacer — subtle dot indicator
            <span className="w-1 h-1 rounded-full bg-white/20 mx-auto" />
          )}
        </span>

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
            />
          ))}
        </div>
      )}
    </>
  );
}

// ─── Public component ─────────────────────────────────────────────────────────

export function ResourceTree({
  resources,
  onSelect,
  selectedId,
  actions,
}: ResourceTreeProps) {
  const roots = useMemo(() => buildTree(resources), [resources]);

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
      {roots.map((node) => (
        <TreeNodeRow
          key={node.resource.id}
          node={node}
          depth={0}
          onSelect={onSelect}
          selectedId={selectedId}
          actions={actions}
        />
      ))}
    </div>
  );
}

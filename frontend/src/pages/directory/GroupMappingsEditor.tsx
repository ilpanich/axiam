import { Plus, Trash2 } from "lucide-react";
import type { Group } from "@/services/users";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { GROUP_MAPPINGS_MAX, newMappingRow, type MappingRow } from "./directoryForm";

interface GroupMappingsEditorProps {
  rows: MappingRow[];
  groups: Group[];
  groupsLoading: boolean;
  onChange: (rows: MappingRow[]) => void;
  disabled?: boolean;
}

/**
 * The group-mapping table (D-30), editable.
 *
 * **The table is the only way a directory group reaches an AXIAM group**: there
 * is no match by name and no AXIAM group is created from a directory one, so a
 * directory administrator who names a group `admins` gains nothing unless a
 * tenant administrator maps it here. The picker therefore offers this tenant's
 * existing groups and nothing else; a row whose group was since deleted keeps
 * its id as an option so it is visible rather than silently blank.
 */
export function GroupMappingsEditor({
  rows,
  groups,
  groupsLoading,
  onChange,
  disabled,
}: GroupMappingsEditorProps) {
  function update(key: string, patch: Partial<MappingRow>) {
    onChange(rows.map((row) => (row.key === key ? { ...row, ...patch } : row)));
  }

  return (
    <fieldset className="space-y-3" disabled={disabled}>
      <legend className="text-sm font-medium text-foreground">Group mappings</legend>
      <p className="text-xs text-muted-foreground">
        Members of a directory group are put into the AXIAM group you choose at
        every directory sign-in and by the sync job. Only memberships made this way
        are managed: one an administrator added by hand is never touched. A
        directory group matches by its DN, compared after normalisation
        (<code>CN=Staff, OU=Groups</code> equals <code>cn=staff,ou=groups</code>).
        With no rows, no directory group maps to anything.
      </p>
      {rows.length === 0 ? (
        <p className="text-sm text-muted-foreground">No mappings.</p>
      ) : (
        <ul className="space-y-2">
          {rows.map((row, index) => {
            const known = groups.some((g) => g.id === row.groupId);
            return (
              <li key={row.key} className="flex flex-col gap-2 sm:flex-row sm:items-center">
                <Input
                  aria-label={`Directory group DN for mapping ${index + 1}`}
                  placeholder="cn=staff,ou=groups,dc=example,dc=com"
                  value={row.dn}
                  onChange={(e) => update(row.key, { dn: e.target.value })}
                  className="font-mono text-xs sm:flex-1"
                />
                <select
                  aria-label={`AXIAM group for mapping ${index + 1}`}
                  value={row.groupId}
                  onChange={(e) => update(row.key, { groupId: e.target.value })}
                  className="flex h-9 rounded-md border border-input bg-background/50 px-3 py-1 text-sm sm:w-56"
                >
                  <option value="">
                    {groupsLoading ? "Loading groups…" : "Choose a group…"}
                  </option>
                  {!known && row.groupId !== "" && (
                    <option value={row.groupId}>
                      Unknown group ({row.groupId.slice(0, 8)}…)
                    </option>
                  )}
                  {groups.map((group) => (
                    <option key={group.id} value={group.id}>
                      {group.name}
                    </option>
                  ))}
                </select>
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  aria-label={`Remove mapping ${index + 1}`}
                  onClick={() => onChange(rows.filter((r) => r.key !== row.key))}
                >
                  <Trash2 size={14} aria-hidden="true" />
                </Button>
              </li>
            );
          })}
        </ul>
      )}
      <Button
        type="button"
        variant="outline"
        size="sm"
        onClick={() => onChange([...rows, newMappingRow()])}
        disabled={rows.length >= GROUP_MAPPINGS_MAX}
      >
        <Plus size={14} aria-hidden="true" />
        Add mapping
      </Button>
    </fieldset>
  );
}

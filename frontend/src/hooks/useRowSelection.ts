import { useCallback, useMemo, useState } from "react";

import { type PageSelection, pageSelection, rangeBetween } from "../features/intel/selection";

interface Picked {
  /** What the ticks were made on. A different page or filter is a different scope. */
  scope: string;
  ids: ReadonlySet<string>;
  /** The row clicked last, where a shift-click range starts. */
  anchor: string | null;
}

const NOTHING: ReadonlySet<string> = new Set();

function nothingPicked(scope: string): Picked {
  return { scope, ids: NOTHING, anchor: null };
}

export interface RowSelection {
  /** The ticked rows that are on screen, in the order they are on screen. */
  selected: readonly string[];
  isSelected: (id: string) => boolean;
  overall: PageSelection;
  /** Ticks or unticks one row. With `range`, every row between it and the last one clicked changes too. */
  set: (id: string, ticked: boolean, range?: boolean) => void;
  /** Ticks or unticks every row on screen. */
  setAll: (ticked: boolean) => void;
  clear: () => void;
  /** Forgets rows that no longer exist, for example because they were deleted. */
  drop: (ids: readonly string[]) => void;
}

/**
 * Which rows of a table are ticked. `scope` names what is on screen (the page and filters), and a
 * change of scope starts again with nothing ticked, so a tick never lingers on a page that is no
 * longer showing it. `rowIds` are the rows on screen, in order; a tick on a row that has gone
 * from the screen no longer counts.
 */
export function useRowSelection(scope: string, rowIds: readonly string[]): RowSelection {
  const [picked, setPicked] = useState<Picked>(() => nothingPicked(scope));
  // Done while rendering, which React allows for state that depends on a prop: it re-renders at
  // once, before anything is shown or any effect runs.
  if (picked.scope !== scope) setPicked(nothingPicked(scope));
  const ids = picked.scope === scope ? picked.ids : NOTHING;

  const selected = useMemo(() => rowIds.filter((id) => ids.has(id)), [rowIds, ids]);
  const overall = useMemo(() => pageSelection(rowIds, ids), [rowIds, ids]);
  const isSelected = useCallback((id: string) => ids.has(id), [ids]);

  const set = useCallback(
    (id: string, ticked: boolean, range = false) => {
      setPicked((current) => {
        const base = current.scope === scope ? current : nothingPicked(scope);
        const changed = range && base.anchor !== null ? rangeBetween(rowIds, base.anchor, id) : [id];
        const next = new Set(base.ids);
        for (const changedId of changed) {
          if (ticked) next.add(changedId);
          else next.delete(changedId);
        }
        return { scope, ids: next, anchor: id };
      });
    },
    [scope, rowIds],
  );

  const setAll = useCallback(
    (ticked: boolean) => {
      setPicked((current) => {
        const base = current.scope === scope ? current : nothingPicked(scope);
        const next = new Set(base.ids);
        for (const id of rowIds) {
          if (ticked) next.add(id);
          else next.delete(id);
        }
        return { scope, ids: next, anchor: null };
      });
    },
    [scope, rowIds],
  );

  const clear = useCallback(() => setPicked(nothingPicked(scope)), [scope]);

  const drop = useCallback(
    (gone: readonly string[]) => {
      setPicked((current) => {
        if (current.scope !== scope) return current;
        const next = new Set(current.ids);
        for (const id of gone) next.delete(id);
        const anchor = current.anchor !== null && gone.includes(current.anchor) ? null : current.anchor;
        return { scope, ids: next, anchor };
      });
    },
    [scope],
  );

  return { selected, isSelected, overall, set, setAll, clear, drop };
}

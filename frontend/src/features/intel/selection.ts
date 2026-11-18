/** How many of the rows on screen are ticked. */
export type PageSelection = "none" | "some" | "all";

export function pageSelection(rowIds: readonly string[], ticked: ReadonlySet<string>): PageSelection {
  const count = rowIds.filter((id) => ticked.has(id)).length;
  if (count === 0) return "none";
  return count === rowIds.length ? "all" : "some";
}

/**
 * The rows from one end of a shift-click to the other, both included, in the order they are on
 * screen. When the row the range starts from is not on screen, only the row that was clicked.
 */
export function rangeBetween(rowIds: readonly string[], from: string, to: string): string[] {
  const end = rowIds.indexOf(to);
  if (end === -1) return [];
  const start = rowIds.indexOf(from);
  if (start === -1) return [to];
  return rowIds.slice(Math.min(start, end), Math.max(start, end) + 1);
}

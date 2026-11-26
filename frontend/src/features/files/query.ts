/** How many files one page of the list shows. */
export const PAGE_SIZE = 10;

const MAX_PAGE = 100_000;

/** The file the address names, or null when it is missing or cannot be an id (so no request is made). */
export function parseFileParam(value: string | null): string | null {
  if (value === null) return null;
  const id = value.trim();
  return /^[A-Za-z0-9_-]{1,64}$/.test(id) ? id : null;
}

/** A 1-based page number from the address; anything that is not a whole number from 1 is page 1. */
export function parsePageParam(value: string | null): number {
  if (value === null || !/^\d{1,6}$/.test(value)) return 1;
  const page = Number(value);
  return page >= 1 && page <= MAX_PAGE ? page : 1;
}

/** The query string for a view of the list; a default (page 1, no file) is left out. */
export function buildQuery(page: number, fileId: string | null): string {
  const params = new URLSearchParams();
  if (fileId !== null) params.set("file", fileId);
  if (page > 1) params.set("page", String(page));
  const query = params.toString();
  return query === "" ? "" : `?${query}`;
}

/** The id of the link that opens a file's details, so focus can return to it when they close. */
export function fileLinkId(fileId: string): string {
  return `file-link-${fileId}`;
}

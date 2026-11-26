import { BUTTON } from "./styles";

interface PaginationProps {
  /** 1-based. */
  page: number;
  pageSize: number;
  total: number;
  /** The last page the API will serve, when it limits how deep results can be browsed. */
  maxPage?: number;
  /** What a screen reader calls this navigation. Several lists on one screen each need a name of their own. */
  label?: string;
  onPageChange: (page: number) => void;
}

export default function Pagination({
  page,
  pageSize,
  total,
  maxPage = Number.POSITIVE_INFINITY,
  label = "Pagination",
  onPageChange,
}: PaginationProps) {
  if (total <= 0) return null;

  const first = (page - 1) * pageSize + 1;
  const last = Math.min(page * pageSize, total);
  const hasMore = page * pageSize < total;
  const atLimit = page >= maxPage;

  return (
    <nav aria-label={label} className="flex flex-wrap items-center justify-between gap-3 text-sm">
      <p className="text-ink-200">
        Showing {first}–{last} of {total}
      </p>
      <div className="flex items-center gap-2">
        <button
          type="button"
          className={BUTTON}
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          Previous
        </button>
        <button
          type="button"
          className={BUTTON}
          disabled={!hasMore || atLimit}
          onClick={() => onPageChange(page + 1)}
        >
          Next
        </button>
      </div>
      {hasMore && atLimit ? (
        <p className="w-full text-ink-300">
          Only the first {maxPage * pageSize} results can be browsed. Narrow the filters to see the
          rest.
        </p>
      ) : null}
    </nav>
  );
}

import { useCallback, useId, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router";

import ErrorNotice from "../components/ErrorNotice";
import IndicatorTable from "../components/intel/IndicatorTable";
import LoadingNote from "../components/LoadingNote";
import Pagination from "../components/Pagination";
import { BUTTON, FIELD, LINK } from "../components/styles";
import { CLASSIFICATIONS_BY_SEVERITY, CLASSIFICATION_META } from "../features/intel/classification";
import {
  MAX_PAGE,
  MAX_SEARCH_LENGTH,
  PAGE_SIZE,
  type IndicatorFilters,
  hasActiveFilters,
  readFilters,
  toQuery,
  writeFilters,
} from "../features/intel/filters";
import { INDICATOR_TYPE_LABELS } from "../features/intel/labels";
import { useApiResource } from "../hooks/useApiResource";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { listIndicators } from "../services/intelService";
import { INDICATOR_TYPES } from "../types/intel";

interface Option {
  value: string;
  label: string;
}

const TYPE_OPTIONS: Option[] = [
  { value: "", label: "All types" },
  ...INDICATOR_TYPES.map((type) => ({ value: type, label: INDICATOR_TYPE_LABELS[type] })),
];

const CLASSIFICATION_OPTIONS: Option[] = [
  { value: "", label: "All classifications" },
  ...CLASSIFICATIONS_BY_SEVERITY.map((classification) => ({
    value: classification,
    label: CLASSIFICATION_META[classification].label,
  })),
];

const SORT_OPTIONS: Option[] = [
  { value: "recent", label: "Most recently checked" },
  { value: "risk", label: "Highest risk first" },
];

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string;
  value: string;
  options: readonly Option[];
  onChange: (value: string) => void;
}) {
  const id = useId();
  return (
    <div>
      <label htmlFor={id} className="block text-sm font-medium text-slate-200">
        {label}
      </label>
      <select
        id={id}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className={`${FIELD} mt-1`}
      >
        {options.map((option) => (
          <option key={option.value} value={option.value}>
            {option.label}
          </option>
        ))}
      </select>
    </div>
  );
}

/** Keeps what is being typed to itself until the analyst searches, so each keystroke is not a request. */
function SearchBox({ initial, onSearch }: { initial: string; onSearch: (text: string) => void }) {
  const [draft, setDraft] = useState(initial);
  const id = useId();
  return (
    <form
      role="search"
      onSubmit={(event) => {
        event.preventDefault();
        onSearch(draft);
      }}
      className="flex items-end gap-2"
    >
      <div className="min-w-0 flex-1">
        <label htmlFor={id} className="block text-sm font-medium text-slate-200">
          Search
        </label>
        <input
          id={id}
          type="search"
          value={draft}
          onChange={(event) => setDraft(event.target.value)}
          maxLength={MAX_SEARCH_LENGTH}
          autoComplete="off"
          spellCheck={false}
          placeholder="Part of an address, domain, URL or hash"
          className={`${FIELD} mt-1`}
        />
      </div>
      <button type="submit" className={BUTTON}>
        Search
      </button>
    </form>
  );
}

export default function IndicatorsPage() {
  useDocumentTitle("Indicators");
  const [searchParams, setSearchParams] = useSearchParams();

  // The address bar is the source of truth, so filters survive reloads, back and sharing a link.
  const queryString = searchParams.toString();
  const filters = useMemo(() => readFilters(new URLSearchParams(queryString)), [queryString]);
  const load = useCallback(
    (signal: AbortSignal) => listIndicators(toQuery(filters), signal),
    [filters],
  );
  const { state, reload } = useApiResource(load);

  const update = (changes: Partial<IndicatorFilters>) =>
    setSearchParams(writeFilters({ ...filters, page: 1, ...changes }));
  const goToPage = (page: number) => setSearchParams(writeFilters({ ...filters, page }));
  const reset = () => setSearchParams(new URLSearchParams());

  const filtered = hasActiveFilters(filters);
  const total = state.status === "success" ? state.data.total : null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Indicators</h1>
        <p className="mt-1 text-sm text-slate-400">
          Every indicator that has been investigated. Open one to see each provider&apos;s answer.
        </p>
      </div>

      <div className="space-y-3">
        <SearchBox
          key={filters.q}
          initial={filters.q}
          onSearch={(text) => update({ q: text.trim() })}
        />
        <div className="flex flex-wrap items-end gap-3">
          <Select
            label="Type"
            value={filters.type}
            options={TYPE_OPTIONS}
            onChange={(value) => update({ type: value as IndicatorFilters["type"] })}
          />
          <Select
            label="Classification"
            value={filters.classification}
            options={CLASSIFICATION_OPTIONS}
            onChange={(value) =>
              update({ classification: value as IndicatorFilters["classification"] })
            }
          />
          <Select
            label="Sort by"
            value={filters.sort}
            options={SORT_OPTIONS}
            onChange={(value) => update({ sort: value as IndicatorFilters["sort"] })}
          />
          {filtered ? (
            <button type="button" onClick={reset} className={BUTTON}>
              Reset filters
            </button>
          ) : null}
        </div>
      </div>

      <p role="status" className="sr-only">
        {total === null ? "" : `${total} ${total === 1 ? "indicator" : "indicators"} found.`}
      </p>

      {state.status === "loading" ? <LoadingNote>Loading indicators…</LoadingNote> : null}
      {state.status === "error" ? <ErrorNotice error={state.error} onRetry={reload} /> : null}

      {state.status === "success" ? (
        state.data.items.length > 0 ? (
          <div className="space-y-4">
            <IndicatorTable
              indicators={state.data.items}
              caption={`Indicators, sorted by ${filters.sort === "risk" ? "highest risk" : "most recent check"}`}
            />
            <Pagination
              page={filters.page}
              pageSize={PAGE_SIZE}
              total={state.data.total}
              maxPage={MAX_PAGE}
              onPageChange={goToPage}
            />
          </div>
        ) : (
          <div className="rounded-lg border border-slate-800 bg-slate-900 p-5 text-sm text-slate-300">
            {state.data.total > 0 ? (
              <>
                <p>This page has no results.</p>
                <button type="button" onClick={() => goToPage(1)} className={`${BUTTON} mt-3`}>
                  Go to the first page
                </button>
              </>
            ) : filtered ? (
              <>
                <p>No indicators match these filters.</p>
                <button type="button" onClick={reset} className={`${BUTTON} mt-3`}>
                  Reset filters
                </button>
              </>
            ) : (
              <>
                <p>No indicators have been investigated yet.</p>
                <Link to="/investigate" className={`${LINK} mt-2 inline-block`}>
                  Investigate one now
                </Link>
              </>
            )}
          </div>
        )
      ) : null}
    </div>
  );
}

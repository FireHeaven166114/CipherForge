import { PAGE_SIZE } from "../../features/files/query";
import { plural } from "../../features/intel/format";
import type { LiveState } from "../../hooks/useLiveResource";
import type { FileList as FileListData, StoredFile } from "../../types/files";
import ErrorNotice from "../ErrorNotice";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import Pagination from "../Pagination";
import { BUTTON } from "../styles";
import FileList from "./FileList";

interface FileListPanelProps {
  state: LiveState<FileListData>;
  page: number;
  selectedId: string | null;
  hrefFor: (id: string) => string;
  onPageChange: (page: number) => void;
  onDelete: (file: StoredFile) => void;
  onRefresh: () => void;
}

/** The person's files, newest first, with the states of a list that is loading, failed or empty. */
export default function FileListPanel({
  state,
  page,
  selectedId,
  hrefFor,
  onPageChange,
  onDelete,
  onRefresh,
}: FileListPanelProps) {
  if (state.status === "loading") return <LoadingNote>Loading files…</LoadingNote>;
  if (state.status === "error") return <ErrorNotice error={state.error} onRetry={onRefresh} />;

  const { items, total } = state.data;

  return (
    <>
      {state.refreshError ? <ErrorNotice error={state.refreshError} onRetry={onRefresh} /> : null}

      {items.length === 0 ? (
        <Panel title="Your files" code="VLT" bodyClassName="p-6">
          {total > 0 ? (
            <>
              <p>This page has no files.</p>
              <button type="button" onClick={() => onPageChange(1)} className={`${BUTTON} mt-3`}>
                Go to the first page
              </button>
            </>
          ) : (
            <p>No files have been uploaded yet. Upload one above to encrypt it and share it.</p>
          )}
        </Panel>
      ) : (
        <Panel
          title="Your files"
          code="VLT"
          bodyClassName="p-0"
          actions={<p className="font-mono text-xs text-cipher">{plural(total, "file")} stored</p>}
        >
          <FileList files={items} selectedId={selectedId} hrefFor={hrefFor} onDelete={onDelete} />
          <div className="border-t border-ink-700/70 px-4 py-3">
            <Pagination page={page} pageSize={PAGE_SIZE} total={total} onPageChange={onPageChange} />
          </div>
        </Panel>
      )}
    </>
  );
}

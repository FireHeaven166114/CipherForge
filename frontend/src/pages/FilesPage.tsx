import { useCallback, useEffect, useRef, useState } from "react";
import { useSearchParams } from "react-router";

import ErrorNotice from "../components/ErrorNotice";
import DeleteFileDialog from "../components/files/DeleteFileDialog";
import FileDetailPanel from "../components/files/FileDetailPanel";
import FileListPanel from "../components/files/FileListPanel";
import FileUploadPanel from "../components/files/FileUploadPanel";
import NotConfiguredNotice from "../components/files/NotConfiguredNotice";
import PageHeader from "../components/hud/PageHeader";
import LoadingNote from "../components/LoadingNote";
import { BUTTON } from "../components/styles";
import {
  PAGE_SIZE,
  buildQuery,
  fileLinkId,
  parseFileParam,
  parsePageParam,
} from "../features/files/query";
import { useApiResource } from "../hooks/useApiResource";
import { useDocumentTitle } from "../hooks/useDocumentTitle";
import { useFileAction } from "../hooks/useFileAction";
import { useLiveResource } from "../hooks/useLiveResource";
import { deleteStoredFile, getFileStatus, listFiles } from "../services/filesService";
import type { FileFeatureStatus, StoredFile } from "../types/files";

/** The part of the page that needs the server's limits, so it only exists once they are known. */
function FilesWorkspace({ status }: { status: FileFeatureStatus }) {
  const [searchParams, setSearchParams] = useSearchParams();
  // The address bar is the source of truth, so the open file and the page survive reloads and sharing.
  const page = parsePageParam(searchParams.get("page"));
  const selectedId = parseFileParam(searchParams.get("file"));
  // A file named by the address when the page opened is not "opened" by the person, so it keeps focus still.
  const [initialId] = useState(selectedId);

  const loadList = useCallback(
    (signal: AbortSignal) => listFiles({ limit: PAGE_SIZE, offset: (page - 1) * PAGE_SIZE }, signal),
    [page],
  );
  const list = useLiveResource(loadList, 0);
  const deletion = useFileAction();
  const [deleteTarget, setDeleteTarget] = useState<StoredFile | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const noticeRef = useRef<HTMLDivElement>(null);
  const workspace = useRef<HTMLDivElement>(null);

  // The row that opened the dialog is usually gone once the list reloads, and focus would be lost
  // with it. The notice is a steady place to put it.
  useEffect(() => {
    if (notice !== null) noticeRef.current?.focus();
  }, [notice]);

  const total = list.state.status === "ready" ? list.state.data.total : 0;
  const go = (nextPage: number, fileId: string | null) =>
    setSearchParams(new URLSearchParams(buildQuery(nextPage, fileId)));
  const hrefFor = (id: string) => buildQuery(page, id);

  function closeDetail() {
    const closing = selectedId;
    go(page, null);
    // Back to the row that opened it, or to the page when that row is on another page.
    const row = closing === null ? null : document.getElementById(fileLinkId(closing));
    (row ?? workspace.current)?.focus();
  }

  function handleUploaded() {
    if (page === 1) list.refresh();
    else go(1, selectedId);
  }

  function askToDelete(file: StoredFile) {
    deletion.reset();
    setDeleteTarget(file);
  }

  function cancelDelete() {
    deletion.reset();
    setDeleteTarget(null);
  }

  async function confirmDelete() {
    if (deleteTarget === null) return;
    const target = deleteTarget;
    const deleted = await deletion.run(() => deleteStoredFile(target.id));
    // A failure leaves the dialog open, showing why, so the person can try again or give up.
    if (deleted === null) return;

    setDeleteTarget(null);
    setNotice(`${target.name} was deleted. Every link made for it stopped working.`);
    // This page may now be past the end of the list: go to the last page that still has files.
    const lastPage = Math.max(1, Math.ceil((total - 1) / PAGE_SIZE));
    const nextPage = Math.min(page, lastPage);
    const nextFile = selectedId === target.id ? null : selectedId;
    if (nextPage !== page || nextFile !== selectedId) go(nextPage, nextFile);
    list.refresh();
  }

  return (
    <div ref={workspace} tabIndex={-1} className="space-y-6 focus:outline-none">
      {status.configured ? null : <NotConfiguredNotice />}

      <FileUploadPanel status={status} fileHref={hrefFor} onUploaded={handleUploaded} />

      {notice !== null ? (
        <div
          ref={noticeRef}
          role="status"
          tabIndex={-1}
          className="cf-plate flex flex-wrap items-center justify-between gap-3 rounded-ui border border-ok/50 p-4 text-sm text-ink-100 [--plate:var(--color-ok)]"
        >
          <p className="flex min-w-0 items-center gap-2">
            <span aria-hidden="true" className="text-ok">
              ✓
            </span>
            <span className="min-w-0 break-words">{notice}</span>
          </p>
          <button type="button" onClick={() => setNotice(null)} className={BUTTON}>
            Dismiss
          </button>
        </div>
      ) : null}

      <FileListPanel
        state={list.state}
        page={page}
        selectedId={selectedId}
        hrefFor={hrefFor}
        onPageChange={(next) => go(next, selectedId)}
        onDelete={askToDelete}
        onRefresh={list.refresh}
      />

      {selectedId === null ? null : (
        <FileDetailPanel
          key={selectedId}
          fileId={selectedId}
          status={status}
          focusOnOpen={selectedId !== initialId}
          onChanged={list.refresh}
          onClose={closeDetail}
          onDelete={askToDelete}
        />
      )}

      <DeleteFileDialog
        file={deleteTarget}
        busy={deletion.busy}
        error={deletion.error}
        onConfirm={() => void confirmDelete()}
        onCancel={cancelDelete}
      />
    </div>
  );
}

export default function FilesPage() {
  useDocumentTitle("Files");
  const { state, reload } = useApiResource(getFileStatus);

  return (
    <div className="space-y-6">
      <PageHeader
        code="MOD-06 · ENCRYPTED VAULT"
        title="Files"
        description="Encrypt a file, keep it in the vault and share it through links that expire, run out of downloads or can be revoked."
      />

      {state.status === "loading" ? (
        <LoadingNote>Checking whether encrypted files are available…</LoadingNote>
      ) : null}
      {state.status === "error" ? <ErrorNotice error={state.error} onRetry={reload} /> : null}
      {state.status === "success" ? <FilesWorkspace status={state.data} /> : null}
    </div>
  );
}

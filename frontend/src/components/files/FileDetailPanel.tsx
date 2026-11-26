import { useCallback, useEffect, useRef, useState } from "react";

import { shortId } from "../../features/files/labels";
import { buildShareLink } from "../../features/files/link";
import { useFileAction } from "../../hooks/useFileAction";
import { useLiveResource } from "../../hooks/useLiveResource";
import { getFileActivity, getStoredFile, revokeShare } from "../../services/filesService";
import type { FileFeatureStatus, Share, ShareCreated, StoredFile } from "../../types/files";
import ErrorNotice from "../ErrorNotice";
import Panel from "../hud/Panel";
import LoadingNote from "../LoadingNote";
import { BUTTON } from "../styles";
import CreateShareForm from "./CreateShareForm";
import FileActivityPanel from "./FileActivityPanel";
import FileSummary from "./FileSummary";
import RevokeShareDialog from "./RevokeShareDialog";
import ShareLinkPanel from "./ShareLinkPanel";
import ShareList from "./ShareList";

interface FileDetailPanelProps {
  fileId: string;
  status: FileFeatureStatus;
  /** True when the person just opened this file, so focus moves to it. A deep link leaves focus alone. */
  focusOnOpen: boolean;
  /** Called after a link is made or revoked, because the file list shows how many links a file has. */
  onChanged: () => void;
  onClose: () => void;
  onDelete: (file: StoredFile) => void;
}

/** The link just made. It lives here, in memory, until it is hidden or the file is closed. */
interface IssuedLink {
  link: string;
  share: Share;
}

function blockedReason(file: StoredFile, status: FileFeatureStatus): string | null {
  if (file.status === "corrupt") return "This file failed its integrity check, so it cannot be shared.";
  if (!status.configured) return "Sharing is switched off until the server has a master key.";
  return null;
}

/**
 * One file, opened: what it is, the links made for it (with revoking), a form for a new link, and
 * its activity. The page keys this by file, so moving to another file drops any link shown here.
 */
export default function FileDetailPanel({
  fileId,
  status,
  focusOnOpen,
  onChanged,
  onClose,
  onDelete,
}: FileDetailPanelProps) {
  const loadDetail = useCallback((signal: AbortSignal) => getStoredFile(fileId, signal), [fileId]);
  const loadActivity = useCallback((signal: AbortSignal) => getFileActivity(fileId, signal), [fileId]);
  const detail = useLiveResource(loadDetail, 0);
  const activity = useLiveResource(loadActivity, 0);
  const revoke = useFileAction();
  const [issued, setIssued] = useState<IssuedLink | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<Share | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const heading = useRef<HTMLHeadingElement>(null);
  const noticeRef = useRef<HTMLDivElement>(null);
  const createArea = useRef<HTMLDivElement>(null);
  const focused = useRef(false);

  const { state } = detail;
  const ready = state.status === "ready";

  useEffect(() => {
    if (!focusOnOpen || !ready || focused.current) return;
    focused.current = true;
    heading.current?.focus();
  }, [focusOnOpen, ready]);

  useEffect(() => {
    if (notice !== null) noticeRef.current?.focus();
  }, [notice]);

  function refreshAll() {
    detail.refresh();
    activity.refresh();
    onChanged();
  }

  function handleCreated(created: ShareCreated) {
    setIssued({ link: buildShareLink(created.path), share: created.share });
    setNotice(null);
    refreshAll();
  }

  function hideLink() {
    setIssued(null);
    createArea.current?.focus();
  }

  function cancelRevoke() {
    setRevokeTarget(null);
    revoke.reset();
  }

  async function confirmRevoke() {
    if (revokeTarget === null) return;
    const target = revokeTarget;
    const revoked = await revoke.run(() => revokeShare(fileId, target.id));
    if (revoked === null) return;
    setRevokeTarget(null);
    setNotice(`Link ${shortId(target.id)} was revoked. It no longer works.`);
    refreshAll();
  }

  if (state.status === "loading") {
    return (
      <Panel title="File details" code="FIL">
        <LoadingNote>Loading the file…</LoadingNote>
      </Panel>
    );
  }

  if (state.status === "error") {
    const missing = state.error.status === 404;
    return (
      <Panel title="File details" code="FIL">
        {missing ? (
          <div className="space-y-3">
            <p role="alert" className="text-ink-100">
              This file no longer exists. It may have been deleted.
            </p>
            <button
              type="button"
              onClick={() => {
                onChanged();
                onClose();
              }}
              className={BUTTON}
            >
              Close
            </button>
          </div>
        ) : (
          <ErrorNotice error={state.error} onRetry={detail.refresh} />
        )}
      </Panel>
    );
  }

  const { data: file, refreshError } = state;

  return (
    <div className="space-y-4">
      <FileSummary file={file} headingRef={heading} onClose={onClose} onDelete={onDelete} />

      <Panel title="Share links" code="LNK" bodyClassName="p-0">
        {notice === null ? null : (
          <div
            ref={noticeRef}
            role="status"
            tabIndex={-1}
            className="cf-plate m-4 flex flex-wrap items-center justify-between gap-3 rounded-ui border border-ok/50 p-3 text-sm text-ink-100 [--plate:var(--color-ok)]"
          >
            <p className="flex items-center gap-2">
              <span aria-hidden="true" className="text-ok">
                ✓
              </span>
              {notice}
            </p>
            <button type="button" onClick={() => setNotice(null)} className={BUTTON}>
              Dismiss
            </button>
          </div>
        )}
        {refreshError ? (
          <div className="p-4">
            <ErrorNotice error={refreshError} onRetry={detail.refresh} />
          </div>
        ) : null}
        {file.shares.length === 0 ? (
          <p className="p-4">No links have been made for this file yet. Create the first one below.</p>
        ) : (
          <ShareList shares={file.shares} onRevoke={setRevokeTarget} />
        )}
      </Panel>

      <Panel title="Create a share link" code="NEW">
        <div ref={createArea} tabIndex={-1} className="space-y-4 focus:outline-none">
          {issued === null ? null : (
            <ShareLinkPanel key={issued.share.id} link={issued.link} share={issued.share} onDismiss={hideLink} />
          )}
          <CreateShareForm
            fileId={file.id}
            status={status}
            blockedReason={blockedReason(file, status)}
            onCreated={handleCreated}
          />
        </div>
      </Panel>

      <FileActivityPanel state={activity.state} onRefresh={activity.refresh} />

      <RevokeShareDialog
        share={revokeTarget}
        busy={revoke.busy}
        error={revoke.error}
        onConfirm={() => void confirmRevoke()}
        onCancel={cancelRevoke}
      />
    </div>
  );
}

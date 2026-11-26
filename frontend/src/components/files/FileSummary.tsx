import type { RefObject } from "react";

import { FILE_STATE_META, describeLinks } from "../../features/files/labels";
import { formatBytes } from "../../features/units";
import type { StoredFileDetail } from "../../types/files";
import DateTime from "../DateTime";
import FactList from "../FactList";
import { CloseIcon, TrashIcon } from "../hud/Icons";
import Panel from "../hud/Panel";
import StatusBadge from "../StatusBadge";
import { BUTTON, DANGER_BUTTON } from "../styles";

interface FileSummaryProps {
  file: StoredFileDetail;
  /** The file's name, which takes focus when the person opens the file. */
  headingRef: RefObject<HTMLHeadingElement | null>;
  onClose: () => void;
  onDelete: (file: StoredFileDetail) => void;
}

/** What is known about one stored file. Its name is text from the API and is only ever shown as text. */
export default function FileSummary({ file, headingRef, onClose, onDelete }: FileSummaryProps) {
  const state = FILE_STATE_META[file.status];

  return (
    <Panel
      title="File details"
      code="FIL"
      actions={
        <button type="button" onClick={onClose} className={BUTTON}>
          <CloseIcon className="size-4" />
          Close
        </button>
      }
    >
      <h3
        ref={headingRef}
        tabIndex={-1}
        className="break-all font-mono text-base font-semibold text-ink-50 focus:outline-none"
      >
        {file.name}
      </h3>

      {file.status === "corrupt" ? (
        <div
          role="note"
          className="cf-plate mt-3 rounded-ui border border-crit/60 p-3 text-sm text-ink-100 [--plate:var(--color-crit)]"
        >
          <p className="flex items-center gap-2 font-semibold text-crit">
            <span aria-hidden="true">✕</span>
            Integrity problem
          </p>
          <p className="mt-1">
            This file failed its integrity check, so CipherForge will not release it and it cannot be
            shared. Links made for it already answer with an error. Delete it and upload the original
            again.
          </p>
        </div>
      ) : null}

      <div className="mt-3">
        <FactList
          facts={[
            { label: "Size", value: formatBytes(file.size_bytes) },
            { label: "Uploaded", value: <DateTime value={file.created_at} /> },
            { label: "State", value: <StatusBadge tone={state.tone}>{state.label}</StatusBadge> },
            { label: "Encryption", value: file.algorithm },
            { label: "Links", value: describeLinks(file) },
          ]}
        />
      </div>

      <div className="mt-4">
        <button type="button" onClick={() => onDelete(file)} className={DANGER_BUTTON}>
          <TrashIcon className="size-4" />
          Delete file
        </button>
      </div>
    </Panel>
  );
}

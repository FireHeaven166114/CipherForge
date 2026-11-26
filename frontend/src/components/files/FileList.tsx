import { Link } from "react-router";

import { FILE_STATE_META, describeLinks } from "../../features/files/labels";
import { fileLinkId } from "../../features/files/query";
import { formatBytes } from "../../features/units";
import type { StoredFile } from "../../types/files";
import DateTime from "../DateTime";
import { TrashIcon } from "../hud/Icons";
import StatusBadge from "../StatusBadge";
import { BUTTON, LABEL, LINK } from "../styles";

const HEADER = `px-4 py-3 ${LABEL}`;

interface FileListProps {
  files: readonly StoredFile[];
  /** The file whose details are open, if any. */
  selectedId: string | null;
  /** The address that opens a file's details. */
  hrefFor: (id: string) => string;
  onDelete: (file: StoredFile) => void;
}

export default function FileList({ files, selectedId, hrefFor, onDelete }: FileListProps) {
  return (
    <div className="relative overflow-x-auto">
      <table className="w-full min-w-[44rem] text-left text-sm">
        <caption className="sr-only">Encrypted files, newest first</caption>
        <thead className="border-b border-ink-600 bg-ink-900/70">
          <tr>
            <th scope="col" className={`${HEADER} pl-5`}>
              File
            </th>
            <th scope="col" className={`${HEADER} text-right`}>
              Size
            </th>
            <th scope="col" className={HEADER}>
              Uploaded
            </th>
            <th scope="col" className={HEADER}>
              State
            </th>
            <th scope="col" className={HEADER}>
              Share links
            </th>
            <th scope="col" className="w-12 py-3 pl-0 pr-3">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-700/60">
          {files.map((file) => {
            const selected = file.id === selectedId;
            const corrupt = file.status === "corrupt";
            const state = FILE_STATE_META[file.status];
            return (
              <tr
                key={file.id}
                className={`align-top transition hover:bg-cipher/5 ${selected ? "bg-cipher/10" : ""}`}
              >
                <th scope="row" className="relative max-w-xs py-3 pl-5 pr-4 font-normal">
                  <span
                    aria-hidden="true"
                    className={`absolute inset-y-2 left-0 w-0.5 rounded-full ${
                      selected ? "bg-cipher" : corrupt ? "bg-bad" : "bg-ink-500"
                    }`}
                  />
                  <Link
                    id={fileLinkId(file.id)}
                    to={hrefFor(file.id)}
                    aria-current={selected ? "true" : undefined}
                    className={`${LINK} break-all`}
                  >
                    {file.name}
                  </Link>
                </th>
                <td className="px-4 py-3 text-right font-mono tabular-nums">{formatBytes(file.size_bytes)}</td>
                <td className="px-4 py-3">
                  <DateTime value={file.created_at} stacked />
                </td>
                <td className="px-4 py-3">
                  <StatusBadge tone={state.tone}>{state.label}</StatusBadge>
                </td>
                <td className="px-4 py-3">
                  {corrupt ? "Cannot be shared" : describeLinks(file)}
                </td>
                <td className="py-2 pl-0 pr-3">
                  <button
                    type="button"
                    title="Delete this file"
                    onClick={() => onDelete(file)}
                    className={`${BUTTON} !px-2 hover:!border-crit/60 hover:!text-crit`}
                  >
                    <TrashIcon className="size-4" />
                    <span className="sr-only">Delete {file.name}</span>
                  </button>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

import { SHARE_STATUS_META, shortId } from "../../features/files/labels";
import { plural } from "../../features/intel/format";
import type { Share } from "../../types/files";
import DateTime from "../DateTime";
import { LockIcon } from "../hud/Icons";
import StatusBadge from "../StatusBadge";
import { BUTTON, LABEL } from "../styles";

const HEADER = `px-4 py-3 ${LABEL}`;

interface ShareListProps {
  shares: readonly Share[];
  onRevoke: (share: Share) => void;
}

/** The links made for one file. A link's address is never here: it was shown once, when it was made. */
export default function ShareList({ shares, onRevoke }: ShareListProps) {
  return (
    <div
      className="relative overflow-x-auto"
      role="region"
      aria-label="Share links for this file, scrolls sideways"
      tabIndex={0}
    >
      <table className="w-full min-w-[56rem] text-left text-sm">
        <caption className="sr-only">Share links for this file, newest first</caption>
        <thead className="border-b border-ink-600 bg-ink-900/70">
          <tr>
            <th scope="col" className={HEADER}>
              Link
            </th>
            <th scope="col" className={HEADER}>
              Created
            </th>
            <th scope="col" className={HEADER}>
              Expires
            </th>
            <th scope="col" className={HEADER}>
              Downloads
            </th>
            <th scope="col" className={HEADER}>
              Last download
            </th>
            <th scope="col" className={HEADER}>
              Revoked
            </th>
            <th scope="col" className="w-12 py-3 pl-0 pr-3">
              <span className="sr-only">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody className="divide-y divide-ink-700/60">
          {shares.map((share) => {
            const status = SHARE_STATUS_META[share.status];
            return (
              <tr key={share.id} className="align-top transition hover:bg-cipher/5">
                <th scope="row" className="px-4 py-3 font-normal">
                  <div className="flex flex-wrap items-center gap-2">
                    <StatusBadge tone={status.tone}>{status.label}</StatusBadge>
                    {share.password_protected ? (
                      <span className="inline-flex items-center gap-1 rounded-chip border border-ink-500 bg-ink-800/70 px-2 py-1 text-xs text-ink-200">
                        <LockIcon className="size-3" />
                        Password
                      </span>
                    ) : null}
                  </div>
                  <p className="mt-1 font-mono text-xs text-ink-300">
                    <span className="sr-only">Link</span> {shortId(share.id)}
                  </p>
                </th>
                <td className="px-4 py-3">
                  <DateTime value={share.created_at} stacked />
                </td>
                <td className="px-4 py-3">
                  <DateTime value={share.expires_at} stacked />
                </td>
                <td className="px-4 py-3">
                  <p className="font-mono tabular-nums text-ink-50">
                    {share.download_count} / {share.max_downloads} <span className="sr-only">used</span>
                  </p>
                  <p className="text-xs text-ink-300">{plural(share.downloads_remaining, "download")} left</p>
                </td>
                <td className="px-4 py-3">
                  <DateTime value={share.last_downloaded_at} fallback="Never" stacked />
                </td>
                <td className="px-4 py-3">
                  <DateTime value={share.revoked_at} fallback="Not revoked" stacked />
                </td>
                <td className="py-2 pl-0 pr-3">
                  <button
                    type="button"
                    disabled={share.status !== "active"}
                    onClick={() => onRevoke(share)}
                    className={`${BUTTON} hover:!border-crit/60 hover:!text-crit`}
                  >
                    Revoke <span className="sr-only">link {shortId(share.id)}</span>
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
